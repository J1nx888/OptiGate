package worker

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// gatewayResolveTimeout bounds how long ResolveGateway waits for a real
// ARP reply before giving up -- see that method's own comment for why
// this can't just block forever on the IPC dispatch path. 2s matches
// DefaultConfig's own poisoning-tick Interval: a generous ARP
// round-trip budget on a LAN, while still failing a stuck resolve fast
// enough that one unresponsive gateway doesn't wedge every subsequent
// replace_targets call.
const gatewayResolveTimeout = 2 * time.Second

// Worker runs the poisoning/restoration loop for one interface. It
// holds no controller-facing state at all (that's internal/ipc's job,
// glued together in cmd/pp-arp-worker/main.go) -- callers drive it
// purely through ApplyGeneration and Shutdown.
type Worker struct {
	sender  ARPSender
	selfMAC net.HardwareAddr
	cfg     Config

	mu sync.Mutex
	rg *runningGen // nil if nothing is currently running

	sentCounters sync.Map // ip.String() -> *uint64

	// consecutiveSendFailures counts ARPSender.Reply() failures since
	// the most recent success, across every target/direction combined
	// -- reset to 0 on any successful send, incremented on any failed
	// one. Reported to the controller in "heartbeat_ack" messages (see
	// ConsecutiveSendFailures below) so a sustained failure (the
	// realistic case: the whole bound interface going down, which
	// fails every send regardless of target) surfaces as real
	// controller-visible health data instead of only a local log line
	// -- closing the gap sendGratuitousReply's own TODO comment used
	// to flag, confirmed live 2026-08-31 via a NIC-down test against a
	// properly-isolated veth harness: interception_runtime stayed
	// "running" throughout a real, sustained send-failure window
	// because nothing upstream of this field existed yet to report it.
	consecutiveSendFailures uint64
}

// runningGen tracks the one active generation's goroutine so
// ApplyGeneration/Shutdown can synchronously wait for it to actually
// stop (via stopped) before deciding what corrective ARPs, if any, to
// send -- see the ApplyGeneration doc comment for why this can't be
// left to the goroutine itself.
type runningGen struct {
	gen     Generation
	cancel  context.CancelFunc
	stopped chan struct{}
}

// New creates a Worker. selfMAC is the worker's own interface hardware
// address -- the MAC every poisoning reply claims ownership under.
func New(sender ARPSender, selfMAC net.HardwareAddr, cfg Config) *Worker {
	return &Worker{sender: sender, selfMAC: selfMAC, cfg: cfg}
}

// ApplyGeneration stops any in-flight generation and starts a new one.
//
// It deliberately does NOT send a blanket corrective pass for
// everything in the old generation: a target present in BOTH the old
// and new generation must stay continuously poisoned. Sending it a
// real-MAC "corrective" ARP here would race against the new
// generation's own poisoning ticks -- whichever finishes last wins,
// which could leave a still-in-scope device un-poisoned. Instead only
// targets that are leaving scope entirely (present in old, absent from
// new) get a corrective pass, computed by restorationSet.
func (w *Worker) ApplyGeneration(ctx context.Context, gen Generation) {
	w.mu.Lock()
	prev := w.rg
	genCtx, cancel := context.WithCancel(ctx)
	stopped := make(chan struct{})
	w.rg = &runningGen{gen: gen, cancel: cancel, stopped: stopped}
	w.mu.Unlock()

	if prev != nil {
		prev.cancel()
		<-prev.stopped // wait for the old ticker loop to actually stop before touching the wire again
		w.sendCorrective(restorationSet(prev.gen, gen))
	}

	go w.runGeneration(genCtx, stopped, gen)
}

// Shutdown cancels the active generation (if any) and blocks until a
// full corrective pass has been sent for every target in it. Callers
// (SIGTERM handling in main.go, the systemd ExecStop path, and lease
// expiry) must call this before the process exits or the worker is
// otherwise left unattended -- this is the concrete fail-open
// mechanism RoadMap.md requires.
func (w *Worker) Shutdown() {
	w.mu.Lock()
	rg := w.rg
	w.rg = nil
	w.mu.Unlock()

	if rg == nil {
		return // nothing was ever applied -- nothing to restore
	}
	rg.cancel()
	<-rg.stopped
	w.sendCorrective(correctiveSet{
		gateway:    rg.gen.Gateway,
		targets:    rg.gen.Targets,
		fullDuplex: rg.gen.FullDuplex,
	})
}

func (w *Worker) runGeneration(ctx context.Context, stopped chan struct{}, gen Generation) {
	defer close(stopped)

	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, t := range gen.Targets {
				// "gateway is at my MAC" -> told to the client.
				w.sendGratuitousReply(gen.Gateway.IP, w.selfMAC, t.IP, t.MAC)
				if gen.FullDuplex {
					// "client is at my MAC" -> told to the gateway.
					w.sendGratuitousReply(t.IP, w.selfMAC, gen.Gateway.IP, gen.Gateway.MAC)
				}
				w.incrementCounter(t.IP)
			}
		}
	}
}

func (w *Worker) sendGratuitousReply(senderIP net.IP, senderMAC net.HardwareAddr, dstIP net.IP, dstMAC net.HardwareAddr) {
	if err := w.sender.Reply(senderIP, senderMAC, dstIP, dstMAC); err != nil {
		atomic.AddUint64(&w.consecutiveSendFailures, 1)
		if w.cfg.OnSendError != nil {
			w.cfg.OnSendError(err)
		}
		return
	}
	// A single dropped frame doesn't tear down the whole generation (a
	// single successful send elsewhere in the same tick still resets
	// this to 0, which is deliberate -- see ConsecutiveSendFailures'
	// own doc comment for why a global, not per-target, counter is the
	// right granularity for what this is used for).
	atomic.StoreUint64(&w.consecutiveSendFailures, 0)
}

// ConsecutiveSendFailures returns how many ARPSender.Reply() calls
// have failed in a row since the most recent success, across every
// target/direction combined -- reported to the controller in
// "heartbeat_ack" messages (see cmd/pp-arp-worker/main.go's
// HandleHeartbeat) so it can escalate a sustained run of failures (the
// realistic case is the whole bound interface going down, which fails
// every send regardless of target) into a real fail_open report,
// rather than this only ever being visible as a local log line. A
// global rather than per-target counter is the right granularity here:
// the motivating failure mode (an interface going down) fails every
// send at once, and this field only needs to answer "is ARP
// transmission broken right now," not diagnose which specific target
// is affected -- ipc.GenerationApplied's own ResolutionFailures already
// covers per-target reporting at generation-apply time.
func (w *Worker) ConsecutiveSendFailures() uint64 {
	return atomic.LoadUint64(&w.consecutiveSendFailures)
}

// correctiveSet is what sendCorrective actually restores: a gateway
// and the specific targets that need the truth re-sent to them.
type correctiveSet struct {
	gateway    Target
	targets    []Target
	fullDuplex bool
}

// sendCorrective sends the truth -- the gateway's real MAC and each
// target's real MAC -- to every target in restore, repeated
// cfg.CorrectiveRepeats times with cfg.CorrectiveSpacing between
// rounds. Every path that stops poisoning a target (generation switch,
// shutdown, lease expiry) must route through this before that target
// is left unattended.
func (w *Worker) sendCorrective(restore correctiveSet) {
	if len(restore.targets) == 0 {
		return
	}
	for i := 0; i < w.cfg.CorrectiveRepeats; i++ {
		for _, t := range restore.targets {
			w.sendGratuitousReply(restore.gateway.IP, restore.gateway.MAC, t.IP, t.MAC)
			if restore.fullDuplex {
				w.sendGratuitousReply(t.IP, t.MAC, restore.gateway.IP, restore.gateway.MAC)
			}
		}
		if i < w.cfg.CorrectiveRepeats-1 {
			time.Sleep(w.cfg.CorrectiveSpacing)
		}
	}
}

// restorationSet computes which of prev's targets are NOT present in
// next (by IP) -- see the ApplyGeneration doc comment for why only
// this subset gets a corrective pass on a direct generation switch.
func restorationSet(prev, next Generation) correctiveSet {
	keep := make(map[string]bool, len(next.Targets))
	for _, t := range next.Targets {
		keep[t.IP.String()] = true
	}
	var leaving []Target
	for _, t := range prev.Targets {
		if !keep[t.IP.String()] {
			leaving = append(leaving, t)
		}
	}
	return correctiveSet{gateway: prev.Gateway, targets: leaving, fullDuplex: prev.FullDuplex}
}

func (w *Worker) incrementCounter(ip net.IP) {
	key := ip.String()
	v, _ := w.sentCounters.LoadOrStore(key, new(uint64))
	atomic.AddUint64(v.(*uint64), 1)
}

// SentCounters returns a snapshot of per-target sent-packet counts,
// reported to the controller in "heartbeat_ack" messages.
func (w *Worker) SentCounters() map[string]uint64 {
	out := make(map[string]uint64)
	w.sentCounters.Range(func(k, v any) bool {
		out[k.(string)] = atomic.LoadUint64(v.(*uint64))
		return true
	})
	return out
}

// ResolveGateway live-verifies gatewayIP's real hardware address via a
// genuine ARP exchange, bounded by gatewayResolveTimeout -- see the
// package-level ResolveGateway in safety.go for why this must never be
// satisfied from a cache. Exposed as a Worker method (rather than
// requiring callers to reach into Worker's private sender field) so
// cmd/pp-arp-worker/main.go's controllerHandler can re-verify the
// wire-supplied gateway MAC on every replace_targets call (added
// 2026-09-12: safety.go's own ResolveGateway had never actually been
// wired up to anything, found by code review the previous night).
//
// On timeout, the underlying ARPSender.Resolve() call is abandoned, not
// cancelled -- github.com/mdlayher/arp's Client.Resolve has no
// context/deadline parameter to cancel it early, so the goroutine below
// keeps running until that call itself eventually returns (or the
// process exits). This trades a small, bounded per-timeout goroutine
// leak for never hanging the IPC dispatch path indefinitely on an
// unresponsive gateway -- acceptable since a gateway that never answers
// ARP at all is itself a rare, abnormal condition, not something
// replace_targets calls will hit repeatedly in steady-state operation.
func (w *Worker) ResolveGateway(gatewayIP net.IP) (net.HardwareAddr, error) {
	type result struct {
		mac net.HardwareAddr
		err error
	}
	ch := make(chan result, 1)
	go func() {
		mac, err := ResolveGateway(w.sender, gatewayIP)
		ch <- result{mac, err}
	}()
	select {
	case r := <-ch:
		return r.mac, r.err
	case <-time.After(gatewayResolveTimeout):
		return nil, fmt.Errorf("resolving gateway %s timed out after %s", gatewayIP, gatewayResolveTimeout)
	}
}
