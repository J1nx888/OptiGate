// Command pp-arp-worker is the privileged ARP worker process described
// in RoadMap.md and docs/design/phase3-technical-design.md. It holds
// CAP_NET_RAW and nothing else; all policy/DB/reconciliation logic
// lives in the separate interception-controller process (not yet
// written), which drives this one exclusively over the Unix socket
// IPC protocol in internal/ipc/protocol.go.
//
// NOT YET BUILT OR TESTED -- see the design doc's header note. Verify
// internal/arpio's mdlayher/arp API usage against a real `go get`
// before the first build.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"

	"github.com/J1nx888/parental_proxy/phase3/arp-worker/internal/arpio"
	"github.com/J1nx888/parental_proxy/phase3/arp-worker/internal/ipc"
	"github.com/J1nx888/parental_proxy/phase3/arp-worker/internal/worker"
)

func main() {
	ifaceName := flag.String("iface", "", "LAN interface to bind to (required)")
	socketPath := flag.String("socket", "/run/optigate/arp-worker.sock", "controller IPC socket path")
	// -1 default (not 0) deliberately: 0 is root's real, legitimate UID, so
	// using it as the "not provided" sentinel would make this flag
	// silently un-settable to 0 -- found via a real integration test where
	// the controller happened to run as root in a container. flag.Uint
	// can't represent -1, hence Int here with an explicit range check
	// instead of Uint's implicit zero-value trap.
	controllerUID := flag.Int("controller-uid", -1, "UID the interception-controller process runs as (required, checked via SO_PEERCRED)")
	leaseMissedCycles := flag.Int("lease-missed-cycles", 5, "missed heartbeat cycles before entering repair-only mode")
	flag.Parse()

	if *ifaceName == "" || *controllerUID < 0 {
		log.Fatal("-iface and -controller-uid are both required")
	}

	ifi, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("resolve interface %s: %v", *ifaceName, err)
	}

	// Queried directly from the OS, not trusted from anything the
	// controller sends -- see controllerHandler.selfIP's own comment.
	selfIP, subnet, err := firstIPv4Addr(ifi)
	if err != nil {
		log.Fatalf("determine %s's own IPv4 address: %v", *ifaceName, err)
	}

	sender, err := arpio.Dial(ifi)
	if err != nil {
		log.Fatalf("dial ARP client on %s (needs CAP_NET_RAW): %v", *ifaceName, err)
	}
	defer sender.Close()

	cfg := worker.DefaultConfig() // placeholder constants -- see RoadMap.md section 8
	cfg.OnSendError = func(err error) {
		log.Printf("ARP send failed (worker keeps running, see worker.Config.OnSendError's own doc comment): %v", err)
	}
	w := worker.New(sender, ifi.HardwareAddr, cfg)

	h := &controllerHandler{worker: w, selfIP: selfIP, subnet: subnet}
	h.lease = worker.NewLeaseMonitor(cfg.Interval, *leaseMissedCycles, h.onLeaseExpired)
	defer h.lease.Stop()

	srv, err := ipc.Listen(*socketPath, uint32(*controllerUID), h)
	if err != nil {
		log.Fatalf("listen on %s: %v", *socketPath, err)
	}
	defer srv.Close()
	h.notifier = srv // see controllerHandler.notifier's own comment on this ordering

	go func() {
		if err := srv.Serve(); err != nil {
			log.Printf("ipc server stopped: %v", err)
		}
	}()

	if ok, notifyErr := daemon.SdNotify(false, daemon.SdNotifyReady); notifyErr != nil {
		log.Printf("sd_notify READY failed (non-fatal, likely not running under systemd): %v", notifyErr)
	} else if !ok {
		log.Print("sd_notify not supported here (not running under systemd) -- continuing without watchdog pings")
	} else {
		go watchdogLoop()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig

	log.Print("shutting down: sending corrective ARPs before exit")
	w.Shutdown() // fail-open: restores real ARP state for the current generation
}

func watchdogLoop() {
	interval, err := daemon.SdWatchdogEnabled(false)
	if err != nil || interval == 0 {
		return // WatchdogSec not set in the unit file -- nothing to do
	}
	ticker := time.NewTicker(interval / 3) // notify at ~3x the required rate, standard sd_notify practice
	defer ticker.Stop()
	for range ticker.C {
		_, _ = daemon.SdNotify(false, daemon.SdNotifyWatchdog)
	}
}

// controllerHandler implements ipc.Handler, translating IPC messages
// into worker.Worker calls and lease resets. This is glue code, not
// the interesting logic -- see internal/worker for that.
type controllerHandler struct {
	worker *worker.Worker
	lease  *worker.LeaseMonitor
	// selfIP/subnet (added 2026-09-02) are this worker's own bound
	// interface's IPv4 address/network, queried directly from the OS at
	// startup (see firstIPv4Addr) rather than trusted from anything the
	// controller sends -- used by HandleReplaceTargets to run every
	// candidate target through worker.ValidateTargets before it's ever
	// handed to ApplyGeneration. See that call site's own comment for
	// why bypass_v4 isn't checked here yet too.
	selfIP net.IP
	subnet *net.IPNet
	// notifier is set once, right after ipc.Listen returns (see main()
	// below) -- necessarily after this struct itself is constructed,
	// since ipc.Listen needs the handler as an argument. onLeaseExpired
	// only ever fires later, once the lease monitor's own timer expires
	// (at the earliest, one full lease duration after startup), so this
	// ordering is safe in practice; nil-checked below regardless.
	notifier *ipc.Server
}

func (h *controllerHandler) HandleReplaceTargets(m ipc.ReplaceTargets) []any {
	gwIP := net.ParseIP(m.Gateway.IP)
	gwMAC := parseMACOrNil(m.Gateway.MAC)
	if gwIP == nil || gwMAC == nil {
		// Fixed 2026-09-11, found by code review: a missing/malformed
		// gateway field used to flow straight into worker.ValidateTargets
		// as a nil net.IP -- net.IP.Equal against nil always returns
		// false, so every t.IP.Equal(gateway.IP) check silently returns
		// false too, defeating the is_gateway safety check for every
		// candidate in this generation instead of failing the request.
		// Fail closed instead, matching this project's own convention
		// (AGENTS.md "Everything is fail-closed by convention"): apply
		// nothing and report every candidate as a resolution failure, so
		// the controller can see this generation was rejected outright
		// rather than silently accepted with its safety check disabled.
		log.Printf("rejecting replace_targets generation %d: malformed or missing gateway (ip=%q mac=%q)",
			m.Generation, m.Gateway.IP, m.Gateway.MAC)
		return rejectGeneration(m)
	}

	// Fixed 2026-09-12, found by code review the previous night:
	// safety.go's own ResolveGateway (a genuine ARP exchange, never
	// satisfied from the OS neighbor cache) was never actually called
	// anywhere -- this worker trusted the wire-supplied gateway MAC
	// outright. Re-verified once per generation (not just at startup, so
	// a cache/config gone bad mid-run is still caught; not on an
	// independent timer, to avoid a second background goroutine for a
	// check that's naturally paced by how often targets actually
	// change), matching this project's own stated threat model: an
	// independently-confirmed live rogue ARP-spoofer already runs on the
	// production LAN, so a wrong gateway MAC reaching this worker (a
	// controller-side bug, or that same rogue spoofer having poisoned
	// whatever fed the controller) must not be blindly trusted here too.
	// A resolve failure/timeout and a confirmed mismatch are both
	// treated as fail-closed -- reject the whole generation rather than
	// poison anything based on a gateway this worker couldn't verify.
	resolvedMAC, err := h.worker.ResolveGateway(gwIP)
	if err != nil {
		log.Printf("rejecting replace_targets generation %d: could not live-verify gateway %s: %v",
			m.Generation, gwIP, err)
		return rejectGeneration(m)
	}
	if !bytes.Equal(resolvedMAC, gwMAC) {
		log.Printf("rejecting replace_targets generation %d: gateway %s resolved to %s over a real ARP exchange, "+
			"but the controller sent %s -- refusing to trust a mismatched gateway",
			m.Generation, gwIP, resolvedMAC, gwMAC)
		return rejectGeneration(m)
	}
	gw := worker.Target{IP: gwIP, MAC: gwMAC}

	var targets []worker.Target
	var failures []string
	for _, t := range m.Targets {
		ip := net.ParseIP(t.IP)
		mac := parseMACOrNil(t.MAC)
		if ip == nil || mac == nil {
			failures = append(failures, t.IP)
			continue
		}
		targets = append(targets, worker.Target{IP: ip, MAC: mac})
	}

	// Fixed 2026-09-02 (was a TODO, and dead-code review separately
	// found this simply wasn't being called at all): run every
	// candidate through worker.ValidateTargets before it's ever handed
	// to ApplyGeneration, so a controller-side bug or race can't make
	// this worker send poisoning ARPs claiming ownership of the gateway,
	// broadcast, multicast, or its own address -- see safety.go's own
	// doc comment.
	//
	// bypass_v4 is still NOT checked here (passing nil for that
	// parameter) -- unlike self/gateway/broadcast/multicast, which this
	// handler can determine entirely on its own (selfIP/subnet are
	// queried from the OS at startup, gw comes from this same message),
	// the bypass set is authoritative only on the controller's side
	// (device_bindings/devices.ignored) and isn't part of the
	// replace_targets wire schema today. Closing that residual gap
	// needs a new wire field threaded through
	// controller/ipc_client.py's replace_targets() and its callers, not
	// something to guess at here -- tracked as a separate follow-up.
	accepted, rejected := worker.ValidateTargets(h.selfIP, gw, h.subnet, nil, targets)
	for _, r := range rejected {
		log.Printf("rejected target %s (%s): %s", r.Target.IP, r.Target.MAC, r.Reason)
		failures = append(failures, r.Target.IP.String())
	}
	targets = accepted

	gen := worker.Generation{ID: m.Generation, Gateway: gw, Targets: targets, FullDuplex: m.FullDuplex}
	h.worker.ApplyGeneration(context.Background(), gen)
	h.lease.Rearm() // a fresh replace_targets is exactly the "must not auto-resume without an explicit new generation" trigger from the design doc

	return []any{ipc.GenerationApplied{
		V: ipc.ProtocolVersion, Op: "generation_applied",
		Generation: m.Generation, TargetCount: len(targets), ResolutionFailures: failures,
	}}
}

// rejectGeneration fails the whole generation closed: applies nothing,
// reporting every candidate target as a resolution failure. Shared by
// HandleReplaceTargets' two "the gateway itself can't be trusted" exits
// (malformed wire field; live ARP resolve failed or mismatched) -- see
// each call site's own comment for the specific reason, logged there
// before calling this.
func rejectGeneration(m ipc.ReplaceTargets) []any {
	failures := make([]string, 0, len(m.Targets))
	for _, t := range m.Targets {
		failures = append(failures, t.IP)
	}
	return []any{ipc.GenerationApplied{
		V: ipc.ProtocolVersion, Op: "generation_applied",
		Generation: m.Generation, TargetCount: 0, ResolutionFailures: failures,
	}}
}

func (h *controllerHandler) HandleHeartbeat(m ipc.Heartbeat) []any {
	h.lease.Heartbeat()
	return []any{ipc.HeartbeatAck{
		V: ipc.ProtocolVersion, Op: "heartbeat_ack",
		Sequence: m.Sequence, SentCounters: h.worker.SentCounters(),
		ConsecutiveSendFailures: h.worker.ConsecutiveSendFailures(),
	}}
}

func (h *controllerHandler) HandleShutdown(m ipc.ShutdownMsg) []any {
	h.worker.Shutdown()
	return nil
}

func (h *controllerHandler) onLeaseExpired() {
	log.Print("lease expired: no heartbeat received in time, entering repair-only mode")
	h.worker.Shutdown() // sends one corrective round and drops the stale generation, per the design doc's lease rule

	// Fixed 2026-09-02: this used to be the ENTIRE function -- a purely
	// local log line, with no way for the controller (or, through it,
	// the admin dashboard) to ever learn this happened at all. For a
	// household with an unchanging device list, controller/reconcile.py
	// only sends a fresh replace_targets (the only thing that re-arms
	// this lease) when desired state actually changes, so nothing would
	// ever prompt the worker to speak again -- interception silently and
	// permanently stopped while interception_runtime.mode kept reading
	// "running" forever. h.notifier is nil only in the narrow startup
	// window before ipc.Listen returns (see main(), below) -- lease
	// expiry can't fire before then, since LeaseMonitor needs at least
	// one full lease duration to elapse first, but this is checked
	// rather than assumed.
	if h.notifier != nil {
		err := h.notifier.Notify(ipc.Fault{
			V: ipc.ProtocolVersion, Op: "fault",
			Reason: "lease_expired", Action: "entering_repair_only_mode",
		})
		if err != nil {
			// No active connection to notify -- the controller is
			// already disconnected (it'll notice this same repair-only
			// state some other way, e.g. its own heartbeat timing out),
			// not a reason to treat this as a fatal worker-side error.
			log.Printf("could not notify controller of lease expiry (no active connection?): %v", err)
		}
	}
}

func parseMACOrNil(s string) net.HardwareAddr {
	mac, err := net.ParseMAC(s)
	if err != nil {
		return nil
	}
	return mac
}

// firstIPv4Addr returns ifi's own IPv4 address and subnet -- used to
// populate controllerHandler.selfIP/subnet so worker.ValidateTargets
// can reject a candidate target that is this worker's own address or
// that subnet's broadcast address (see safety.go's own doc comment on
// why that matters), without trusting either value from the
// controller. An interface can carry more than one address; the first
// IPv4 one found is used, matching this project's existing assumption
// elsewhere that the worker's LAN-facing interface has exactly one
// IPv4 address that matters.
func firstIPv4Addr(ifi *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("list addresses on %s: %w", ifi.Name, err)
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip4 := ipNet.IP.To4(); ip4 != nil {
			return ip4, ipNet, nil
		}
	}
	return nil, nil, fmt.Errorf("no IPv4 address found on %s", ifi.Name)
}
