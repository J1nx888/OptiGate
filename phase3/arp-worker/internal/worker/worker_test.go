package worker

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSender is a test double for ARPSender that just records every
// Reply call -- it lets the scheduling/switching logic in worker.go be
// verified with no real NIC, no CAP_NET_RAW, and no OS dependency.
type fakeSender struct {
	mu       sync.Mutex
	calls    []replyCall
	replyErr error // if non-nil, every Reply() call fails with this
}

type replyCall struct {
	senderIP  net.IP
	senderMAC net.HardwareAddr
	dstIP     net.IP
	dstMAC    net.HardwareAddr
}

func (f *fakeSender) Reply(senderIP net.IP, senderMAC net.HardwareAddr, dstIP net.IP, dstMAC net.HardwareAddr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, replyCall{senderIP, senderMAC, dstIP, dstMAC})
	return f.replyErr
}

func (f *fakeSender) Resolve(ip net.IP) (net.HardwareAddr, error) {
	return mustMAC("02:00:00:00:ff:ff"), nil
}

func (f *fakeSender) Close() error { return nil }

func (f *fakeSender) snapshot() []replyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]replyCall, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeSender) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func TestApplyGeneration_PoisonsWithOwnMAC(t *testing.T) {
	fs := &fakeSender{}
	selfMAC := mustMAC("02:00:00:00:00:01")
	w := New(fs, selfMAC, Config{Interval: 10 * time.Millisecond, CorrectiveRepeats: 1, CorrectiveSpacing: time.Millisecond})

	gw := Target{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC("02:00:00:00:00:02")}
	victim := Target{IP: net.ParseIP("192.168.1.21"), MAC: mustMAC("02:00:00:00:00:03")}
	gen := Generation{ID: 1, Gateway: gw, Targets: []Target{victim}, FullDuplex: true}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.ApplyGeneration(ctx, gen)
	time.Sleep(35 * time.Millisecond) // a few ticks

	calls := fs.snapshot()
	if len(calls) == 0 {
		t.Fatal("expected at least one poisoning ARP reply, got none")
	}
	for _, c := range calls {
		if c.senderMAC.String() != selfMAC.String() {
			t.Errorf("poisoning reply sender MAC = %s, want the worker's own MAC %s (never a real owner's during poisoning)", c.senderMAC, selfMAC)
		}
	}

	w.Shutdown()
	after := fs.snapshot()
	if len(after) <= len(calls) {
		t.Fatal("expected Shutdown to send at least one corrective ARP")
	}
	last := after[len(after)-1]
	if last.senderMAC.String() != gw.MAC.String() && last.senderMAC.String() != victim.MAC.String() {
		t.Errorf("corrective reply sender MAC = %s, want a real owner MAC (gateway %s or victim %s)", last.senderMAC, gw.MAC, victim.MAC)
	}
}

func TestApplyGeneration_OverlappingTargetStaysUninterrupted(t *testing.T) {
	fs := &fakeSender{}
	selfMAC := mustMAC("02:00:00:00:00:01")
	w := New(fs, selfMAC, Config{Interval: 5 * time.Millisecond, CorrectiveRepeats: 1, CorrectiveSpacing: time.Millisecond})

	gw := Target{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC("02:00:00:00:00:02")}
	stays := Target{IP: net.ParseIP("192.168.1.21"), MAC: mustMAC("02:00:00:00:00:03")}
	leaves := Target{IP: net.ParseIP("192.168.1.22"), MAC: mustMAC("02:00:00:00:00:04")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.ApplyGeneration(ctx, Generation{ID: 1, Gateway: gw, Targets: []Target{stays, leaves}})
	time.Sleep(20 * time.Millisecond)
	fs.reset() // scope the following assertions to just the generation switch

	w.ApplyGeneration(ctx, Generation{ID: 2, Gateway: gw, Targets: []Target{stays}})
	time.Sleep(20 * time.Millisecond)

	for _, c := range fs.snapshot() {
		if c.dstIP.Equal(stays.IP) && c.senderMAC.String() != selfMAC.String() {
			t.Errorf("target present in both generations received a non-poisoning reply during the switch: %+v -- this is exactly the race restorationSet() exists to prevent", c)
		}
	}

	w.Shutdown()
}

func TestApplyGeneration_LeavingTargetGetsCorrective(t *testing.T) {
	fs := &fakeSender{}
	selfMAC := mustMAC("02:00:00:00:00:01")
	w := New(fs, selfMAC, Config{Interval: 5 * time.Millisecond, CorrectiveRepeats: 1, CorrectiveSpacing: time.Millisecond})

	gw := Target{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC("02:00:00:00:00:02")}
	leaves := Target{IP: net.ParseIP("192.168.1.22"), MAC: mustMAC("02:00:00:00:00:04")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.ApplyGeneration(ctx, Generation{ID: 1, Gateway: gw, Targets: []Target{leaves}})
	time.Sleep(20 * time.Millisecond)
	fs.reset()

	// New generation drops "leaves" entirely.
	w.ApplyGeneration(ctx, Generation{ID: 2, Gateway: gw, Targets: nil})
	time.Sleep(10 * time.Millisecond)

	found := false
	for _, c := range fs.snapshot() {
		if c.dstIP.Equal(leaves.IP) && c.senderMAC.String() == gw.MAC.String() {
			found = true
		}
	}
	if !found {
		t.Error("expected a corrective (real gateway MAC) reply sent to the target that left scope, got none")
	}

	w.Shutdown()
}

// TestApplyGeneration_ReportsSendFailuresViaOnSendError confirms that
// when every ARPSender.Reply() call fails, Config.OnSendError is
// called rather than the failure being silently swallowed -- it's the
// mechanism a caller (cmd/pp-arp-worker/main.go) uses to surface this.
func TestApplyGeneration_ReportsSendFailuresViaOnSendError(t *testing.T) {
	fs := &fakeSender{replyErr: errors.New("simulated: operation not permitted")}
	selfMAC := mustMAC("02:00:00:00:00:01")

	var errCount int64
	cfg := Config{Interval: 5 * time.Millisecond, CorrectiveRepeats: 1, CorrectiveSpacing: time.Millisecond}
	cfg.OnSendError = func(err error) {
		atomic.AddInt64(&errCount, 1)
	}
	w := New(fs, selfMAC, cfg)

	gw := Target{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC("02:00:00:00:00:02")}
	target := Target{IP: net.ParseIP("192.168.1.22"), MAC: mustMAC("02:00:00:00:00:04")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.ApplyGeneration(ctx, Generation{ID: 1, Gateway: gw, Targets: []Target{target}})
	time.Sleep(20 * time.Millisecond)
	w.Shutdown()

	if atomic.LoadInt64(&errCount) == 0 {
		t.Error("expected OnSendError to have been called at least once for a sender that always fails")
	}
	// The generation must keep running through send failures -- the
	// fake sender still recorded every attempted call even though each
	// one "failed."
	if len(fs.snapshot()) == 0 {
		t.Error("expected the poisoning loop to keep attempting sends despite failures, not stop after the first")
	}
}

// TestApplyGeneration_NilOnSendErrorIsSafe guards the zero-value case --
// Config{} with OnSendError left nil must not panic on a send failure.
func TestApplyGeneration_NilOnSendErrorIsSafe(t *testing.T) {
	fs := &fakeSender{replyErr: errors.New("simulated failure")}
	selfMAC := mustMAC("02:00:00:00:00:01")
	w := New(fs, selfMAC, Config{Interval: 5 * time.Millisecond, CorrectiveRepeats: 1, CorrectiveSpacing: time.Millisecond})

	gw := Target{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC("02:00:00:00:00:02")}
	target := Target{IP: net.ParseIP("192.168.1.22"), MAC: mustMAC("02:00:00:00:00:04")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.ApplyGeneration(ctx, Generation{ID: 1, Gateway: gw, Targets: []Target{target}})
	time.Sleep(15 * time.Millisecond)
	w.Shutdown() // must not panic
}

// TestConsecutiveSendFailures_IncrementsOnFailure confirms
// ConsecutiveSendFailures increments when sends fail, since it's what
// heartbeat_ack reports to let the controller detect a sustained run
// of failures (otherwise invisible past a local log line via
// OnSendError).
func TestConsecutiveSendFailures_IncrementsOnFailure(t *testing.T) {
	fs := &fakeSender{replyErr: errors.New("simulated: network is down")}
	selfMAC := mustMAC("02:00:00:00:00:01")
	cfg := Config{Interval: 5 * time.Millisecond, CorrectiveRepeats: 1, CorrectiveSpacing: time.Millisecond}
	w := New(fs, selfMAC, cfg)

	gw := Target{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC("02:00:00:00:00:02")}
	target := Target{IP: net.ParseIP("192.168.1.22"), MAC: mustMAC("02:00:00:00:00:04")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if got := w.ConsecutiveSendFailures(); got != 0 {
		t.Fatalf("expected 0 before any sends, got %d", got)
	}

	w.ApplyGeneration(ctx, Generation{ID: 1, Gateway: gw, Targets: []Target{target}})
	time.Sleep(20 * time.Millisecond)
	w.Shutdown()

	if got := w.ConsecutiveSendFailures(); got == 0 {
		t.Error("expected ConsecutiveSendFailures to be nonzero after a sender that always fails")
	}
}

// TestConsecutiveSendFailures_ResetsToZeroOnSuccess guards the reset
// half of the same behavior -- a transient failure that later recovers
// (the realistic case: the bound interface comes back up) must not
// leave a stale nonzero count that permanently looks unhealthy.
func TestConsecutiveSendFailures_ResetsToZeroOnSuccess(t *testing.T) {
	fs := &fakeSender{replyErr: errors.New("simulated: network is down")}
	selfMAC := mustMAC("02:00:00:00:00:01")
	cfg := Config{Interval: 5 * time.Millisecond, CorrectiveRepeats: 1, CorrectiveSpacing: time.Millisecond}
	w := New(fs, selfMAC, cfg)

	gw := Target{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC("02:00:00:00:00:02")}
	target := Target{IP: net.ParseIP("192.168.1.22"), MAC: mustMAC("02:00:00:00:00:04")}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w.ApplyGeneration(ctx, Generation{ID: 1, Gateway: gw, Targets: []Target{target}})
	time.Sleep(20 * time.Millisecond)

	if got := w.ConsecutiveSendFailures(); got == 0 {
		t.Fatal("expected a nonzero failure count before the sender recovers")
	}

	fs.mu.Lock()
	fs.replyErr = nil // "the interface comes back up"
	fs.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	w.Shutdown()

	if got := w.ConsecutiveSendFailures(); got != 0 {
		t.Errorf("expected ConsecutiveSendFailures to reset to 0 after a successful send, got %d", got)
	}
}
