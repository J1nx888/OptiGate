package main

import (
	"errors"
	"net"
	"testing"

	"github.com/J1nx888/parental_proxy/phase3/arp-worker/internal/ipc"
	"github.com/J1nx888/parental_proxy/phase3/arp-worker/internal/worker"
)

var errResolveTimedOut = errors.New("fake: gateway ARP resolve timed out")

// testGatewayMAC is the gateway MAC every existing test's wire message
// already used before HandleReplaceTargets started live-verifying it
// (2026-09-12) -- fakeSender's default Resolve() return matches this so
// those tests keep exercising their OWN concern (target validation, not
// gateway verification) without also having to know about the new
// check.
var testGatewayMAC = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}

// fakeSender is a minimal worker.ARPSender double -- no real socket or
// CAP_NET_RAW needed, just enough for a *worker.Worker to exist and
// ApplyGeneration to run without erroring, so HandleReplaceTargets's
// OWN logic (target validation, target count, failure reporting, and --
// added 2026-09-12 -- gateway live-verification) can be tested in
// isolation. resolveMAC/resolveErr are configurable per test; the zero
// value of fakeSender{} would resolve to (nil, nil), which fails EVERY
// generation shut (a nil MAC never bytes.Equal()s a real one) -- tests
// that don't care about gateway verification should use
// newTestHandler() below, which sets resolveMAC to testGatewayMAC.
type fakeSender struct {
	resolveMAC net.HardwareAddr
	resolveErr error
}

func (fakeSender) Reply(net.IP, net.HardwareAddr, net.IP, net.HardwareAddr) error { return nil }
func (f fakeSender) Resolve(net.IP) (net.HardwareAddr, error)                     { return f.resolveMAC, f.resolveErr }
func (fakeSender) Close() error                                                   { return nil }

func newTestHandler(t *testing.T) *controllerHandler {
	t.Helper()
	return newTestHandlerWithSender(t, fakeSender{resolveMAC: testGatewayMAC})
}

func newTestHandlerWithSender(t *testing.T, sender fakeSender) *controllerHandler {
	t.Helper()
	w := worker.New(sender, net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x99}, worker.DefaultConfig())
	_, subnet, err := net.ParseCIDR("192.168.1.50/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	h := &controllerHandler{
		worker: w,
		selfIP: net.ParseIP("192.168.1.50"),
		subnet: subnet,
	}
	h.lease = worker.NewLeaseMonitor(worker.DefaultConfig().Interval, 5, h.onLeaseExpired)
	t.Cleanup(h.lease.Stop)
	return h
}

// TestHandleReplaceTargets_RejectsTheGateway is a regression test for a
// real gap found by code review (2026-09-02): worker.ValidateTargets
// existed but HandleReplaceTargets never called it, so a
// controller-side bug sending the gateway's own IP as a "poison this"
// target would have been applied unquestioningly.
func TestHandleReplaceTargets_RejectsTheGateway(t *testing.T) {
	h := newTestHandler(t)
	reply := h.HandleReplaceTargets(ipc.ReplaceTargets{
		V: ipc.ProtocolVersion, Op: "replace_targets", Generation: 1,
		Gateway: ipc.Target{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:01"},
		Targets: []ipc.Target{
			{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:01"},  // the gateway itself -- must be rejected
			{IP: "192.168.1.21", MAC: "aa:bb:cc:dd:ee:22"}, // a normal target -- must be accepted
		},
	})
	ack, ok := reply[0].(ipc.GenerationApplied)
	if !ok {
		t.Fatalf("expected a GenerationApplied reply, got %T", reply[0])
	}
	if ack.TargetCount != 1 {
		t.Fatalf("expected exactly 1 accepted target (the gateway rejected), got %d", ack.TargetCount)
	}
	found := false
	for _, f := range ack.ResolutionFailures {
		if f == "192.168.1.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the gateway's IP in ResolutionFailures, got %v", ack.ResolutionFailures)
	}
}

// TestHandleReplaceTargets_RejectsSelfAndBroadcast covers the other two
// checks achievable without a wire-protocol change (self and subnet
// broadcast -- see HandleReplaceTargets's own comment on why bypass_v4
// isn't checked here yet).
func TestHandleReplaceTargets_RejectsSelfAndBroadcast(t *testing.T) {
	h := newTestHandler(t)
	reply := h.HandleReplaceTargets(ipc.ReplaceTargets{
		V: ipc.ProtocolVersion, Op: "replace_targets", Generation: 1,
		Gateway: ipc.Target{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:01"},
		Targets: []ipc.Target{
			{IP: "192.168.1.50", MAC: "aa:bb:cc:dd:ee:50"},  // this worker's own IP
			{IP: "192.168.1.255", MAC: "aa:bb:cc:dd:ee:ff"}, // the /24's broadcast address
			{IP: "192.168.1.21", MAC: "aa:bb:cc:dd:ee:22"},  // a normal target
		},
	})
	ack, ok := reply[0].(ipc.GenerationApplied)
	if !ok {
		t.Fatalf("expected a GenerationApplied reply, got %T", reply[0])
	}
	if ack.TargetCount != 1 {
		t.Fatalf("expected exactly 1 accepted target (self and broadcast rejected), got %d", ack.TargetCount)
	}
}

// TestHandleReplaceTargets_AcceptsOrdinaryTargets is the negative case:
// confirm the new validation step doesn't reject anything it shouldn't.
func TestHandleReplaceTargets_AcceptsOrdinaryTargets(t *testing.T) {
	h := newTestHandler(t)
	reply := h.HandleReplaceTargets(ipc.ReplaceTargets{
		V: ipc.ProtocolVersion, Op: "replace_targets", Generation: 1,
		Gateway: ipc.Target{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:01"},
		Targets: []ipc.Target{
			{IP: "192.168.1.21", MAC: "aa:bb:cc:dd:ee:22"},
			{IP: "192.168.1.22", MAC: "aa:bb:cc:dd:ee:23"},
		},
	})
	ack, ok := reply[0].(ipc.GenerationApplied)
	if !ok {
		t.Fatalf("expected a GenerationApplied reply, got %T", reply[0])
	}
	if ack.TargetCount != 2 {
		t.Fatalf("expected both ordinary targets accepted, got %d", ack.TargetCount)
	}
	if len(ack.ResolutionFailures) != 0 {
		t.Fatalf("expected no failures for ordinary targets, got %v", ack.ResolutionFailures)
	}
}

// TestHandleReplaceTargets_RejectsTheGenerationOnGatewayResolveFailure is
// a regression test for a real gap found by code review (2026-09-11,
// fixed 2026-09-12): safety.go's ResolveGateway -- a genuine ARP
// exchange verifying the gateway's real MAC, never satisfied from a
// cache -- existed but was never actually called anywhere, so this
// worker trusted the wire-supplied gateway MAC outright. A resolve
// failure (e.g. the real gateway not answering ARP) must now fail the
// whole generation closed, not just proceed with the unverified value.
func TestHandleReplaceTargets_RejectsTheGenerationOnGatewayResolveFailure(t *testing.T) {
	h := newTestHandlerWithSender(t, fakeSender{resolveErr: errResolveTimedOut})
	reply := h.HandleReplaceTargets(ipc.ReplaceTargets{
		V: ipc.ProtocolVersion, Op: "replace_targets", Generation: 1,
		Gateway: ipc.Target{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:01"},
		Targets: []ipc.Target{
			{IP: "192.168.1.21", MAC: "aa:bb:cc:dd:ee:22"},
			{IP: "192.168.1.22", MAC: "aa:bb:cc:dd:ee:23"},
		},
	})
	ack, ok := reply[0].(ipc.GenerationApplied)
	if !ok {
		t.Fatalf("expected a GenerationApplied reply, got %T", reply[0])
	}
	if ack.TargetCount != 0 {
		t.Fatalf("expected the whole generation rejected (0 accepted) when the gateway can't be verified, got %d", ack.TargetCount)
	}
	if len(ack.ResolutionFailures) != 2 {
		t.Fatalf("expected both candidate targets reported as failures, got %v", ack.ResolutionFailures)
	}
}

// TestHandleReplaceTargets_RejectsTheGenerationOnGatewayMACMismatch is
// the sibling case: the ARP exchange succeeds, but resolves to a
// DIFFERENT MAC than the controller sent over the wire -- exactly the
// scenario ResolveGateway's own doc comment warns about (a
// controller-side bug, or a rogue ARP-spoofer having poisoned whatever
// fed the controller). Must also fail closed, not trust either value.
func TestHandleReplaceTargets_RejectsTheGenerationOnGatewayMACMismatch(t *testing.T) {
	wrongMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} // NOT aa:bb:cc:dd:ee:01
	h := newTestHandlerWithSender(t, fakeSender{resolveMAC: wrongMAC})
	reply := h.HandleReplaceTargets(ipc.ReplaceTargets{
		V: ipc.ProtocolVersion, Op: "replace_targets", Generation: 1,
		Gateway: ipc.Target{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:01"},
		Targets: []ipc.Target{
			{IP: "192.168.1.21", MAC: "aa:bb:cc:dd:ee:22"},
		},
	})
	ack, ok := reply[0].(ipc.GenerationApplied)
	if !ok {
		t.Fatalf("expected a GenerationApplied reply, got %T", reply[0])
	}
	if ack.TargetCount != 0 {
		t.Fatalf("expected the whole generation rejected (0 accepted) on a gateway MAC mismatch, got %d", ack.TargetCount)
	}
}
