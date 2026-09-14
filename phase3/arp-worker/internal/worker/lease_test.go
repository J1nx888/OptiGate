package worker

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestLeaseMonitor_ExpiresAfterMissedHeartbeats(t *testing.T) {
	var expired int32
	lm := NewLeaseMonitor(5*time.Millisecond, 2, func() { atomic.StoreInt32(&expired, 1) })
	defer lm.Stop()

	time.Sleep(30 * time.Millisecond)
	if atomic.LoadInt32(&expired) == 0 {
		t.Fatal("expected the lease to expire after missed heartbeats, but onExpire was never called")
	}
}

func TestLeaseMonitor_HeartbeatPreventsExpiry(t *testing.T) {
	var expired int32
	lm := NewLeaseMonitor(10*time.Millisecond, 2, func() { atomic.StoreInt32(&expired, 1) })
	defer lm.Stop()

	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		lm.Heartbeat()
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&expired) != 0 {
		t.Fatal("lease expired despite regular heartbeats")
	}
}

func TestLeaseMonitor_LateHeartbeatDoesNotReviveExpiredLease(t *testing.T) {
	var expireCount int32
	lm := NewLeaseMonitor(5*time.Millisecond, 1, func() { atomic.AddInt32(&expireCount, 1) })
	defer lm.Stop()

	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&expireCount); got != 1 {
		t.Fatalf("expected exactly one expiry, got %d", got)
	}

	// An explicit fresh replace_targets (modeled here as Rearm) is
	// required before poisoning can resume -- a late heartbeat alone
	// must be a no-op.
	lm.Heartbeat()
	time.Sleep(10 * time.Millisecond)
	if got := atomic.LoadInt32(&expireCount); got != 1 {
		t.Fatal("a heartbeat received after expiry should not reset the expired flag")
	}

	lm.Rearm()
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&expireCount); got != 2 {
		t.Fatalf("expected a second expiry after Rearm followed by another missed window, got count=%d", got)
	}
}
