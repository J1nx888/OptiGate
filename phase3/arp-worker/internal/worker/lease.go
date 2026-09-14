package worker

import (
	"sync"
	"time"
)

// LeaseMonitor implements the fail-open lease rule from
// docs/design/phase3-technical-design.md section 4: if the worker
// receives no heartbeat within missedCyclesAllowed x interval, it must
// stop forging replies and enter a passive repair-only state rather
// than silently keep poisoning on a possibly-stale generation.
type LeaseMonitor struct {
	mu                  sync.Mutex
	interval            time.Duration
	missedCyclesAllowed int
	onExpire            func()
	timer               *time.Timer
	expired             bool
}

// NewLeaseMonitor starts the lease clock immediately. onExpire is
// called at most once per expiry (from the timer's own goroutine) --
// keep it fast and non-blocking; it should trigger a corrective ARP
// pass and a mode change, not do that work inline.
func NewLeaseMonitor(interval time.Duration, missedCyclesAllowed int, onExpire func()) *LeaseMonitor {
	if missedCyclesAllowed <= 0 {
		missedCyclesAllowed = 5 // matches the design doc's "start conservative" default
	}
	lm := &LeaseMonitor{
		interval:            interval,
		missedCyclesAllowed: missedCyclesAllowed,
		onExpire:            onExpire,
	}
	lm.timer = time.AfterFunc(lm.leaseDuration(), lm.expire)
	return lm
}

func (lm *LeaseMonitor) leaseDuration() time.Duration {
	return lm.interval * time.Duration(lm.missedCyclesAllowed)
}

// Heartbeat resets the lease clock. Call this whenever a valid
// "heartbeat" IPC message arrives from the controller. A heartbeat
// received after the lease has already expired is deliberately a
// no-op -- a worker must not auto-resume a stale generation on its
// own; only a Rearm following a fresh replace_targets can do that.
func (lm *LeaseMonitor) Heartbeat() {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	if lm.expired {
		return
	}
	lm.timer.Reset(lm.leaseDuration())
}

func (lm *LeaseMonitor) expire() {
	lm.mu.Lock()
	if lm.expired {
		lm.mu.Unlock()
		return
	}
	lm.expired = true
	cb := lm.onExpire
	lm.mu.Unlock()
	if cb != nil {
		cb()
	}
}

// Rearm re-enables the lease after a fresh replace_targets is applied
// following an expiry. This is what makes "must not auto-resume an
// old target generation after restart/expiry" concrete: the lease
// never revives itself, it has to be explicitly re-armed by new
// controller traffic.
func (lm *LeaseMonitor) Rearm() {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.expired = false
	lm.timer.Reset(lm.leaseDuration())
}

// Stop releases the underlying timer. Call this on worker shutdown.
func (lm *LeaseMonitor) Stop() {
	lm.timer.Stop()
}
