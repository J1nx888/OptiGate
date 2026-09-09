package nft

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/policy"
)

// FlushConntrackForSource deletes every kernel conntrack entry whose
// ORIGINAL source address is ip.
//
// Real gap found live 2026-09-09, during a supervised interception
// test: baselineRules' own `ct mark set 0x1` (bypass_v4/authenticated_v4
// only) is deliberately set once, on a connection's first packet, and
// persists for that connection's ENTIRE lifetime -- see that function's
// own doc comment for why (ct mark, not meta mark, specifically so
// DOCKER-USER's forwarding-accept rule keeps seeing it at the FORWARD
// hook long after prerouting). That's correct and intentional for a
// device that's already authenticated staying connected through a
// later, unrelated policy recompute -- but it also means reclassifying
// a device to something MORE restrictive (unauthenticated_v4/
// quarantine_v4) has never actually revoked an already-accepted
// connection -- only a NEW connection, evaluated fresh against the
// device's current classification, was ever correctly blocked.
// Confirmed live: an Amazon Echo kept answering voice commands over its
// own always-on, long-lived cloud connection (accepted before the
// device was correctly reclassified as unauthenticated) for as long as
// that one connection stayed open -- only a power-cycle, forcing a
// fresh connection, actually cut it off. Enforcement was correct going
// forward; it was never applied retroactively.
//
// Shells out to conntrack-tools' own `conntrack` CLI -- a DIFFERENT
// kernel subsystem and a DIFFERENT tool than `nft` (which knftables
// itself already shells out to, see this project's own Dockerfile
// comment on that): nftables' rule engine has no equivalent "delete an
// already-tracked connection" primitive of its own. Reusing the
// standard, purpose-built tool here matches this project's own existing
// "shell out to a well-known binary rather than hand-roll raw netlink
// protocol code no one could safely verify without live kernel testing"
// precedent (e.g. the Python side shelling out to openssl for
// certificate work).
func FlushConntrackForSource(ctx context.Context, ip string) error {
	cmd := exec.CommandContext(ctx, "conntrack", "-D", "-s", ip)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	// conntrack-tools has no distinct exit code for "ran fine, but
	// nothing matched" versus a real failure -- both are a nonzero exit,
	// and the ONLY way to tell them apart is this exact, documented
	// stderr text. "Nothing matched" is the common, expected case (most
	// reclassifications are a device that was never holding an
	// already-accepted connection open in the first place) and must NOT
	// be treated as an error -- confirmed against the real conntrack-tools
	// CLI (v1.4.x, the version this project's Dockerfile installs).
	if strings.Contains(strings.ToLower(string(output)), "0 flow entries have been deleted") {
		return nil
	}
	return fmt.Errorf("conntrack -D -s %s: %s: %w", ip, strings.TrimSpace(string(output)), err)
}

// FlushConntrackForReclassifiedDevices deletes conntrack entries for
// every IP that just moved INTO SetUnauthenticated or SetQuarantine in
// this reconcile round -- see FlushConntrackForSource's own doc comment
// for the full story. Deliberately does not touch SetAuthenticated/
// SetBypass additions: a device becoming LESS restricted needs no
// flush (any pre-existing connection either already carried the
// ct-mark it's now also entitled to, or is a plain new connection that
// will be correctly marked on its own next packet) -- flushing there
// would only add a disruptive, pointless reconnect for zero benefit.
//
// Best-effort and non-fatal by design: the caller (reconcileOnce) logs
// each returned error as a warning and keeps going, exactly like it
// already does for policy conflicts. A failed flush is meaningfully
// LESS severe than a failed ApplyDiffs -- the nftables rules (already
// applied, atomically, before this ever runs) already correctly deny
// this device's NEW connections regardless of whether this flush
// succeeds; a failure here only means one already-open connection
// predating the reclassification keeps working a little longer than it
// should, never a new bypass of anything this project's own rules
// control.
func (m *Manager) FlushConntrackForReclassifiedDevices(ctx context.Context, diffs map[policy.SetName]policy.SetDiff) []error {
	var errs []error
	for _, name := range []policy.SetName{policy.SetUnauthenticated, policy.SetQuarantine} {
		diff, ok := diffs[name]
		if !ok {
			continue
		}
		for _, ip := range diff.Add {
			if err := FlushConntrackForSource(ctx, ip); err != nil {
				errs = append(errs, fmt.Errorf("flush conntrack for %s (newly %s): %w", ip, name, err))
			}
		}
	}
	return errs
}
