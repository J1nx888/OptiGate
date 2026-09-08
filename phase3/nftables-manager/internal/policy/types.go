// Package policy implements the pure logic for Milestone 5's four
// nftables policy classes (docs/design/phase3-technical-design.md
// section 5): computing what a desired policy should look like and
// diffing it against actual nftables set membership. No nftables
// dependency at all -- the knftables-backed adapter that actually
// reads/writes the kernel's ruleset lives in the sibling ../nft
// package, so everything here is unit tested without CAP_NET_ADMIN.
package policy

// SetName is one of the four named nftables sets from the design doc's
// skeleton (table inet optigate). Fixed and closed -- unlike the
// worker's arbitrary target list, there are exactly these four classes.
type SetName string

const (
	SetAuthenticated   SetName = "authenticated_v4"
	SetUnauthenticated SetName = "unauthenticated_v4"
	SetBypass          SetName = "bypass_v4"
	SetQuarantine      SetName = "quarantine_v4"

	// SetBump is the fifth set, added for the "two independent axes"
	// architecture correction locked in RoadMap.md 2026-08-30:
	// devices.bump_enabled is a separate, admin-only, per-device opt-in
	// for Squid/SSL-bump refinement, layered ON TOP of an already
	// authenticated device -- not a fifth mutually-exclusive policy
	// class. An IP can (correctly) be a member of both SetAuthenticated
	// and SetBump at once. Deliberately excluded from AllSetNames below
	// for exactly that reason -- see its doc comment.
	SetBump SetName = "bump_v4"
)

// AllSetNames in the design skeleton's evaluation-order priority --
// highest priority (checked/short-circuited first in the prerouting
// chain) to lowest. ResolveConflicts uses this order to decide which
// set wins when an IP is (incorrectly) requested in more than one.
//
// SetBump is NOT included here. This list's whole purpose is driving
// ResolveConflicts' winner-take-all logic, which assumes membership in
// one of these sets excludes membership in the others -- that
// assumption is true for these four (a device is in exactly one) but
// false for bump_v4, which composes with SetAuthenticated rather than
// competing with it. See ResolveConflicts' own doc comment for how
// bump membership is validated instead.
var AllSetNames = []SetName{SetBypass, SetAuthenticated, SetUnauthenticated, SetQuarantine}

// DesiredPolicy is what the controller wants nftables set membership
// to be right now, one IPv4 address list per class, plus the
// independent Bump opt-in list. Mirrors controller/reconcile.go's
// DesiredState on the ARP-worker side, but for firewall policy instead
// of poisoning targets -- a deliberately separate concept, since (per
// the design doc) interception scope and policy scope are different
// axes.
type DesiredPolicy struct {
	Authenticated   []string
	Unauthenticated []string
	Bypass          []string
	Quarantine      []string

	// Bump holds the IPs of bump_enabled devices that are ALSO
	// authenticated (see ResolveConflicts). Deliberately not part of
	// the four fields above's mutual exclusivity -- an IP can appear
	// here and in Authenticated simultaneously.
	Bump []string
}

// ByName returns the desired member list for one set, including the
// orthogonal SetBump.
func (d DesiredPolicy) ByName(name SetName) []string {
	switch name {
	case SetAuthenticated:
		return d.Authenticated
	case SetUnauthenticated:
		return d.Unauthenticated
	case SetBypass:
		return d.Bypass
	case SetQuarantine:
		return d.Quarantine
	case SetBump:
		return d.Bump
	default:
		return nil
	}
}

// ActualPolicy is a snapshot of what nftables currently holds, read
// live from the kernel (never cached/assumed) before every
// reconciliation -- same "never trust a possibly-stale cache" spirit
// as the ARP worker's ResolveGateway.
type ActualPolicy map[SetName][]string
