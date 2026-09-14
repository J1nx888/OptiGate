package policy

import "sort"

// Conflict records that an IP was requested in more than one policy
// set at once -- ambiguous input the caller (controller) should log
// and treat as a bug in its own desired-state computation, not
// something to silently paper over without a trace.
type Conflict struct {
	IP       string
	Sets     []SetName // every set that requested this IP, in priority order
	Resolved SetName   // which set it was actually kept in
}

// ResolveConflicts returns a DesiredPolicy where every IP appears in at
// most one of the four mutually-exclusive sets (AllSetNames), keeping
// each conflicting IP only in its highest-priority set (AllSetNames
// order: bypass > authenticated > unauthenticated > quarantine,
// matching the design skeleton's prerouting chain evaluation order --
// bypass short-circuits via `return` before anything else is checked,
// so an IP that's also listed in quarantine but belongs in bypass must
// never be dropped), plus the list of conflicts found so the caller
// can log them. An empty conflict list means the input was already
// well-formed.
//
// desired.Bump is resolved separately and is NOT part of the four-way
// exclusivity above -- it composes with Authenticated rather than
// competing with it (see SetBump's doc comment). Its only precondition
// is that a bump-enabled device must also BE an authenticated one,
// since bump-tier is a refinement of authenticated access, not a
// standalone class. A bump IP that didn't
// resolve into Authenticated above (e.g. a device flagged bump_enabled
// while also ignored or quarantined -- a bug in the caller's own
// desired-state computation, not something that should happen) is
// dropped here rather than trusted blindly, with a Conflict recorded
// (Resolved left as the zero value, meaning "member of no set") so it
// isn't silently swallowed.
//
// Output ordering is deterministic (sorted by IP) so callers -- and
// this package's own tests -- can compare results without needing an
// order-insensitive comparison.
func ResolveConflicts(desired DesiredPolicy) (DesiredPolicy, []Conflict) {
	membership := make(map[string][]SetName)
	for _, name := range AllSetNames { // already priority-ordered
		for _, ip := range desired.ByName(name) {
			membership[ip] = append(membership[ip], name)
		}
	}

	ips := make([]string, 0, len(membership))
	for ip := range membership {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	resolved := DesiredPolicy{}
	var conflicts []Conflict
	for _, ip := range ips {
		sets := membership[ip]
		winner := sets[0] // membership was built in priority order, so sets[0] is the highest priority
		if len(sets) > 1 {
			conflicts = append(conflicts, Conflict{
				IP:       ip,
				Sets:     append([]SetName(nil), sets...),
				Resolved: winner,
			})
		}
		resolved = appendIP(resolved, winner, ip)
	}

	resolved.Bump, conflicts = resolveBump(desired.Bump, resolved.Authenticated, conflicts)
	return resolved, conflicts
}

// resolveBump keeps only the bump IPs that are also members of the
// (already-resolved) authenticated set, deduplicates, sorts, and
// records a Conflict for anything dropped. Split out from
// ResolveConflicts for the same reason diffSet is split out in
// reconcile.go: it's an independent piece of logic with its own
// precondition, not another branch of the four-way exclusivity above.
func resolveBump(bump, authenticated []string, conflicts []Conflict) ([]string, []Conflict) {
	authenticatedSet := toSet(authenticated)
	seen := make(map[string]bool, len(bump))
	var kept []string
	for _, ip := range bump {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if !authenticatedSet[ip] {
			conflicts = append(conflicts, Conflict{IP: ip, Sets: []SetName{SetBump}})
			continue
		}
		kept = append(kept, ip)
	}
	sort.Strings(kept)
	return kept, conflicts
}

func appendIP(d DesiredPolicy, name SetName, ip string) DesiredPolicy {
	switch name {
	case SetAuthenticated:
		d.Authenticated = append(d.Authenticated, ip)
	case SetUnauthenticated:
		d.Unauthenticated = append(d.Unauthenticated, ip)
	case SetBypass:
		d.Bypass = append(d.Bypass, ip)
	case SetQuarantine:
		d.Quarantine = append(d.Quarantine, ip)
	}
	return d
}
