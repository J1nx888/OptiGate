//go:build linux

// Package nft adapts sigs.k8s.io/knftables to the pure
// policy.Reconcile/ResolveConflicts logic in ../policy. This is the one
// piece of nftables-manager that actually needs CAP_NET_ADMIN.
//
// NOT VERIFIED AGAINST A REAL BUILD as first written -- same situation
// as phase3/arp-worker/internal/arpio's mdlayher/arp adapter before its
// own fix: written from memory of knftables' documented shape (as used
// in kube-proxy), not checked against a fetched copy, because no Go
// toolchain was available while writing it. Expect API mismatches here
// specifically -- fix against `go doc sigs.k8s.io/knftables` once
// fetched, same workflow that fixed the ARP worker's adapter.
package nft

import (
	"context"
	"fmt"
	"log"

	"sigs.k8s.io/knftables"

	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/policy"
)

// Manager wraps a knftables.Interface scoped to the dedicated
// "optigate" table for everything except one deliberate,
// narrow exception: dockerUserNft, used only to fix the FORWARD-chain
// black hole documented on ensureDockerUserException below. Every
// other method on this type only ever touches "optigate".
type Manager struct {
	nft knftables.Interface

	// dockerUserNft is scoped to the "ip filter" table Docker itself
	// creates and manages -- see ensureDockerUserException's own doc
	// comment for why this single, narrow exception exists.
	dockerUserNft knftables.Interface

	// dnsRedirectPort is the local port baselineRules() redirects
	// port-53/853 traffic to -- AdGuard's own DNS listener. Zero value
	// (every existing test's plain Manager{...} struct literal, and any
	// caller that doesn't care) falls back to DefaultDNSRedirectPort in
	// baselineRules() below, so this field is optional in practice, not
	// just in name. Added 2026-09-08: a real deployment found
	// avahi-daemon (mDNS) already squatting the previous hardcoded
	// :5353 default -- a port conflict any other user running this on a
	// typical Debian/Ubuntu box (avahi is a common default package) was
	// always going to hit sooner or later, not a one-off. Making this
	// genuinely configurable, not just picking a different hardcoded
	// number, is the actual fix -- see docker-compose.yml's
	// ADGUARD_DNS_PORT and this binary's own -dns-redirect-port flag.
	dnsRedirectPort int
}

// DefaultDNSRedirectPort is used whenever a Manager's dnsRedirectPort is
// left at its zero value -- see that field's own comment. 5354, not
// 5353: the latter is IANA-registered for mDNS and a common default
// package (avahi-daemon) on many Linux distributions already binds it,
// so picking a merely-different-by-convention neighbor keeps this
// project from being the second thing fighting over the same
// well-known port on someone else's box.
const DefaultDNSRedirectPort = 5354

// allManagedSets is every nftables set this package creates and reads
// -- policy.AllSetNames' four mutually-exclusive classes plus the
// orthogonal policy.SetBump. Deliberately not the same slice as
// policy.AllSetNames: that list's contract is "priority-ordered,
// mutually exclusive" (see its doc comment), which bump_v4 doesn't
// satisfy, but EnsureBaseline/ReadActual just need "every set this
// process manages," so they get their own list instead of overloading
// AllSetNames' meaning.
var allManagedSets = append(append([]policy.SetName{}, policy.AllSetNames...), policy.SetBump)

// New opens a knftables interface for the `inet` family's
// "optigate" table, plus a second interface scoped to Docker's
// own "ip filter" table (see ensureDockerUserException). Requires
// CAP_NET_ADMIN. dnsRedirectPort of 0 means DefaultDNSRedirectPort --
// see that field's own comment.
func New(dnsRedirectPort int) (*Manager, error) {
	nft, err := knftables.New(knftables.InetFamily, "optigate")
	if err != nil {
		return nil, fmt.Errorf("open knftables interface: %w", err)
	}
	dockerUserNft, err := knftables.New(knftables.IPv4Family, "filter")
	if err != nil {
		return nil, fmt.Errorf("open knftables interface for docker's ip filter table: %w", err)
	}
	return &Manager{nft: nft, dockerUserNft: dockerUserNft, dnsRedirectPort: dnsRedirectPort}, nil
}

// EnsureBaseline creates the table, the five named sets (allManagedSets), and the
// prerouting redirect chain if they don't already exist, and
// (re-)establishes the redirect rules -- fully idempotent, safe to
// call on every startup regardless of whether the table already has
// the baseline from a previous run (e.g. this process restarting under
// systemd's Restart=on-failure). Matches
// docs/design/phase3-technical-design.md section 5's skeleton exactly;
// keep the two in sync if either changes.
//
// The table/set/chain Add() calls are natively idempotent (knftables'
// Add is "ensure it exists," matching `nft add table` etc.) -- the one
// piece that ISN'T is rules, which Add() always appends rather than
// deduplicating by content (rules have no name/identity the way
// tables/sets/chains do). Flushing the chain before re-adding the
// rules is what makes a second EnsureBaseline call converge back to
// exactly the baseline rule set instead of appending a duplicate copy
// every restart -- verified by TestEnsureBaseline_IsIdempotentAcrossRepeatedCalls.
func (m *Manager) EnsureBaseline(ctx context.Context) error {
	tx := m.nft.NewTransaction()

	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("optigate interception policy -- see RoadMap.md"),
	})

	for _, name := range allManagedSets {
		tx.Add(&knftables.Set{
			Name:  string(name),
			Type:  "ipv4_addr",
			Flags: []knftables.SetFlag{knftables.IntervalFlag},
		})
	}

	tx.Add(&knftables.Chain{
		Name:     "prerouting",
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Priority: knftables.PtrTo(knftables.DNATPriority),
	})

	// Clear any rules a previous EnsureBaseline call left in this chain
	// before re-adding the baseline below -- a no-op the very first time
	// (empty chain), and what makes a restart not duplicate rules.
	tx.Flush(&knftables.Chain{Name: "prerouting"})

	for _, rule := range m.baselineRules() {
		tx.Add(&knftables.Rule{Chain: "prerouting", Rule: rule})
	}

	if err := m.nft.Run(ctx, tx); err != nil {
		return err
	}

	return m.ensureDockerUserException(ctx)
}

// dockerUserComment tags the one rule this project ever adds outside
// its own table, so ensureDockerUserException can find and replace
// exactly that rule (and nothing else a human or another tool put in
// DOCKER-USER) on every restart, instead of accumulating a duplicate
// copy each time -- the same idempotency goal EnsureBaseline's own
// Flush-then-readd achieves within "optigate" itself, just done
// by comment-matching here since flushing the whole chain would be
// unsafe (DOCKER-USER isn't ours to clear).
const dockerUserComment = "optigate: allow marked connections (see knftables_adapter.go)"

// ensureDockerUserException fixes a real gap discovered live 2026-09-07:
// every container in this project runs with network_mode: host, so
// Docker's own bridge-network NAT/isolation rules (the "ip filter"
// table's DOCKER*/DOCKER-USER chains, auto-created the moment the
// Docker daemon starts, independent of whether any bridge container
// ever runs) provide this project literally nothing -- but its FORWARD
// base chain's policy is still `drop` by default (Docker 20.10+), and
// nothing before this fix ever told it otherwise. A base chain's own
// `accept` policy or an early same-hook chain's `accept` verdict does
// NOT override a *different* base chain's later `drop` policy at the
// same hook (verified against a real box, not assumed -- an `accept`
// verdict only means "this particular chain is done with the packet,"
// or a *jumped-to* sub-chain, netfilter still runs every other base
// chain registered at that hook afterward, and any one of them
// returning `drop` is immediately final). The one chain Docker
// guarantees it creates once and never overwrites the contents of --
// specifically so operators can add exactly this kind of exception --
// is DOCKER-USER, jumped to from the very first line of Docker's own
// FORWARD chain, before its policy=drop fallback ever applies.
//
// Sets are table-scoped in nftables, so a rule living in "ip filter"
// can't reference "optigate"'s own @bypass_v4/@authenticated_v4
// sets directly -- conntrack marks bridge the two tables instead:
// baselineRules (in "optigate", evaluated first, at the
// prerouting/dstnat hook) tags every bypass_v4/authenticated_v4
// connection with `ct mark set 0x1`, a kernel-wide, table-independent
// property; this function's one rule in DOCKER-USER then just checks
// that mark. `ct mark` (not `meta mark`) specifically because it
// persists for the connection's whole lifetime once set on its first
// packet, not just the packet that set it -- exactly what's needed
// since the mark is set in prerouting but read again later at the
// forward hook.
//
// Deliberately does NOT touch DOCKER-USER at all if it doesn't exist
// (ListRules returns an error) -- most likely explanation is Docker's
// own iptables/nftables management is disabled entirely (e.g.
// "iptables": false in daemon.json), in which case there's no
// Docker-installed drop policy to work around in the first place, and
// forcing the chain into existence here would be reaching further
// into Docker's own management than this project has any business
// doing. Logged, not fatal -- EnsureBaseline's caller decides whether
// that's acceptable for its environment.
func (m *Manager) ensureDockerUserException(ctx context.Context) error {
	if m.dockerUserNft == nil {
		// A Manager built directly (every existing test, and any future
		// caller that only needs the "optigate" side) rather than
		// via New() -- same "nothing to do" outcome as the chain not
		// existing below, just without a real interface to even try.
		return nil
	}
	existing, err := m.dockerUserNft.ListRules(ctx, "DOCKER-USER")
	if err != nil {
		log.Printf("DOCKER-USER chain not found (%v) -- skipping the forwarding-permit rule; "+
			"this is expected if Docker's own iptables management is disabled, otherwise "+
			"forwarded traffic for bypass/authenticated devices may be silently dropped", err)
		return nil
	}

	tx := m.dockerUserNft.NewTransaction()
	for _, rule := range existing {
		if rule.Comment != nil && *rule.Comment == dockerUserComment {
			tx.Delete(&knftables.Rule{Chain: "DOCKER-USER", Handle: rule.Handle})
		}
	}
	tx.Insert(&knftables.Rule{
		Chain:   "DOCKER-USER",
		Rule:    "ct mark 0x1 counter accept",
		Comment: knftables.PtrTo(dockerUserComment),
	})
	return m.dockerUserNft.Run(ctx, tx)
}

// baselineRules are the redirect rules from the design skeleton,
// applied in the order given (evaluation order matters -- bypass must
// be checked, and short-circuit via `return`, before anything else).
//
// Corrected 2026-08-30 for the "two independent axes" architecture
// (RoadMap.md, locked that date): the old ruleset redirected EVERY
// authenticated_v4 device's tcp 80/443 to Squid unconditionally, which
// was wrong -- Squid access is a separate, admin-chosen per-device
// opt-in (bump_v4), not a consequence of authentication. authenticated_v4
// now only carries its DNS redirect; bump_v4 independently carries the
// tcp 80/443 redirect to Squid's intercept ports, and composes with
// (does not replace) authenticated_v4 -- a device is normally a member
// of both. Squid itself narrows this all-or-nothing per-device redirect
// down to specific domains via its own unchanged SNI splice/bump logic
// (nftables can't see hostnames below the TLS layer, so it can't be
// selective by domain the way Squid can) -- see RoadMap.md's Squid
// intercept-mode section.
// tcp dport 853 (DNS-over-TLS) redirects, added 2026-09-02 to close a
// real, silent DNS-tier bypass found by code review: before this, ONLY
// port 53 was ever touched, so a device with DoT enabled (e.g. Android's
// one-tap Settings > Private DNS, no browser setting or technical skill
// needed) resolved every domain via an encrypted TLS session straight to
// whatever public resolver it was pointed at, with AdGuard's domain/
// category/schedule/SafeSearch/anti-DoH rules never in the path at all.
// Redirecting to :5353 -- the SAME plain-DNS port 53 already redirects
// to -- is deliberate, not a mistake: AdGuard's listener there speaks
// plain DNS, not TLS, so a redirected DoT ClientHello simply fails the
// handshake (this box has no certificate a random public resolver's
// hostname would validate against, and minting one would mean actually
// terminating arbitrary TLS, a materially bigger undertaking than
// blocking). A failed handshake is the desired outcome here, matching
// how this project already treats an unconfigured bump-mode domain
// (deny the connection outright, see docs/security/overview.md) rather
// than attempting to impersonate the far end -- most DNS stacks fall
// back to their configured plaintext resolver (which IS then correctly
// filtered) when a DoT upstream is unreachable. No UDP 853 rule needed:
// DNS-over-TLS is TCP-only (RFC 7858).
//
// bump_v4 needs no port-853 rule of its own: a bump-eligible device is
// ALWAYS also a member of authenticated_v4 (see the "two independent
// axes" comment above), so the authenticated_v4 rule below already
// covers it.
//
// Known, pre-existing asymmetry NOT addressed here (out of scope for
// this fix, flagged for a future look): unauthenticated_v4 has no tcp
// dport 53 rule, only udp -- a PREAUTH device using TCP-based plain DNS
// (large responses, some resolvers' defaults) would bypass the DNS
// redirect the same way DoT did, though it can never reach an actual
// destination beyond this box's own :5353 either way once port 853 is
// closed off, since PREAUTH's only other open door is tcp/80 to the
// captive portal.
//
// The two `ct mark set 0x1` statements, added 2026-09-07: real traffic
// for bypass_v4 (its ordinary, non-redirected browsing) and
// authenticated_v4 (its ordinary web traffic, as opposed to the DNS
// ports redirected above) needs to actually be forwarded back out this
// single-NIC box to reach the real internet -- a genuine `redirect` to
// a local port isn't the right tool for that (there's no local service
// for it to terminate at), so unlike every other line here it doesn't
// end in a terminal verdict. `ct mark` is the intentional choice over
// `meta mark`: it's read again much later, at the forward hook, by
// ensureDockerUserException's rule in a completely different table --
// `ct mark` persists for a connection's whole lifetime once set on its
// first packet, `meta mark` would not still be attached by then. See
// that function's own doc comment for the full story (a real,
// previously-undiscovered bug: nothing ever actually verified a client
// could reach the real internet through this box end-to-end, only that
// its traffic arrived here via ARP redirection). unauthenticated_v4
// deliberately gets no such rule -- its only legitimate paths are the
// locally-terminating redirects above; anything else (e.g. a raw HTTPS
// request bypassing the captive portal) is meant to fail, the same as
// any real-world captive portal.
//
// The DNS/DoT redirect target (:5353 below, historically -- see
// DefaultDNSRedirectPort's own comment on why that changed) comes from
// (*Manager).baselineRules() below, not this literal slice -- this
// package-level var exists only so every existing test that references
// `baselineRules` directly by name keeps working unchanged, built via a
// zero-value Manager so it reflects DefaultDNSRedirectPort exactly like
// any other caller that doesn't override the port.
var baselineRules = (&Manager{}).baselineRules()

// baselineRules builds the redirect ruleset using this Manager's own
// dnsRedirectPort (DefaultDNSRedirectPort if left at zero -- see that
// field's own comment). A method, not a package-level literal, so the
// same box's chosen port (e.g. because :5354 also collided with
// something) is reflected everywhere this ruleset gets used, not just
// baked in once at compile time.
func (m *Manager) baselineRules() []string {
	port := m.dnsRedirectPort
	if port == 0 {
		port = DefaultDNSRedirectPort
	}
	return []string{
		"ip saddr @bypass_v4 ct mark set 0x1 return",
		"ip saddr @bump_v4 tcp dport 80 redirect to :3129",
		"ip saddr @bump_v4 tcp dport 443 redirect to :3130",
		fmt.Sprintf("ip saddr @authenticated_v4 udp dport 53 redirect to :%d", port),
		fmt.Sprintf("ip saddr @authenticated_v4 tcp dport 53 redirect to :%d", port),
		fmt.Sprintf("ip saddr @authenticated_v4 tcp dport 853 redirect to :%d", port),
		"ip saddr @authenticated_v4 ct mark set 0x1",
		fmt.Sprintf("ip saddr @unauthenticated_v4 udp dport 53 redirect to :%d", port),
		fmt.Sprintf("ip saddr @unauthenticated_v4 tcp dport 853 redirect to :%d", port),
		"ip saddr @unauthenticated_v4 tcp dport 80 redirect to :3131",
		"ip saddr @quarantine_v4 counter drop",
	}
}

// ReadActual reads the live membership of all five sets (allManagedSets)
// from the kernel -- never cached, matching policy.ActualPolicy's own
// doc comment on why a reconciler must always read fresh.
func (m *Manager) ReadActual(ctx context.Context) (policy.ActualPolicy, error) {
	actual := make(policy.ActualPolicy, len(allManagedSets))
	for _, name := range allManagedSets {
		elements, err := m.nft.ListElements(ctx, "set", string(name))
		if err != nil {
			return nil, fmt.Errorf("list elements of %s: %w", name, err)
		}
		ips := make([]string, 0, len(elements))
		for _, el := range elements {
			if len(el.Key) > 0 {
				ips = append(ips, el.Key[0])
			}
		}
		actual[name] = ips
	}
	return actual, nil
}

// ApplyDiffs applies every set's add/remove changes in ONE atomic
// transaction -- either all of it lands, or (per knftables' own
// atomic-transaction guarantee cited in the design doc section 1)
// none of it does. This is what makes Milestone 5's "atomic
// apply/rollback" requirement concrete.
func (m *Manager) ApplyDiffs(ctx context.Context, diffs map[policy.SetName]policy.SetDiff) error {
	if len(diffs) == 0 {
		return nil
	}
	tx := m.nft.NewTransaction()
	for name, diff := range diffs {
		for _, ip := range diff.Add {
			tx.Add(&knftables.Element{Set: string(name), Key: []string{ip}})
		}
		for _, ip := range diff.Remove {
			tx.Delete(&knftables.Element{Set: string(name), Key: []string{ip}})
		}
	}
	return m.nft.Run(ctx, tx)
}
