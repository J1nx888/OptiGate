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
	"net"
	"net/url"

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

	// selfIP is this box's own LAN IP (e.g. "192.168.1.250"), used by
	// baselineRules() below to exclude traffic addressed to the box
	// itself from bump_v4's Squid redirect -- see that field's own
	// comment for the full fix this closes (RoadMap.md items 7/18/20).
	// Empty string (every existing test's plain Manager{...} struct
	// literal, and any caller that doesn't know its own LAN IP) means
	// baselineRules() just omits the exception rules entirely -- same
	// "not configured, not an error" treatment
	// common/optigate_rewrite.py's parse_block_page_ip() already gives
	// the identical fact on the Python side.
	selfIP string
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
// see that field's own comment. selfIP of "" means baselineRules()
// installs no self-IP exception -- see that field's own comment; use
// SelfIPFromDashboardURL to derive it from this project's existing
// DASHBOARD_URL setting rather than inventing a second one.
func New(dnsRedirectPort int, selfIP string) (*Manager, error) {
	nft, err := knftables.New(knftables.InetFamily, "optigate")
	if err != nil {
		return nil, fmt.Errorf("open knftables interface: %w", err)
	}
	dockerUserNft, err := knftables.New(knftables.IPv4Family, "filter")
	if err != nil {
		return nil, fmt.Errorf("open knftables interface for docker's ip filter table: %w", err)
	}
	return &Manager{nft: nft, dockerUserNft: dockerUserNft, dnsRedirectPort: dnsRedirectPort, selfIP: selfIP}, nil
}

// SelfIPFromDashboardURL extracts a literal IPv4 host from a
// DASHBOARD_URL-shaped value (e.g. "http://192.168.1.250:8787" ->
// "192.168.1.250") -- the Go-side equivalent of
// common/optigate_rewrite.py's parse_block_page_ip(), which already
// does this identical extraction for the Python side. DASHBOARD_URL is
// this project's one existing source of truth for "this box's own LAN
// IP" (docker-compose.yml's controller service already requires it) --
// deliberately reused here rather than introducing a second,
// separately-configured self-IP setting that could silently drift from
// it if only one were ever updated. Returns "" for anything that isn't
// a plain IPv4 host (a real hostname, an unset/malformed URL, or an
// IPv6 literal) -- same "not configured, not an error" treatment the
// Python original gives it: baselineRules() just skips the self-IP
// exception rules entirely rather than failing.
func SelfIPFromDashboardURL(dashboardURL string) string {
	if dashboardURL == "" {
		return ""
	}
	u, err := url.Parse(dashboardURL)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.String()
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

// Teardown removes the "optigate" table entirely (the Go equivalent of
// `nft delete table inet optigate`) and the one rule this project adds
// outside it (see ensureDockerUserException). Real fix for the gap
// found live 2026-09-08 shutting down a soak-test window: SIGTERM
// (cmd/pp-nftables-manager/main.go) used to just log and return,
// leaving every baseline redirect rule active in the kernel with the
// managing process gone -- forcing a manual `sudo nft delete table
// inet optigate` on the host to actually return the box to normal
// pass-through. Tolerates the table already being gone (knftables'
// IsNotFound), so this is safe to call even if EnsureBaseline was
// never reached (e.g. this process crashed during its own startup) --
// same "call it unconditionally, let idempotency do the work" style as
// EnsureBaseline itself.
func (m *Manager) Teardown(ctx context.Context) error {
	tx := m.nft.NewTransaction()
	tx.Delete(&knftables.Table{})
	if err := m.nft.Run(ctx, tx); err != nil && !knftables.IsNotFound(err) {
		return fmt.Errorf("delete optigate table: %w", err)
	}

	return m.removeDockerUserException(ctx)
}

// removeDockerUserException undoes ensureDockerUserException's own
// insert, by the same comment-match that function already uses to
// avoid duplicating it on every EnsureBaseline call -- see that
// function's doc comment for the full reasoning. Never touches
// DOCKER-USER itself (deleting or flushing the whole chain isn't this
// project's business, only removing the one rule it added).
func (m *Manager) removeDockerUserException(ctx context.Context) error {
	if m.dockerUserNft == nil {
		// Same "nothing to do" case EnsureBaseline's own
		// ensureDockerUserException documents for a Manager built
		// directly rather than via New().
		return nil
	}
	existing, err := m.dockerUserNft.ListRules(ctx, "DOCKER-USER")
	if err != nil {
		log.Printf("DOCKER-USER chain not found (%v) -- nothing to remove", err)
		return nil
	}

	tx := m.dockerUserNft.NewTransaction()
	found := false
	for _, rule := range existing {
		if rule.Comment != nil && *rule.Comment == dockerUserComment {
			tx.Delete(&knftables.Rule{Chain: "DOCKER-USER", Handle: rule.Handle})
			found = true
		}
	}
	if !found {
		return nil
	}
	return m.dockerUserNft.Run(ctx, tx)
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
//
// **Self-IP exception, added for RoadMap.md items 7/18/20 (2026-09-09,
// next session):** bump_v4's own two redirect rules below match on
// source IP and destination PORT only, with no destination-IP
// exception for the box's own address -- confirmed live to cause two
// real problems, not just a hypothetical one. Item 18: a bump-enabled
// device's request for the `optigate.home` troubleshooting page never
// reached dashboard/block_page_server.py's real port-80 listener at
// all, it hit Squid first, which has no special-case awareness that
// `optigate.home` is a synthetic system hostname -- so it showed the
// box's own IP instead of the requesting device's. Item 20: worse than
// cosmetic -- when AdGuard correctly DNS-rewrites a hard-denied domain
// to the box's own IP for the friendly block page, the same
// unconditional redirect sweeps a bump-enabled device's HTTPS attempt
// to that rewritten address into Squid too, which then sees a
// connection whose real destination is the box's own IP but whose SNI
// says (say) "www.youtube.com", correctly flags its own built-in
// Host-header-forgery check, and kills the connection outright --
// invisible to the Report page, since that Squid-internal check fires
// before proxy/authz_helper.py or proxy/sni_helper.py (the only places
// that ever write to access_log) get a chance to run at all.
//
// Chose this fix over a Squid-side special case (the other candidate
// RoadMap.md's dated entry considered) because it's the one change
// that actually closes BOTH gaps at once: Squid's own docs/mailing
// list (core developer Amos Jeffries, confirmed directly, not assumed)
// say its Host-header-forgery check has no config directive to relax
// for specific cases, and even if it did, a rule keyed to the literal
// `optigate.home` hostname could never help item 20's case -- the SNI
// Squid sees there is the actual denied domain, not `optigate.home`.
// Excluding the box's own destination IP from the redirect instead
// means traffic addressed to the gateway itself never reaches Squid in
// the first place, regardless of what SNI it carries -- matching how a
// real router already treats packets addressed to its own interface.
// `return` (not `accept`) so the packet falls through to this base
// chain's own policy verdict exactly as if bump_v4 had never matched
// it at all, rather than this project asserting a verdict of its own.
//
// Deliberately does NOT touch authenticated_v4/unauthenticated_v4/
// quarantine_v4 -- none of those have this specific problem (only
// bump_v4 redirects port 80/443 to Squid at all), and touching
// unauthenticated_v4's own captive-portal redirect would be a separate,
// untested behavior change nobody asked for. selfIP of "" (no
// DASHBOARD_URL configured, or it's not a plain IPv4 host -- see
// SelfIPFromDashboardURL) means these two exception rules are omitted
// entirely, leaving bump_v4's redirect exactly as it was before this
// fix -- every existing test's plain Manager{} still gets that
// unchanged baseline.
func (m *Manager) baselineRules() []string {
	port := m.dnsRedirectPort
	if port == 0 {
		port = DefaultDNSRedirectPort
	}
	rules := []string{"ip saddr @bypass_v4 ct mark set 0x1 return"}
	if m.selfIP != "" {
		rules = append(rules,
			fmt.Sprintf("ip saddr @bump_v4 ip daddr %s tcp dport 80 return", m.selfIP),
			fmt.Sprintf("ip saddr @bump_v4 ip daddr %s tcp dport 443 return", m.selfIP),
			// Symmetry with the two tcp returns above -- nothing on this
			// box listens on udp/443, but keeping the self-IP carve-out
			// on all three protocols/ports means the "traffic to the box
			// itself never enters the interception path" invariant holds
			// no matter what a client sends.
			fmt.Sprintf("ip saddr @bump_v4 ip daddr %s udp dport 443 return", m.selfIP),
		)
	}
	return append(rules,
		"ip saddr @bump_v4 tcp dport 80 redirect to :3129",
		"ip saddr @bump_v4 tcp dport 443 redirect to :3130",
		// QUIC / HTTP-3 (udp/443) has no ssl-bump equivalent -- there is
		// no forged-certificate MITM for it -- so a bump device left
		// free to use it sends every HTTPS request over a path Squid
		// can't see: per-domain, per-path and per-show rules, plus all
		// Report-page logging, silently bypassed. Confirmed live
		// 2026-09-10: a bump device played non-whitelisted Crunchyroll
		// because Chrome moved to H3 after its first TCP request (via
		// Cloudflare's Alt-Svc) and never came back to TCP. Dropping
		// udp/443 makes the browser fall back to tcp/443, which the rule
		// directly above redirects into Squid -- the standard fix every
		// intercepting proxy uses, since QUIC can't be intercepted, only
		// denied. Scoped to bump_v4 only: a DNS-tier (authenticated_v4)
		// device's QUIC is already gated by AdGuard at resolution time
		// and has no decryption expectation to defeat.
		"ip saddr @bump_v4 udp dport 443 drop",
		fmt.Sprintf("ip saddr @authenticated_v4 udp dport 53 redirect to :%d", port),
		fmt.Sprintf("ip saddr @authenticated_v4 tcp dport 53 redirect to :%d", port),
		fmt.Sprintf("ip saddr @authenticated_v4 tcp dport 853 redirect to :%d", port),
		"ip saddr @authenticated_v4 ct mark set 0x1",
		fmt.Sprintf("ip saddr @unauthenticated_v4 udp dport 53 redirect to :%d", port),
		fmt.Sprintf("ip saddr @unauthenticated_v4 tcp dport 853 redirect to :%d", port),
		"ip saddr @unauthenticated_v4 tcp dport 80 redirect to :3131",
		"ip saddr @quarantine_v4 counter drop",
	)
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
