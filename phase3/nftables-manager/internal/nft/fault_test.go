package nft

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"sigs.k8s.io/knftables"

	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/policy"
)

// Milestone 9 (fault campaign) coverage for the "partial nftables
// failure" scenario: knftables' own Run() is documented as atomic
// (all-or-nothing), so a failure can never leave the KERNEL in a
// partial state -- the real risk is this PROCESS erroring between
// ReadActual and ApplyDiffs, which the tests below confirm is
// propagated rather than panicking or silently swallowed, so the
// caller's reconciliation loop (cmd/pp-nftables-manager) can log it
// and simply retry next cycle against freshly-read actual state.

// listOnlyFake is a minimal Interface fake for ListElements-only error
// injection. It deliberately does NOT support a working
// NewTransaction/Add/Delete (see failingRun below for why that needs a
// real knftables.Fake instead) -- ReadActual never touches those, so
// this is enough for its tests.
type listOnlyFake struct {
	result map[string][]*knftables.Element
	err    error
}

func (f *listOnlyFake) NewTransaction() *knftables.Transaction                     { return nil }
func (f *listOnlyFake) Run(ctx context.Context, tx *knftables.Transaction) error   { return nil }
func (f *listOnlyFake) Check(ctx context.Context, tx *knftables.Transaction) error { return nil }
func (f *listOnlyFake) ListAll(ctx context.Context) (map[string][]string, error)   { return nil, nil }
func (f *listOnlyFake) List(ctx context.Context, objectType string) ([]string, error) {
	return nil, nil
}
func (f *listOnlyFake) ListRules(ctx context.Context, chain string) ([]*knftables.Rule, error) {
	return nil, nil
}
func (f *listOnlyFake) ListElements(ctx context.Context, objectType, name string) ([]*knftables.Element, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.result[name], nil
}
func (f *listOnlyFake) ListCounters(ctx context.Context) ([]*knftables.Counter, error) {
	return nil, nil
}

func TestReadActual_PropagatesListElementsError(t *testing.T) {
	m := &Manager{nft: &listOnlyFake{err: errors.New("kernel unreachable")}}
	if _, err := m.ReadActual(context.Background()); err == nil {
		t.Fatal("expected ReadActual to propagate the list error, got nil")
	}
}

func TestReadActual_ReturnsAllFiveSetsEvenWhenEmpty(t *testing.T) {
	m := &Manager{nft: &listOnlyFake{result: map[string][]*knftables.Element{}}}
	actual, err := m.ReadActual(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range allManagedSets {
		if _, ok := actual[name]; !ok {
			t.Errorf("expected actual to have an (empty) entry for %s", name)
		}
	}
}

func TestReadActual_SkipsElementsWithNoKey(t *testing.T) {
	// A defensive case: an Element with an empty Key must not panic on
	// el.Key[0].
	m := &Manager{nft: &listOnlyFake{result: map[string][]*knftables.Element{
		"authenticated_v4": {{Key: nil}, {Key: []string{"192.168.1.21"}}},
	}}}
	actual, err := m.ReadActual(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := actual[policy.SetAuthenticated]; len(got) != 1 || got[0] != "192.168.1.21" {
		t.Fatalf("expected only the well-formed element, got %v", got)
	}
}

// failingRun wraps a REAL knftables.Fake (sigs.k8s.io/knftables's own
// in-memory test double -- so NewTransaction/Add/Delete all work
// correctly against real internal table state) but forces Run() to
// fail. This is how ApplyDiffs' error-propagation path is tested: a
// hand-rolled bare fake's Transaction panics on Add/Delete
// (Transaction.validate() dereferences internal wiring that only a
// genuine Interface implementation -- Fake included -- sets up when
// NewTransaction() is called), so the Run-side failure has to be
// injected by wrapping a real, working Fake instead.
type failingRun struct {
	*knftables.Fake
	err error
}

func (f *failingRun) Run(ctx context.Context, tx *knftables.Transaction) error {
	return f.err
}

func TestApplyDiffs_PropagatesTransactionError(t *testing.T) {
	m := &Manager{nft: &failingRun{
		Fake: knftables.NewFake(knftables.InetFamily, "optigate"),
		err:  errors.New("boom"),
	}}
	diffs := map[policy.SetName]policy.SetDiff{
		policy.SetAuthenticated: {Add: []string{"192.168.1.21"}},
	}
	if err := m.ApplyDiffs(context.Background(), diffs); err == nil {
		t.Fatal("expected ApplyDiffs to propagate the transaction error, got nil")
	}
}

func TestApplyDiffs_EmptyDiffsNeverCallsRun(t *testing.T) {
	// If ApplyDiffs called Run for an empty diff set, this would return
	// the deliberately-wrong error below -- passing proves it
	// short-circuited instead.
	m := &Manager{nft: &failingRun{
		Fake: knftables.NewFake(knftables.InetFamily, "optigate"),
		err:  errors.New("Run must not be called for an empty diff"),
	}}
	if err := m.ApplyDiffs(context.Background(), map[policy.SetName]policy.SetDiff{}); err != nil {
		t.Fatalf("expected no error for empty diffs, got %v", err)
	}
}

// TestEnsureBaselineThenApplyDiffs_AgainstFake is a genuine end-to-end
// check using knftables' own in-memory Fake -- no CAP_NET_ADMIN or real
// kernel needed, so it runs as a normal `go test`. This complements
// (doesn't replace) the live --cap-add=NET_ADMIN container
// verification recorded in this module's README and commit history --
// that proved the real kernel behaves this way; this proves the Go
// logic driving it does too, fast enough to run on every change.
func TestEnsureBaselineThenApplyDiffs_AgainstFake(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	m := &Manager{nft: fake}
	ctx := context.Background()

	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline: %v", err)
	}

	actual, err := m.ReadActual(ctx)
	if err != nil {
		t.Fatalf("ReadActual (initial): %v", err)
	}
	for _, name := range allManagedSets {
		if len(actual[name]) != 0 {
			t.Fatalf("expected set %s to start empty, got %v", name, actual[name])
		}
	}

	desired := policy.DesiredPolicy{
		Authenticated: []string{"192.168.1.21"},
		Bump:          []string{"192.168.1.21"}, // composes with Authenticated, not exclusive with it
	}
	resolved, conflicts := policy.ResolveConflicts(desired)
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %+v", conflicts)
	}
	diffs := policy.Reconcile(resolved, actual)
	if err := m.ApplyDiffs(ctx, diffs); err != nil {
		t.Fatalf("ApplyDiffs: %v", err)
	}

	actual2, err := m.ReadActual(ctx)
	if err != nil {
		t.Fatalf("ReadActual (after apply): %v", err)
	}
	if got := actual2[policy.SetAuthenticated]; len(got) != 1 || got[0] != "192.168.1.21" {
		t.Fatalf("expected 192.168.1.21 in authenticated_v4, got %v", got)
	}
	if got := actual2[policy.SetBump]; len(got) != 1 || got[0] != "192.168.1.21" {
		t.Fatalf("expected 192.168.1.21 in bump_v4 too (composes with authenticated_v4), got %v", got)
	}

	// Re-reconcile against unchanged desired state -- must be a no-op,
	// same idempotency property verified live against real nftables
	// earlier.
	if diffs2 := policy.Reconcile(resolved, actual2); len(diffs2) != 0 {
		t.Fatalf("expected no diffs on unchanged desired state, got %+v", diffs2)
	}
}

// TestEnsureBaseline_IsIdempotentAcrossRepeatedCalls covers the
// scenario EnsureBaseline's own doc comment calls out: this process
// restarting under systemd's Restart=on-failure must not duplicate the
// prerouting chain's redirect rules on every restart. Without the
// Flush() fix, a second EnsureBaseline call would append a second copy
// of every rule (knftables' Add() always appends a Rule rather than
// deduplicating it by content, unlike tables/sets/chains).
func TestEnsureBaseline_IsIdempotentAcrossRepeatedCalls(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	m := &Manager{nft: fake}
	ctx := context.Background()

	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline (first call): %v", err)
	}
	rulesAfterFirst, err := fake.ListRules(ctx, "prerouting")
	if err != nil {
		t.Fatalf("ListRules (after first call): %v", err)
	}
	if len(rulesAfterFirst) != len(baselineRules) {
		t.Fatalf("expected %d rules after the first EnsureBaseline, got %d",
			len(baselineRules), len(rulesAfterFirst))
	}

	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline (second call, simulating a restart): %v", err)
	}
	rulesAfterSecond, err := fake.ListRules(ctx, "prerouting")
	if err != nil {
		t.Fatalf("ListRules (after second call): %v", err)
	}
	if len(rulesAfterSecond) != len(baselineRules) {
		t.Fatalf("expected still exactly %d rules after a second EnsureBaseline call (simulating "+
			"a process restart), got %d -- rules were duplicated instead of re-converged",
			len(baselineRules), len(rulesAfterSecond))
	}
}

// TestTeardown_RemovesTheTableEnsureBaselineCreated is a regression
// test for the real gap found live 2026-09-08 shutting down a
// soak-test window: SIGTERM used to just log and return, leaving the
// optigate table (and every baseline redirect rule in it) active in
// the kernel with the managing process gone. Confirms Teardown
// actually removes what EnsureBaseline created, at the same
// Fake-interface level TestEnsureBaseline_IsIdempotentAcrossRepeatedCalls
// already verifies creation at.
func TestTeardown_RemovesTheTableEnsureBaselineCreated(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	m := &Manager{nft: fake}
	ctx := context.Background()

	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline: %v", err)
	}
	if _, err := fake.ListRules(ctx, "prerouting"); err != nil {
		t.Fatalf("ListRules after EnsureBaseline should succeed (table should exist): %v", err)
	}

	if err := m.Teardown(ctx); err != nil {
		t.Fatalf("Teardown: %v", err)
	}

	if _, err := fake.ListRules(ctx, "prerouting"); err == nil {
		t.Fatal("expected ListRules to fail after Teardown (table should be gone), but it succeeded")
	} else if !knftables.IsNotFound(err) {
		t.Fatalf("expected a not-found error after Teardown, got: %v", err)
	}
}

// TestTeardown_ToleratesATableThatWasNeverCreated confirms Teardown is
// safe to call unconditionally -- e.g. this process exiting via SIGTERM
// before EnsureBaseline ever ran -- rather than requiring callers to
// track whether the baseline actually got established first.
func TestTeardown_ToleratesATableThatWasNeverCreated(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	m := &Manager{nft: fake}

	if err := m.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown on a never-created table should be a no-op, not an error: %v", err)
	}
}

// TestBaselineRules_RedirectsDNSOverTLS is a regression test for a real
// DNS-tier bypass found by code review (2026-09-02): before this fix,
// baselineRules only ever touched port 53, so a device with
// DNS-over-TLS enabled (e.g. Android's one-tap Settings > Private DNS)
// resolved every domain over an encrypted TCP/853 session this project
// never saw at all, bypassing every domain/category/schedule/SafeSearch
// rule. Confirms the fix at the same Go-slice level a future accidental
// removal of these two lines would be caught at.
func TestBaselineRules_RedirectsDNSOverTLS(t *testing.T) {
	want := []string{
		fmt.Sprintf("ip saddr @authenticated_v4 tcp dport 853 redirect to :%d", DefaultDNSRedirectPort),
		fmt.Sprintf("ip saddr @unauthenticated_v4 tcp dport 853 redirect to :%d", DefaultDNSRedirectPort),
	}
	for _, w := range want {
		found := false
		for _, r := range baselineRules {
			if r == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected baselineRules to contain %q (DNS-over-TLS redirect), it did not -- full ruleset: %v", w, baselineRules)
		}
	}
}

// TestEnsureBaseline_InstallsDNSOverTLSRedirect_AgainstFake is the
// stronger, end-to-end version of the test above: confirms
// EnsureBaseline actually installs both port-853 rules into the real
// prerouting chain (via knftables' own in-memory Fake), not just that
// the Go source slice happens to contain the right strings.
// TestBaselineRules_MarkForwardableTraffic is a regression test for the
// real bug found live 2026-09-07 (documented in full on
// ensureDockerUserException's own doc comment): before this fix,
// bypass_v4 and authenticated_v4 devices' ordinary (non-redirected)
// traffic had no way to signal "this connection is allowed to actually
// leave the box" to the separate DOCKER-USER exception rule, so it was
// silently dropped by Docker's own FORWARD chain policy even though
// nftables-manager's own table never intended to block it.
func TestBaselineRules_MarkForwardableTraffic(t *testing.T) {
	want := []string{
		"ip saddr @bypass_v4 ct mark set 0x1 return",
		"ip saddr @authenticated_v4 ct mark set 0x1",
	}
	for _, w := range want {
		found := false
		for _, r := range baselineRules {
			if r == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected baselineRules to contain %q (forwarding ct mark), it did not -- full ruleset: %v", w, baselineRules)
		}
	}
}

// TestEnsureBaseline_PrunesLegacyRenamedTable covers the cleanup for
// the bug found live 2026-09-10: a pre-rename version of this binary
// left an `inet parental_proxy` table in the kernel, registered at the
// same prerouting/dstnat hook as the current `inet optigate` table, with
// stale device-set membership that silently shadowed the live policy.
// EnsureBaseline must delete every legacyTableNames table before
// building the current one.
func TestEnsureBaseline_PrunesLegacyRenamedTable(t *testing.T) {
	ctx := context.Background()
	optigateFake := knftables.NewFake(knftables.InetFamily, "optigate")
	legacyFake := knftables.NewFake(knftables.InetFamily, "parental_proxy")

	// Stand up the legacy table the way the old binary would have.
	seed := legacyFake.NewTransaction()
	seed.Add(&knftables.Table{})
	seed.Add(&knftables.Chain{Name: "prerouting"})
	if err := legacyFake.Run(ctx, seed); err != nil {
		t.Fatalf("seeding legacy table: %v", err)
	}
	if chains, err := legacyFake.List(ctx, "chains"); err != nil || len(chains) == 0 {
		t.Fatalf("legacy table should exist before prune (chains=%v err=%v)", chains, err)
	}

	m := &Manager{nft: optigateFake, legacyNfts: map[string]knftables.Interface{"parental_proxy": legacyFake}}
	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline: %v", err)
	}

	if _, err := legacyFake.List(ctx, "chains"); err == nil || !knftables.IsNotFound(err) {
		t.Errorf("legacy table inet parental_proxy should be gone after EnsureBaseline, got err=%v", err)
	}
	if _, err := optigateFake.List(ctx, "chains"); err != nil {
		t.Errorf("current table inet optigate should exist after EnsureBaseline, got err=%v", err)
	}

	// Second call is a no-op, not an error (legacy table already gone).
	if err := m.EnsureBaseline(ctx); err != nil {
		t.Errorf("second EnsureBaseline after prune should not error: %v", err)
	}
}

// TestBaselineRules_DropsQUICForBumpDevices is a regression test for the
// HTTPS-interception bypass found live 2026-09-10: a bump device played
// non-whitelisted Crunchyroll because Chrome switched to HTTP-3 over
// QUIC (udp/443) after its first TCP request and never came back, so
// every per-domain/per-path/per-show rule Squid enforces was silently
// skipped. baselineRules must drop udp/443 for bump_v4 so the browser
// falls back to tcp/443 (which the redirect rule then bumps). Scoped to
// bump_v4 only -- a DNS-tier device's QUIC is fine.
func TestBaselineRules_DropsQUICForBumpDevices(t *testing.T) {
	const want = "ip saddr @bump_v4 udp dport 443 drop"
	found := false
	for _, r := range baselineRules {
		if r == want {
			found = true
		}
		if strings.Contains(r, "udp dport 443") && strings.Contains(r, "drop") && !strings.Contains(r, "@bump_v4") {
			t.Errorf("udp/443 drop leaked onto a non-bump_v4 rule: %q", r)
		}
	}
	if !found {
		t.Errorf("expected baselineRules to contain %q, it did not -- full ruleset: %v", want, baselineRules)
	}
}

// TestBaselineRules_QUICDropComesAfterSelfIPReturn confirms the udp/443
// self-IP carve-out (present only when selfIP is set) precedes the
// udp/443 drop, exactly as the tcp rules are ordered -- a drop is
// terminal, so a "return" for traffic to the box's own address is
// useless after it.
func TestBaselineRules_QUICDropComesAfterSelfIPReturn(t *testing.T) {
	m := &Manager{selfIP: "192.168.1.250"}
	rules := m.baselineRules()
	returnIdx, dropIdx := -1, -1
	for i, r := range rules {
		switch r {
		case "ip saddr @bump_v4 ip daddr 192.168.1.250 udp dport 443 return":
			returnIdx = i
		case "ip saddr @bump_v4 udp dport 443 drop":
			dropIdx = i
		}
	}
	if returnIdx == -1 || dropIdx == -1 {
		t.Fatalf("expected both the udp/443 self-IP return and the udp/443 drop -- full ruleset: %v", rules)
	}
	if returnIdx >= dropIdx {
		t.Errorf("udp/443 self-IP return (index %d) must come before the udp/443 drop (index %d)", returnIdx, dropIdx)
	}
}

// TestBaselineRules_OmitsSelfIPExceptionWhenNotConfigured confirms a
// Manager with no selfIP (every existing test's plain Manager{}, and the
// package-level `baselineRules` var itself) gets exactly the pre-fix
// ruleset -- RoadMap.md items 7/18/20's self-IP exception must never
// apply itself silently just because a Manager exists.
func TestBaselineRules_OmitsSelfIPExceptionWhenNotConfigured(t *testing.T) {
	m := &Manager{}
	for _, r := range m.baselineRules() {
		if strings.Contains(r, "ip daddr") {
			t.Errorf("expected no destination-IP-scoped rule with selfIP unset, found %q", r)
		}
	}
}

// TestBaselineRules_InstallsSelfIPExceptionForBumpV4Only confirms the
// fix itself: with selfIP configured, both bump_v4 redirect ports (80
// and 443) get a matching "ip daddr <selfIP> ... return" exception, and
// -- just as important -- no OTHER source set (authenticated_v4,
// unauthenticated_v4, quarantine_v4) gets any destination-IP-scoped
// rule at all, since none of them share bump_v4's specific
// Squid-redirect problem this fix exists for.
func TestBaselineRules_InstallsSelfIPExceptionForBumpV4Only(t *testing.T) {
	m := &Manager{selfIP: "192.168.1.250"}
	rules := m.baselineRules()

	want := []string{
		"ip saddr @bump_v4 ip daddr 192.168.1.250 tcp dport 80 return",
		"ip saddr @bump_v4 ip daddr 192.168.1.250 tcp dport 443 return",
	}
	for _, w := range want {
		found := false
		for _, r := range rules {
			if r == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected baselineRules to contain %q, it did not -- full ruleset: %v", w, rules)
		}
	}
	for _, r := range rules {
		if strings.Contains(r, "ip daddr") && !strings.Contains(r, "@bump_v4") {
			t.Errorf("self-IP exception leaked onto a non-bump_v4 rule: %q", r)
		}
	}
}

// TestBaselineRules_SelfIPExceptionComesBeforeTheRedirectItGuards is a
// regression test for the one detail that actually makes the fix work:
// nftables evaluates a base chain's rules in order and a redirect is a
// terminating verdict, so the "return" exception is USELESS if it
// doesn't appear before "redirect to :3129"/":3130" in the slice --
// EnsureBaseline adds rules to the kernel in exactly this order (see
// its own doc comment), so slice order here IS kernel rule order.
func TestBaselineRules_SelfIPExceptionComesBeforeTheRedirectItGuards(t *testing.T) {
	m := &Manager{selfIP: "192.168.1.250"}
	rules := m.baselineRules()

	exceptionIdx, redirect80Idx, redirect443Idx := -1, -1, -1
	for i, r := range rules {
		switch r {
		case "ip saddr @bump_v4 ip daddr 192.168.1.250 tcp dport 80 return":
			exceptionIdx = i
		case "ip saddr @bump_v4 tcp dport 80 redirect to :3129":
			redirect80Idx = i
		case "ip saddr @bump_v4 tcp dport 443 redirect to :3130":
			redirect443Idx = i
		}
	}
	if exceptionIdx == -1 || redirect80Idx == -1 || redirect443Idx == -1 {
		t.Fatalf("one of the expected rules was missing entirely -- full ruleset: %v", rules)
	}
	if exceptionIdx >= redirect80Idx || exceptionIdx >= redirect443Idx {
		t.Errorf("self-IP exception (index %d) must come before both bump_v4 redirects "+
			"(80 at %d, 443 at %d) or it can never fire", exceptionIdx, redirect80Idx, redirect443Idx)
	}
}

// TestSelfIPFromDashboardURL covers the extraction this fix relies on
// to avoid inventing a second, separately-configured setting (see that
// function's own doc comment) -- mirrors
// common/optigate_rewrite.py's own parse_block_page_ip() test coverage
// on the Python side.
func TestSelfIPFromDashboardURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain http URL with port", "http://192.168.1.250:8787", "192.168.1.250"},
		{"plain http URL with no port", "http://192.168.1.250", "192.168.1.250"},
		{"https URL", "https://192.168.1.250:8787", "192.168.1.250"},
		{"empty string", "", ""},
		{"a real hostname, not an IP", "http://dashboard.example.com:8787", ""},
		{"malformed URL", "://not a url", ""},
		{"IPv6 literal", "http://[::1]:8787", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SelfIPFromDashboardURL(tc.in); got != tc.want {
				t.Errorf("SelfIPFromDashboardURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEnsureDockerUserException_NilManagerIsANoOp covers a Manager built
// directly (every test above does this, and any future caller that only
// needs the "optigate" side) rather than via New() -- dockerUserNft
// is nil in that case, and EnsureBaseline must not panic calling into it.
func TestEnsureDockerUserException_NilManagerIsANoOp(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	m := &Manager{nft: fake}
	if err := m.EnsureBaseline(context.Background()); err != nil {
		t.Fatalf("EnsureBaseline with a nil dockerUserNft: %v", err)
	}
}

// TestEnsureDockerUserException_MissingChainIsANoOp covers the case
// documented on ensureDockerUserException: DOCKER-USER not existing at
// all (most likely because Docker's own iptables/nftables management is
// disabled) must be logged, not treated as a fatal error -- there's no
// drop policy to work around in that case.
func TestEnsureDockerUserException_MissingChainIsANoOp(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	dockerFake := knftables.NewFake(knftables.IPv4Family, "filter")
	// Deliberately never add a DOCKER-USER chain to dockerFake.
	m := &Manager{nft: fake, dockerUserNft: dockerFake}
	if err := m.EnsureBaseline(context.Background()); err != nil {
		t.Fatalf("EnsureBaseline with no DOCKER-USER chain present: %v", err)
	}
}

// TestEnsureDockerUserException_InsertsExactlyOneAcceptRule_AgainstFake
// is the real end-to-end check: given a DOCKER-USER chain that already
// exists (simulating what Docker itself creates at daemon startup,
// independent of this project), EnsureBaseline must insert exactly one
// rule accepting ct-marked traffic, tagged with dockerUserComment so a
// later call can find and replace it.
func TestEnsureDockerUserException_InsertsExactlyOneAcceptRule_AgainstFake(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	dockerFake := knftables.NewFake(knftables.IPv4Family, "filter")
	ctx := context.Background()

	// Simulate Docker having already created its own chain (and, as
	// Docker itself would, some rule of its own already in it -- this
	// project must never touch that rule).
	setupTx := dockerFake.NewTransaction()
	setupTx.Add(&knftables.Table{})
	setupTx.Add(&knftables.Chain{Name: "DOCKER-USER"})
	setupTx.Add(&knftables.Rule{Chain: "DOCKER-USER", Rule: "iifname \"docker0\" accept"})
	if err := dockerFake.Run(ctx, setupTx); err != nil {
		t.Fatalf("simulating Docker's own DOCKER-USER setup: %v", err)
	}

	m := &Manager{nft: fake, dockerUserNft: dockerFake}
	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline: %v", err)
	}

	rules, err := dockerFake.ListRules(ctx, "DOCKER-USER")
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules in DOCKER-USER (Docker's own + ours), got %d: %+v", len(rules), rules)
	}
	var ours, dockersOwnStillPresent bool
	for _, r := range rules {
		if r.Rule == "ct mark 0x1 counter accept" && r.Comment != nil && *r.Comment == dockerUserComment {
			ours = true
		}
		if r.Rule == "iifname \"docker0\" accept" {
			dockersOwnStillPresent = true
		}
	}
	if !ours {
		t.Errorf("expected our ct-mark accept rule in DOCKER-USER, got %+v", rules)
	}
	if !dockersOwnStillPresent {
		t.Errorf("expected Docker's own pre-existing rule to survive untouched, got %+v", rules)
	}
}

// TestEnsureDockerUserException_IsIdempotentAcrossRepeatedCalls mirrors
// TestEnsureBaseline_IsIdempotentAcrossRepeatedCalls for the DOCKER-USER
// side: a restart must replace our one rule, not accumulate a duplicate
// copy of it every time, while still never touching anyone else's rules
// in that shared chain.
func TestEnsureDockerUserException_IsIdempotentAcrossRepeatedCalls(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	dockerFake := knftables.NewFake(knftables.IPv4Family, "filter")
	ctx := context.Background()

	setupTx := dockerFake.NewTransaction()
	setupTx.Add(&knftables.Table{})
	setupTx.Add(&knftables.Chain{Name: "DOCKER-USER"})
	if err := dockerFake.Run(ctx, setupTx); err != nil {
		t.Fatalf("simulating Docker's own DOCKER-USER setup: %v", err)
	}

	m := &Manager{nft: fake, dockerUserNft: dockerFake}
	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline (first call): %v", err)
	}
	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline (second call, simulating a restart): %v", err)
	}

	rules, err := dockerFake.ListRules(ctx, "DOCKER-USER")
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected exactly 1 rule after two EnsureBaseline calls, got %d (duplicated instead of replaced): %+v", len(rules), rules)
	}
}

func TestEnsureBaseline_InstallsDNSOverTLSRedirect_AgainstFake(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "optigate")
	m := &Manager{nft: fake}
	ctx := context.Background()

	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline: %v", err)
	}

	rules, err := fake.ListRules(ctx, "prerouting")
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}

	wantAuth := fmt.Sprintf("ip saddr @authenticated_v4 tcp dport 853 redirect to :%d", DefaultDNSRedirectPort)
	wantUnauth := fmt.Sprintf("ip saddr @unauthenticated_v4 tcp dport 853 redirect to :%d", DefaultDNSRedirectPort)
	var gotAuth, gotUnauth bool
	for _, r := range rules {
		switch r.Rule {
		case wantAuth:
			gotAuth = true
		case wantUnauth:
			gotUnauth = true
		}
	}
	if !gotAuth {
		t.Errorf("expected the real prerouting chain to contain %q after EnsureBaseline, it did not", wantAuth)
	}
	if !gotUnauth {
		t.Errorf("expected the real prerouting chain to contain %q after EnsureBaseline, it did not", wantUnauth)
	}
}
