package nft

import (
	"context"
	"errors"
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
		Fake: knftables.NewFake(knftables.InetFamily, "parental_proxy"),
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
		Fake: knftables.NewFake(knftables.InetFamily, "parental_proxy"),
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
	fake := knftables.NewFake(knftables.InetFamily, "parental_proxy")
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
	fake := knftables.NewFake(knftables.InetFamily, "parental_proxy")
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
		"ip saddr @authenticated_v4 tcp dport 853 redirect to :5353",
		"ip saddr @unauthenticated_v4 tcp dport 853 redirect to :5353",
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

// TestEnsureDockerUserException_NilManagerIsANoOp covers a Manager built
// directly (every test above does this, and any future caller that only
// needs the "parental_proxy" side) rather than via New() -- dockerUserNft
// is nil in that case, and EnsureBaseline must not panic calling into it.
func TestEnsureDockerUserException_NilManagerIsANoOp(t *testing.T) {
	fake := knftables.NewFake(knftables.InetFamily, "parental_proxy")
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
	fake := knftables.NewFake(knftables.InetFamily, "parental_proxy")
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
	fake := knftables.NewFake(knftables.InetFamily, "parental_proxy")
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
	fake := knftables.NewFake(knftables.InetFamily, "parental_proxy")
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
	fake := knftables.NewFake(knftables.InetFamily, "parental_proxy")
	m := &Manager{nft: fake}
	ctx := context.Background()

	if err := m.EnsureBaseline(ctx); err != nil {
		t.Fatalf("EnsureBaseline: %v", err)
	}

	rules, err := fake.ListRules(ctx, "prerouting")
	if err != nil {
		t.Fatalf("ListRules: %v", err)
	}

	wantAuth := "ip saddr @authenticated_v4 tcp dport 853 redirect to :5353"
	wantUnauth := "ip saddr @unauthenticated_v4 tcp dport 853 redirect to :5353"
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
