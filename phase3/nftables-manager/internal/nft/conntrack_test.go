package nft

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/policy"
)

// fakeConntrackBinary writes a tiny shell script named "conntrack" into
// a fresh directory and prepends that directory to PATH for the
// duration of the test, so exec.CommandContext(ctx, "conntrack", ...)
// resolves to it instead of (or in the absence of) a real conntrack
// binary -- this package's tests run without CAP_NET_ADMIN or a real
// kernel conntrack table, same reasoning fault_test.go's fakes already
// apply to knftables itself, just via PATH injection instead of an
// interface fake since exec.Command has no interface to substitute.
func fakeConntrackBinary(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "conntrack")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("writing fake conntrack binary: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestFlushConntrackForSource_SuccessWhenEntriesDeleted(t *testing.T) {
	fakeConntrackBinary(t, `echo "conntrack v1.4.3 (conntrack-tools): 1 flow entries have been deleted."; exit 0`)

	if err := FlushConntrackForSource(context.Background(), "192.168.1.18"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestFlushConntrackForSource_NoMatchingEntriesIsNotAnError(t *testing.T) {
	// conntrack-tools' own documented behavior: exits nonzero for "ran
	// fine, but nothing matched" -- the common case for a device that
	// was never holding an already-accepted connection open. Must not
	// be surfaced as a failure.
	fakeConntrackBinary(t, `echo "conntrack v1.4.3 (conntrack-tools): 0 flow entries have been deleted." >&2; exit 1`)

	if err := FlushConntrackForSource(context.Background(), "192.168.1.18"); err != nil {
		t.Fatalf("expected 'nothing matched' to be treated as success, got %v", err)
	}
}

func TestFlushConntrackForSource_RealFailureIsReported(t *testing.T) {
	fakeConntrackBinary(t, `echo "conntrack v1.4.3 (conntrack-tools): netlink error: Operation not permitted" >&2; exit 1`)

	err := FlushConntrackForSource(context.Background(), "192.168.1.18")
	if err == nil {
		t.Fatal("expected a real conntrack failure to be reported, got nil")
	}
	if !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("expected the error to include conntrack's own output, got: %v", err)
	}
}

func TestFlushConntrackForSource_MissingBinaryIsReported(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty directory -- "conntrack" resolves to nothing
	err := FlushConntrackForSource(context.Background(), "192.168.1.18")
	if err == nil {
		t.Fatal("expected a missing conntrack binary to be reported as an error, got nil")
	}
}

func TestFlushConntrackForReclassifiedDevices_OnlyFlushesUnauthenticatedAndQuarantineAdditions(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls.log")
	fakeConntrackBinary(t, `echo "$3" >> `+logPath+`; exit 0`) // $1=-D $2=-s $3=<ip>

	m := &Manager{}
	diffs := map[policy.SetName]policy.SetDiff{
		policy.SetAuthenticated:   {Remove: []string{"192.168.1.30"}},
		policy.SetUnauthenticated: {Add: []string{"192.168.1.30"}},
		policy.SetBypass:          {Add: []string{"192.168.1.40"}},
	}

	errs := m.FlushConntrackForReclassifiedDevices(context.Background(), diffs)
	if len(errs) != 0 {
		t.Fatalf("expected no errors from a successful flush, got %v", errs)
	}

	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected the fake conntrack binary to have been called at least once: %v", err)
	}
	got := strings.TrimSpace(string(logged))
	if got != "192.168.1.30" {
		t.Fatalf("expected conntrack to be invoked ONLY for 192.168.1.30 (the unauthenticated_v4 addition), got: %q", got)
	}
}

func TestFlushConntrackForReclassifiedDevices_IgnoresBypassAndAuthenticatedAdditions(t *testing.T) {
	// A device becoming LESS restricted (added to bypass_v4/
	// authenticated_v4) must never trigger a flush -- confirmed by
	// pointing PATH at a directory with no conntrack binary at all: if
	// this ever attempted a flush for these additions, it would report
	// an error.
	t.Setenv("PATH", t.TempDir())

	m := &Manager{}
	diffs := map[policy.SetName]policy.SetDiff{
		policy.SetBypass:        {Add: []string{"192.168.1.65"}},
		policy.SetAuthenticated: {Add: []string{"192.168.1.30"}},
	}

	errs := m.FlushConntrackForReclassifiedDevices(context.Background(), diffs)
	if len(errs) != 0 {
		t.Fatalf("expected no flush attempts (and so no errors) for bypass/authenticated additions, got %v", errs)
	}
}

func TestFlushConntrackForReclassifiedDevices_ReportsAFailureForEachIPButKeepsGoing(t *testing.T) {
	fakeConntrackBinary(t, `echo "conntrack v1.4.3 (conntrack-tools): netlink error: Operation not permitted" >&2; exit 1`)

	m := &Manager{}
	diffs := map[policy.SetName]policy.SetDiff{
		policy.SetUnauthenticated: {Add: []string{"192.168.1.18", "192.168.1.57"}},
		policy.SetQuarantine:      {Add: []string{"192.168.1.90"}},
	}

	errs := m.FlushConntrackForReclassifiedDevices(context.Background(), diffs)
	if len(errs) != 3 {
		t.Fatalf("expected one error per failed IP (3), got %d: %v", len(errs), errs)
	}
}

func TestFlushConntrackForReclassifiedDevices_NoOpWhenNeitherSetChanged(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	m := &Manager{}
	diffs := map[policy.SetName]policy.SetDiff{
		policy.SetBypass: {Add: []string{"192.168.1.65"}},
	}

	errs := m.FlushConntrackForReclassifiedDevices(context.Background(), diffs)
	if len(errs) != 0 {
		t.Fatalf("expected no errors when unauthenticated/quarantine have no diff entry at all, got %v", errs)
	}
}
