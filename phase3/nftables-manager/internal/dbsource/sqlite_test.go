package dbsource

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// setupDB creates a throwaway SQLite file with just enough schema
// (interception_runtime's singleton row) for ReadDesiredPolicy/WriteHealth
// to exercise against -- a minimal stand-in for common/db.py's real
// migration, since this package only ever touches this one table.
func setupDB(t *testing.T, desiredPolicyJSON string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		CREATE TABLE interception_runtime (
			singleton_id INTEGER PRIMARY KEY,
			desired_policy_json TEXT,
			nft_mode TEXT,
			nft_last_healthy_at TEXT,
			nft_fail_reason TEXT
		)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	if desiredPolicyJSON != "" {
		if _, err := db.Exec(
			"INSERT INTO interception_runtime (singleton_id, desired_policy_json) VALUES (1, ?)",
			desiredPolicyJSON,
		); err != nil {
			t.Fatalf("seed row: %v", err)
		}
	}

	return path
}

// Regression test for the bug found 2026-08-30 while preparing a
// live-Squid verification pass: desiredPolicyWire never declared a
// "bump" JSON field, so a real desired_policy_json blob written by
// controller/policy_state.py -- which always includes a "bump" key,
// see tests/test_controller_run_cycle.py's own expected dict -- had its
// bump membership silently discarded on every read, meaning
// pp-nftables-manager could never actually redirect any device to
// Squid's intercept ports no matter how many devices had
// bump_enabled set in the database.
func TestReadDesiredPolicy_PopulatesBumpField(t *testing.T) {
	path := setupDB(t, `{
		"authenticated": ["192.168.1.10"],
		"unauthenticated": [],
		"bypass": [],
		"quarantine": [],
		"bump": ["192.168.1.10"]
	}`)

	got, err := ReadDesiredPolicy(path)
	if err != nil {
		t.Fatalf("ReadDesiredPolicy: %v", err)
	}

	if len(got.Bump) != 1 || got.Bump[0] != "192.168.1.10" {
		t.Fatalf("Bump = %v, want [192.168.1.10]", got.Bump)
	}
	if len(got.Authenticated) != 1 || got.Authenticated[0] != "192.168.1.10" {
		t.Fatalf("Authenticated = %v, want [192.168.1.10]", got.Authenticated)
	}
}

// Regression test for a real gap found by code review 2026-09-11, fixed
// 2026-09-12 per the project owner's explicit decision: this used to
// return (DesiredPolicy{}, nil) for a missing row -- indistinguishable
// from a REAL, controller-computed policy where every list is
// legitimately empty (e.g. every device was deleted). Collapsing the
// two meant reconcileOnce would diff "nothing computed yet" against
// whatever the kernel currently enforces and wipe every nftables set,
// with no error anywhere, the moment this row went missing while real
// devices were still enforced. Must now return the distinguishable
// ErrNoDesiredPolicy instead.
func TestReadDesiredPolicy_NoRowReturnsErrNoDesiredPolicy(t *testing.T) {
	path := setupDB(t, "")

	_, err := ReadDesiredPolicy(path)
	if !errors.Is(err, ErrNoDesiredPolicy) {
		t.Fatalf("ReadDesiredPolicy err = %v, want ErrNoDesiredPolicy", err)
	}
}

// Sibling case: a row DOES exist (e.g. a pre-Milestone-6/7 database
// whose ALTER TABLE just added this column, or a future schema
// migration doing the same) but desired_policy_json is NULL rather
// than the row being entirely absent -- a different code path
// (sql.NullString.Valid, not sql.ErrNoRows) that must return the same
// ErrNoDesiredPolicy, not silently collapse into an empty policy.
func TestReadDesiredPolicy_NullColumnReturnsErrNoDesiredPolicy(t *testing.T) {
	path := setupDB(t, "")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()
	if _, err := db.Exec(
		"INSERT INTO interception_runtime (singleton_id, desired_policy_json) VALUES (1, NULL)",
	); err != nil {
		t.Fatalf("seed NULL row: %v", err)
	}

	_, err = ReadDesiredPolicy(path)
	if !errors.Is(err, ErrNoDesiredPolicy) {
		t.Fatalf("ReadDesiredPolicy err = %v, want ErrNoDesiredPolicy", err)
	}
}

// The other side of the same distinction: a REAL, controller-computed
// policy where every list is legitimately empty (e.g. every device was
// deleted) must NOT be confused with ErrNoDesiredPolicy -- it's a valid
// desired state and should be returned normally, letting reconcileOnce
// apply it (which could legitimately mean clearing every nftables set,
// exactly as the admin intended).
func TestReadDesiredPolicy_RealEmptyPolicyIsNotAnError(t *testing.T) {
	path := setupDB(t, `{
		"authenticated": [],
		"unauthenticated": [],
		"bypass": [],
		"quarantine": [],
		"bump": []
	}`)

	got, err := ReadDesiredPolicy(path)
	if err != nil {
		t.Fatalf("ReadDesiredPolicy: %v", err)
	}
	if len(got.Bump) != 0 || len(got.Authenticated) != 0 {
		t.Fatalf("expected zero-value DesiredPolicy, got %+v", got)
	}
}

func readNftHealth(t *testing.T, path string) (mode string, healthyAt sql.NullString, failReason sql.NullString) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()

	row := db.QueryRow("SELECT nft_mode, nft_last_healthy_at, nft_fail_reason FROM interception_runtime WHERE singleton_id = 1")
	if err := row.Scan(&mode, &healthyAt, &failReason); err != nil {
		t.Fatalf("scan health row: %v", err)
	}
	return mode, healthyAt, failReason
}

// Regression test for the bug found via code review 2026-08-30: WriteHealth
// used to unconditionally refresh nft_last_healthy_at on every call,
// including fail-open reports, unlike controller/health.py's
// report_fail_open() (Python side) which deliberately leaves
// last_healthy_at untouched on failure. A continuously fail-open-but-
// still-polling nftables-manager kept refreshing its own "last healthy"
// timestamp forever, which would have made dashboard.py's staleness
// detection (_is_stale) wrongly treat it as fresh/healthy on any future
// use that didn't also gate on nft_mode != "fail_open".
func TestWriteHealth_DoesNotAdvanceLastHealthyOnFailOpen(t *testing.T) {
	path := setupDB(t, "")

	if err := WriteHealth(path, "running", nil); err != nil {
		t.Fatalf("WriteHealth(running): %v", err)
	}
	_, firstHealthyAt, _ := readNftHealth(t, path)
	if !firstHealthyAt.Valid || firstHealthyAt.String == "" {
		t.Fatalf("expected nft_last_healthy_at to be set after a successful report, got %+v", firstHealthyAt)
	}

	if err := WriteHealth(path, "fail_open", errFake{"nft command failed"}); err != nil {
		t.Fatalf("WriteHealth(fail_open): %v", err)
	}
	mode, healthyAtAfterFailure, failReason := readNftHealth(t, path)

	if mode != "fail_open" {
		t.Fatalf("nft_mode = %q, want fail_open", mode)
	}
	if !failReason.Valid || failReason.String != "nft command failed" {
		t.Fatalf("nft_fail_reason = %+v, want \"nft command failed\"", failReason)
	}
	if healthyAtAfterFailure != firstHealthyAt {
		t.Fatalf("nft_last_healthy_at changed on a fail-open report: was %+v, now %+v", firstHealthyAt, healthyAtAfterFailure)
	}
}

// A fail-open report on the very first-ever write (no prior successful
// report) should leave nft_last_healthy_at NULL, not set it -- matching
// controller/health.py's report_fail_open(), which never mentions
// last_healthy_at in its INSERT either.
func TestWriteHealth_FailOpenOnFirstWriteLeavesLastHealthyNull(t *testing.T) {
	path := setupDB(t, "")

	if err := WriteHealth(path, "fail_open", errFake{"never started"}); err != nil {
		t.Fatalf("WriteHealth(fail_open): %v", err)
	}
	mode, healthyAt, failReason := readNftHealth(t, path)

	if mode != "fail_open" {
		t.Fatalf("nft_mode = %q, want fail_open", mode)
	}
	if healthyAt.Valid {
		t.Fatalf("nft_last_healthy_at = %+v, want NULL on a first-ever fail-open report", healthyAt)
	}
	if !failReason.Valid || failReason.String != "never started" {
		t.Fatalf("nft_fail_reason = %+v, want \"never started\"", failReason)
	}
}

// Regression test for the real bug found live 2026-09-08, resuming the
// soak test after the wipe-and-redeploy: WriteHealth (and
// ReadDesiredPolicy) opened their modernc.org/sqlite connection with no
// _busy_timeout DSN parameter at all, unlike common/db.py's own
// `PRAGMA busy_timeout=5000` on the Python side -- so a real
// SQLITE_BUSY here (all six containers touching the shared file within
// the same second at startup) failed immediately instead of waiting a
// realistic amount of time for whichever other process briefly held
// the write lock. Holds a real write lock on the same file from a
// separate connection for longer than SQLite's own default (zero)
// busy_timeout would tolerate, but well inside the 5000ms this
// package now sets, then releases it -- WriteHealth must wait it out
// and succeed, not fail with "database is locked".
func TestWriteHealth_WaitsOutABriefLockInsteadOfFailingImmediately(t *testing.T) {
	path := setupDB(t, "")

	holder, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open holder: %v", err)
	}
	defer holder.Close()
	conn, err := holder.Conn(context.Background())
	if err != nil {
		t.Fatalf("acquire pinned conn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("BEGIN IMMEDIATE: %v", err)
	}

	released := make(chan struct{})
	go func() {
		time.Sleep(300 * time.Millisecond)
		if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			t.Errorf("release lock: %v", err)
		}
		close(released)
	}()

	if err := WriteHealth(path, "running", nil); err != nil {
		t.Fatalf("WriteHealth should have waited out the brief lock, not failed: %v", err)
	}
	<-released
}

type errFake struct{ msg string }

func (e errFake) Error() string { return e.msg }
