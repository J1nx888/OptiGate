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

// Guards against desiredPolicyWire silently dropping the "bump" JSON
// field: controller/policy_state.py always writes one (see
// tests/test_controller_run_cycle.py's own expected dict), and a
// missing field here would discard bump membership on every read,
// leaving pp-nftables-manager unable to ever redirect a device to
// Squid's intercept ports.
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

// A missing row must return ErrNoDesiredPolicy, not (DesiredPolicy{},
// nil) -- the latter is indistinguishable from a REAL,
// controller-computed policy where every list is legitimately empty
// (e.g. every device was deleted), and would let reconcileOnce diff
// "nothing computed yet" against the kernel and wipe every nftables set
// with no error.
func TestReadDesiredPolicy_NoRowReturnsErrNoDesiredPolicy(t *testing.T) {
	path := setupDB(t, "")

	_, err := ReadDesiredPolicy(path)
	if !errors.Is(err, ErrNoDesiredPolicy) {
		t.Fatalf("ReadDesiredPolicy err = %v, want ErrNoDesiredPolicy", err)
	}
}

// Sibling case: a row DOES exist (e.g. an older database whose ALTER
// TABLE just added this column, or a future schema migration doing the
// same) but desired_policy_json is NULL rather than the row being
// entirely absent -- a different code path (sql.NullString.Valid, not
// sql.ErrNoRows) that must return the same ErrNoDesiredPolicy, not
// silently collapse into an empty policy.
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

// WriteHealth must not refresh nft_last_healthy_at on a fail-open
// report, matching controller/health.py's report_fail_open() (Python
// side) which deliberately leaves last_healthy_at untouched on
// failure. Advancing it unconditionally would let a continuously
// fail-open-but-still-polling nftables-manager keep refreshing its own
// "last healthy" timestamp forever, defeating dashboard.py's staleness
// detection (_is_stale) for any check that didn't also gate on
// nft_mode != "fail_open".
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

// WriteHealth (and ReadDesiredPolicy) must open their modernc.org/
// sqlite connection with a _busy_timeout DSN parameter, matching
// common/db.py's own `PRAGMA busy_timeout=5000` on the Python side --
// without it, a real SQLITE_BUSY fails immediately instead of waiting
// for whichever other process briefly holds the write lock. This test
// holds a real write lock on the same file from a separate connection
// for longer than SQLite's own default (zero) busy_timeout would
// tolerate, but well inside the 5000ms this package sets, then
// releases it -- WriteHealth must wait it out and succeed, not fail
// with "database is locked".
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
