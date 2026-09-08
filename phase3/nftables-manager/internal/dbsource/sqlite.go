// Package dbsource reads the DesiredPolicy JSON blob that
// controller/policy_state.py (Python) computes and writes into the
// shared SQLite database's interception_runtime table, and writes this
// process's own health back into the same table -- following this
// project's own established "one shared database, live reads, no
// separate sync" pattern (see docs/project.md's Key technical
// decisions) instead of a new controller<->nftables-manager IPC
// protocol.
//
// Uses modernc.org/sqlite (pure Go, no cgo) specifically because this
// project's sandboxed test accounts have no C compiler available
// (confirmed while verifying phase3/arp-worker -- `which gcc` found
// nothing on the smoke-test VM), and the real production deployment
// target shouldn't need one installed either.
package dbsource

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/policy"
)

type desiredPolicyWire struct {
	Authenticated   []string `json:"authenticated"`
	Unauthenticated []string `json:"unauthenticated"`
	Bypass          []string `json:"bypass"`
	Quarantine      []string `json:"quarantine"`

	// Bump: added 2026-08-30 alongside policy.DesiredPolicy.Bump /
	// policy.SetBump for the "two independent axes" architecture. This
	// struct's fields are what actually gets populated from the JSON --
	// missing this one meant ReadDesiredPolicy silently returned an
	// empty Bump list on every cycle regardless of what
	// controller/policy_state.py had written, so pp-nftables-manager
	// would never actually redirect any device to Squid no matter how
	// many devices had bump_enabled set. Found by inspection while
	// preparing a live-Squid verification pass, before that pass ever
	// ran -- see RoadMap.md.
	Bump []string `json:"bump"`
}

// ReadDesiredPolicy opens dbPath read-only and reads the current
// desired_policy_json column from interception_runtime's singleton
// row. Returns a zero-value (all-empty) DesiredPolicy, not an error,
// if the row or column doesn't exist/isn't set yet -- that's the
// legitimate "nothing computed yet" state, not a fault worth failing a
// reconcile cycle over.
func ReadDesiredPolicy(dbPath string) (policy.DesiredPolicy, error) {
	// _busy_timeout=5000 matches common/db.py's own PRAGMA busy_timeout=5000
	// on the Python side (confirmed live 2026-09-08: this driver
	// (modernc.org/sqlite) accepts a bare _busy_timeout DSN query param,
	// applied as `pragma busy_timeout = <ms>` -- see sqlite.go's own
	// dsnPick("_busy_timeout", "_timeout") handling). Without this, a
	// SQLITE_BUSY here failed immediately instead of waiting a
	// realistic amount of time for whichever other process (dashboard,
	// proxy, controller's own Python connection, which already sets
	// this) briefly held the write lock -- found live resuming the
	// soak test after the wipe-and-redeploy: WriteHealth() below hit
	// this within the first few seconds of all six containers starting
	// and touching the shared file at once.
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		return policy.DesiredPolicy{}, fmt.Errorf("open %s: %w", dbPath, err)
	}
	defer db.Close()

	var raw sql.NullString
	err = db.QueryRow(
		"SELECT desired_policy_json FROM interception_runtime WHERE singleton_id = 1",
	).Scan(&raw)
	if err == sql.ErrNoRows {
		return policy.DesiredPolicy{}, nil
	}
	if err != nil {
		return policy.DesiredPolicy{}, fmt.Errorf("query interception_runtime: %w", err)
	}
	if !raw.Valid {
		return policy.DesiredPolicy{}, nil
	}

	var wire desiredPolicyWire
	if err := json.Unmarshal([]byte(raw.String), &wire); err != nil {
		return policy.DesiredPolicy{}, fmt.Errorf("parse desired_policy_json: %w", err)
	}

	return policy.DesiredPolicy{
		Authenticated:   wire.Authenticated,
		Unauthenticated: wire.Unauthenticated,
		Bypass:          wire.Bypass,
		Quarantine:      wire.Quarantine,
		Bump:            wire.Bump,
	}, nil
}

// WriteHealth updates nftables-manager's own health columns
// (nft_mode/nft_last_healthy_at/nft_fail_reason) in interception_runtime
// -- deliberately separate from the ARP-worker-pipeline's mode/
// last_healthy_at/fail_open_reason columns (see common/db.py's schema
// comment) so the two subsystems never clobber each other's status in
// the shared singleton row. Pass a nil failReason to report success.
//
// nft_last_healthy_at is only ever advanced on a successful ("running")
// report -- deliberately mirroring controller/health.py's own
// report_healthy()/report_fail_open() split, where report_fail_open()
// doesn't mention last_healthy_at at all and so leaves it untouched. An
// earlier version of this function unconditionally set it to "now" on
// every call, including fail-open ones, which meant a continuously
// failing-but-still-polling nftables-manager kept refreshing its own
// "last healthy" timestamp forever -- caught by code review 2026-08-30,
// before the dashboard's staleness view (see dashboard/dashboard.py's
// _is_stale) grew a reason to compare this column directly.
func WriteHealth(dbPath, mode string, failReason error) error {
	// _busy_timeout=5000: see ReadDesiredPolicy's own comment above --
	// this write path is the one that actually hit SQLITE_BUSY live,
	// since it's a real write racing dashboard/proxy/controller's own
	// writes to the same file, not just a read.
	db, err := sql.Open("sqlite", dbPath+"?_busy_timeout=5000")
	if err != nil {
		return fmt.Errorf("open %s: %w", dbPath, err)
	}
	defer db.Close()

	var reason sql.NullString
	if failReason != nil {
		reason = sql.NullString{String: failReason.Error(), Valid: true}
	}

	var healthyAt sql.NullString
	if mode != "fail_open" {
		healthyAt = sql.NullString{String: nowISO(), Valid: true}
	}

	_, err = db.Exec(
		"INSERT INTO interception_runtime (singleton_id, nft_mode, nft_last_healthy_at, nft_fail_reason) "+
			"VALUES (1, ?, ?, ?) "+
			"ON CONFLICT(singleton_id) DO UPDATE SET nft_mode = excluded.nft_mode, "+
			// COALESCE, not a plain assignment: on a fail_open report
			// healthyAt is NULL, and this keeps whatever nft_last_healthy_at
			// already held rather than wiping it to NULL.
			"nft_last_healthy_at = COALESCE(excluded.nft_last_healthy_at, nft_last_healthy_at), "+
			"nft_fail_reason = excluded.nft_fail_reason",
		mode, healthyAt, reason,
	)
	if err != nil {
		return fmt.Errorf("write health: %w", err)
	}
	return nil
}

// nowISO matches common/db.py's now_iso() format exactly
// ("%Y-%m-%dT%H:%M:%SZ") -- other code in this project relies on that
// format being lexicographically comparable (see db.py's
// iso_secs_ago() docstring), so writing SQLite's own datetime('now')
// format here instead would quietly break that assumption for anything
// that later compares nft_last_healthy_at against a Python-written
// timestamp.
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05") + "Z"
}
