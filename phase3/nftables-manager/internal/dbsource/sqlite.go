// Package dbsource reads the DesiredPolicy JSON blob that
// controller/policy_state.py (Python) computes and writes into the
// shared SQLite database's interception_runtime table, and writes this
// process's own health back into the same table -- following this
// project's own established "one shared database, live reads, no
// separate sync" pattern (see docs/project.md's Key technical
// decisions) instead of a new controller<->nftables-manager IPC
// protocol.
//
// Uses modernc.org/sqlite (pure Go, no cgo) since this project's
// sandboxed test accounts have no C compiler available, and the real
// production deployment target shouldn't need one installed either.
package dbsource

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	_ "modernc.org/sqlite"

	"github.com/J1nx888/parental_proxy/phase3/nftables-manager/internal/policy"
)

// ErrNoDesiredPolicy is returned by ReadDesiredPolicy when
// interception_runtime's singleton row doesn't exist yet, or its
// desired_policy_json column is NULL -- deliberately distinguished
// from a REAL, controller-computed policy that happens to have every
// list empty (e.g. every device was deleted, a legitimate desired
// state). Collapsing the two would mean this process treats a missing
// row/column exactly like "the policy is: nobody is authenticated,
// bypassed, or quarantined," diffs that against whatever the kernel
// currently enforces, and wipes every nftables set -- with no error
// anywhere -- the moment this row/column goes missing while real
// devices are still enforced (e.g. a mishandled DB restore/reset).
// Callers (reconcileOnce in cmd/pp-nftables-manager/main.go) must treat
// this error specially -- hold current kernel state and retry next
// cycle, rather than applying an empty diff.
var ErrNoDesiredPolicy = errors.New("no desired policy computed yet (interception_runtime row or desired_policy_json column is missing)")

type desiredPolicyWire struct {
	Authenticated   []string `json:"authenticated"`
	Unauthenticated []string `json:"unauthenticated"`
	Bypass          []string `json:"bypass"`
	Quarantine      []string `json:"quarantine"`

	// Bump must stay present and correctly tagged: this struct's fields
	// are what actually get populated from the JSON, and a missing or
	// mistagged field here means ReadDesiredPolicy silently returns an
	// empty Bump list every cycle regardless of what
	// controller/policy_state.py wrote, so pp-nftables-manager would
	// never redirect any device to Squid no matter how many devices had
	// bump_enabled set.
	Bump []string `json:"bump"`
}

// ReadDesiredPolicy opens dbPath read-only and reads the current
// desired_policy_json column from interception_runtime's singleton
// row. Returns ErrNoDesiredPolicy (see its own doc comment) if the row
// or column doesn't exist/isn't set yet -- callers must NOT treat that
// the same as a real, controller-computed empty policy.
func ReadDesiredPolicy(dbPath string) (policy.DesiredPolicy, error) {
	// _busy_timeout=5000 matches common/db.py's own PRAGMA
	// busy_timeout=5000 on the Python side (this driver, modernc.org/
	// sqlite, accepts a bare _busy_timeout DSN query param, applied as
	// `pragma busy_timeout = <ms>`). Without this, a SQLITE_BUSY here
	// fails immediately instead of waiting for whichever other process
	// (dashboard, proxy, controller's own Python connection, which
	// already sets this) briefly holds the write lock.
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
		return policy.DesiredPolicy{}, ErrNoDesiredPolicy
	}
	if err != nil {
		return policy.DesiredPolicy{}, fmt.Errorf("query interception_runtime: %w", err)
	}
	if !raw.Valid {
		return policy.DesiredPolicy{}, ErrNoDesiredPolicy
	}

	var wire desiredPolicyWire
	if err := json.Unmarshal([]byte(raw.String), &wire); err != nil {
		return policy.DesiredPolicy{}, fmt.Errorf("parse desired_policy_json: %w", err)
	}

	return policy.DesiredPolicy{
		Authenticated:   validIPv4s("authenticated", wire.Authenticated),
		Unauthenticated: validIPv4s("unauthenticated", wire.Unauthenticated),
		Bypass:          validIPv4s("bypass", wire.Bypass),
		Quarantine:      validIPv4s("quarantine", wire.Quarantine),
		Bump:            validIPv4s("bump", wire.Bump),
	}, nil
}

// validIPv4s drops any entry that isn't a well-formed IPv4 address,
// logging each one dropped, so a single malformed entry (a Python-side
// bug, encoding issue, or a future non-IPv4 device record) can't fail
// policy.Reconcile's downstream atomic knftables transaction and block
// every OTHER legitimate change computed that cycle.
func validIPv4s(setName string, ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if net.ParseIP(ip).To4() == nil {
			log.Printf("dropping malformed IPv4 entry %q from desired %s set", ip, setName)
			continue
		}
		out = append(out, ip)
	}
	return out
}

// WriteHealth updates nftables-manager's own health columns
// (nft_mode/nft_last_healthy_at/nft_fail_reason) in interception_runtime
// -- deliberately separate from the ARP-worker-pipeline's mode/
// last_healthy_at/fail_open_reason columns (see common/db.py's schema
// comment) so the two subsystems never clobber each other's status in
// the shared singleton row. Pass a nil failReason to report success.
//
// nft_last_healthy_at is only ever advanced on a successful ("running")
// report -- mirroring controller/health.py's own
// report_healthy()/report_fail_open() split, where report_fail_open()
// leaves it untouched. Advancing it unconditionally (including on
// fail-open reports) would let a continuously failing-but-still-polling
// nftables-manager keep refreshing its own "last healthy" timestamp
// forever, defeating the dashboard's staleness check
// (dashboard/dashboard.py's _is_stale).
func WriteHealth(dbPath, mode string, failReason error) error {
	// _busy_timeout=5000: see ReadDesiredPolicy's own comment above --
	// this write path races dashboard/proxy/controller's own writes to
	// the same file, so it needs the same wait-for-the-lock behavior.
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
