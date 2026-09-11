"""common/system_events.py: the operational failure/recovery event log
that gives the dashboard's Events page (2026-09-01, added ahead of G1
real-network testing) something to show besides docker-compose-logs-only
visibility."""
from __future__ import annotations

import pytest

import system_events


def test_log_event_accepts_info_severity(conn):
    """Added 2026-09-09: a real, narrow-scope third severity (see
    common/db.py's schema comment and system_events.py's own module
    docstring for exactly which two callers use it and why) -- not a
    general "log routine success" escape hatch."""
    system_events.log_event(conn, "network_sweep", "info", "Manual sweep complete: probed 254 address(es).")
    row = conn.execute("SELECT * FROM system_events").fetchone()
    assert row["severity"] == "info"


def test_migrate_widens_an_existing_pre_info_table_without_losing_data(tmp_path, monkeypatch):
    """Regression test for the real migration in db._migrate(): SQLite
    can't ALTER a CHECK constraint in place, so this rebuilds the whole
    table -- must preserve every existing row (including its original
    id) and must actually accept 'info' afterward, on a database that
    predates that severity ever existing."""
    import sqlite3
    import db

    db_file = tmp_path / "pre_info.db"
    monkeypatch.setattr(db, "DB_PATH", db_file)
    raw_conn = sqlite3.connect(db_file)
    raw_conn.row_factory = sqlite3.Row
    # The OLD schema, exactly as it existed before 'info' was added --
    # deliberately hand-written here, not copied from db.SCHEMA (which
    # already has 'info'), so this test actually exercises migrating
    # FROM the old shape, not just re-running the current one.
    raw_conn.executescript(
        """
        CREATE TABLE system_events (
            id       INTEGER PRIMARY KEY,
            ts       TEXT NOT NULL,
            source   TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('error', 'recovery')),
            message  TEXT NOT NULL,
            detail   TEXT
        );
        INSERT INTO system_events (id, ts, source, severity, message, detail)
            VALUES (1, '2026-01-01T00:00:00Z', 'adguard_sync', 'error', 'old failure', 'old detail');
        INSERT INTO system_events (id, ts, source, severity, message, detail)
            VALUES (2, '2026-01-01T00:05:00Z', 'adguard_sync', 'recovery', 'old recovery', NULL);
        """
    )
    raw_conn.commit()
    raw_conn.close()

    conn = db.get_conn()
    db.init_db(conn)  # runs _migrate() as part of its own normal startup path

    rows = conn.execute("SELECT * FROM system_events ORDER BY id").fetchall()
    assert len(rows) == 2, "the pre-existing rows must survive the rebuild"
    assert rows[0]["id"] == 1
    assert rows[0]["message"] == "old failure"
    assert rows[0]["detail"] == "old detail"
    assert rows[1]["id"] == 2
    assert rows[1]["message"] == "old recovery"

    # The real proof the constraint was actually widened, not just that
    # the table still exists: an 'info' insert that would have raised
    # sqlite3.IntegrityError against the old CHECK now succeeds.
    system_events.log_event(conn, "network_sweep", "info", "new info row")
    assert conn.execute(
        "SELECT COUNT(*) c FROM system_events WHERE severity = 'info'"
    ).fetchone()["c"] == 1
    conn.close()


def test_migrate_is_idempotent_for_an_already_migrated_table(conn):
    """Calling _migrate() again (e.g. every container startup) against
    a database that already has 'info' must be a safe no-op, not a
    second rebuild attempt."""
    import db

    db._migrate(conn)  # the `conn` fixture's own init_db() already ran this once
    db._migrate(conn)  # a second time, explicitly, for good measure

    system_events.log_event(conn, "network_sweep", "info", "still works")
    assert conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"] == 1


def test_log_event_inserts_a_row(conn):
    system_events.log_event(conn, "adguard_sync", "error", "adguard sync failed: boom")
    row = conn.execute("SELECT * FROM system_events").fetchone()
    assert row["source"] == "adguard_sync"
    assert row["severity"] == "error"
    assert row["message"] == "adguard sync failed: boom"
    assert row["detail"] is None
    assert row["ts"]


def test_log_event_stores_optional_detail(conn):
    system_events.log_event(conn, "category_fetch", "error", "fetch failed", detail="Traceback: ...")
    row = conn.execute("SELECT detail FROM system_events").fetchone()
    assert row["detail"] == "Traceback: ..."


def test_log_event_rejects_an_invalid_severity(conn):
    with pytest.raises(ValueError, match="severity"):
        system_events.log_event(conn, "adguard_sync", "critical", "oops")
    assert conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"] == 0


def test_log_event_prunes_back_down_to_the_cap(conn, monkeypatch):
    """Regression test for a real gap (fixed 2026-09-02): this table had
    no row cap at all, and became attacker-influenceable once failed
    login attempts (rate-limited but never fully blocked) started
    writing here too -- an attacker who never once succeeds could grow
    it indefinitely. A small cap (monkeypatched down from the real 5000
    so this test doesn't need to insert thousands of rows) confirms
    log_event() actually prunes back down to it after every insert,
    keeping the NEWEST rows."""
    monkeypatch.setattr(system_events, "_MAX_STORED_EVENTS", 3)

    for i in range(5):
        system_events.log_event(conn, "adguard_sync", "error", f"failure {i}")

    rows = conn.execute("SELECT message FROM system_events ORDER BY id").fetchall()
    assert len(rows) == 3, f"expected the table capped at 3 rows, got {len(rows)}"
    assert [r["message"] for r in rows] == ["failure 2", "failure 3", "failure 4"], (
        "expected the OLDEST rows pruned, newest 3 kept"
    )


def test_log_event_never_prunes_below_the_cap(conn, monkeypatch):
    monkeypatch.setattr(system_events, "_MAX_STORED_EVENTS", 10)

    for i in range(3):
        system_events.log_event(conn, "adguard_sync", "error", f"failure {i}")

    count = conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"]
    assert count == 3, "pruning must never remove rows when already under the cap"


def test_failure_recovery_callbacks_logs_every_failure_occurrence(conn):
    # failure_recovery_callbacks() opens its OWN connection internally
    # (db.get_conn(), per its own docstring) rather than accepting one
    # from the caller -- the `conn` fixture fixture already monkeypatches
    # db.DB_PATH to a real temp file, so db.get_conn() here opens a
    # genuinely separate connection to that SAME file, exactly like
    # production does. Reading back through the `conn` fixture's own
    # connection object confirms the write is really visible, not just
    # trusting the callback didn't raise.
    on_error, on_success = system_events.failure_recovery_callbacks("adguard_sync")
    on_error(RuntimeError("first"))
    on_error(RuntimeError("second"))

    rows = conn.execute("SELECT severity, message FROM system_events ORDER BY id").fetchall()
    assert len(rows) == 2
    assert all(r["severity"] == "error" for r in rows)
    assert "first" in rows[0]["message"]
    assert "second" in rows[1]["message"]


def test_failure_recovery_callbacks_logs_recovery_only_after_a_failure(conn):
    on_error, on_success = system_events.failure_recovery_callbacks("adguard_sync")

    # No prior failure -- an ordinary successful cycle must NOT log
    # anything at all (this is the whole point of "key failures/
    # recoveries only," not a firehose of every routine success).
    on_success()
    assert conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"] == 0

    on_error(RuntimeError("boom"))
    on_success()  # the actual recovery
    on_success()  # a second, ordinary success -- must not log again

    rows = conn.execute("SELECT severity FROM system_events ORDER BY id").fetchall()
    assert [r["severity"] for r in rows] == ["error", "recovery"]


def test_failure_recovery_callbacks_are_independent_per_source(conn):
    a_error, a_success = system_events.failure_recovery_callbacks("adguard_sync")
    b_error, b_success = system_events.failure_recovery_callbacks("category_fetch")

    a_error(RuntimeError("a failed"))
    b_success()  # b was never failing -- must not log a spurious recovery

    rows = conn.execute("SELECT source, severity FROM system_events").fetchall()
    assert [(r["source"], r["severity"]) for r in rows] == [("adguard_sync", "error")]


# ============================================================
# Real production incident, 2026-09-11 (see this module's own dated
# docstring on failure_recovery_callbacks()): log_event()'s own write
# can itself raise (sqlite3.OperationalError: database is locked, on a
# real box with several containers hitting the shared DB at once) --
# and since on_error's whole JOB is reporting some OTHER failure, that
# second exception used to have nowhere to go, escaping uncaught and
# killing the periodic task's entire background thread. Neither
# callback may ever raise, regardless of what log_event does.
# ============================================================

def test_on_error_never_raises_even_if_log_event_itself_fails(conn, monkeypatch, caplog):
    def _boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(system_events, "log_event", _boom)
    on_error, _ = system_events.failure_recovery_callbacks("adguard_sync")

    on_error(RuntimeError("the original failure being reported"))  # must not raise

    assert "failed to record its own failure event" in caplog.text


def test_on_success_never_raises_even_if_log_event_itself_fails(conn, monkeypatch, caplog):
    # Real, un-monkeypatched log_event here, so the first on_error()
    # genuinely records a failure and sets state["failing"] = True --
    # otherwise on_success() would short-circuit before ever reaching
    # log_event() at all, and this test would prove nothing.
    on_error, on_success = system_events.failure_recovery_callbacks("adguard_sync")
    on_error(RuntimeError("boom"))

    def _boom(*args, **kwargs):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(system_events, "log_event", _boom)

    on_success()  # must not raise

    assert "failed to record its own recovery event" in caplog.text
