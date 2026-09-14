"""A transient SQLite lock from a concurrent writer must not crash the
controller's health/policy writes -- common/db.py's get_conn() sets
busy_timeout=5000, so a short-lived lock from another connection should
just be a brief wait, not a hard failure that would otherwise take down
run_cycle's health reporting.
"""
from __future__ import annotations

import threading
import time

import db
from health import report_healthy


def test_report_healthy_waits_out_a_transient_lock_instead_of_failing(conn):
    # `conn` (the fixture) already points db.DB_PATH at a tmp file via
    # monkeypatch. A sqlite3 connection can only be used from the
    # thread that created it (Python's sqlite3 module enforces this by
    # default), so the second connection that holds the competing write
    # lock must be BOTH created and released on the background thread
    # -- not created here and released there.
    release_after = 0.3
    lock_acquired = threading.Event()

    def hold_lock_briefly():
        blocker = db.get_conn()
        blocker.execute("BEGIN IMMEDIATE")  # takes a real RESERVED write lock
        lock_acquired.set()
        time.sleep(release_after)
        blocker.execute("COMMIT")
        blocker.close()

    t = threading.Thread(target=hold_lock_briefly)
    t.start()
    lock_acquired.wait(timeout=2)
    try:
        start = time.monotonic()
        report_healthy(conn, applied_generation=1)  # must block briefly, then succeed
        elapsed = time.monotonic() - start
        assert elapsed >= release_after * 0.5, (
            "report_healthy returned suspiciously fast -- expected it to actually "
            "wait for the lock via busy_timeout, not silently skip or fail instantly"
        )
    finally:
        t.join(timeout=2)

    row = conn.execute("SELECT mode FROM interception_runtime WHERE singleton_id = 1").fetchone()
    assert row["mode"] == "running", "the write must have actually landed once the lock cleared"
