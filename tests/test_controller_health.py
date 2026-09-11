"""controller/health.py: interception_runtime health reporting for the
controller<->ARP-worker pipeline (Milestone 6)."""
from __future__ import annotations

from health import report_fail_open, report_healthy, report_repair_only


def _row(conn):
    return conn.execute("SELECT * FROM interception_runtime WHERE singleton_id = 1").fetchone()


def test_report_healthy_creates_singleton_row(conn):
    report_healthy(conn, applied_generation=5)
    row = _row(conn)
    assert row["mode"] == "running"
    assert row["applied_generation"] == 5
    assert row["fail_open_reason"] is None
    assert row["last_healthy_at"] is not None


def test_report_healthy_upserts_not_duplicates(conn):
    report_healthy(conn, applied_generation=1)
    report_healthy(conn, applied_generation=2)
    count = conn.execute("SELECT COUNT(*) AS c FROM interception_runtime").fetchone()["c"]
    assert count == 1
    assert _row(conn)["applied_generation"] == 2


def test_report_fail_open_sets_mode_and_reason(conn):
    report_healthy(conn, applied_generation=3)
    report_fail_open(conn, "worker connection lost")
    row = _row(conn)
    assert row["mode"] == "fail_open"
    assert row["fail_open_reason"] == "worker connection lost"
    assert row["applied_generation"] == 3, "fail_open must not clobber the last-known-good generation"


def test_report_healthy_after_fail_open_clears_reason(conn):
    report_fail_open(conn, "transient error")
    report_healthy(conn, applied_generation=7)
    row = _row(conn)
    assert row["mode"] == "running"
    assert row["fail_open_reason"] is None


# ============================================================
# report_fail_open's optional applied_generation (added 2026-08-31 for
# controller/main.py's sustained-ARP-send-failure report -- a cycle
# where reconciliation genuinely succeeded but fail_open is reported
# for an orthogonal reason, so there IS a fresh, true generation to
# preserve, unlike the reconcile-cycle-itself-failed callers above.)
# ============================================================

def test_report_fail_open_with_explicit_generation_writes_it_on_first_ever_row(conn):
    """Regression test for the real bug this fix's own integration test
    caught: a bare report_fail_open() on a brand-new row (no prior
    report_healthy call) let applied_generation default to 0, silently
    understating a real, true value on the very first fail_open cycle."""
    report_fail_open(conn, "arp-worker: 5 consecutive ARP send failures", applied_generation=1)
    row = _row(conn)
    assert row["mode"] == "fail_open"
    assert row["applied_generation"] == 1


def test_report_fail_open_with_explicit_generation_updates_an_existing_row(conn):
    report_healthy(conn, applied_generation=3)
    report_fail_open(conn, "arp-worker: 5 consecutive ARP send failures", applied_generation=4)
    row = _row(conn)
    assert row["mode"] == "fail_open"
    assert row["applied_generation"] == 4


def test_report_fail_open_without_generation_still_preserves_the_prior_value(conn):
    """The default (None) behavior from the existing tests above must
    be completely unaffected by this new parameter's addition."""
    report_healthy(conn, applied_generation=9)
    report_fail_open(conn, "worker connection lost")
    row = _row(conn)
    assert row["mode"] == "fail_open"
    assert row["applied_generation"] == 9


def test_report_repair_only_sets_mode_and_reason(conn):
    report_healthy(conn, applied_generation=2)
    report_repair_only(conn, "worker lease expired, already self-corrected")
    row = _row(conn)
    assert row["mode"] == "repair_only"
    assert row["fail_open_reason"] == "worker lease expired, already self-corrected"
    assert row["applied_generation"] == 2, "repair_only must not clobber the last-known-good generation"


# ============================================================
# Real production incident, 2026-09-11: a health-status write itself
# failing (e.g. sqlite3.OperationalError: database is locked, on a real
# box with several containers hitting the shared DB at once) used to
# propagate straight out of these functions -- most dangerously when
# called from an except block already handling some OTHER failure
# (controller/main.py's run_cycle()), where the second exception had
# nowhere to go and killed the entire caller. None of these three
# functions may ever raise, regardless of what the connection does.
# ============================================================

def test_report_healthy_never_raises_even_if_the_write_fails(conn, caplog):
    conn.close()  # simplest reliable way to make the next execute() raise
    report_healthy(conn, applied_generation=1)  # must not raise
    assert "failed to write health status" in caplog.text


def test_report_fail_open_never_raises_even_if_the_write_fails(conn, caplog):
    conn.close()
    report_fail_open(conn, "some reason")  # must not raise
    assert "failed to write health status" in caplog.text


def test_report_repair_only_never_raises_even_if_the_write_fails(conn, caplog):
    conn.close()
    report_repair_only(conn, "some reason")  # must not raise
    assert "failed to write health status" in caplog.text
