"""controller/adguard_discovery.py: the AdGuard query-log discovery
source, which confirms active IP usage. Network access always goes
through adguard_client, which every test here fakes -- same pattern as
test_controller_adguard_sync.py.
"""
from __future__ import annotations

import threading
import time

import pytest

import adguard_client
import adguard_discovery
import identity

MAC_A = "aa:bb:cc:dd:ee:01"
IP_1 = "192.168.1.10"


def _entry(client: str, time_str: str) -> dict:
    return {"client": client, "time": time_str}


# ============================================================
# correlate_once
# ============================================================

def test_correlate_once_refreshes_last_seen_at_for_a_matching_binding(conn, monkeypatch):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-30T00:00:00Z")
    monkeypatch.setattr(
        adguard_discovery.adguard_client, "get_query_log",
        lambda *a, **k: [_entry(IP_1, "2026-08-31T13:17:13.089285447Z")],
    )

    touched = adguard_discovery.correlate_once(conn, "http://x", "a", "b")

    assert touched == 1
    row = conn.execute(
        "SELECT last_seen_at, source FROM device_bindings WHERE ipv4_address = ?", (IP_1,)
    ).fetchone()
    assert row["last_seen_at"] == "2026-08-31T13:17:13Z"
    assert row["source"] == "adguard"


def test_correlate_once_skips_ips_with_no_active_binding(conn, monkeypatch):
    monkeypatch.setattr(
        adguard_discovery.adguard_client, "get_query_log",
        lambda *a, **k: [_entry("192.168.1.99", "2026-08-31T13:17:13Z")],
    )

    assert adguard_discovery.correlate_once(conn, "http://x", "a", "b") == 0


def test_correlate_once_skips_malformed_entries_without_failing_the_batch(conn, monkeypatch):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-30T00:00:00Z")
    monkeypatch.setattr(
        adguard_discovery.adguard_client, "get_query_log",
        lambda *a, **k: [
            {"client": None, "time": "2026-08-31T13:17:13Z"},  # missing client
            {"client": IP_1, "time": None},  # missing time
            _entry(IP_1, "2026-08-31T13:17:14Z"),  # the one good entry
        ],
    )

    touched = adguard_discovery.correlate_once(conn, "http://x", "a", "b")

    assert touched == 1
    row = conn.execute(
        "SELECT last_seen_at FROM device_bindings WHERE ipv4_address = ?", (IP_1,)
    ).fetchone()
    assert row["last_seen_at"] == "2026-08-31T13:17:14Z"


def test_correlate_once_never_regresses_last_seen_at(conn, monkeypatch):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-31T14:00:00Z")
    monkeypatch.setattr(
        adguard_discovery.adguard_client, "get_query_log",
        lambda *a, **k: [_entry(IP_1, "2026-08-31T13:00:00Z")],  # older than current last_seen_at
    )

    touched = adguard_discovery.correlate_once(conn, "http://x", "a", "b")

    assert touched == 0
    row = conn.execute(
        "SELECT last_seen_at, source FROM device_bindings WHERE ipv4_address = ?", (IP_1,)
    ).fetchone()
    assert row["last_seen_at"] == "2026-08-31T14:00:00Z"
    assert row["source"] == "rtnetlink"


# ============================================================
# run_loop -- wiring correlate_once() into a background PeriodicTask
# ============================================================
#
# Same reasoning/pattern as test_controller_adguard_sync.py's run_loop
# tests: run_loop() opens its OWN connection lazily on its background
# thread, so the `conn` fixture's monkeypatched db.DB_PATH is what lets
# that internal db.get_conn() call land on the same on-disk test DB
# these tests read back from.

def test_run_loop_calls_correlate_repeatedly(conn, monkeypatch):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-30T00:00:00Z")
    calls = []

    def fake_get_query_log(*a, **k):
        calls.append(1)
        return [_entry(IP_1, "2026-08-31T13:17:13Z")]

    monkeypatch.setattr(adguard_discovery.adguard_client, "get_query_log", fake_get_query_log)

    task = adguard_discovery.run_loop(interval=0.02, base_url="http://x", username="a", password="b")
    try:
        time.sleep(0.15)
    finally:
        task.stop()

    assert len(calls) >= 2, "expected correlate_once to run repeatedly on the interval"


def test_run_loop_stops_promptly(conn, monkeypatch):
    monkeypatch.setattr(adguard_discovery.adguard_client, "get_query_log", lambda *a, **k: [])

    task = adguard_discovery.run_loop(interval=0.05, base_url="http://x", username="a", password="b")
    time.sleep(0.02)
    started_stop = time.monotonic()
    task.stop()
    elapsed = time.monotonic() - started_stop
    assert elapsed < 0.5, f"stop() took {elapsed:.3f}s, expected it to return promptly"


def test_run_loop_reports_correlation_errors_via_on_error_without_dying(conn, monkeypatch):
    def _boom(*a, **k):
        raise adguard_client.AdGuardError("adguard unreachable")

    monkeypatch.setattr(adguard_discovery.adguard_client, "get_query_log", _boom)

    errors = []
    lock = threading.Lock()

    def on_error(exc):
        with lock:
            errors.append(exc)

    task = adguard_discovery.run_loop(
        interval=0.02, base_url="http://x", username="a", password="b", on_error=on_error
    )
    try:
        time.sleep(0.1)
    finally:
        task.stop()

    with lock:
        got = len(errors)
    assert got >= 2, "expected repeated errors, not a dead loop"
