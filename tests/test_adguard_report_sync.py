"""dashboard/adguard_report_sync.py: back-fills the Report page's
`access_log` with the DNS-tier hard-denies that never reach a logging
call otherwise (a hard-denied domain over HTTPS resolves to the box's own
IP, the connection is refused on port 443, nothing ever calls
log_access()). Network access always goes through adguard_client, which
every test here fakes -- same pattern as test_controller_adguard_discovery.py.
"""
from __future__ import annotations

import re
import threading
import time

import adguard_report_sync
import db
import identity

MAC_A = "aa:bb:cc:dd:ee:01"
IP_1 = "192.168.1.10"
BLOCK_PAGE_IP = "192.168.1.250"


def _entry(hostname, client, *, answer_ip=BLOCK_PAGE_IP, time_str="2026-09-09T13:17:13.089285447Z"):
    """A querylog entry shaped like AdGuard Home's real one -- question /
    client / answer / time. answer_ip=None produces an answer-less entry
    (NXDOMAIN-style)."""
    answer = [] if answer_ip is None else [{"type": "A", "value": answer_ip, "ttl": 10}]
    return {
        "question": {"class": "IN", "name": hostname, "type": "A"},
        "client": client,
        "answer": answer,
        "reason": "RewriteRule",
        "time": time_str,
    }


def _insert_domain(conn, pattern, mode="bump", is_global=True):
    conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, created_at) "
        "VALUES (?, ?, 'generic', ?, datetime('now'))",
        (pattern, mode, int(is_global)),
    )
    conn.commit()


def _insert_category_with_domain(conn, name, pattern, *, is_global=True):
    conn.execute(
        "INSERT INTO categories (name, is_global, created_at) VALUES (?, ?, datetime('now'))",
        (name, int(is_global)),
    )
    category_id = conn.execute("SELECT id FROM categories WHERE name = ?", (name,)).fetchone()["id"]
    conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) "
        "VALUES (?, ?, 'manual', datetime('now'))",
        (category_id, pattern),
    )
    conn.commit()


def _fake_log(entries):
    return lambda *a, **k: list(entries)


def _rows(conn):
    return conn.execute(
        "SELECT domain, username, allowed, reason, device_id, ip_address FROM access_log ORDER BY id"
    ).fetchall()


# ============================================================
# correlate_once -- the core back-fill
# ============================================================

def test_writes_a_blocked_row_for_a_bump_domain_hard_deny(conn, monkeypatch):
    _insert_domain(conn, r"youtube\.com", mode="bump")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("www.youtube.com", IP_1)]),
    )

    written = adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP)

    assert written == 1
    row = _rows(conn)[0]
    assert row["domain"] == "www.youtube.com"
    assert row["allowed"] == 0
    assert row["reason"] == "dns_hard_deny"
    assert row["ip_address"] == IP_1


def test_writes_a_blocked_row_for_a_splice_domain_hard_deny(conn, monkeypatch):
    _insert_domain(conn, r"tracker\.example", mode="splice")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("ads.tracker.example", IP_1)]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 1
    assert _rows(conn)[0]["domain"] == "ads.tracker.example"


def test_writes_a_blocked_row_for_a_category_domain_hard_deny(conn, monkeypatch):
    _insert_category_with_domain(conn, "Games", re.escape("badgames.com"))
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("badgames.com", IP_1)]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 1
    assert _rows(conn)[0]["domain"] == "badgames.com"


def test_ignores_an_ordinary_allowed_lookup(conn, monkeypatch):
    """An entry whose answer is a real external IP, not the block page --
    the overwhelmingly common case -- must never produce a row."""
    _insert_domain(conn, r"youtube\.com", mode="bump")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("www.youtube.com", IP_1, answer_ip="142.250.72.206")]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 0
    assert _rows(conn) == []


def test_ignores_a_domain_this_project_does_not_manage(conn, monkeypatch):
    """Answer IS the block-page IP, but the domain isn't one of ours --
    e.g. an admin's own unrelated AdGuard Rewrites-list entry pointing at
    the same box. Must not be misattributed as our block."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("someones-nas.example", IP_1)]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 0
    assert _rows(conn) == []


def test_attributes_the_row_to_the_resolved_device_and_user(conn, monkeypatch):
    _insert_domain(conn, r"youtube\.com", mode="bump")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    device_id = conn.execute("SELECT id FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()["id"]
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) VALUES ('kid1','Kid One','h',?)",
        (db.now_iso(),),
    )
    user_id = conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    conn.execute("UPDATE devices SET user_id = ? WHERE id = ?", (user_id, device_id))
    conn.commit()
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("www.youtube.com", IP_1)]),
    )

    adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP)

    row = _rows(conn)[0]
    assert row["username"] == "kid1"
    assert row["device_id"] == device_id


def test_still_logs_against_the_raw_ip_when_no_device_is_bound(conn, monkeypatch):
    _insert_domain(conn, r"youtube\.com", mode="bump")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("www.youtube.com", "192.168.1.77")]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 1
    row = _rows(conn)[0]
    assert row["username"] == "(unauthenticated)"
    assert row["device_id"] is None
    assert row["ip_address"] == "192.168.1.77"


def test_advances_the_watermark_and_a_second_pass_re_logs_nothing(conn, monkeypatch):
    _insert_domain(conn, r"youtube\.com", mode="bump")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("www.youtube.com", IP_1, time_str="2026-09-09T13:00:00Z")]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 1
    assert db.get_setting(conn, "adguard_report_sync_watermark") == "2026-09-09T13:00:00Z"
    # same entry, same page, next poll -- already at/under the watermark
    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 0
    assert len(_rows(conn)) == 1


def test_only_new_entries_past_the_watermark_are_processed(conn, monkeypatch):
    _insert_domain(conn, r"youtube\.com", mode="bump")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    db.set_setting(conn, "adguard_report_sync_watermark", "2026-09-09T13:00:00Z")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([
            _entry("www.youtube.com", IP_1, time_str="2026-09-09T12:59:59Z"),  # stale
            _entry("www.youtube.com", IP_1, time_str="2026-09-09T13:00:05Z"),  # new
        ]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 1
    assert db.get_setting(conn, "adguard_report_sync_watermark") == "2026-09-09T13:00:05Z"


def test_empty_querylog_is_a_clean_no_op(conn, monkeypatch):
    monkeypatch.setattr(adguard_report_sync.adguard_client, "get_query_log", _fake_log([]))
    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 0


def test_malformed_entries_are_skipped_without_failing_the_batch(conn, monkeypatch):
    _insert_domain(conn, r"youtube\.com", mode="bump")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([
            {"client": IP_1, "time": None},  # missing time
            {"question": None, "client": IP_1, "answer": [], "time": "2026-09-09T13:17:13Z"},  # no question
            {"question": {"name": "www.youtube.com"}, "client": None,
             "answer": [{"type": "A", "value": BLOCK_PAGE_IP}], "time": "2026-09-09T13:17:14Z"},  # no client
            _entry("www.youtube.com", IP_1, time_str="2026-09-09T13:17:15Z"),  # the one good entry
        ]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 1


def test_answerless_entry_is_not_treated_as_a_block(conn, monkeypatch):
    _insert_domain(conn, r"youtube\.com", mode="bump")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    monkeypatch.setattr(
        adguard_report_sync.adguard_client, "get_query_log",
        _fake_log([_entry("www.youtube.com", IP_1, answer_ip=None)]),
    )

    assert adguard_report_sync.correlate_once(conn, "http://x", "a", "b", BLOCK_PAGE_IP) == 0


# ============================================================
# start() -- the background poll loop
# ============================================================

def test_start_runs_correlate_repeatedly(conn, monkeypatch):
    monkeypatch.setenv("DASHBOARD_URL", f"http://{BLOCK_PAGE_IP}:8787")
    db.set_setting(conn, "adguard_url", "http://127.0.0.1:3000")
    db.set_setting(conn, "adguard_password", "secret")
    calls = []
    monkeypatch.setattr(
        adguard_report_sync, "correlate_once",
        lambda *a, **k: calls.append(1) or 0,
    )
    stop = threading.Event()

    thread = adguard_report_sync.start(interval=0.02, stop_event=stop)
    try:
        time.sleep(0.15)
    finally:
        stop.set()
        thread.join(timeout=1)

    assert thread.daemon is True
    assert len(calls) >= 2


def test_start_survives_an_adguard_error_without_dying(conn, monkeypatch):
    monkeypatch.setenv("DASHBOARD_URL", f"http://{BLOCK_PAGE_IP}:8787")
    db.set_setting(conn, "adguard_url", "http://127.0.0.1:3000")
    db.set_setting(conn, "adguard_password", "secret")
    calls = []

    def _boom(*a, **k):
        calls.append(1)
        raise adguard_report_sync.adguard_client.AdGuardError("unreachable")

    monkeypatch.setattr(adguard_report_sync, "correlate_once", _boom)
    stop = threading.Event()

    thread = adguard_report_sync.start(interval=0.02, stop_event=stop)
    try:
        time.sleep(0.12)
    finally:
        stop.set()
        thread.join(timeout=1)

    assert len(calls) >= 2, "loop should keep polling after an AdGuardError, not die"


def test_start_skips_when_dashboard_url_is_not_a_plain_ip(conn, monkeypatch):
    monkeypatch.setenv("DASHBOARD_URL", "http://dashboard.example.com:8787")
    db.set_setting(conn, "adguard_url", "http://127.0.0.1:3000")
    db.set_setting(conn, "adguard_password", "secret")
    calls = []
    monkeypatch.setattr(adguard_report_sync, "correlate_once", lambda *a, **k: calls.append(1) or 0)
    stop = threading.Event()

    thread = adguard_report_sync.start(interval=0.02, stop_event=stop)
    try:
        time.sleep(0.1)
    finally:
        stop.set()
        thread.join(timeout=1)

    assert calls == [], "correlate_once must not run without a usable block-page IP"
