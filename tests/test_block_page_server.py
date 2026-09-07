"""dashboard/block_page_server.py: the tiny stdlib-only HTTP server for
the AdGuard-side friendly block page. Real integration test -- binds an
ephemeral port and makes real HTTP requests, since this module has no
pure logic worth unit-testing in isolation (it's a handful of lines of
stdlib http.server wiring; the actual "does the request produce the
right page" behavior is what matters).

Since 2026-08-31 this server also writes to access_log (see its own
module docstring) -- tests exercising that need the `conn` fixture
(tests/conftest.py) so db.DB_PATH points at an isolated test DB; the
page-rendering tests above that predate this don't need it at all
(the DB write is wrapped in its own try/except specifically so a
missing/broken DB can never break the actual page response -- see
`test_page_still_renders_even_if_logging_is_unreachable` below).
"""
from __future__ import annotations

import http.client

import pytest

import block_page_server
import db
import identity


@pytest.fixture
def server():
    srv = block_page_server.start(host="127.0.0.1", port=0)  # port=0 -> OS picks a free one
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _get(server, path="/", host_header="crunchyroll.com", method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        conn.request(method, path, headers={"Host": host_header})
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8"), dict(resp.getheaders())
    finally:
        conn.close()


def test_returns_403_with_html_body(server):
    status, body, headers = _get(server)
    assert status == 403
    assert "text/html" in headers["Content-Type"]
    assert "isn't approved" in body


def test_shows_the_requested_host_in_the_page(server):
    _, body, _ = _get(server, host_header="netflix.com")
    assert "netflix.com" in body


def test_strips_a_nonstandard_port_from_the_displayed_host(server):
    _, body, _ = _get(server, host_header="netflix.com:8080")
    assert "netflix.com" in body
    assert "8080" not in body


def test_falls_back_to_a_generic_label_with_no_host_header(server):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        # http.client always sends a Host header for HTTP/1.1 -- send a
        # raw HTTP/1.0 request instead, which doesn't require one, to
        # genuinely exercise the missing-Host-header fallback.
        conn._http_vsn = 10
        conn._http_vsn_str = "HTTP/1.0"
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
    finally:
        conn.close()
    assert "this site" in body


def test_head_and_post_also_get_the_page(server):
    status, body, _ = _get(server, method="HEAD")
    assert status == 403
    status, body, _ = _get(server, method="POST")
    assert status == 403
    assert "isn't approved" in body


def test_any_path_gets_the_same_page(server):
    status, body, _ = _get(server, path="/some/deep/path?query=1")
    assert status == 403
    assert "isn't approved" in body


# ============================================================
# access_log writes (added 2026-08-31 -- see module docstring / GH #9)
# ============================================================

def test_writes_access_log_row_for_a_known_device(server, conn):
    mac = "aa:bb:cc:dd:ee:01"
    conn.execute("INSERT INTO devices (mac_address, created_at) VALUES (?, ?)", (mac, db.now_iso()))
    conn.commit()
    identity.record_binding(conn, mac, "127.0.0.1", source="rtnetlink")

    _get(server, host_header="crunchyroll.com")

    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None
    assert row["domain"] == "crunchyroll.com"
    assert row["allowed"] == 0
    assert row["reason"] == "dns_tier_denied"
    assert row["device_id"] is not None
    assert row["user_id"] is None  # bare device, no user assigned


def test_writes_placeholder_row_for_an_unrecognized_ip(server, conn):
    """The requesting IP (127.0.0.1, since the test server binds
    localhost) has no device_bindings row at all -- same
    "(unauthenticated)" fallback the Squid helpers use for a never-seen
    device."""
    _get(server, host_header="crunchyroll.com")

    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None
    assert row["username"] == "(unauthenticated)"
    assert row["user_id"] is None
    assert row["device_id"] is None


def test_page_still_renders_even_if_logging_is_unreachable(server, monkeypatch):
    """The block page itself must never break just because the DB write
    failed -- a kid staring at a blank connection error would be strictly
    worse than a working page with a silently-skipped log line."""
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated DB failure")

    monkeypatch.setattr(block_page_server.db, "get_conn", _boom)
    status, body, _ = _get(server, host_header="crunchyroll.com")
    assert status == 403
    assert "isn't approved" in body


# ============================================================
# optigate.home memorable-URL device-info page (RoadMap.md's dated
# 2026-09-07 entry)
# ============================================================

def test_optigate_hostname_shows_a_known_devices_info(server, conn):
    mac = "aa:bb:cc:dd:ee:02"
    conn.execute(
        "INSERT INTO devices (mac_address, label, created_at) VALUES (?, ?, ?)",
        (mac, "Kitchen Cam", db.now_iso()),
    )
    conn.commit()
    identity.record_binding(conn, mac, "127.0.0.1", source="rtnetlink")

    status, body, headers = _get(server, host_header="optigate.home")

    assert status == 200
    assert "text/html" in headers["Content-Type"]
    assert "Kitchen Cam" in body
    assert mac in body
    assert "127.0.0.1" in body
    assert "Not tracked yet" in body  # device name -- honestly not captured anywhere yet


def test_optigate_hostname_shows_the_assigned_users_display_name(server, conn):
    mac = "aa:bb:cc:dd:ee:03"
    conn.execute(
        "INSERT INTO users (username, password_hash, display_name, created_at) VALUES (?, ?, ?, ?)",
        ("kid1", "x", "Alex", db.now_iso()),
    )
    user_id = conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    conn.execute(
        "INSERT INTO devices (mac_address, user_id, created_at) VALUES (?, ?, ?)",
        (mac, user_id, db.now_iso()),
    )
    conn.commit()
    identity.record_binding(conn, mac, "127.0.0.1", source="rtnetlink")

    _, body, _ = _get(server, host_header="optigate.home")

    assert "Alex" in body


def test_optigate_hostname_shows_the_assigned_groups_name(server, conn):
    mac = "aa:bb:cc:dd:ee:04"
    conn.execute("INSERT INTO groups (name, created_at) VALUES (?, ?)", ("IoT", db.now_iso()))
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    conn.execute(
        "INSERT INTO devices (mac_address, group_id, created_at) VALUES (?, ?, ?)",
        (mac, group_id, db.now_iso()),
    )
    conn.commit()
    identity.record_binding(conn, mac, "127.0.0.1", source="rtnetlink")

    _, body, _ = _get(server, host_header="optigate.home")

    assert "IoT" in body


def test_optigate_hostname_shows_ignored_for_a_bypassed_device(server, conn):
    mac = "aa:bb:cc:dd:ee:05"
    conn.execute(
        "INSERT INTO devices (mac_address, ignored, created_at) VALUES (?, 1, ?)", (mac, db.now_iso())
    )
    conn.commit()
    identity.record_binding(conn, mac, "127.0.0.1", source="rtnetlink")

    _, body, _ = _get(server, host_header="optigate.home")

    assert "Ignored" in body


def test_optigate_hostname_unrecognized_ip_shows_just_the_ip(server, conn):
    status, body, _ = _get(server, host_header="optigate.home")

    assert status == 200
    assert "127.0.0.1" in body
    assert "Not recognized" in body


def test_optigate_hostname_is_case_insensitive_and_ignores_port(server, conn):
    status, body, _ = _get(server, host_header="OptiGate.Home:8080")
    assert status == 200
    assert "Not recognized" in body


def test_optigate_hostname_respects_custom_prefix_setting(server, conn):
    db.set_setting(conn, "optigate_hostname_prefix", "mynetwork")
    conn.commit()

    status, body, _ = _get(server, host_header="mynetwork.home")
    assert status == 200
    assert "Not recognized" in body

    # The old default no longer matches once the prefix has been changed
    # -- falls through to the ordinary blocked-page response instead.
    status, body, _ = _get(server, host_header="optigate.home")
    assert status == 403


def test_other_hostnames_still_get_the_ordinary_blocked_page(server, conn):
    status, body, _ = _get(server, host_header="crunchyroll.com")
    assert status == 403
    assert "isn't approved" in body


def test_optigate_page_falls_back_to_blocked_page_if_hostname_lookup_fails(server, monkeypatch):
    """A total DB outage means the current hostname setting can't be
    read at all -- falls through to the ordinary blocked-page response
    (which has its own, separate DB-failure fallback, already covered by
    test_page_still_renders_even_if_logging_is_unreachable) rather than
    crashing the request."""
    def _boom(*args, **kwargs):
        raise RuntimeError("simulated DB failure")

    monkeypatch.setattr(block_page_server.db, "get_conn", _boom)
    status, body, _ = _get(server, host_header="optigate.home")
    assert status == 403
    assert "isn't approved" in body
