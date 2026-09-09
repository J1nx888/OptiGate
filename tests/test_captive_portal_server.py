"""dashboard/captive_portal_server.py: Phase 4 milestone 3's
captive-portal login server. Real integration test -- binds an
ephemeral port and makes real HTTP requests, same style as
test_block_page_server.py, since a stdlib http.server handler is what's
actually under test, not something worth mocking. do_POST's DB access
uses the `conn` fixture's own db.DB_PATH (a process-global db.py
attribute), so the server's own request-handling threads -- which open
their own connection per request, see the module's own docstring for
why -- land on the exact same on-disk temp DB these tests set up.
"""
from __future__ import annotations

import http.client
from urllib.parse import urlencode

import pytest

import auth
import captive_portal_server
import db
import identity
import rate_limit

MAC_A = "aa:bb:cc:dd:ee:01"
# The real source address of every http.client request this test file
# makes -- record_binding() must bind MAC_A to THIS address, not an
# arbitrary LAN-looking one, or resolve_device() correctly finds no
# active binding for the connection that's actually arriving.
IP_1 = "127.0.0.1"


@pytest.fixture(autouse=True)
def _reset_rate_limit():
    """The shared common/rate_limit.RateLimiter instance's own state
    (see captive_portal_server.py's own comment on why it's a
    module-level instance, not per-request) would otherwise leak between
    tests -- every test in this file's real HTTP requests come from the
    same source address (127.0.0.1), so a failed login recorded by one
    test would count against a completely unrelated later test without
    this. Swapping in a fresh instance (rather than reaching into its
    private dict) resets it the same way a real process restart would."""
    captive_portal_server._LOGIN_LIMITER = rate_limit.RateLimiter(
        captive_portal_server._MAX_ATTEMPTS, captive_portal_server._WINDOW_SECONDS
    )
    yield


@pytest.fixture
def server(conn):  # noqa: ARG001 -- depended on for its db.DB_PATH monkeypatch side effect
    srv = captive_portal_server.start(host="127.0.0.1", port=0)  # port=0 -> OS picks a free one
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _get(server, path="/", host_header="captive.apple.com", method="GET"):
    http_conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        http_conn.request(method, path, headers={"Host": host_header})
        resp = http_conn.getresponse()
        return resp.status, resp.read().decode("utf-8"), dict(resp.getheaders())
    finally:
        http_conn.close()


def _post(server, username, password):
    body = urlencode({"username": username, "password": password})
    http_conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        http_conn.request(
            "POST", "/", body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))},
        )
        resp = http_conn.getresponse()
        return resp.status, resp.read().decode("utf-8")
    finally:
        http_conn.close()


def _add_user(conn, username, password, display_name=None):
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) VALUES (?,?,?,?)",
        (username, display_name or username, auth.hash_password(password), db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


def _set_admin_credentials(conn, username="admin", password="adminpw"):
    db.set_setting(conn, "admin_username", username)
    db.set_setting(conn, "admin_password_hash", auth.hash_password(password))


def _add_group(conn, name):
    conn.execute("INSERT INTO groups (name, created_at) VALUES (?, ?)", (name, db.now_iso()))
    conn.commit()
    return conn.execute("SELECT id FROM groups WHERE name = ?", (name,)).fetchone()["id"]


def _post_admin(server, admin_username, admin_password, action, group_id=None):
    fields = {"admin_username": admin_username, "admin_password": admin_password, "action": action}
    if group_id is not None:
        fields["group_id"] = group_id
    body = urlencode(fields)
    http_conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        http_conn.request(
            "POST", "/admin", body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))},
        )
        resp = http_conn.getresponse()
        return resp.status, resp.read().decode("utf-8")
    finally:
        http_conn.close()


# ============================================================
# GET/HEAD -- always the same login page, regardless of path/Host
# ============================================================

def test_get_returns_the_login_page(server):
    status, body, headers = _get(server)
    assert status == 200
    assert "text/html" in headers["Content-Type"]
    assert "Sign in" in body
    assert "<form" in body


def test_any_path_or_host_gets_the_same_login_page(server):
    """The whole design (see module docstring): every major OS's
    captive-portal probe uses a different hostname/path, but nftables
    redirects by source IP + destination port, not by hostname -- so
    every one of them must land on the exact same response."""
    for host, path in [
        ("captive.apple.com", "/hotspot-detect.html"),
        ("connectivitycheck.gstatic.com", "/generate_204"),
        ("www.msftconnecttest.com", "/connecttest.txt"),
        ("detectportal.firefox.com", "/success.txt"),
        ("example.com", "/"),
    ]:
        status, body, _ = _get(server, path=path, host_header=host)
        assert status == 200, f"{host}{path} did not get the login page"
        assert "Sign in" in body


def test_head_request_gets_a_200_with_no_body_assertion_needed(server):
    status, _, headers = _get(server, method="HEAD")
    assert status == 200
    assert "text/html" in headers["Content-Type"]


def test_responses_are_never_cached(server):
    _, _, headers = _get(server)
    assert headers.get("Cache-Control") == "no-store"


# ============================================================
# POST -- the actual login
# ============================================================

def test_successful_login_authenticates_the_device_and_shows_success(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    device_id = conn.execute("SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)).fetchone()["device_id"]
    user_id = _add_user(conn, "kid1", "correcthorse")

    status, body = _post(server, "kid1", "correcthorse")

    assert status == 200
    assert "signed in" in body.lower()
    row = conn.execute("SELECT is_authenticated, user_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1
    assert row["user_id"] == user_id


def test_success_page_has_no_bump_reminder_for_a_kid_with_no_other_devices(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    _, body = _post(server, "kid1", "correcthorse")

    assert "extra access" not in body


def test_success_page_shows_a_bump_reminder_when_the_same_user_has_a_bump_enabled_device_elsewhere(server, conn):
    """Design sketch (RoadMap.md): logging in here only ever grants
    DNS-tier access -- a kid whose usual device has full SSL-Bump
    refinement would otherwise have no idea why this new device is more
    limited."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    user_id = _add_user(conn, "kid1", "correcthorse")
    conn.execute(
        "INSERT INTO devices (mac_address, user_id, bump_enabled, created_at) VALUES (?,?,1,?)",
        ("aa:bb:cc:dd:ee:77", user_id, db.now_iso()),
    )
    conn.commit()

    _, body = _post(server, "kid1", "correcthorse")

    assert "extra access" in body


def test_success_page_bump_reminder_ignores_a_different_users_bump_enabled_device(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")
    other_user_id = _add_user(conn, "kid2", "somethingelse")
    conn.execute(
        "INSERT INTO devices (mac_address, user_id, bump_enabled, created_at) VALUES (?,?,1,?)",
        ("aa:bb:cc:dd:ee:78", other_user_id, db.now_iso()),
    )
    conn.commit()

    _, body = _post(server, "kid1", "correcthorse")

    assert "extra access" not in body


def test_login_never_sets_bump_enabled(server, conn):
    """Phase 4's own design sketch: the login flow grants DNS-tier
    access ONLY, never bump_enabled -- that stays a separate, deliberate
    admin action."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    _post(server, "kid1", "correcthorse")

    row = conn.execute("SELECT bump_enabled FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["bump_enabled"] == 0


def test_login_does_not_overwrite_an_existing_user_assignment(server, conn):
    """COALESCE semantics: an admin who already assigned this device to
    someone else keeps that assignment even if a different login
    happens to succeed against it (e.g. a shared family device)."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    device_id = conn.execute("SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)).fetchone()["device_id"]
    original_owner_id = _add_user(conn, "parent1", "adminpw")
    conn.execute("UPDATE devices SET user_id = ? WHERE id = ?", (original_owner_id, device_id))
    conn.commit()
    _add_user(conn, "kid1", "correcthorse")

    _post(server, "kid1", "correcthorse")

    row = conn.execute("SELECT user_id, is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["user_id"] == original_owner_id
    assert row["is_authenticated"] == 1


def test_wrong_password_does_not_authenticate(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    status, body = _post(server, "kid1", "wrongpassword")

    assert status == 200
    assert "incorrect" in body.lower()
    row = conn.execute("SELECT is_authenticated FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["is_authenticated"] == 0


def test_failed_login_records_the_attempting_devices_mac(server, conn):
    # Real gap fixed 2026-09-07: dashboard.py's pending-devices card
    # needs to answer "has this device already tried and been denied",
    # which requires the failed-login event to actually be correlated
    # to a device -- previously only client_ip/username were recorded.
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    _post(server, "kid1", "wrongpassword")

    row = conn.execute(
        "SELECT detail FROM system_events WHERE source = 'captive_portal_login' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None
    assert row["detail"] == MAC_A


def test_unknown_username_does_not_authenticate(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")

    status, body = _post(server, "nosuchkid", "whatever")

    assert status == 200
    assert "incorrect" in body.lower()


def test_login_from_an_ip_with_no_active_binding_fails_gracefully(server, conn):
    """By construction this request could only reach the server via
    nftables' own unauthenticated_v4 redirect, which requires an active
    binding to exist -- but this must still fail closed, not crash, if
    that assumption is ever violated (e.g. a real race)."""
    _add_user(conn, "kid1", "correcthorse")

    status, body = _post(server, "kid1", "correcthorse")

    assert status == 200
    # html.escape() turns the apostrophe into &#x27; -- match on a
    # substring either side of it rather than the raw literal string.
    assert "identify your device" in body


def test_login_ip_is_looked_up_independent_of_which_device_it_belongs_to(server, conn):
    """Two devices, only one of which is making this request -- login
    must only ever touch the device whose IP the request actually came
    from (127.0.0.1, since these are real loopback HTTP requests),
    never a different, unrelated device that merely happens to also be
    active in device_bindings at the same time."""
    identity.record_binding(conn, "aa:bb:cc:dd:ee:03", "192.168.1.99", source="rtnetlink")
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    _post(server, "kid1", "correcthorse")

    untouched = conn.execute("SELECT is_authenticated FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:03'").fetchone()
    touched = conn.execute("SELECT is_authenticated FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert untouched["is_authenticated"] == 0
    assert touched["is_authenticated"] == 1


# ============================================================
# Brute-force rate limiting -- built alongside the login form itself
# rather than retrofitted later, per this project's standing
# security-by-design practice (RoadMap.md's cross-cutting section).
# ============================================================

# Pure sliding-window logic (is_limited/record_failure/clear, window
# expiry) is now covered by tests/test_rate_limit.py against
# common/rate_limit.RateLimiter directly, since that's where the logic
# actually lives (2026-09-02) -- this file keeps only the integration-
# level coverage below (real HTTP requests through the real handler).


def test_rate_limit_blocks_further_attempts_after_the_max(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    for _ in range(captive_portal_server._MAX_ATTEMPTS):
        status, body = _post(server, "kid1", "wrongpassword")
        assert status == 200
        assert "incorrect" in body.lower()

    # The (max+1)th attempt is blocked outright -- even with the
    # CORRECT password this time, since a rate limiter that only
    # blocks incorrect guesses would let an attacker use up its own
    # budget testing wrong passwords and slip the right one in at the
    # end unrestricted.
    status, body = _post(server, "kid1", "correcthorse")
    assert status == 200
    assert "too many attempts" in body.lower()
    row = conn.execute("SELECT is_authenticated FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["is_authenticated"] == 0, "the rate-limited attempt must not have logged the device in"


# ============================================================
# Failed-login visibility on the dashboard's own Events page --
# added 2026-09-02 alongside the rate-limiter refactor, so an admin has
# somewhere to see a guessing attack besides docker compose logs.
# ============================================================

def test_failed_kid_login_logs_a_system_event(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    _post(server, "kid1", "wrongpassword")

    row = conn.execute(
        "SELECT source, severity, message FROM system_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["source"] == "captive_portal_login"
    assert row["severity"] == "error"
    assert IP_1 in row["message"]
    assert "kid1" in row["message"]
    assert "correcthorse" not in row["message"], "the password itself must never be logged"


def test_successful_kid_login_logs_no_system_event(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    # Baseline taken AFTER setup, not before: record_binding() above is a
    # genuinely brand-new MAC, which (2026-09-09, system_events.py's own
    # narrow 'info' severity) now correctly logs a "new device
    # discovered" event of its own -- that's the setup step's business,
    # not the login's. This test's real claim is narrower: the LOGIN
    # itself must add nothing further.
    before = conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"]

    _post(server, "kid1", "correcthorse")

    after = conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"]
    assert after == before, "system_events is deliberately not a firehose -- a normal successful login isn't an event"


def test_one_attempt_below_the_limit_still_succeeds_with_the_right_password(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")

    for _ in range(captive_portal_server._MAX_ATTEMPTS - 1):
        _post(server, "kid1", "wrongpassword")
    status, body = _post(server, "kid1", "correcthorse")
    assert "signed in" in body.lower(), "one attempt below the limit must still succeed with the right password"


def test_a_success_does_not_reset_the_shared_failure_count(server, conn):
    """Regression test for a real bug (fixed 2026-09-02): _LOGIN_LIMITER
    is deliberately shared between the kid-login form and the portal
    admin-action form (see _handle_admin_action's own comment), but a
    prior version cleared it on EITHER surface's success -- so a normal
    household member's kid login succeeding from a shared/NAT'd IP
    would silently hand an in-progress admin-password guesser a fresh
    budget. Neither surface may clear the other's (or even its own)
    accumulated failures on success anymore; failures only age out of
    the window on their own."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _add_user(conn, "kid1", "correcthorse")
    _set_admin_credentials(conn)

    for _ in range(captive_portal_server._MAX_ATTEMPTS - 1):  # 4 wrong admin guesses
        _post_admin(server, "admin", "wrongpassword", "bypass")

    # A normal household member logs in successfully from the same IP.
    status, body = _post(server, "kid1", "correcthorse")
    assert "signed in" in body.lower()

    # One more wrong admin guess is the 5th recorded failure overall --
    # if the kid's success above had wrongly reset the counter, this
    # would still be comfortably under the limit.
    _post_admin(server, "admin", "wrongpassword", "bypass")

    # So the NEXT admin attempt must be rate-limited, even with the
    # correct password this time.
    status, body = _post_admin(server, "admin", "adminpw", "bypass")
    assert "too many attempts" in body.lower()
    row = conn.execute("SELECT bypass_login FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["bypass_login"] == 0


# ============================================================
# Portal-side admin action -- the design sketch's "same portal screen"
# alternative to Milestone 2's dashboard-based admin path, for an
# admin physically at the gated device itself.
# ============================================================

def test_login_page_shows_the_admin_section(server):
    _, body, _ = _get(server)
    assert "Admin username" in body
    assert 'action="/admin"' in body


def test_login_page_has_no_group_dropdown_when_no_groups_exist(server):
    _, body, _ = _get(server)
    assert "assign_group" not in body


def test_login_page_shows_a_group_dropdown_when_groups_exist(server, conn):
    _add_group(conn, "Gaming Computers")
    _, body, _ = _get(server)
    assert "Gaming Computers" in body
    assert "assign_group" in body


def test_admin_bypass_sets_bypass_login_and_lands_the_device_in_authenticated(server, conn):
    """End-to-end proof, not just the DB flag: after the fix to
    common/policy_class.py's classify_device() (2026-08-31), bypass_login
    alone is enough to actually leave PREAUTH."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _set_admin_credentials(conn)

    status, body = _post_admin(server, "admin", "adminpw", "bypass")

    assert status == 200
    assert "no longer needs to log in" in body
    row = conn.execute("SELECT bypass_login FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["bypass_login"] == 1

    from policy_class import PolicyClass, classify_device
    full_row = conn.execute("SELECT * FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert classify_device(full_row) == PolicyClass.AUTHENTICATED


def test_admin_assign_group_sets_group_and_authenticates_the_device(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _set_admin_credentials(conn)
    group_id = _add_group(conn, "IoT")

    status, body = _post_admin(server, "admin", "adminpw", "assign_group", group_id=group_id)

    assert status == 200
    assert "IoT" in body
    row = conn.execute("SELECT group_id, user_id, is_authenticated FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["group_id"] == group_id
    assert row["user_id"] is None
    assert row["is_authenticated"] == 1


def test_admin_assign_group_clears_a_prior_user_assignment(server, conn):
    """devices.user_id/group_id are mutually exclusive (the table's own
    CHECK constraint) -- assigning a group must clear any prior
    personal-user assignment, not just add a group on top of it."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    device_id = conn.execute("SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)).fetchone()["device_id"]
    user_id = _add_user(conn, "kid1", "correcthorse")
    conn.execute("UPDATE devices SET user_id = ? WHERE id = ?", (user_id, device_id))
    conn.commit()
    _set_admin_credentials(conn)
    group_id = _add_group(conn, "IoT")

    _post_admin(server, "admin", "adminpw", "assign_group", group_id=group_id)

    row = conn.execute("SELECT group_id, user_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["group_id"] == group_id
    assert row["user_id"] is None


def test_admin_action_with_wrong_admin_password_is_rejected(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _set_admin_credentials(conn)

    status, body = _post_admin(server, "admin", "wrongpassword", "bypass")

    assert status == 200
    assert "incorrect admin" in body.lower()
    row = conn.execute("SELECT bypass_login FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["bypass_login"] == 0


def test_failed_admin_action_logs_a_system_event(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _set_admin_credentials(conn)

    _post_admin(server, "admin", "wrongpassword", "bypass")

    row = conn.execute(
        "SELECT source, severity, message FROM system_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["source"] == "captive_portal_admin_action"
    assert row["severity"] == "error"
    assert IP_1 in row["message"]
    assert "adminpw" not in row["message"], "the password itself must never be logged"


def test_admin_action_cannot_be_done_with_kid_credentials(server, conn):
    """The admin action must check the SAME admin credentials the
    dashboard's own HTTP-Basic login uses -- a kid's own
    users.password_hash must never work here."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _set_admin_credentials(conn)
    _add_user(conn, "kid1", "correcthorse")

    status, body = _post_admin(server, "kid1", "correcthorse", "bypass")

    assert "incorrect admin" in body.lower()


def test_admin_action_shares_the_kid_logins_rate_limiter(server, conn):
    """The more conservative design choice (see module docstring): a
    wrong admin-password guess counts against the SAME per-IP budget
    the kid login form uses, not a separate, easier-to-exhaust one."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _set_admin_credentials(conn)

    for _ in range(captive_portal_server._MAX_ATTEMPTS):
        _post_admin(server, "admin", "wrongpassword", "bypass")

    status, body = _post_admin(server, "admin", "adminpw", "bypass")  # correct password this time
    assert "too many attempts" in body.lower()
    row = conn.execute("SELECT bypass_login FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["bypass_login"] == 0


def test_admin_assign_group_rejects_a_nonexistent_group(server, conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    _set_admin_credentials(conn)

    status, body = _post_admin(server, "admin", "adminpw", "assign_group", group_id="999999")

    assert status == 200
    assert "no longer exists" in body
    row = conn.execute("SELECT group_id FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["group_id"] is None


def test_admin_action_from_an_ip_with_no_active_binding_fails_gracefully(server, conn):
    _set_admin_credentials(conn)

    status, body = _post_admin(server, "admin", "adminpw", "bypass")

    assert status == 200
    assert "identify this device" in body
