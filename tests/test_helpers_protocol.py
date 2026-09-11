"""Drive the Squid helper scripts' actual decision logic and the shared
stdin/stdout protocol loop (common/squid_helper.py) directly -- no Docker,
no real Squid, no network. The helper modules' own `sys.path.insert(0,
"/opt/optigate")` is a no-op off-container (that path doesn't exist),
which is fine: conftest.py already puts common/ and proxy/ on sys.path so
their real `import auth` / `import db` etc. resolve correctly either way.
"""
from __future__ import annotations

import io
import itertools

import auth
import authz_helper
import db
import identity
import matching
import series_resolve
import sni_helper
import squid_helper


def _add_user(conn, username, password, display_name=None):
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) VALUES (?,?,?,?)",
        (username, display_name or username, auth.hash_password(password), db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


_mac_counter = itertools.count(1)


def _bind_ip_to_user(conn, user_id, ip):
    """Give `ip` a resolvable device identity (RoadMap.md's intercept-mode
    identity model): a `devices` row assigned to user_id, bound to ip via a
    real common/identity.record_binding() call -- the same path the DNS
    tier's own identity resolution goes through, exercised here instead of
    inserting device_bindings rows by hand. A fresh MAC per call, since
    device_bindings is unique on (mac_address, ipv4_address) and several
    tests reuse the same IP for different users."""
    mac = f"aa:bb:cc:dd:ee:{next(_mac_counter):02x}"
    conn.execute(
        "INSERT INTO devices (mac_address, user_id, created_at) VALUES (?, ?, ?)",
        (mac, user_id, db.now_iso()),
    )
    conn.commit()
    identity.record_binding(conn, mac, ip, source="rtnetlink")


def _bind_ip_to_group(conn, group_id, ip):
    """Same as _bind_ip_to_user, but for a device assigned to a GROUP
    instead of a user (user_id NULL, group_id set) -- the case
    common/matching.py's device_domain_reason() was added to fix (see its
    own docstring)."""
    mac = f"aa:bb:cc:dd:ee:{next(_mac_counter):02x}"
    conn.execute(
        "INSERT INTO devices (mac_address, group_id, created_at) VALUES (?, ?, ?)",
        (mac, group_id, db.now_iso()),
    )
    conn.commit()
    identity.record_binding(conn, mac, ip, source="rtnetlink")
    return conn.execute("SELECT id FROM devices WHERE mac_address = ?", (mac,)).fetchone()["id"]


def _bind_ip_to_bare_device(conn, ip):
    """A device with neither user_id nor group_id -- only ever authorized
    via a direct device_domains grant."""
    mac = f"aa:bb:cc:dd:ee:{next(_mac_counter):02x}"
    conn.execute("INSERT INTO devices (mac_address, created_at) VALUES (?, ?)", (mac, db.now_iso()))
    conn.commit()
    identity.record_binding(conn, mac, ip, source="rtnetlink")
    return conn.execute("SELECT id FROM devices WHERE mac_address = ?", (mac,)).fetchone()["id"]


def _add_group(conn, name="TVs"):
    conn.execute("INSERT INTO groups (name, created_at) VALUES (?, ?)", (name, db.now_iso()))
    conn.commit()
    return conn.execute("SELECT * FROM groups WHERE name = ?", (name,)).fetchone()["id"]


def _add_domain(conn, pattern, mode, is_global=1, kind="generic"):
    conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, note, created_at) VALUES (?,?,?,?,NULL,?)",
        (pattern, mode, kind, is_global, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM domains WHERE pattern = ?", (pattern,)).fetchone()


# ============================================================
# squid_helper.run() -- the shared protocol loop itself
# ============================================================

def _run_protocol(monkeypatch, lines, field_count, handler, **kwargs):
    monkeypatch.setattr("sys.stdin", io.StringIO("\n".join(lines) + "\n" if lines else ""))
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    # squid_helper.run() opens its own db connection via db.get_conn(); the
    # `conn` fixture already monkeypatched db.DB_PATH for this test.
    squid_helper.run("test", field_count, handler, **kwargs)
    return out.getvalue().splitlines()


def test_protocol_ok_err_per_line(conn, monkeypatch):
    def handler(c, a, b):
        return a == "yes"

    replies = _run_protocol(monkeypatch, ["yes x", "no x"], 2, handler)
    assert replies == ["OK", "ERR"]


def test_protocol_wrong_field_count_is_err(conn, monkeypatch):
    def handler(c, a, b):
        return True

    replies = _run_protocol(monkeypatch, ["only-one-field"], 2, handler)
    assert replies == ["ERR"]


def test_protocol_unquotes_percent_encoded_fields_by_default(conn, monkeypatch):
    seen = {}

    def handler(c, a):
        seen["value"] = a
        return True

    _run_protocol(monkeypatch, ["hello%20world"], 1, handler)
    assert seen["value"] == "hello world"


def test_protocol_keep_trailing_spaces_for_password_field(conn, monkeypatch):
    seen = {}

    def handler(c, username, password):
        seen["password"] = password
        return True

    _run_protocol(
        monkeypatch, ["kid1 pass with spaces"], 2, handler,
        unquote=False, keep_trailing_spaces=True,
    )
    assert seen["password"] == "pass with spaces"


def test_protocol_handler_exception_is_err_and_does_not_kill_the_loop(conn, monkeypatch):
    def handler(c, a):
        if a == "boom":
            raise ValueError("kaboom")
        return True

    replies = _run_protocol(monkeypatch, ["boom", "ok"], 1, handler)
    assert replies == ["ERR", "OK"]


# ============================================================
# sni_helper -- ssl_bump step2 decisions
# ============================================================

def test_sni_handle_bump_true_only_for_bump_mode(conn):
    _add_domain(conn, r"crunchyroll\.com", mode="bump")
    _add_domain(conn, r"example\.com", mode="splice")
    assert sni_helper.handle_bump(conn, "1.2.3.4", "crunchyroll.com") is True
    assert sni_helper.handle_bump(conn, "1.2.3.4", "example.com") is False
    assert sni_helper.handle_bump(conn, "1.2.3.4", "unknown.com") is False


def test_sni_handle_trusted_true_only_for_trusted_mode(conn):
    _add_domain(conn, r"crunchyrollcdn\.com", mode="trusted")
    assert sni_helper.handle_trusted(conn, "1.2.3.4", "crunchyrollcdn.com") is True
    assert sni_helper.handle_trusted(conn, "1.2.3.4", "elsewhere.com") is False


def test_sni_handle_splice_unresolved_identity_denied_and_logged(conn):
    # No device_bindings row at all for this IP -- device_identity.resolve_user
    # returns None, the intercept-mode equivalent of the old empty %LOGIN.
    _add_domain(conn, r"example\.com", mode="splice")
    assert sni_helper.handle_splice(conn, "192.168.1.5", "example.com") is False
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["reason"] == "not_authenticated"
    assert row["allowed"] == 0


def test_sni_handle_splice_outside_lan_denied_and_logged(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    conn.commit()
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "10.0.0.9")
    _add_domain(conn, r"example\.com", mode="splice")
    assert sni_helper.handle_splice(conn, "10.0.0.9", "example.com") is False
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["reason"] == "outside_lan"


def test_sni_handle_splice_global_domain_allowed(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="splice", is_global=1)
    assert sni_helper.handle_splice(conn, "192.168.1.5", "example.com") is True
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["allowed"] == 1
    assert row["reason"] == "global_domain"


def test_sni_handle_splice_per_user_domain_requires_assignment(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    domain = _add_domain(conn, r"example\.com", mode="splice", is_global=0)
    assert sni_helper.handle_splice(conn, "192.168.1.5", "example.com") is False

    conn.execute("INSERT INTO user_domains (user_id, domain_id) VALUES (?,?)", (user["id"], domain["id"]))
    conn.commit()
    assert sni_helper.handle_splice(conn, "192.168.1.5", "example.com") is True


def test_sni_handle_splice_group_assigned_device_gets_access(conn):
    """The core regression test for the group/device authorization bug
    (see common/matching.py's device_domain_reason() docstring): a device
    assigned to a GROUP, not a user, used to resolve to no identity at all
    (device_identity.resolve_user() INNER JOINs devices.user_id) and was
    denied unconditionally before ever reaching a domain check."""
    group_id = _add_group(conn, "TVs")
    _bind_ip_to_group(conn, group_id, "192.168.1.5")
    domain = _add_domain(conn, r"example\.com", mode="splice", is_global=0)
    assert sni_helper.handle_splice(conn, "192.168.1.5", "example.com") is False
    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row["reason"] == "domain_not_assigned"
    assert row["username"] != "(unauthenticated)"  # a real device identity, just no user

    conn.execute("INSERT INTO group_domains (group_id, domain_id) VALUES (?,?)", (group_id, domain["id"]))
    conn.commit()
    assert sni_helper.handle_splice(conn, "192.168.1.5", "example.com") is True
    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row["reason"] == "group_domain"
    assert row["user_id"] is None
    assert row["device_id"] is not None


def test_sni_handle_splice_wrong_mode_domain_denied(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1)
    assert sni_helper.handle_splice(conn, "192.168.1.5", "crunchyroll.com") is False


def test_sni_handle_splice_unconfigured_domain_allowed_and_logged(conn):
    """Fixed 2026-09-08, real gap found live: a domain with no `domains`
    row at all used to be denied (falling through to handle_block_page)
    even though controller/adguard_sync.py's own docstring says an
    unconfigured domain is "deliberately still default-allow at the DNS
    tier." A non-bump device never even reaches Squid for this domain at
    all, so Squid re-denying it here for a bump-enabled device meant
    turning bump on silently switched that device's ENTIRE traffic to a
    stricter policy than the rest of the household gets. Confirmed live:
    this is exactly what blocked Netflix (never configured anywhere) on
    a bump-enabled device -- nothing to do with Netflix specifically."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    assert sni_helper.handle_splice(conn, "192.168.1.5", "unknown-site.example") is True
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row is not None
    assert row["username"] == "kid1"
    assert row["domain"] == "unknown-site.example"
    assert row["allowed"] == 1
    assert row["reason"] == "unconfigured_domain"


def test_sni_handle_block_page_terminate_default(conn):
    assert sni_helper.handle_block_page(conn, "1.2.3.4", "anything.com") is False


def test_sni_handle_block_page_redirect_when_configured(conn):
    db.set_setting(conn, "block_page_mode", "redirect")
    conn.commit()
    assert sni_helper.handle_block_page(conn, "1.2.3.4", "anything.com") is True


def test_sni_handle_block_page_unrecognized_mode_value_denies(conn):
    """Code-review fix, still relevant after 2026-09-08's logging cleanup:
    the deny condition matches any mode value other than the literal
    'redirect', not just the literal string 'terminate', so a
    corrupted/unexpected setting value still denies rather than silently
    defaulting to the more permissive (bump-for-a-real-page) behavior."""
    db.set_setting(conn, "block_page_mode", "some-unexpected-value")
    conn.commit()
    assert sni_helper.handle_block_page(conn, "192.168.1.5", "unknown-site.example") is False


def test_sni_handle_block_page_terminate_does_not_double_log_configured_domain(conn):
    """A configured splice-mode domain the user isn't permitted is already
    logged by handle_splice before this rule is ever reached -- logging it
    again here would just be a worse duplicate. Fixed 2026-09-08:
    handle_block_page no longer logs anything at all (that
    responsibility moved entirely to handle_splice, including for
    unconfigured domains -- see
    test_sni_handle_splice_unconfigured_domain_allowed_and_logged), so
    this now also covers "handle_block_page never logs, period"."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="splice", is_global=0)
    sni_helper.handle_block_page(conn, "192.168.1.5", "example.com")
    assert conn.execute("SELECT * FROM access_log").fetchone() is None


# ============================================================
# authz_helper.decide -- HTTP-layer decision (every request that reaches
# this helper: bump-mode domains fully, plus every other mode via the
# plain-HTTP path -- see the module's own 2026-09-08 docstring entry)
# ============================================================

def test_authz_unresolved_identity_denied(conn):
    # No device_bindings row at all for this IP.
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/") is False


def test_authz_outside_lan_denied_and_logged(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    conn.commit()
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "10.0.0.1")
    assert authz_helper.decide(conn, "10.0.0.1", "example.com:443", "/") is False
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["reason"] == "outside_lan"


def test_authz_unconfigured_domain_allowed(conn):
    """Fixed 2026-09-08, real gap found live: this plain-HTTP path used
    to deny any domain that wasn't mode='bump', including a genuinely
    unconfigured one -- see sni_helper.py's own
    test_sni_handle_splice_unconfigured_domain_allowed_and_logged for
    the full writeup (this is that same fix's plain-HTTP counterpart,
    since HTTP has no SNI stage for sni_helper.py to catch this first)."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    assert authz_helper.decide(conn, "192.168.1.5", "unknown.example:443", "/") is True
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["allowed"] == 1
    assert row["reason"] == "unconfigured_domain"


def test_authz_trusted_mode_domain_always_allowed_unlogged(conn):
    """Matches sni_helper.py's handle_trusted()/"trusted mode is
    deliberately never logged" convention at every layer."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="trusted", is_global=1)
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/") is True
    assert conn.execute("SELECT * FROM access_log").fetchone() is None


def test_authz_splice_mode_global_domain_allowed(conn):
    """Fixed 2026-09-08 alongside the unconfigured-domain gap: a
    splice-mode domain reaching this plain-HTTP path used to be denied
    outright as "not_bump_mode" regardless of actual authorization --
    even a globally-assigned one. Now matches sni_helper.py's own
    handle_splice() exactly."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="splice", is_global=1)
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/") is True
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["allowed"] == 1
    assert row["reason"] == "global_domain"


def test_authz_splice_mode_domain_not_assigned_denied(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="splice", is_global=0)
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/") is False
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["allowed"] == 0
    assert row["reason"] == "domain_not_assigned"


def test_authz_bump_domain_not_assigned_to_user_denied(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="bump", is_global=0)
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/") is False
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["reason"] == "domain_not_assigned"


def test_authz_device_only_assignment_works_with_no_user_or_group(conn):
    """Second half of the authorization-bug regression coverage: a device
    with NEITHER user_id NOR group_id, authorized only via a direct
    device_domains grant."""
    device_id = _bind_ip_to_bare_device(conn, "192.168.1.5")
    domain = _add_domain(conn, r"example\.com", mode="bump", is_global=0)
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/") is False

    conn.execute("INSERT INTO device_domains (device_id, domain_id) VALUES (?,?)", (device_id, domain["id"]))
    conn.commit()
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/") is True
    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row["reason"] == "device_domain"
    assert row["user_id"] is None
    assert row["device_id"] == device_id


def test_authz_generic_bump_domain_no_path_rules_denies_beyond_root(conn):
    """Changed 2026-09-07 (RoadMap.md's dated entry, project owner's
    explicit direction): a domain with zero domain_paths rows used to
    allow every path by default -- switching a domain to bump mode
    silently opened its entire site until an admin came back and
    narrowed it. Now only the bare root is allowed until at least one
    path rule is added."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="bump", is_global=1)
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/whatever") is False
    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row["reason"] == "path_not_allowed"


def test_authz_generic_bump_domain_no_path_rules_still_allows_bare_root(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="bump", is_global=1)
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/") is True


def test_authz_generic_bump_domain_with_path_rules_enforces_them(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    domain = _add_domain(conn, r"example\.com", mode="bump", is_global=1)
    conn.execute("INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)", (domain["id"], r"^/allowed"))
    conn.commit()
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/allowed/x") is True
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:443", "/blocked") is False


def test_authz_strips_port_from_dst(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"example\.com", mode="bump", is_global=1)
    assert authz_helper.decide(conn, "192.168.1.5", "example.com:8443", "/") is True


def test_authz_crunchyroll_cms_objects_always_allowed(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    assert authz_helper.decide(
        conn, "192.168.1.5", "www.crunchyroll.com:443",
        "/content/v2/cms/objects/GYE5K0XVR",
    ) is True


def test_authz_crunchyroll_denied_when_device_has_no_resolvable_user(conn):
    """A group-assigned device can be authorized for the crunchyroll DOMAIN
    itself (via group_domains), but user_shows is keyed by user_id only --
    there's no group/device-level show list to check, so this must fail
    closed with a distinct reason rather than allow blindly or crash."""
    group_id = _add_group(conn, "TVs")
    _bind_ip_to_group(conn, group_id, "192.168.1.5")
    domain = _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=0, kind="crunchyroll")
    conn.execute("INSERT INTO group_domains (group_id, domain_id) VALUES (?,?)", (group_id, domain["id"]))
    conn.commit()

    path = "/series/GYE5K0XVR/ace-attorney"
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is False
    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row["reason"] == "show_requires_user"


def test_authz_crunchyroll_series_page_requires_approval(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    path = "/series/GYE5K0XVR/ace-attorney"
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is False

    conn.execute(
        "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?, 'GYE5K0XVR', 'Ace Attorney')",
        (user["id"],),
    )
    conn.commit()
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is True


def test_authz_crunchyroll_up_next_requires_approval(conn):
    """RoadMap.md finding #1d: the "continue watching" feed carries the
    series id directly in the path, same direct check as SERIES_PAGE --
    no series_resolve call needed. Before this classifier existed, this
    exact path fell through to OTHER and was blanket-allowed by the (now
    removed) `^/content/v[0-9]+/` domain_paths rule regardless of show
    ownership -- this is the regression test for that gap."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    path = "/content/v2/discover/up_next/GYE5K0XVR"
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is False
    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row["reason"] == "show_not_approved"

    conn.execute(
        "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?, 'GYE5K0XVR', 'Ace Attorney')",
        (user["id"],),
    )
    conn.commit()
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is True


def test_authz_crunchyroll_up_next_malformed_shape_fails_closed(conn):
    """The '/discover/up_next/' guarded marker is present but no id
    follows -- must be BLOCKED_SHAPE, not fall through to OTHER (and from
    there to the domain's own broader /content/v.../discover/ path rule,
    which deliberately excludes up_next but shouldn't need to matter here
    at all -- this shape should never reach path matching in the first
    place)."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    path = "/content/v2/discover/up_next/"
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is False
    row = conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row["reason"] == "blocked_shape"


def test_authz_crunchyroll_watch_page_resolves_series_and_checks_approval(conn, monkeypatch):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")

    monkeypatch.setattr(
        series_resolve, "resolve_series_ids", lambda c, ids: {i: "GYE5K0XVR" for i in ids}
    )
    path = "/watch/G6NQ5DWX6/episode-1"
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is False

    conn.execute(
        "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?, 'GYE5K0XVR', 'Ace Attorney')",
        (user["id"],),
    )
    conn.commit()
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is True


def test_authz_crunchyroll_resolution_failure_fails_closed(conn, monkeypatch):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")

    monkeypatch.setattr(series_resolve, "resolve_series_ids", lambda c, ids: None)
    path = "/watch/G6NQ5DWX6/episode-1"
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is False
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["reason"] == "resolution_failed"


def test_authz_crunchyroll_blocked_shape_denied(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    # '/watch/' marker present but id has an invalid character -> BLOCKED_SHAPE
    path = "/watch/bad!id"
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", path) is False
    row = conn.execute("SELECT * FROM access_log").fetchone()
    assert row["reason"] == "blocked_shape"


def test_authz_crunchyroll_other_shape_falls_back_to_path_allowlist(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    domain = _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    conn.execute("INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)", (domain["id"], r"^/discover"))
    conn.commit()
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", "/discover") is True
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", "/not-configured") is False


def test_authz_crunchyroll_other_shape_with_no_path_rules_denies_beyond_root(conn):
    """Same 2026-09-07 deny-by-default-beyond-root change as the generic
    bump-domain test above, for Crunchyroll's own OTHER-shape fallback --
    in practice defaults.py always seeds a real path list for this
    domain, so this only matters for a hand-configured Crunchyroll-kind
    domain that hasn't had paths added yet."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", "/") is True
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", "/some-other-page") is False


def test_authz_crunchyroll_content_v2_no_longer_blanket_allowed(conn):
    """RoadMap.md finding #1d: `^/content/v[0-9]+/` used to be a seeded
    blanket domain_paths rule -- ANY unrecognized request under that
    prefix was allowed regardless of show ownership. It's gone now
    (defaults/seed_defaults.py's CRUNCHYROLL_PATHS); the narrower
    discover/watchlist replacements below should allow the genuinely
    id-free endpoints while an arbitrary unrecognized /content/v.../
    shape still denies."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "192.168.1.5")
    domain = _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    for pattern in (
        r"^/content/v[0-9]+/discover/(?!up_next/)",
        r"^/content/v[0-9]+/[^/]+/watchlist",
    ):
        conn.execute("INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)", (domain["id"], pattern))
    conn.commit()

    # Id-free endpoints under the narrower replacements: allowed.
    assert authz_helper.decide(conn, "192.168.1.5", "www.crunchyroll.com:443", "/content/v2/discover/browse") is True
    assert authz_helper.decide(
        conn, "192.168.1.5", "www.crunchyroll.com:443", "/content/v2/some-account-uuid/watchlist"
    ) is True
    # A hypothetical future /content/v.../ shape that isn't one of the
    # narrow replacements -- outside both "discover/" and ".../watchlist"
    # -- and isn't recognized by cr_urls.classify() either now denies
    # instead of the old blanket-allow.
    assert authz_helper.decide(
        conn, "192.168.1.5", "www.crunchyroll.com:443", "/content/v2/some-unrecognized-endpoint"
    ) is False


def test_authz_crunchyroll_discover_path_rule_negative_lookahead_excludes_up_next(conn):
    """The narrow `^/content/v[0-9]+/discover/(?!up_next/)` replacement
    rule's own negative lookahead never actually matters in practice --
    cr_urls.classify() always intercepts and gates a real up_next URL as
    its own RequestKind before path rules are ever consulted (see
    test_authz_crunchyroll_up_next_requires_approval) -- but this
    confirms the lookahead itself holds, directly against
    matching.path_allowed(), as a belt-and-suspenders check independent
    of the classifier."""
    domain = _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)",
        (domain["id"], r"^/content/v[0-9]+/discover/(?!up_next/)"),
    )
    conn.commit()
    assert matching.path_allowed(conn, domain["id"], "/content/v2/discover/browse") is True
    assert matching.path_allowed(conn, domain["id"], "/content/v2/discover/up_next/GYE5K0XVR") is False


# ============================================================
# ip_address capture on every Squid-helper log_access() call site
# (RoadMap follow-up, 2026-09-10) -- the raw client IP is already a
# parameter of decide()/handle_splice(); these confirm it now reaches
# the access_log row, on both the SNI tier and the HTTP tier, including
# the branch threaded through _decide_crunchyroll().
# ============================================================

_CLIENT_IP = "192.168.1.77"


def _last_log(conn):
    return conn.execute("SELECT * FROM access_log ORDER BY id DESC LIMIT 1").fetchone()


def test_sni_splice_records_client_ip_on_an_unresolved_identity_denial(conn):
    _add_domain(conn, r"example\.com", mode="splice")
    assert sni_helper.handle_splice(conn, _CLIENT_IP, "example.com") is False
    assert _last_log(conn)["ip_address"] == _CLIENT_IP


def test_sni_splice_records_client_ip_on_outside_lan(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    conn.commit()
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "10.0.0.9")
    _add_domain(conn, r"example\.com", mode="splice")
    assert sni_helper.handle_splice(conn, "10.0.0.9", "example.com") is False
    assert _last_log(conn)["ip_address"] == "10.0.0.9"


def test_sni_splice_records_client_ip_on_an_allowed_unconfigured_domain(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], _CLIENT_IP)
    assert sni_helper.handle_splice(conn, _CLIENT_IP, "brand-new.example") is True
    row = _last_log(conn)
    assert row["allowed"] == 1 and row["ip_address"] == _CLIENT_IP


def test_sni_splice_records_client_ip_on_a_domain_not_assigned_denial(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], _CLIENT_IP)
    _add_domain(conn, r"example\.com", mode="splice", is_global=0)
    assert sni_helper.handle_splice(conn, _CLIENT_IP, "example.com") is False
    assert _last_log(conn)["ip_address"] == _CLIENT_IP


def test_authz_records_client_ip_on_outside_lan(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    conn.commit()
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], "10.0.0.1")
    assert authz_helper.decide(conn, "10.0.0.1", "example.com:443", "/") is False
    assert _last_log(conn)["ip_address"] == "10.0.0.1"


def test_authz_records_client_ip_on_an_allowed_unconfigured_domain(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], _CLIENT_IP)
    assert authz_helper.decide(conn, _CLIENT_IP, "unknown.example:443", "/") is True
    row = _last_log(conn)
    assert row["allowed"] == 1 and row["ip_address"] == _CLIENT_IP


def test_authz_records_client_ip_on_a_bump_domain_not_assigned_denial(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], _CLIENT_IP)
    _add_domain(conn, r"example\.com", mode="bump", is_global=0)
    assert authz_helper.decide(conn, _CLIENT_IP, "example.com:443", "/") is False
    assert _last_log(conn)["ip_address"] == _CLIENT_IP


def test_authz_records_client_ip_through_decide_crunchyroll(conn):
    """The one branch where client_ip has to be threaded into a helper --
    _decide_crunchyroll() got a new param. A series-page hit for an
    unapproved show must still stamp the row with the client IP."""
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], _CLIENT_IP)
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    path = "/series/GYE5K0XVR/ace-attorney"
    assert authz_helper.decide(conn, _CLIENT_IP, "www.crunchyroll.com:443", path) is False
    row = _last_log(conn)
    assert row["reason"] == "show_not_approved"
    assert row["ip_address"] == _CLIENT_IP


def test_authz_stamps_the_show_name_on_the_row_when_any_user_has_it_approved(conn):
    """Owner request 2026-09-11: the Report page needs the show NAME next
    to the id on a blocked row. If any user has the show approved, its
    title is on file in user_shows -- authz_helper stamps it onto the
    access_log row for free (cheap indexed lookup, no network)."""
    watcher = _add_user(conn, "kid1", "pw")
    other = _add_user(conn, "kid2", "pw")
    _bind_ip_to_user(conn, watcher["id"], _CLIENT_IP)
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    conn.execute(
        "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?, 'GRE50KV36', 'Black Clover')",
        (other["id"],),
    )
    conn.commit()

    # kid1 has NOT approved Black Clover -> denied, but the name is known.
    assert authz_helper.decide(
        conn, _CLIENT_IP, "www.crunchyroll.com:443", "/series/GRE50KV36/black-clover"
    ) is False
    row = _last_log(conn)
    assert row["reason"] == "show_not_approved"
    assert row["series_id"] == "GRE50KV36"
    assert row["series_name"] == "Black Clover"


def test_authz_leaves_series_name_null_when_no_one_has_the_show(conn):
    user = _add_user(conn, "kid1", "pw")
    _bind_ip_to_user(conn, user["id"], _CLIENT_IP)
    _add_domain(conn, r"crunchyroll\.com", mode="bump", is_global=1, kind="crunchyroll")
    assert authz_helper.decide(
        conn, _CLIENT_IP, "www.crunchyroll.com:443", "/series/GUNKNOWN99/whatever"
    ) is False
    row = _last_log(conn)
    assert row["series_id"] == "GUNKNOWN99"
    assert row["series_name"] is None  # Report page back-fills this via cr_api at render time
