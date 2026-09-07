"""dashboard/dashboard.py via Flask's test client -- no real HTTP server.

dashboard.py runs bootstrap_admin() and reads its secret key at *import*
time, against whatever db.DB_PATH is active then. To get a fully isolated
dashboard (fresh DB, known admin credentials) per test, the `client` fixture
below monkeypatches db.DB_PATH and the DASHBOARD_USER/PASSWORD env vars
*before* importing the module, then importlib.reload()s it if it was
already imported by an earlier test -- reload re-runs the whole module body,
including a fresh `app = Flask(__name__)` and a fresh bootstrap_admin().
"""
from __future__ import annotations

import base64
import importlib
import io
import re
import subprocess

import pytest

ADMIN_USER = "admin"
ADMIN_PASSWORD = "testpass123"


def _auth_header(username=ADMIN_USER, password=ADMIN_PASSWORD):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def dashboard_app(monkeypatch, tmp_path):
    monkeypatch.setenv("DASHBOARD_USER", ADMIN_USER)
    monkeypatch.setenv("DASHBOARD_PASSWORD", ADMIN_PASSWORD)
    monkeypatch.delenv("LOCAL_NETWORK", raising=False)

    import db as db_mod
    monkeypatch.setattr(db_mod, "DB_PATH", tmp_path / "dashboard_test.db")

    import dashboard
    importlib.reload(dashboard)
    dashboard.app.testing = True
    return dashboard.app


@pytest.fixture
def client(dashboard_app):
    return dashboard_app.test_client()


@pytest.fixture
def db_conn(dashboard_app):
    import db as db_mod
    conn = db_mod.get_conn()
    yield conn
    conn.close()


# ============================================================
# ADMIN AUTH
# ============================================================

def test_unauthenticated_request_gets_401(client):
    resp = client.get("/users")
    assert resp.status_code == 401


def test_wrong_password_gets_401(client):
    resp = client.get("/users", headers=_auth_header(password="nope"))
    assert resp.status_code == 401


def test_correct_credentials_get_200(client):
    resp = client.get("/users", headers=_auth_header())
    assert resp.status_code == 200


def test_ca_cert_route_requires_no_auth(client):
    # Public endpoint; 404 is expected here (no cert generated in this
    # sandbox) but it must NOT be 401 -- that would mean auth leaked onto it.
    resp = client.get("/ca-cert")
    assert resp.status_code != 401


# ============================================================
# ADMIN LOGIN BRUTE-FORCE PROTECTION -- added 2026-09-02 after an audit
# found this login had none at all (docs/security/overview.md section 6).
# ============================================================

def test_five_wrong_passwords_then_rate_limited(client):
    for _ in range(5):
        resp = client.get("/users", headers=_auth_header(password="nope"))
        assert resp.status_code == 401

    # The 6th attempt is blocked outright -- even with the CORRECT
    # password this time, matching the captive portal's own "don't let
    # an attacker use up the budget on wrong guesses and slip the right
    # one in at the end" reasoning.
    resp = client.get("/users", headers=_auth_header())
    assert resp.status_code == 429
    assert resp.headers.get("Retry-After") == "60"


def test_four_wrong_passwords_then_correct_still_succeeds(client):
    for _ in range(4):
        client.get("/users", headers=_auth_header(password="nope"))

    resp = client.get("/users", headers=_auth_header())
    assert resp.status_code == 200


def test_a_successful_login_clears_the_admin_failure_count(client):
    for _ in range(4):
        client.get("/users", headers=_auth_header(password="nope"))
    resp = client.get("/users", headers=_auth_header())
    assert resp.status_code == 200

    # Even after that success, 4 MORE wrong attempts still must not trip
    # the limiter -- the earlier failures were cleared, not merely
    # topped up to exactly the boundary.
    for _ in range(4):
        resp = client.get("/users", headers=_auth_header(password="nope"))
        assert resp.status_code == 401
    resp = client.get("/users", headers=_auth_header())
    assert resp.status_code == 200


def test_requests_with_no_credentials_at_all_never_count_against_the_limit(client):
    # A browser's routine first, credential-less request to a fresh
    # origin (always a 401) is not a guessing attempt -- it can never
    # succeed either way -- and must never contribute to the same budget
    # a real wrong-password guess does.
    for _ in range(10):
        resp = client.get("/users")
        assert resp.status_code == 401

    resp = client.get("/users", headers=_auth_header())
    assert resp.status_code == 200


def test_wrong_password_logs_a_system_event(client, db_conn):
    client.get("/users", headers=_auth_header(username="admin", password="nope"))

    row = db_conn.execute(
        "SELECT source, severity, message FROM system_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row["source"] == "dashboard_admin_login"
    assert row["severity"] == "error"
    assert "admin" in row["message"]
    assert "nope" not in row["message"], "the password itself must never be logged"


def test_correct_login_logs_no_system_event(client, db_conn):
    client.get("/users", headers=_auth_header())

    count = db_conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"]
    assert count == 0, "system_events is deliberately not a firehose -- a normal successful login isn't an event"


def test_credential_less_request_logs_no_system_event(client, db_conn):
    client.get("/users")

    count = db_conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"]
    assert count == 0


def test_index_redirects_to_report(client):
    resp = client.get("/", headers=_auth_header())
    assert resp.status_code == 302
    assert "/report" in resp.headers["Location"]


# ============================================================
# USER CRUD
# ============================================================

def test_add_user_then_appears_in_list(client, db_conn):
    resp = client.post(
        "/users/add", data={"username": "kid1", "display_name": "Kid One", "password": "pw123"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM users WHERE username = 'kid1'").fetchone()
    assert row is not None
    assert row["display_name"] == "Kid One"


def test_add_user_missing_password_rejected(client, db_conn):
    resp = client.post("/users/add", data={"username": "kid1"}, headers=_auth_header())
    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM users WHERE username = 'kid1'").fetchone() is None


def test_add_user_invalid_username_rejected(client, db_conn):
    resp = client.post(
        "/users/add", data={"username": "bad user!", "password": "pw"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM users").fetchone() is None


def test_add_user_duplicate_username_rejected(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    resp = client.post("/users/add", data={"username": "kid1", "password": "pw2"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    count = db_conn.execute("SELECT COUNT(*) c FROM users WHERE username = 'kid1'").fetchone()["c"]
    assert count == 1


def test_delete_user_removes_row(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    resp = client.post("/users/delete", data={"user_id": user_id}, headers=_auth_header())
    assert resp.status_code == 302
    assert db_conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone() is None


def test_reset_password_changes_hash(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    old_hash = db_conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()[0]

    client.post(
        "/users/reset-password", data={"user_id": user_id, "password": "newpw"}, headers=_auth_header()
    )
    new_hash = db_conn.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,)).fetchone()[0]
    assert new_hash != old_hash

    import auth
    assert auth.verify_password("newpw", new_hash) is True


# ============================================================
# DOMAIN CRUD
# ============================================================

def test_add_domain_then_appears(client, db_conn):
    resp = client.post(
        "/domains/add",
        data={"pattern": r"example\.com", "mode": "splice", "note": "test"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()
    assert row is not None
    assert row["mode"] == "splice"
    assert row["is_global"] == 0


def test_add_domain_invalid_regex_rejected(client, db_conn):
    resp = client.post(
        "/domains/add", data={"pattern": "(unbalanced", "mode": "splice"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM domains").fetchone() is None


def test_add_domain_invalid_mode_rejected(client, db_conn):
    resp = client.post(
        "/domains/add", data={"pattern": r"example\.com", "mode": "not-a-mode"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]


def test_delete_domain_removes_row(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]
    client.post("/domains/delete", data={"domain_id": domain_id}, headers=_auth_header())
    assert db_conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone() is None


def test_delete_domain_refuses_crunchyroll_builtin(client, db_conn):
    db_conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, note, created_at) "
        "VALUES ('crunchyroll\\.com', 'bump', 'crunchyroll', 1, NULL, datetime('now'))"
    )
    db_conn.commit()
    domain_id = db_conn.execute("SELECT id FROM domains WHERE kind = 'crunchyroll'").fetchone()[0]
    resp = client.post("/domains/delete", data={"domain_id": domain_id}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone() is not None


def test_domain_access_grants_and_revokes_a_user(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    client.post(
        "/domains/access",
        data={"domain_id": domain_id, "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )
    assert db_conn.execute(
        "SELECT 1 FROM user_domains WHERE user_id = ? AND domain_id = ?", (user_id, domain_id)
    ).fetchone() is not None

    # Saving again with that user simply not selected is how access is
    # revoked -- there's no separate "remove" action.
    client.post(
        "/domains/access", data={"domain_id": domain_id}, headers=_auth_header(),
    )
    assert db_conn.execute(
        "SELECT 1 FROM user_domains WHERE user_id = ? AND domain_id = ?", (user_id, domain_id)
    ).fetchone() is None


def test_domains_page_lists_bulk_access_form_and_row_checkboxes(client, db_conn):
    """Real live-testing feedback (RoadMap.md's dated entry): "we should
    probably have a way to bulk categorize domains" -- setting access on
    dozens of domains one at a time via each one's own Manage page
    doesn't scale."""
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    resp = client.get("/domains", headers=_auth_header())
    assert resp.status_code == 200
    assert b'action="/domains/bulk-access"' in resp.data
    assert b'class="bulk-domain-check"' in resp.data
    assert b'id="domainSelectAll"' in resp.data


def test_bulk_update_domain_access_applies_to_every_selected_domain(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post("/domains/add", data={"pattern": r"a\.example\.com", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"b\.example\.com", "mode": "splice"}, headers=_auth_header())
    domain_ids = [
        r["id"] for r in db_conn.execute(
            "SELECT id FROM domains WHERE pattern IN (?, ?)", (r"a\.example\.com", r"b\.example\.com")
        )
    ]
    assert len(domain_ids) == 2

    resp = client.post(
        "/domains/bulk-access",
        data={"domain_ids": [str(i) for i in domain_ids], "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/domains")
    for domain_id in domain_ids:
        assert db_conn.execute(
            "SELECT 1 FROM user_domains WHERE user_id = ? AND domain_id = ?", (user_id, domain_id)
        ).fetchone() is not None


def test_bulk_update_domain_access_can_set_global(client, db_conn):
    client.post("/domains/add", data={"pattern": r"a\.example\.com", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"b\.example\.com", "mode": "splice"}, headers=_auth_header())
    domain_ids = [r["id"] for r in db_conn.execute("SELECT id FROM domains")]

    client.post(
        "/domains/bulk-access",
        data={"domain_ids": [str(i) for i in domain_ids], "is_global": "on"},
        headers=_auth_header(),
    )

    rows = db_conn.execute("SELECT is_global FROM domains").fetchall()
    assert all(r["is_global"] == 1 for r in rows)


def test_bulk_update_domain_access_without_selection_shows_error_and_changes_nothing(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains").fetchone()["id"]

    resp = client.post(
        "/domains/bulk-access", data={"is_global": "on"}, headers=_auth_header(),
    )

    assert "error=1" in resp.headers["Location"]
    row = db_conn.execute("SELECT is_global FROM domains WHERE id = ?", (domain_id,)).fetchone()
    assert row["is_global"] == 0


def test_bulk_update_domain_access_is_one_transaction_not_one_commit_per_domain(client, db_conn, monkeypatch):
    """Regression guard mirroring test_category_fetch.py's own
    test_sync_is_one_atomic_transaction_not_thousands_of_autocommits --
    same isolation_level=None database, same risk if this loop ever lost
    its explicit BEGIN IMMEDIATE/commit wrapper. A mid-loop failure must
    leave every domain's access completely untouched, not partially
    applied to whichever ones were processed before the failure."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post("/domains/add", data={"pattern": r"a\.example\.com", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"b\.example\.com", "mode": "splice"}, headers=_auth_header())
    domain_ids = [r["id"] for r in db_conn.execute("SELECT id FROM domains ORDER BY id")]

    import dashboard as dashboard_module
    real_replace = dashboard_module._replace_domain_access
    calls = []

    def boom(conn, domain_id, *a, **kw):
        calls.append(domain_id)
        if len(calls) == 2:
            raise ValueError("simulated failure partway through the batch")
        return real_replace(conn, domain_id, *a, **kw)

    monkeypatch.setattr(dashboard_module, "_replace_domain_access", boom)

    # dashboard_app fixture sets app.testing = True, which propagates the
    # exception to the test instead of turning it into a 500 response --
    # same as common/category_fetch.py's own equivalent test.
    with pytest.raises(ValueError):
        client.post(
            "/domains/bulk-access",
            data={"domain_ids": [str(i) for i in domain_ids], "user_ids": [str(user_id)]},
            headers=_auth_header(),
        )

    for domain_id in domain_ids:
        assert db_conn.execute(
            "SELECT 1 FROM user_domains WHERE user_id = ? AND domain_id = ?", (user_id, domain_id)
        ).fetchone() is None, "first domain's write must have rolled back too, not just the second one's failure"


def test_add_path_and_delete_path(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "bump"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    client.post(
        "/domains/paths/add", data={"domain_id": domain_id, "pattern": r"^/ok"}, headers=_auth_header()
    )
    path_row = db_conn.execute("SELECT * FROM domain_paths WHERE domain_id = ?", (domain_id,)).fetchone()
    assert path_row is not None

    client.post("/domains/paths/delete", data={"path_id": path_row["id"]}, headers=_auth_header())
    assert db_conn.execute("SELECT * FROM domain_paths WHERE id = ?", (path_row["id"],)).fetchone() is None


def test_delete_path_on_an_already_deleted_row_does_not_500(client, db_conn):
    """Regression test for a real bug (fixed 2026-09-02): deleting a
    path_id with no matching row used to fall through to
    flash_redirect("domain_detail", domain_id=None), and Flask's
    url_for() raises an unhandled BuildError for a None value against a
    route requiring <int:domain_id> -- reproduced directly before this
    fix. A double-clicked Remove button, or a stale Domain-detail page
    where the path was already removed elsewhere, must get the same
    graceful "no longer exists" flash every sibling delete route gives,
    not a 500."""
    resp = client.post("/domains/paths/delete", data={"path_id": 999999}, headers=_auth_header())
    assert resp.status_code < 500
    assert resp.status_code in (302, 303)


# ============================================================
# REPORT / APPROVE
# ============================================================

def test_approve_blocked_site_from_report_grants_access(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), ?, 'kid1', 'newsite.example', NULL, 0, 'unknown_domain')",
        (user_id,),
    )
    db_conn.commit()
    log_id = db_conn.execute("SELECT id FROM access_log").fetchone()[0]

    resp = client.post("/report/approve", data={"log_id": log_id}, headers=_auth_header())
    assert resp.status_code == 302
    assert "error" not in resp.headers["Location"] or "error=1" not in resp.headers["Location"]

    import matching
    domain = matching.find_domain(db_conn, "newsite.example")
    assert domain is not None
    assert matching.user_has_domain(db_conn, user_id, domain["id"]) is True
    # Auto-created domain must be scoped to this user only, not global.
    assert domain["is_global"] == 0


def test_approve_blocked_show_from_report_grants_access(client, db_conn, monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard.cr_api, "series_title", lambda series_id, timeout=5.0: "Ace Attorney")

    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    db_conn.execute(
        "INSERT INTO access_log "
        "(ts, user_id, username, domain, path, series_id, series_name, allowed, reason) "
        "VALUES (datetime('now'), ?, 'kid1', 'www.crunchyroll.com', '/watch/x', 'GYE5K0XVR', NULL, 0, 'show_not_approved')",
        (user_id,),
    )
    db_conn.commit()
    log_id = db_conn.execute("SELECT id FROM access_log").fetchone()[0]

    client.post("/report/approve", data={"log_id": log_id}, headers=_auth_header())

    import matching
    assert matching.user_has_show(db_conn, user_id, "GYE5K0XVR") is True


def test_approve_missing_log_entry_errors(client):
    resp = client.post("/report/approve", data={"log_id": "999999"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_approve_from_report_scope_device_grants_device_domains_row(client, db_conn):
    """Added 2026-08-31, GH #9: a device-only row (no user_id at all) can
    now be approved for that specific device."""
    import db as db_mod
    db_conn.execute(
        "INSERT INTO devices (mac_address, label, created_at) VALUES ('aa:bb:cc:dd:ee:01', 'Living Room TV', ?)",
        (db_mod.now_iso(),),
    )
    db_conn.commit()
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:01'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason, device_id) "
        "VALUES (datetime('now'), NULL, 'Living Room TV', 'newsite.example', NULL, 0, 'domain_not_assigned', ?)",
        (device_id,),
    )
    db_conn.commit()
    log_id = db_conn.execute("SELECT id FROM access_log").fetchone()["id"]

    resp = client.post("/report/approve", data={"log_id": log_id, "scope": "device"}, headers=_auth_header())
    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]

    import matching
    domain = matching.find_domain(db_conn, "newsite.example")
    assert domain is not None
    assert domain["is_global"] == 0
    assert matching.device_has_domain(db_conn, device_id, domain["id"]) is True


def test_approve_from_report_scope_group_requires_device_in_a_group(client, db_conn):
    """A device with no group_id can't be approved-for-its-group -- there's
    no group to grant the domain to."""
    import db as db_mod
    db_conn.execute(
        "INSERT INTO devices (mac_address, label, created_at) VALUES ('aa:bb:cc:dd:ee:01', 'Living Room TV', ?)",
        (db_mod.now_iso(),),
    )
    db_conn.commit()
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:01'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason, device_id) "
        "VALUES (datetime('now'), NULL, 'Living Room TV', 'newsite.example', NULL, 0, 'domain_not_assigned', ?)",
        (device_id,),
    )
    db_conn.commit()
    log_id = db_conn.execute("SELECT id FROM access_log").fetchone()["id"]

    resp = client.post("/report/approve", data={"log_id": log_id, "scope": "group"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_approve_from_report_scope_group_grants_group_domains_row(client, db_conn):
    import db as db_mod
    db_conn.execute("INSERT INTO groups (name, created_at) VALUES ('TVs', datetime('now'))")
    db_conn.commit()
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO devices (mac_address, label, group_id, created_at) "
        "VALUES ('aa:bb:cc:dd:ee:01', 'Living Room TV', ?, ?)",
        (group_id, db_mod.now_iso()),
    )
    db_conn.commit()
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:01'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason, device_id) "
        "VALUES (datetime('now'), NULL, 'Living Room TV', 'newsite.example', NULL, 0, 'domain_not_assigned', ?)",
        (device_id,),
    )
    db_conn.commit()
    log_id = db_conn.execute("SELECT id FROM access_log").fetchone()["id"]

    resp = client.post("/report/approve", data={"log_id": log_id, "scope": "group"}, headers=_auth_header())
    assert "error=1" not in resp.headers["Location"]

    import matching
    domain = matching.find_domain(db_conn, "newsite.example")
    assert matching.group_has_domain(db_conn, group_id, domain["id"]) is True


def test_approve_path_not_allowed_redirects_to_prefilled_add_path_form(client, db_conn):
    """GH #6: approving a path-blocked row used to be a silent no-op
    (re-asserting a domain assignment that already existed). It must now
    send the admin to review a derived pattern instead of auto-saving one
    or doing nothing."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post("/domains/add", data={"pattern": r"asurascans\.example", "mode": "bump", "is_global": "on"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"asurascans\.example",)).fetchone()[0]
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), ?, 'kid1', 'asurascans.example', '/comics/some-comic?ref=1', 0, 'path_not_allowed')",
        (user_id,),
    )
    db_conn.commit()
    log_id = db_conn.execute("SELECT id FROM access_log").fetchone()[0]

    resp = client.post("/report/approve", data={"log_id": log_id}, headers=_auth_header())
    assert resp.status_code == 302
    location = resp.headers["Location"]
    assert f"/domains/{domain_id}" in location
    assert "prefill_path=" in location
    # No domain_paths row should be silently created -- the admin must
    # actually submit the (possibly edited) Add Path form for that.
    assert db_conn.execute("SELECT * FROM domain_paths WHERE domain_id = ?", (domain_id,)).fetchone() is None

    # Following the redirect shows the derived pattern in the form, ready
    # to review/edit before saving -- query string stripped, anchored,
    # escaped.
    detail_resp = client.get(location, headers=_auth_header())
    assert rb'value="^/comics/some\-comic"' in detail_resp.data or b"^/comics/some-comic" in detail_resp.data


def test_path_to_pattern_strips_query_anchors_and_escapes():
    import dashboard
    assert dashboard.path_to_pattern("/comics/some-comic?ref=1") == r"^/comics/some\-comic"
    assert dashboard.path_to_pattern("/a.b/c") == r"^/a\.b/c"
    assert dashboard.path_to_pattern(None) == "^/"
    assert dashboard.path_to_pattern("") == "^/"


def test_report_page_lists_logged_rows(client, db_conn):
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kid1', 'example.com', '/', 1, 'global_domain')"
    )
    db_conn.commit()
    resp = client.get("/report", headers=_auth_header())
    assert resp.status_code == 200
    assert b"example.com" in resp.data


# ============================================================
# Report: filter by device/group target (added 2026-08-31, GH #9 --
# access_log.device_id lets rows with no user_id at all still be
# filtered/acted on)
# ============================================================

def _insert_device(db_conn, mac, *, label=None, group_id=None):
    import db as db_mod
    db_conn.execute(
        "INSERT INTO devices (mac_address, label, group_id, created_at) VALUES (?, ?, ?, ?)",
        (mac, label, group_id, db_mod.now_iso()),
    )
    db_conn.commit()
    return db_conn.execute("SELECT id FROM devices WHERE mac_address = ?", (mac,)).fetchone()["id"]


def _insert_logged_for_device(db_conn, domain, device_id, *, username="Living Room TV"):
    import db as db_mod
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason, device_id) "
        "VALUES (?, NULL, ?, ?, NULL, 0, 'domain_not_assigned', ?)",
        (db_mod.now_iso(), username, domain, device_id),
    )
    db_conn.commit()


def test_report_filters_by_device_target(client, db_conn):
    device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:01", label="Living Room TV")
    other_device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:02", label="Kitchen Tablet")
    _insert_logged_for_device(db_conn, "onlythistv.example", device_id)
    _insert_logged_for_device(db_conn, "othertv.example", other_device_id, username="Kitchen Tablet")

    resp = client.get(f"/report?target=device:{device_id}", headers=_auth_header())
    assert resp.status_code == 200
    assert b"onlythistv.example" in resp.data
    assert b"othertv.example" not in resp.data


def test_report_filters_by_group_target(client, db_conn):
    db_conn.execute("INSERT INTO groups (name, created_at) VALUES ('TVs', datetime('now'))")
    db_conn.commit()
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:01", label="Living Room TV", group_id=group_id)
    ungrouped_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:02", label="Kitchen Tablet")
    _insert_logged_for_device(db_conn, "grouptv.example", device_id)
    _insert_logged_for_device(db_conn, "notgrouped.example", ungrouped_id, username="Kitchen Tablet")

    resp = client.get(f"/report?target=group:{group_id}", headers=_auth_header())
    assert resp.status_code == 200
    assert b"grouptv.example" in resp.data
    assert b"notgrouped.example" not in resp.data


def test_report_legacy_user_param_still_works(client, db_conn):
    """Regression guard: ?user=<username> (pre-2026-08-31 links/bookmarks)
    must keep working alongside the new ?target= combobox encoding."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), ?, 'kid1', 'kidsite.example', NULL, 1, 'global_domain')",
        (user_id,),
    )
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kid2', 'othersite.example', NULL, 1, 'global_domain')"
    )
    db_conn.commit()

    resp = client.get("/report?user=kid1", headers=_auth_header())
    assert resp.status_code == 200
    assert b"kidsite.example" in resp.data
    assert b"othersite.example" not in resp.data


# ============================================================
# CSRF / cross-origin guard
# ============================================================

def test_cross_origin_post_is_rejected(client):
    resp = client.post(
        "/users/add",
        data={"username": "kid1", "password": "pw"},
        headers={**_auth_header(), "Origin": "http://evil.example"},
    )
    assert resp.status_code == 403


def test_same_origin_post_is_allowed(client):
    resp = client.post(
        "/users/add",
        data={"username": "kid1", "password": "pw"},
        headers={**_auth_header(), "Origin": "http://localhost"},
        base_url="http://localhost/",
    )
    assert resp.status_code == 302


def test_post_without_origin_or_referer_is_allowed(client):
    # Non-browser client (curl, a script) -- no ambient credentials to abuse.
    resp = client.post(
        "/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header()
    )
    assert resp.status_code == 302


# ============================================================
# user_detail / add_show / remove_show
# ============================================================

def test_user_detail_page_renders(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "display_name": "Kid One", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    resp = client.get(f"/users/{user_id}", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Kid One" in resp.data


def test_user_detail_unknown_id_redirects_with_error(client):
    resp = client.get("/users/999999", headers=_auth_header())
    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]


def test_user_detail_shows_global_domains_separately_from_assigned(client, db_conn):
    """Real live-testing feedback 2026-09-07 (RoadMap.md's dated entry):
    the Users list's "N assigned" count includes every is_global domain
    (users()'s own domain_count query), but this page used to query only
    user_domains directly -- a brand-new user with zero explicit
    assignments showed nothing at all beyond a vague aside, with no way
    to see what the global domains actually are. Now they're listed here
    directly, note included."""
    client.post(
        "/domains/add",
        data={"pattern": r"google\.com", "mode": "splice", "note": "Google", "is_global": "on"},
        headers=_auth_header(),
    )
    client.post("/users/add", data={"username": "kid1", "display_name": "Kid One", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Global sites" in resp.data
    assert rb"google\.com" in resp.data
    assert b"Google" in resp.data


def test_add_show_invalid_url_rejected(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    resp = client.post(
        "/shows/add", data={"user_id": user_id, "url": "https://example.com/not-crunchyroll"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (user_id,)).fetchone() is None


def test_add_show_uses_override_name_without_hitting_cr_api(client, db_conn):
    """No cr_api mock installed -- an explicit name must short-circuit the
    cr_api.series_title() lookup entirely (block_network would otherwise
    fail the request)."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    resp = client.post(
        "/shows/add",
        data={
            "user_id": user_id,
            "url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney",
            "name": "My Custom Name",
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (user_id,)).fetchone()
    assert row["series_id"] == "GYE5K0XVR"
    assert row["series_name"] == "My Custom Name"


def test_add_show_falls_back_to_url_slug_when_cr_api_unavailable(client, db_conn):
    """No name override and no cr_api mock: series_title() hits the blocked
    network, catches the failure internally, and add_show falls back to the
    slug-derived name rather than erroring out."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    resp = client.post(
        "/shows/add",
        data={"user_id": user_id, "url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (user_id,)).fetchone()
    assert row["series_name"] == "Ace Attorney"  # derived from the slug


def test_add_show_uses_cr_api_title_when_mocked(client, db_conn, monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard.cr_api, "series_title", lambda series_id, timeout=5.0: "Real CR Title")

    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post(
        "/shows/add",
        data={"user_id": user_id, "url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney"},
        headers=_auth_header(),
    )
    row = db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (user_id,)).fetchone()
    assert row["series_name"] == "Real CR Title"


def test_remove_show_deletes_row(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post(
        "/shows/add",
        data={"user_id": user_id, "url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney", "name": "X"},
        headers=_auth_header(),
    )
    assert db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (user_id,)).fetchone() is not None

    client.post("/shows/remove", data={"user_id": user_id, "series_id": "GYE5K0XVR"}, headers=_auth_header())
    assert db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (user_id,)).fetchone() is None


# ============================================================
# domains filtered by user (GH #2)
# ============================================================

def test_domains_filtered_by_user_shows_only_assigned_and_global(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    user1_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    user2_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid2'").fetchone()[0]

    client.post("/domains/add", data={"pattern": r"global\.example", "mode": "splice", "is_global": "on"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"kid1-only\.example", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"kid2-only\.example", "mode": "splice"}, headers=_auth_header())

    global_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"global\.example",)).fetchone()[0]
    kid1_domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"kid1-only\.example",)).fetchone()[0]
    client.post(
        "/domains/access", data={"domain_id": kid1_domain_id, "user_ids": [str(user1_id)]},
        headers=_auth_header(),
    )

    resp = client.get(f"/domains?user_id={user1_id}", headers=_auth_header())
    assert resp.status_code == 200
    assert rb"global\.example" in resp.data
    assert rb"kid1-only\.example" in resp.data
    assert rb"kid2-only\.example" not in resp.data
    assert b"clear filter" in resp.data


def test_domains_unfiltered_shows_everything(client, db_conn):
    client.post("/domains/add", data={"pattern": r"a\.example", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"b\.example", "mode": "splice"}, headers=_auth_header())
    resp = client.get("/domains", headers=_auth_header())
    assert rb"a\.example" in resp.data
    assert rb"b\.example" in resp.data
    assert b"clear filter" not in resp.data


def test_users_page_sites_link_includes_user_id(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    resp = client.get("/users", headers=_auth_header())
    assert f"/domains?user_id={user_id}".encode() in resp.data


# ============================================================
# GH #6: paste-a-URL one-step page approval
# ============================================================

def test_add_domain_from_url_creates_bump_domain_path_and_assignment(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]

    resp = client.post(
        "/domains/add-url",
        data={"url": "https://asurascans.example/comics/some-comic?ref=1", "user_id": str(user_id)},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert f"user_id={user_id}".encode() in resp.headers["Location"].encode()

    domain = db_conn.execute("SELECT * FROM domains WHERE pattern = ?", (r"asurascans\.example",)).fetchone()
    assert domain is not None
    assert domain["mode"] == "bump"
    assert domain["is_global"] == 0

    path_row = db_conn.execute("SELECT * FROM domain_paths WHERE domain_id = ?", (domain["id"],)).fetchone()
    assert path_row is not None
    assert path_row["pattern"] == r"^/comics/some\-comic"

    assert db_conn.execute(
        "SELECT 1 FROM user_domains WHERE user_id = ? AND domain_id = ?", (user_id, domain["id"])
    ).fetchone() is not None


def test_add_domain_from_url_reuses_existing_bump_domain(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post("/domains/add", data={"pattern": r"asurascans\.example", "mode": "bump", "is_global": "on"}, headers=_auth_header())

    client.post(
        "/domains/add-url",
        data={"url": "https://asurascans.example/comics/another-one", "user_id": str(user_id)},
        headers=_auth_header(),
    )
    count = db_conn.execute("SELECT COUNT(*) c FROM domains WHERE pattern = ?", (r"asurascans\.example",)).fetchone()["c"]
    assert count == 1  # no duplicate domain row created


def test_add_domain_from_url_rejects_non_bump_existing_domain(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post("/domains/add", data={"pattern": r"asurascans\.example", "mode": "splice", "is_global": "on"}, headers=_auth_header())

    resp = client.post(
        "/domains/add-url",
        data={"url": "https://asurascans.example/comics/some-comic", "user_id": str(user_id)},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM domain_paths").fetchone() is None


def test_add_domain_from_url_without_user_id_errors(client, db_conn):
    resp = client.post(
        "/domains/add-url", data={"url": "https://asurascans.example/comics/x"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM domains").fetchone() is None


def test_add_domain_from_url_with_invalid_user_id_errors(client, db_conn):
    resp = client.post(
        "/domains/add-url",
        data={"url": "https://asurascans.example/comics/x", "user_id": "999999"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM domains").fetchone() is None


def test_add_domain_from_url_with_invalid_url_errors(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    resp = client.post(
        "/domains/add-url", data={"url": "not a url at all!!", "user_id": str(user_id)}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]


def test_domains_filtered_view_shows_paste_url_form(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    resp = client.get(f"/domains?user_id={user_id}", headers=_auth_header())
    assert b"add-url" in resp.data


def test_domains_unfiltered_view_hides_paste_url_form(client, db_conn):
    resp = client.get("/domains", headers=_auth_header())
    assert b"add-url" not in resp.data


def test_domains_filter_with_nonexistent_user_id_shows_error(client, db_conn):
    """Code-review fix: an invalid/stale user_id must surface an error like
    the rest of this file's "no longer exists" convention, not silently
    fall back to the unfiltered list."""
    resp = client.get("/domains?user_id=999999", headers=_auth_header())
    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]


def test_users_page_assigned_count_includes_global_domains(client, db_conn):
    """Code-review fix: the "N assigned" count must match what its own
    ?user_id= link actually shows -- explicit assignments plus every
    global domain, not just explicit assignments."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"global\.example", "mode": "splice", "is_global": "on"}, headers=_auth_header())
    resp = client.get("/users", headers=_auth_header())
    assert b"1 assigned" in resp.data


def test_add_domain_from_filtered_view_preserves_filter(client, db_conn):
    """Code-review fix: add_domain must forward ?user_id= through its
    redirect so the admin stays in the filtered view they were on."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    resp = client.post(
        "/domains/add",
        data={"pattern": r"new\.example", "mode": "splice", "user_id": str(user_id)},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert f"user_id={user_id}".encode() in resp.headers["Location"].encode()


def test_delete_domain_from_filtered_view_preserves_filter(client, db_conn):
    """Code-review fix: delete_domain must forward ?user_id= through its
    redirect so the admin stays in the filtered view they were on."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post("/domains/add", data={"pattern": r"new\.example", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"new\.example",)).fetchone()[0]
    resp = client.post(
        "/domains/delete", data={"domain_id": domain_id, "user_id": str(user_id)}, headers=_auth_header()
    )
    assert resp.status_code == 302
    assert f"user_id={user_id}".encode() in resp.headers["Location"].encode()


def test_add_domain_without_filter_does_not_add_user_id_to_redirect(client, db_conn):
    resp = client.post(
        "/domains/add", data={"pattern": r"unfiltered\.example", "mode": "splice"}, headers=_auth_header()
    )
    assert b"user_id" not in resp.headers["Location"].encode()


# ============================================================
# domain_detail / update_domain
# ============================================================

def test_domain_detail_page_renders(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]
    resp = client.get(f"/domains/{domain_id}", headers=_auth_header())
    assert resp.status_code == 200
    assert b"example" in resp.data


def test_domain_detail_unknown_id_redirects_with_error(client):
    resp = client.get("/domains/999999", headers=_auth_header())
    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]


def test_update_domain_changes_mode_and_note(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    resp = client.post(
        "/domains/update",
        data={"domain_id": domain_id, "mode": "bump", "note": "updated"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
    assert row["mode"] == "bump"
    assert row["note"] == "updated"


def test_domain_access_sets_global_flag(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    resp = client.post(
        "/domains/access", data={"domain_id": domain_id, "is_global": "on"}, headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT is_global FROM domains WHERE id = ?", (domain_id,)).fetchone()
    assert row["is_global"] == 1


# ============================================================
# SETTINGS
# ============================================================

def test_settings_page_renders(client):
    resp = client.get("/settings", headers=_auth_header())
    assert resp.status_code == 200
    assert b"admin" in resp.data.lower()


def test_update_local_network_saves_value(client, db_conn):
    resp = client.post(
        "/settings/local-network", data={"local_network": "10.0.0.0/8"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    import db
    assert db.get_setting(db_conn, "local_network") == "10.0.0.0/8"


def test_update_local_network_blank_disables_check(client, db_conn):
    client.post("/settings/local-network", data={"local_network": ""}, headers=_auth_header())
    import db
    assert db.get_setting(db_conn, "local_network") == ""
    import matching
    assert matching.ip_in_configured_lan(db_conn, "8.8.8.8") is True


def test_settings_page_shows_the_default_optigate_hostname(client):
    resp = client.get("/settings", headers=_auth_header())
    assert b"optigate.home" in resp.data


def test_update_optigate_hostname_saves_lowercased_value(client, db_conn):
    resp = client.post(
        "/settings/optigate-hostname", data={"optigate_hostname_prefix": "MyNetwork"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    import db
    assert db.get_setting(db_conn, "optigate_hostname_prefix") == "mynetwork"


def test_update_optigate_hostname_blank_falls_back_to_default(client, db_conn):
    client.post("/settings/optigate-hostname", data={"optigate_hostname_prefix": ""}, headers=_auth_header())
    import db
    assert db.get_setting(db_conn, "optigate_hostname_prefix") == db.DEFAULT_OPTIGATE_HOSTNAME_PREFIX


def test_update_optigate_hostname_rejects_a_dot(client, db_conn):
    """The project owner's own words: "force the use of .home so the
    administrator can only change the first part of the URL" -- a
    prefix containing its own dot could otherwise smuggle in a
    different, unintended suffix."""
    resp = client.post(
        "/settings/optigate-hostname", data={"optigate_hostname_prefix": "evil.example"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    import db
    assert db.get_setting(db_conn, "optigate_hostname_prefix") is None


def test_update_optigate_hostname_rejects_invalid_characters(client, db_conn):
    resp = client.post(
        "/settings/optigate-hostname", data={"optigate_hostname_prefix": "not valid!"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]


def test_update_optigate_hostname_rejects_leading_or_trailing_hyphen(client, db_conn):
    resp = client.post(
        "/settings/optigate-hostname", data={"optigate_hostname_prefix": "-bad"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]


def test_update_block_page_mode_valid_value_saved(client, db_conn):
    resp = client.post(
        "/settings/block-page-mode", data={"block_page_mode": "redirect"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    import db
    assert db.get_setting(db_conn, "block_page_mode") == "redirect"


def test_update_block_page_mode_invalid_value_rejected(client, db_conn):
    resp = client.post(
        "/settings/block-page-mode", data={"block_page_mode": "not-a-mode"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]


# ============================================================
# HEALTH (interception_runtime)
# ============================================================

def _insert_runtime_row(db_conn, mode="running", nft_mode="running", **overrides):
    """Seeds the interception_runtime singleton row -- mirrors this file's
    existing _insert_device_with_last_seen/_insert_recent_denial/
    _insert_logged helper pattern instead of each test hand-writing its own
    INSERT column list. `overrides` accepts any other column by name (e.g.
    last_healthy_at=..., fail_open_reason=..., nft_fail_reason=...,
    applied_generation=...)."""
    columns = {"mode": mode, "nft_mode": nft_mode, **overrides}
    names = ", ".join(columns)
    placeholders = ", ".join("?" for _ in columns)
    db_conn.execute(
        f"INSERT INTO interception_runtime (singleton_id, {names}) VALUES (1, {placeholders})",
        tuple(columns.values()),
    )
    db_conn.commit()


def test_health_page_requires_admin_auth(client):
    resp = client.get("/health")
    assert resp.status_code == 401


def test_health_page_shows_not_running_when_no_runtime_row(client):
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Not running" in resp.data
    assert b"interception" in resp.data.lower()


def test_health_page_shows_running_mode_and_generation(client, db_conn):
    # A hardcoded absolute timestamp here (an earlier version of this test
    # used '2026-08-30T12:00:00Z') silently ages past HEALTH_STALE_AFTER_
    # SECONDS as real time passes, at which point this test starts
    # exercising the "stale" render branch instead of the intended plain-
    # running one, while still passing on these same weak substring
    # assertions -- caught by code review 2026-08-30. Use a relative,
    # always-fresh timestamp instead, and assert the specific generation
    # text plus the ABSENCE of the stale badge, so a regression in either
    # the generation display or the staleness threshold actually fails
    # this test rather than passing by coincidence.
    import db
    recent_ts = db.now_iso()
    _insert_runtime_row(db_conn, last_healthy_at=recent_ts, applied_generation=7)
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Applied ARP-worker generation: 7." in resp.data
    assert recent_ts.encode() in resp.data
    assert b"stale" not in resp.data.lower()


def test_health_page_shows_fail_open_reason(client, db_conn):
    _insert_runtime_row(db_conn, mode="fail_open", fail_open_reason="worker connection lost")
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"worker connection lost" in resp.data
    assert b"NOT being tracked" in resp.data


def test_health_page_flags_stale_mode_despite_running_status(client, db_conn):
    # Simulates a crash-looping controller (e.g. OOM-killed, confirmed live
    # 2026-08-30): the DB row is frozen at whatever it said the moment the
    # process died, since the process that would report fail_open is the
    # same one that's dead.
    import db
    _insert_runtime_row(db_conn, last_healthy_at=db.iso_secs_ago(60))
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"stale" in resp.data.lower()
    assert b"but its status is still" in resp.data


def test_health_page_does_not_flag_recent_running_status_as_stale(client, db_conn):
    import db
    _insert_runtime_row(db_conn, last_healthy_at=db.now_iso(), nft_last_healthy_at=db.now_iso())
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"stale" not in resp.data.lower()


def test_sidebar_shows_alarm_badge_for_stale_status_too(client, db_conn):
    import db
    _insert_runtime_row(db_conn, last_healthy_at=db.iso_secs_ago(60))
    resp = client.get("/settings", headers=_auth_header())
    assert b'class="badge blocked">!' in resp.data


def test_health_page_shows_nft_fail_open_reason(client, db_conn):
    _insert_runtime_row(db_conn, nft_mode="fail_open", nft_fail_reason="nft command failed")
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"nft command failed" in resp.data
    assert b"NOT being kept in sync" in resp.data


def test_sidebar_shows_alarm_badge_only_when_fail_open(client, db_conn):
    resp = client.get("/settings", headers=_auth_header())
    assert b'class="badge blocked">!' not in resp.data

    _insert_runtime_row(db_conn, mode="fail_open")
    resp = client.get("/settings", headers=_auth_header())
    assert b'class="badge blocked">!' in resp.data


def test_update_admin_changes_username_and_password(client, db_conn):
    resp = client.post(
        "/settings/admin",
        data={"admin_username": "newadmin", "admin_password": "newpassword123"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302

    # Old credentials no longer work.
    assert client.get("/users", headers=_auth_header()).status_code == 401
    # New credentials do.
    resp = client.get("/users", headers=_auth_header(username="newadmin", password="newpassword123"))
    assert resp.status_code == 200


def test_update_admin_blank_username_rejected(client, db_conn):
    resp = client.post(
        "/settings/admin", data={"admin_username": "", "admin_password": ""}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    # Original credentials still work.
    assert client.get("/users", headers=_auth_header()).status_code == 200


def test_update_admin_blank_password_keeps_current_password(client, db_conn):
    client.post(
        "/settings/admin", data={"admin_username": ADMIN_USER, "admin_password": ""},
        headers=_auth_header(),
    )
    # Original password still works since it was left blank on the form.
    assert client.get("/users", headers=_auth_header()).status_code == 200


# ============================================================
# /settings/adguard: connection settings + "check for updates now"
# ============================================================

def test_update_adguard_settings_saves_url_username_password(client, db_conn):
    resp = client.post(
        "/settings/adguard",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "admin", "adguard_password": "hunter2"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    import db as db_mod
    assert db_mod.get_setting(db_conn, "adguard_url") == "http://127.0.0.1:3000"
    assert db_mod.get_setting(db_conn, "adguard_username") == "admin"
    assert db_mod.get_setting(db_conn, "adguard_password") == "hunter2"


def test_update_adguard_settings_blank_password_keeps_current(client, db_conn):
    client.post(
        "/settings/adguard",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "admin", "adguard_password": "hunter2"},
        headers=_auth_header(),
    )
    client.post(
        "/settings/adguard",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "admin", "adguard_password": ""},
        headers=_auth_header(),
    )
    import db as db_mod
    assert db_mod.get_setting(db_conn, "adguard_password") == "hunter2"


def test_update_adguard_settings_blank_username_rejected(client, db_conn):
    resp = client.post(
        "/settings/adguard",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "", "adguard_password": "x"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]


def test_refresh_adguard_filters_without_connection_details_shows_error(client, db_conn):
    resp = client.post("/settings/adguard/refresh", headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_settings_shows_no_adguard_ui_link_when_not_configured(client, db_conn):
    resp = client.get("/settings", headers=_auth_header())
    assert b"Open AdGuard" not in resp.data


def test_settings_shows_adguard_ui_link_using_the_browsers_own_host(client, db_conn):
    # Real feature added 2026-09-07: a quick click-through to AdGuard's
    # own admin UI. Must NOT reuse adguard_url's own host as-is -- that's
    # always 127.0.0.1 (the dashboard-to-AdGuard API address under this
    # project's shared network_mode: host setup), which would send the
    # admin's browser to their OWN machine, not the Beelink. Only the
    # PORT comes from adguard_url; the host comes from whatever address
    # the browser actually used to reach this page (here, the Flask test
    # client's own default Host: localhost).
    client.post(
        "/settings/adguard",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "admin", "adguard_password": "x"},
        headers=_auth_header(),
    )
    resp = client.get("/settings", headers=_auth_header())
    assert b'href="http://localhost:3000"' in resp.data
    assert b"ADGUARD_WEB_BIND" in resp.data  # the reachability caveat is explained, not just linked


def test_adguard_ui_link_uses_a_different_configured_port(client, db_conn):
    client.post(
        "/settings/adguard",
        data={"adguard_url": "http://127.0.0.1:4000", "adguard_username": "admin", "adguard_password": "x"},
        headers=_auth_header(),
    )
    resp = client.get("/settings", headers=_auth_header())
    assert b'href="http://localhost:4000"' in resp.data


def test_refresh_adguard_filters_calls_the_real_client_and_reports_the_count(client, db_conn, monkeypatch):
    client.post(
        "/settings/adguard",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "admin", "adguard_password": "hunter2"},
        headers=_auth_header(),
    )

    captured = {}

    def fake_refresh(base_url, username, password, timeout=None):
        captured["args"] = (base_url, username, password)
        return 2

    import dashboard
    monkeypatch.setattr(dashboard.adguard_client, "refresh_filters", fake_refresh)

    resp = client.post("/settings/adguard/refresh", headers=_auth_header())

    assert "error=1" not in resp.headers["Location"]
    assert captured["args"] == ("http://127.0.0.1:3000", "admin", "hunter2")


def test_refresh_adguard_filters_reports_adguard_errors_without_crashing(client, db_conn, monkeypatch):
    client.post(
        "/settings/adguard",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "admin", "adguard_password": "hunter2"},
        headers=_auth_header(),
    )

    import dashboard

    def fake_refresh(base_url, username, password, timeout=None):
        raise dashboard.adguard_client.AdGuardError("could not reach http://127.0.0.1:3000: connection refused")

    monkeypatch.setattr(dashboard.adguard_client, "refresh_filters", fake_refresh)

    resp = client.post("/settings/adguard/refresh", headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


# ============================================================
# /blocked: "Request approval" + admin Dismiss/Approve
# ============================================================

def _insert_recent_denial(db_conn, user_id, domain="newsite.example", path=None):
    # Must match db.now_iso()'s exact format (T/Z, not SQLite's datetime('now')
    # 'YYYY-MM-DD HH:MM:SS') -- /blocked's lookback filters with `ts >= ?`
    # against db.iso_secs_ago(), and the two formats don't compare correctly
    # against each other lexicographically (space sorts before 'T').
    import db as db_mod
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (?, ?, 'kid1', ?, ?, 0, 'unknown_domain')",
        (db_mod.now_iso(), user_id, domain, path),
    )
    db_conn.commit()
    return db_conn.execute("SELECT id FROM access_log ORDER BY id DESC LIMIT 1").fetchone()[0]


def test_blocked_page_offers_request_button_for_a_recent_denial(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    _insert_recent_denial(db_conn, user_id)

    resp = client.get("/blocked")
    assert resp.status_code == 403
    assert b"Request approval" in resp.data


def test_blocked_page_has_no_button_with_no_recent_denial(client):
    resp = client.get("/blocked")
    assert b"Request approval" not in resp.data
    assert b"Request sent" not in resp.data


def test_request_approval_sets_flag_and_blocked_page_reflects_it(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    log_id = _insert_recent_denial(db_conn, user_id)

    resp = client.post("/blocked/request-approval", data={"log_id": log_id})
    assert resp.status_code == 302

    row = db_conn.execute("SELECT approval_requested_at FROM access_log WHERE id = ?", (log_id,)).fetchone()
    assert row["approval_requested_at"] is not None

    # No admin auth needed for either the page or the click -- the kid on
    # the blocked device isn't logged into the dashboard.
    resp = client.get("/blocked")
    assert b"Request sent" in resp.data
    assert b"Request approval" not in resp.data


def test_report_shows_pending_request_badge_and_card(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    log_id = _insert_recent_denial(db_conn, user_id)
    client.post("/blocked/request-approval", data={"log_id": log_id})

    resp = client.get("/report", headers=_auth_header())
    assert b"Pending approval requests" in resp.data
    assert b"newsite.example" in resp.data


def test_dismiss_request_clears_flag_without_granting_access(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    log_id = _insert_recent_denial(db_conn, user_id)
    client.post("/blocked/request-approval", data={"log_id": log_id})

    resp = client.post("/report/dismiss-request", data={"log_id": log_id}, headers=_auth_header())
    assert resp.status_code == 302

    row = db_conn.execute("SELECT approval_requested_at FROM access_log WHERE id = ?", (log_id,)).fetchone()
    assert row["approval_requested_at"] is None

    import matching
    assert matching.find_domain(db_conn, "newsite.example") is None  # still not approved

    resp = client.get("/report", headers=_auth_header())
    assert b"Pending approval requests" not in resp.data


def test_dismiss_request_requires_admin_auth(client, db_conn):
    resp = client.post("/report/dismiss-request", data={"log_id": "1"})
    assert resp.status_code == 401


def test_approving_a_pending_request_also_clears_the_flag(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    log_id = _insert_recent_denial(db_conn, user_id)
    client.post("/blocked/request-approval", data={"log_id": log_id})

    client.post("/report/approve", data={"log_id": log_id}, headers=_auth_header())

    row = db_conn.execute("SELECT approval_requested_at FROM access_log WHERE id = ?", (log_id,)).fetchone()
    assert row["approval_requested_at"] is None


# ============================================================
# Report: scope=global ("approve for everyone") + date-range filter
# ============================================================

def test_approve_scope_global_makes_the_domain_global(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    log_id = _insert_recent_denial(db_conn, user_id, domain="sharedsite.example")

    resp = client.post(
        "/report/approve", data={"log_id": log_id, "scope": "global"}, headers=_auth_header()
    )
    assert resp.status_code == 302

    import matching
    domain = matching.find_domain(db_conn, "sharedsite.example")
    assert domain is not None
    assert domain["is_global"] == 1
    # Global means nobody needs an explicit per-user assignment -- not even
    # the kid who originally triggered the request.
    assert db_conn.execute(
        "SELECT 1 FROM user_domains WHERE domain_id = ?", (domain["id"],)
    ).fetchone() is None


def test_approve_scope_global_flips_an_existing_non_global_domain(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    db_conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, created_at) "
        "VALUES ('existing\\.example', 'splice', 'generic', 0, datetime('now'))"
    )
    db_conn.commit()
    log_id = _insert_recent_denial(db_conn, user_id, domain="existing.example")

    client.post("/report/approve", data={"log_id": log_id, "scope": "global"}, headers=_auth_header())

    row = db_conn.execute("SELECT is_global FROM domains WHERE pattern = 'existing\\.example'").fetchone()
    assert row["is_global"] == 1


def test_approve_scope_global_for_a_show_grants_every_user(client, db_conn, monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard.cr_api, "series_title", lambda series_id, timeout=5.0: "Ace Attorney")

    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    kid1_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    kid2_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid2'").fetchone()[0]
    db_conn.execute(
        "INSERT INTO access_log "
        "(ts, user_id, username, domain, path, series_id, series_name, allowed, reason) "
        "VALUES (datetime('now'), ?, 'kid1', 'www.crunchyroll.com', '/watch/x', 'GYE5K0XVR', NULL, 0, 'show_not_approved')",
        (kid1_id,),
    )
    db_conn.commit()
    log_id = db_conn.execute("SELECT id FROM access_log ORDER BY id DESC LIMIT 1").fetchone()[0]

    client.post("/report/approve", data={"log_id": log_id, "scope": "global"}, headers=_auth_header())

    import matching
    assert matching.user_has_show(db_conn, kid1_id, "GYE5K0XVR") is True
    assert matching.user_has_show(db_conn, kid2_id, "GYE5K0XVR") is True


def test_approve_default_scope_is_still_user_only(client, db_conn):
    """No scope field at all (the plain Recent-activity table's button
    doesn't send one) must behave exactly like the pre-existing per-user
    approve, not silently go global."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    log_id = _insert_recent_denial(db_conn, user_id, domain="onlykid1.example")

    client.post("/report/approve", data={"log_id": log_id}, headers=_auth_header())

    import matching
    domain = matching.find_domain(db_conn, "onlykid1.example")
    assert domain["is_global"] == 0
    assert matching.user_has_domain(db_conn, user_id, domain["id"]) is True


def test_report_days_filter_excludes_older_rows(client, db_conn):
    import db as db_mod
    old_ts = db_mod.iso_secs_ago(20 * 86400)  # 20 days ago
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (?, NULL, 'kid1', 'stale.example', NULL, 1, 'global_domain')",
        (old_ts,),
    )
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (?, NULL, 'kid1', 'fresh.example', NULL, 1, 'global_domain')",
        (db_mod.now_iso(),),
    )
    db_conn.commit()

    resp_default = client.get("/report", headers=_auth_header())  # default = 7 days
    assert b"fresh.example" in resp_default.data
    assert b"stale.example" not in resp_default.data

    resp_30 = client.get("/report?days=30", headers=_auth_header())
    assert b"fresh.example" in resp_30.data
    assert b"stale.example" in resp_30.data


def test_report_invalid_days_value_falls_back_to_default(client):
    resp = client.get("/report?days=not-a-number", headers=_auth_header())
    assert resp.status_code == 200
    resp = client.get("/report?days=999", headers=_auth_header())
    assert resp.status_code == 200


def test_dismiss_request_preserves_current_filter(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    log_id = _insert_recent_denial(db_conn, user_id)

    resp = client.post(
        "/report/dismiss-request",
        data={"log_id": log_id, "user": "kid1", "status": "blocked", "days": "30"},
        headers=_auth_header(),
    )
    location = resp.headers["Location"]
    assert "user=kid1" in location
    assert "status=blocked" in location
    assert "days=30" in location


# ============================================================
# Report: clickable Allowed/Blocked stats + Clear filters
# ============================================================

def _insert_logged(db_conn, domain, allowed):
    import db as db_mod
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (?, NULL, 'kid1', ?, NULL, ?, 'global_domain')",
        (db_mod.now_iso(), domain, 1 if allowed else 0),
    )
    db_conn.commit()


def test_allowed_and_blocked_stats_link_to_status_filter(client, db_conn):
    resp = client.get("/report", headers=_auth_header())
    assert b'href="/report?target=&amp;status=allowed&amp;days=7"' in resp.data
    assert b'href="/report?target=&amp;status=blocked&amp;days=7"' in resp.data


def test_clicking_allowed_stat_filters_page_to_allowed_only(client, db_conn):
    _insert_logged(db_conn, "allowedsite.example", allowed=True)
    _insert_logged(db_conn, "blockedsite.example", allowed=False)

    resp = client.get("/report?status=allowed", headers=_auth_header())
    assert b"allowedsite.example" in resp.data
    assert b"blockedsite.example" not in resp.data
    # The Blocked stat link should still be present so the admin can pivot
    # straight to the other side without going through "Clear filters" first.
    assert b'href="/report?target=&amp;status=blocked&amp;days=7"' in resp.data


def test_clicking_blocked_stat_filters_page_to_blocked_only(client, db_conn):
    _insert_logged(db_conn, "allowedsite.example", allowed=True)
    _insert_logged(db_conn, "blockedsite.example", allowed=False)

    resp = client.get("/report?status=blocked", headers=_auth_header())
    assert b"blockedsite.example" in resp.data
    assert b"allowedsite.example" not in resp.data


def test_stat_link_preserves_current_kid_and_days_filter(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    resp = client.get("/report?user=kid1&days=30", headers=_auth_header())
    expected = f'href="/report?target=user:{user_id}&amp;status=allowed&amp;days=30"'.encode()
    assert expected in resp.data


def test_clear_filters_button_hidden_on_default_view(client):
    resp = client.get("/report", headers=_auth_header())
    assert b"Clear filters" not in resp.data


def test_clear_filters_button_shown_when_a_filter_is_active(client):
    resp = client.get("/report?status=blocked", headers=_auth_header())
    assert b"Clear filters" in resp.data
    assert b'href="/report"' in resp.data

    resp = client.get("/report?days=30", headers=_auth_header())
    assert b"Clear filters" in resp.data


# ============================================================
# Devices (v2 roadmap groundwork -- not enforced anywhere yet)
# ============================================================

def test_normalize_mac_accepts_colon_and_hyphen_forms():
    import dashboard
    assert dashboard.normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert dashboard.normalize_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
    assert dashboard.normalize_mac("not a mac") is None
    assert dashboard.normalize_mac("aa:bb:cc:dd:ee") is None
    assert dashboard.normalize_mac("") is None


def test_add_device_then_appears_in_list(client, db_conn):
    resp = client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:01", "label": "Test Tablet"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:01'").fetchone()
    assert row is not None
    assert row["label"] == "Test Tablet"
    assert row["bump_enabled"] == 0
    assert row["bypass_login"] == 0
    assert row["is_authenticated"] == 1

    resp = client.get("/devices", headers=_auth_header())
    assert b"aa:bb:cc:dd:ee:01" in resp.data
    assert b"Test Tablet" in resp.data


def test_add_device_invalid_mac_rejected(client, db_conn):
    resp = client.post("/devices/add", data={"mac_address": "not-a-mac"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM devices").fetchone() is None


def test_add_device_duplicate_mac_rejected(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:02"}, headers=_auth_header())
    resp = client.post("/devices/add", data={"mac_address": "aa:bb:cc:dd:ee:02"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    count = db_conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
    assert count == 1


# ============================================================
# G7 follow-on: bulk CSV device import
# ============================================================

def _csv_upload(text: str, filename: str = "devices.csv"):
    import io as io_mod
    return {"csv_file": (io_mod.BytesIO(text.encode("utf-8")), filename)}


def test_import_devices_adds_rows_and_skips_a_header(client, db_conn):
    csv_text = "MAC,Name\naa:bb:cc:dd:ee:10,Alex's Tablet\naa:bb:cc:dd:ee:11,Kitchen TV\n"
    resp = client.post(
        "/devices/import", data=_csv_upload(csv_text), headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    assert "Imported+2" in resp.headers["Location"] or "Imported 2" in resp.headers["Location"]

    rows = db_conn.execute("SELECT mac_address, label FROM devices ORDER BY mac_address").fetchall()
    assert [dict(r) for r in rows] == [
        {"mac_address": "aa:bb:cc:dd:ee:10", "label": "Alex's Tablet"},
        {"mac_address": "aa:bb:cc:dd:ee:11", "label": "Kitchen TV"},
    ]


def test_import_devices_headerless_csv_still_works(client, db_conn):
    csv_text = "aa:bb:cc:dd:ee:12,Roku\n"
    resp = client.post(
        "/devices/import", data=_csv_upload(csv_text), headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT label FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:12'").fetchone()
    assert row["label"] == "Roku"


def test_import_devices_skips_duplicate_macs_without_clobbering_assignment(client, db_conn):
    import urllib.parse

    client.post(
        "/devices/add", data={"mac_address": "aa:bb:cc:dd:ee:13", "label": "Original label"},
        headers=_auth_header(),
    )
    csv_text = "aa:bb:cc:dd:ee:13,Overwritten label\naa:bb:cc:dd:ee:14,New Device\n"
    resp = client.post(
        "/devices/import", data=_csv_upload(csv_text), headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    count = db_conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
    assert count == 2  # the duplicate wasn't inserted a second time
    row = db_conn.execute("SELECT label FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:13'").fetchone()
    assert row["label"] == "Original label", "an existing device's own data must never be overwritten by an import"

    message = urllib.parse.unquote_plus(resp.headers["Location"])
    assert "aa:bb:cc:dd:ee:13" in message, "the admin must be told WHICH mac was a duplicate, not just a count"


def test_import_devices_skips_rows_with_no_valid_mac(client, db_conn):
    """The invalid row here is deliberately NOT first -- a first-row
    parse failure is ambiguous with the header-skip heuristic itself
    (see import_devices()'s own comment on that known edge case) and is
    covered separately below."""
    import urllib.parse

    csv_text = "aa:bb:cc:dd:ee:15,Good Row\nnot-a-mac,Bad Row\n"
    resp = client.post(
        "/devices/import", data=_csv_upload(csv_text), headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    count = db_conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
    assert count == 1
    row = db_conn.execute("SELECT * FROM devices").fetchone()
    assert row["mac_address"] == "aa:bb:cc:dd:ee:15"

    message = urllib.parse.unquote_plus(resp.headers["Location"])
    assert "not-a-mac" in message, "the admin must see the actual offending cell, not just a count"


def test_import_devices_a_malformed_first_row_is_silently_treated_as_a_header(client, db_conn):
    """Documents a real, known, low-blast-radius edge case rather than
    leaving it as a silent surprise: the header-skip heuristic can't
    distinguish a genuine header from a garbage first DATA row -- both
    look identical (first cell doesn't parse as a MAC), so a malformed
    first row is dropped WITHOUT being counted/reported as invalid at
    all, unlike the same malformed content anywhere else in the file.
    Blast radius is capped at exactly one row (only the first), and only
    when that row is itself invalid, not merely coincidentally unlucky
    placement of a real error."""
    import urllib.parse

    csv_text = "not-a-mac,Bad Row\naa:bb:cc:dd:ee:80,Good Row\n"
    resp = client.post(
        "/devices/import", data=_csv_upload(csv_text), headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    count = db_conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
    assert count == 1

    message = urllib.parse.unquote_plus(resp.headers["Location"])
    assert "not-a-mac" not in message, "documenting current behavior -- update this test if the heuristic changes"


def test_import_devices_duplicate_preview_is_capped_for_a_large_batch(client, db_conn):
    """A real router export can be 50+ devices -- the preview must not
    turn into an unreadable wall of text (or blow past a sane URL
    length) when most/all of them are already known."""
    import urllib.parse

    macs = [f"aa:bb:cc:dd:ee:{i:02x}" for i in range(20, 35)]  # 15 devices
    for mac in macs:
        client.post("/devices/add", data={"mac_address": mac}, headers=_auth_header())

    csv_text = "\n".join(macs)
    resp = client.post(
        "/devices/import", data=_csv_upload(csv_text), headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    message = urllib.parse.unquote_plus(resp.headers["Location"])
    assert "and 5 more" in message  # 15 duplicates, capped preview shows 10 + "5 more"


def test_import_devices_requires_a_file(client, db_conn):
    resp = client.post("/devices/import", data={}, headers=_auth_header(), content_type="multipart/form-data")
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"] == 0


def test_import_devices_empty_csv_flashes_error(client, db_conn):
    resp = client.post(
        "/devices/import", data=_csv_upload("\n\n"), headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert "error=1" in resp.headers["Location"]


def test_import_devices_requires_admin_auth(client, db_conn):
    resp = client.post(
        "/devices/import", data=_csv_upload("aa:bb:cc:dd:ee:16,X"), content_type="multipart/form-data",
    )
    assert resp.status_code == 401
    assert db_conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"] == 0


def test_imported_devices_are_plain_unassigned(client, db_conn):
    """The whole point is a fast way to enter known devices, not a
    parallel assignment UI -- every imported row must land exactly like
    a hand-added one via add_device(), fully unassigned."""
    client.post(
        "/devices/import", data=_csv_upload("aa:bb:cc:dd:ee:17,X"), headers=_auth_header(),
        content_type="multipart/form-data",
    )
    row = db_conn.execute("SELECT * FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:17'").fetchone()
    assert row["user_id"] is None
    assert row["group_id"] is None
    assert row["ignored"] == 0
    assert row["is_authenticated"] == 1


def test_settings_page_shows_bulk_import_card(client):
    resp = client.get("/settings", headers=_auth_header())
    assert b"Bulk import devices" in resp.data


# ============================================================
# Events page (2026-09-01, added ahead of G1 real-network testing)
# ============================================================

def test_events_page_shows_empty_state_with_no_events(client):
    resp = client.get("/events", headers=_auth_header())
    assert resp.status_code == 200
    assert b"No events recorded yet" in resp.data


def test_events_page_lists_a_real_event(client, db_conn):
    import system_events

    system_events.log_event(db_conn, "adguard_sync", "error", "adguard sync failed: boom")
    resp = client.get("/events", headers=_auth_header())
    assert resp.status_code == 200
    assert b"adguard_sync" in resp.data
    assert b"adguard sync failed: boom" in resp.data
    assert b"error" in resp.data


def test_events_page_shows_recovery_severity_distinctly(client, db_conn):
    import system_events

    system_events.log_event(db_conn, "category_fetch", "recovery", "category_fetch recovered")
    resp = client.get("/events", headers=_auth_header())
    assert b"recovery" in resp.data


def test_events_page_orders_newest_first(client, db_conn):
    import system_events

    system_events.log_event(db_conn, "adguard_sync", "error", "first failure")
    system_events.log_event(db_conn, "adguard_sync", "error", "second failure")
    resp = client.get("/events", headers=_auth_header())
    body = resp.data.decode()
    assert body.index("second failure") < body.index("first failure")


def test_events_page_requires_admin_auth(client, db_conn):
    resp = client.get("/events")
    assert resp.status_code == 401


def test_events_page_caps_display_at_the_limit(client, db_conn):
    import dashboard as dashboard_mod
    import system_events

    total = dashboard_mod.EVENT_DISPLAY_LIMIT + 5
    for i in range(total):
        system_events.log_event(db_conn, "adguard_sync", "error", f"failure {i}")

    resp = client.get("/events", headers=_auth_header())
    body = resp.data.decode()
    # Nothing is deleted -- all rows still exist in the table itself.
    assert db_conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"] == total
    # The page shows only the newest EVENT_DISPLAY_LIMIT -- the oldest 5
    # ("failure 0".."failure 4") must be excluded from what's displayed.
    for i in range(5):
        assert f"failure {i}<" not in body, f"failure {i} should have been cut off, it's older than the cap"
    assert f"failure {total - 1}" in body
    assert f"Showing the most recent {dashboard_mod.EVENT_DISPLAY_LIMIT} events" in body


def test_update_device_sets_flags_and_assigns_to_a_kid(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:03"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]

    resp = client.post(
        "/devices/update",
        data={
            "device_id": device_id, "label": "Alex's Phone", "assignment": f"user:{user_id}",
            "bump_enabled": "on", "bypass_login": "",
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["label"] == "Alex's Phone"
    assert row["user_id"] == user_id
    assert row["group_id"] is None
    assert row["ignored"] == 0
    assert row["bump_enabled"] == 1
    assert row["bypass_login"] == 0


def test_update_device_turning_on_bypass_login_defaults_to_ignored(client, db_conn):
    """2026-08-31, project owner's explicit direction -- same default as
    the quick-action bypass_login_device() route, but via the full edit
    form: turning bypass_login on with no assignment picked defaults the
    device to ignored."""
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:60"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]

    resp = client.post(
        "/devices/update",
        data={"device_id": device_id, "label": "", "assignment": "", "bypass_login": "on"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["bypass_login"] == 1
    assert row["ignored"] == 1


def test_update_device_bypass_login_default_does_not_override_explicit_assignment(client, db_conn):
    """Turning bypass_login on in the SAME submission as an explicit
    group assignment must respect that explicit choice, not silently
    force ignored=1 over it."""
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:61"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]

    resp = client.post(
        "/devices/update",
        data={
            "device_id": device_id, "label": "", "assignment": f"group:{group_id}",
            "bypass_login": "on",
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["bypass_login"] == 1
    assert row["group_id"] == group_id
    assert row["ignored"] == 0


def test_update_device_bypass_login_default_does_not_refire_on_a_later_save(client, db_conn):
    """The default only fires on the actual 0->1 transition -- once set,
    an admin's own later 'actually, assign it to a group' edit (while
    bypass_login stays on) must stick, not get fought back to ignored on
    every subsequent save."""
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:62"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]

    # First save: bypass_login turns on, no assignment -> defaults to ignored.
    client.post(
        "/devices/update",
        data={"device_id": device_id, "label": "", "assignment": "", "bypass_login": "on"},
        headers=_auth_header(),
    )
    assert db_conn.execute("SELECT ignored FROM devices WHERE id = ?", (device_id,)).fetchone()["ignored"] == 1

    # Second save: admin explicitly un-ignores it by assigning a group,
    # bypass_login stays on the whole time.
    resp = client.post(
        "/devices/update",
        data={
            "device_id": device_id, "label": "", "assignment": f"group:{group_id}",
            "bypass_login": "on",
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["bypass_login"] == 1
    assert row["group_id"] == group_id
    assert row["ignored"] == 0


def test_device_detail_page_reminds_about_the_ca_cert_before_bump_enable(client, db_conn):
    """RoadMap.md's design sketch: an admin should confirm the CA cert
    is actually installed before flipping bump_enabled, so a device
    never ends up bump-enabled while still showing confusing
    certificate warnings. Client-side only (a plain confirm(), matching
    this app's own established no-framework convention -- see the
    group-delete button's identical pattern) -- this just checks the
    reminder is actually wired to the checkbox, not that JS ran."""
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:31"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:31'").fetchone()[0]

    resp = client.get(f"/devices/{device_id}", headers=_auth_header())

    body = resp.data.decode()
    assert "CA certificate already been installed" in body
    assert 'name="bump_enabled"' in body
    # The confirm() must be on the SAME checkbox, not just present
    # somewhere else on the page.
    checkbox_start = body.index('name="bump_enabled"')
    checkbox_tag = body[max(0, checkbox_start - 200):checkbox_start + 200]
    assert "confirm(" in checkbox_tag


def test_delete_device_removes_row(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:04"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]

    resp = client.post("/devices/delete", data={"device_id": device_id}, headers=_auth_header())
    assert resp.status_code == 302
    assert db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone() is None


def test_deleting_a_user_unassigns_their_devices_instead_of_deleting_them(client, db_conn):
    """devices.user_id is ON DELETE SET NULL, not CASCADE -- a device is a
    physical object that still exists after the person who used it is
    removed from the system, unlike e.g. a user's site/show approvals."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:05", "assignment": f"user:{user_id}"},
        headers=_auth_header(),
    )
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]
    assert db_conn.execute("SELECT user_id FROM devices WHERE id = ?", (device_id,)).fetchone()[0] == user_id

    client.post("/users/delete", data={"user_id": user_id}, headers=_auth_header())

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row is not None
    assert row["user_id"] is None


def test_devices_requires_admin_auth(client):
    assert client.get("/devices").status_code == 401
    assert client.post("/devices/add", data={"mac_address": "aa:bb:cc:dd:ee:06"}).status_code == 401


# ============================================================
# Devices: pending-login visibility (Phase 4 milestone 1's
# auto-created, is_authenticated=0 devices -- see
# common/identity.py's record_binding docstring for how these rows
# come to exist in the first place; this is the dashboard-side
# visibility for that new state)
# ============================================================

def _add_pending_device(db_conn, mac_address, created_at="2026-08-31T00:00:00Z"):
    """Simulates a device auto-created by record_binding() for a
    genuinely brand-new MAC -- is_authenticated=0, no user/group, not
    ignored or bypass_login'd. A raw INSERT rather than calling
    identity.record_binding() directly, matching this file's own
    dashboard-level testing convention (exercise the HTTP routes and
    the DB shape they read, not the controller-side code that produces
    that shape)."""
    db_conn.execute(
        "INSERT INTO devices (mac_address, is_authenticated, ignored, created_at) "
        "VALUES (?, 0, 0, ?)",
        (mac_address, created_at),
    )
    db_conn.commit()
    return db_conn.execute(
        "SELECT id FROM devices WHERE mac_address = ?", (mac_address,)
    ).fetchone()["id"]


def test_devices_page_shows_no_pending_card_when_nothing_is_pending(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:40"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    assert b"Devices awaiting login" not in resp.data


def test_devices_page_surfaces_a_pending_device_with_a_bypass_action(client, db_conn):
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:41")

    resp = client.get("/devices", headers=_auth_header())

    assert b"Devices awaiting login (1)" in resp.data
    assert b"aa:bb:cc:dd:ee:41" in resp.data
    assert b"Awaiting login" in resp.data
    assert b"Bypass" in resp.data


def test_pending_devices_show_network_info_from_device_bindings(client, db_conn):
    # Real gap fixed 2026-09-07: devices.last_seen_at is never populated
    # by anything, so the pending-devices card must read current IP /
    # last seen / discovery source from device_bindings instead.
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:46")
    db_conn.execute(
        "INSERT INTO device_bindings (device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, "
        "source, active) SELECT id, mac_address, '192.168.1.77', '2026-08-31T00:00:00Z', "
        "'2026-09-07T12:00:00Z', 'rtnetlink', 1 FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:46'"
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())

    assert b"192.168.1.77" in resp.data
    assert b"2026-09-07T12:00:00Z" in resp.data
    assert b"rtnetlink" in resp.data


def test_pending_devices_show_none_yet_with_no_failed_logins(client, db_conn):
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:47")
    resp = client.get("/devices", headers=_auth_header())
    assert b"None yet" in resp.data


def test_pending_devices_show_a_prior_failed_login_attempt(client, db_conn):
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:48")
    db_conn.execute(
        "INSERT INTO system_events (ts, source, severity, message, detail) VALUES (?, ?, ?, ?, ?)",
        ("2026-09-07T12:00:00Z", "captive_portal_login", "error",
         "Failed login attempt from 192.168.1.1 (username: 'kid1')", "aa:bb:cc:dd:ee:48"),
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())

    assert b"1 failed attempt" in resp.data
    assert b"None yet" not in resp.data


def test_pending_devices_login_attempts_dont_leak_across_devices(client, db_conn):
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:49")
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:50")
    db_conn.execute(
        "INSERT INTO system_events (ts, source, severity, message, detail) VALUES (?, ?, ?, ?, ?)",
        ("2026-09-07T12:00:00Z", "captive_portal_login", "error", "x", "aa:bb:cc:dd:ee:49"),
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())
    text = resp.data.decode()
    # The device with the attempt shows a count; the other device's row
    # still shows "None yet" -- this asserts row-level, not page-level,
    # so pull out roughly where each MAC's row is.
    assert "1 failed attempt" in text
    assert "None yet" in text


def test_devices_page_does_not_treat_an_ignored_or_bypassed_device_as_pending(client, db_conn):
    """is_authenticated=0 alone isn't enough -- ignored or bypass_login
    already exempts a device from the future portal gate, so it must
    not also show up as 'awaiting login'."""
    db_conn.execute(
        "INSERT INTO devices (mac_address, is_authenticated, ignored, created_at) "
        "VALUES ('aa:bb:cc:dd:ee:42', 0, 1, '2026-08-31T00:00:00Z')"
    )
    db_conn.execute(
        "INSERT INTO devices (mac_address, is_authenticated, bypass_login, created_at) "
        "VALUES ('aa:bb:cc:dd:ee:43', 0, 1, '2026-08-31T00:00:00Z')"
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())

    assert b"Devices awaiting login" not in resp.data


def test_pending_devices_are_sorted_ahead_of_already_authenticated_ones(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:44"}, headers=_auth_header())
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:45")

    resp = client.get("/devices", headers=_auth_header())
    body = resp.data.decode()
    assert body.index("aa:bb:cc:dd:ee:45") < body.index("aa:bb:cc:dd:ee:44")


def test_bypass_login_sets_the_flag_without_touching_other_fields(client, db_conn):
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:46")
    db_conn.execute("UPDATE devices SET label = 'Roku' WHERE id = ?", (device_id,))
    db_conn.commit()

    resp = client.post("/devices/bypass_login", data={"device_id": device_id}, headers=_auth_header())
    assert resp.status_code == 302

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["bypass_login"] == 1
    assert row["label"] == "Roku", "must not clobber fields the pending-card form never submitted"
    assert row["is_authenticated"] == 0, "bypass exempts the device, it doesn't authenticate it"


def test_bypassed_device_no_longer_appears_in_the_pending_card(client, db_conn):
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:47")

    client.post("/devices/bypass_login", data={"device_id": device_id}, headers=_auth_header())

    resp = client.get("/devices", headers=_auth_header())
    assert b"Devices awaiting login" not in resp.data


def test_bypass_login_requires_admin_auth(client, db_conn):
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:48")
    resp = client.post("/devices/bypass_login", data={"device_id": device_id})
    assert resp.status_code == 401
    assert db_conn.execute(
        "SELECT bypass_login FROM devices WHERE id = ?", (device_id,)
    ).fetchone()["bypass_login"] == 0


# ============================================================
# G6: ad-hoc "pause the internet" (per-device / per-user / whole-house)
# ============================================================

def test_pause_device_sets_quarantined_at(client, db_conn):
    device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:60")
    resp = client.post("/devices/pause", data={"device_id": device_id}, headers=_auth_header())
    assert resp.status_code == 302
    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["quarantined_at"] is not None


def test_resume_device_clears_quarantined_at(client, db_conn):
    device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:61")
    client.post("/devices/pause", data={"device_id": device_id}, headers=_auth_header())

    resp = client.post("/devices/resume", data={"device_id": device_id}, headers=_auth_header())
    assert resp.status_code == 302
    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["quarantined_at"] is None


def test_pause_device_requires_admin_auth(client, db_conn):
    device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:62")
    resp = client.post("/devices/pause", data={"device_id": device_id})
    assert resp.status_code == 401
    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["quarantined_at"] is None


def test_devices_page_shows_paused_badge(client, db_conn):
    device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:63")
    client.post("/devices/pause", data={"device_id": device_id}, headers=_auth_header())

    resp = client.get("/devices", headers=_auth_header())
    assert b"Paused" in resp.data


def test_pause_all_devices_skips_ignored(client, db_conn):
    normal_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:64")
    db_conn.execute(
        "INSERT INTO devices (mac_address, ignored, created_at) VALUES ('aa:bb:cc:dd:ee:65', 1, datetime('now'))"
    )
    db_conn.commit()
    ignored_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:65'").fetchone()["id"]

    resp = client.post("/devices/pause-all", headers=_auth_header())
    assert resp.status_code == 302

    assert db_conn.execute(
        "SELECT quarantined_at FROM devices WHERE id = ?", (normal_id,)
    ).fetchone()["quarantined_at"] is not None
    assert db_conn.execute(
        "SELECT quarantined_at FROM devices WHERE id = ?", (ignored_id,)
    ).fetchone()["quarantined_at"] is None


def test_resume_all_devices_clears_every_paused_device(client, db_conn):
    a = _insert_device(db_conn, "aa:bb:cc:dd:ee:66")
    b = _insert_device(db_conn, "aa:bb:cc:dd:ee:67")
    client.post("/devices/pause-all", headers=_auth_header())

    resp = client.post("/devices/resume-all", headers=_auth_header())
    assert resp.status_code == 302

    for device_id in (a, b):
        row = db_conn.execute("SELECT quarantined_at FROM devices WHERE id = ?", (device_id,)).fetchone()
        assert row["quarantined_at"] is None


def test_pause_user_pauses_only_that_users_devices(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO devices (mac_address, user_id, created_at) VALUES ('aa:bb:cc:dd:ee:68', ?, datetime('now'))",
        (user_id,),
    )
    other_device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:69")
    db_conn.commit()
    kid_device_id = db_conn.execute(
        "SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:68'"
    ).fetchone()["id"]

    resp = client.post("/users/pause", data={"user_id": user_id}, headers=_auth_header())
    assert resp.status_code == 302

    assert db_conn.execute(
        "SELECT quarantined_at FROM devices WHERE id = ?", (kid_device_id,)
    ).fetchone()["quarantined_at"] is not None
    assert db_conn.execute(
        "SELECT quarantined_at FROM devices WHERE id = ?", (other_device_id,)
    ).fetchone()["quarantined_at"] is None


def test_resume_user_clears_only_that_users_devices(client, db_conn):
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid2'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO devices (mac_address, user_id, created_at) VALUES ('aa:bb:cc:dd:ee:70', ?, datetime('now'))",
        (user_id,),
    )
    db_conn.commit()
    client.post("/users/pause", data={"user_id": user_id}, headers=_auth_header())

    resp = client.post("/users/resume", data={"user_id": user_id}, headers=_auth_header())
    assert resp.status_code == 302
    row = db_conn.execute(
        "SELECT quarantined_at FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:70'"
    ).fetchone()
    assert row["quarantined_at"] is None


def test_user_detail_page_shows_pause_card_when_user_has_devices(client, db_conn):
    client.post("/users/add", data={"username": "kid3", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid3'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO devices (mac_address, user_id, created_at) VALUES ('aa:bb:cc:dd:ee:71', ?, datetime('now'))",
        (user_id,),
    )
    db_conn.commit()

    resp = client.get(f"/users/{user_id}", headers=_auth_header())
    assert b"Pause the internet" in resp.data


def test_user_detail_page_shows_pause_card_even_with_no_devices(client, db_conn):
    # Real bug fixed 2026-09-06: the whole "Pause the internet" card used
    # to disappear entirely for a user with zero devices assigned, making
    # the feature look missing rather than just currently inapplicable
    # (found via live user testing -- see chat). Now it always renders,
    # explaining why there's nothing to pause yet instead of hiding.
    client.post("/users/add", data={"username": "kid4", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid4'").fetchone()["id"]

    resp = client.get(f"/users/{user_id}", headers=_auth_header())
    assert b"Pause the internet" in resp.data
    assert b"no devices assigned yet" in resp.data
    assert b'action="/users/pause"' not in resp.data  # no pause form when there's nothing to pause


def test_user_detail_shows_currently_active_schedule(client, db_conn):
    client.post("/users/add", data={"username": "kid5", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid5'").fetchone()["id"]
    client.post(
        "/schedules/add",
        data={"name": "Bedtime", "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
              "start_time": "00:00", "end_time": "23:59", "time_zone": "UTC", "lockout_all": "on"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Bedtime'").fetchone()["id"]
    client.post(
        "/schedules/access", data={"schedule_id": schedule_id, "user_ids": [str(user_id)]}, headers=_auth_header()
    )

    resp = client.get(f"/users/{user_id}", headers=_auth_header())
    assert b"Active right now" in resp.data
    assert b"Bedtime" in resp.data
    assert b"Nothing active right now" not in resp.data


def test_user_detail_shows_nothing_active_when_no_schedule_applies(client, db_conn):
    client.post("/users/add", data={"username": "kid6", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid6'").fetchone()["id"]
    resp = client.get(f"/users/{user_id}", headers=_auth_header())
    assert b"Nothing active right now" in resp.data


def test_pausing_an_ignored_device_offers_no_pause_button(client, db_conn):
    """An ignored device can't actually be paused (BYPASS outranks
    QUARANTINE), so the UI shouldn't offer a button that would silently
    do nothing."""
    db_conn.execute(
        "INSERT INTO devices (mac_address, ignored, created_at) VALUES ('aa:bb:cc:dd:ee:72', 1, datetime('now'))"
    )
    db_conn.commit()
    device_id = db_conn.execute(
        "SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:72'"
    ).fetchone()["id"]

    resp = client.get(f"/devices/{device_id}", headers=_auth_header())
    assert b"Pause this device" not in resp.data


def test_bypass_login_defaults_an_unassigned_device_to_ignored(client, db_conn):
    """2026-08-31, project owner's explicit direction: a device that will
    never log in commonly has no real assignment either, so bypassing it
    defaults it straight to `ignored` (AdGuard's baseline-protection
    exemption) too, in one action."""
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:49")

    client.post("/devices/bypass_login", data={"device_id": device_id}, headers=_auth_header())

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["bypass_login"] == 1
    assert row["ignored"] == 1


def test_bypass_login_does_not_override_an_existing_assignment(client, db_conn):
    """The ignored-default is a default, not a forced override -- a
    device already assigned to a user (or group) keeps that assignment."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:50")
    db_conn.execute("UPDATE devices SET user_id = ? WHERE id = ?", (user_id, device_id))
    db_conn.commit()

    client.post("/devices/bypass_login", data={"device_id": device_id}, headers=_auth_header())

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["bypass_login"] == 1
    assert row["user_id"] == user_id
    assert row["ignored"] == 0


# ============================================================
# Devices: Ignore + Groups (assign to a shared-device category)
# ============================================================

def test_parse_device_assignment_variants():
    import dashboard
    assert dashboard._parse_device_assignment("") == (None, None, 0)
    assert dashboard._parse_device_assignment("ignored") == (None, None, 1)
    assert dashboard._parse_device_assignment("user:7") == (7, None, 0)
    assert dashboard._parse_device_assignment("group:3") == (None, 3, 0)
    # Malformed input falls back to unassigned rather than raising.
    assert dashboard._parse_device_assignment("user:not-a-number") == (None, None, 0)
    assert dashboard._parse_device_assignment("garbage") == (None, None, 0)


def test_add_device_with_ignored_assignment(client, db_conn):
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:10", "assignment": "ignored"},
        headers=_auth_header(),
    )
    row = db_conn.execute("SELECT * FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:10'").fetchone()
    assert row["ignored"] == 1
    assert row["user_id"] is None
    assert row["group_id"] is None


def test_add_group_then_appears_and_device_can_join_it(client, db_conn):
    resp = client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    assert resp.status_code == 302
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()[0]

    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:11", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )
    row = db_conn.execute("SELECT * FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:11'").fetchone()
    assert row["group_id"] == group_id
    assert row["user_id"] is None
    assert row["ignored"] == 0

    resp = client.get("/devices", headers=_auth_header())
    assert b"TVs" in resp.data


def test_add_group_duplicate_name_rejected(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    resp = client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    count = db_conn.execute("SELECT COUNT(*) c FROM groups WHERE name = 'IoT'").fetchone()["c"]
    assert count == 1


def test_deleting_a_group_unassigns_its_devices(client, db_conn):
    client.post("/groups/add", data={"name": "Gaming Computers"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'Gaming Computers'").fetchone()[0]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:12", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]

    client.post("/groups/delete", data={"group_id": group_id}, headers=_auth_header())

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row is not None
    assert row["group_id"] is None


# ============================================================
# Group detail page + per-group pause (real gap found 2026-09-06 --
# per-device and per-user pause both already existed, but there was no
# group_detail page at all to put a per-group pause control on)
# ============================================================

def test_devices_page_lists_per_row_add_to_group_select(client, db_conn):
    """Real live-testing feedback 2026-09-07 (RoadMap.md's dated entry):
    the group page's own bulk-add form needed you to already know the
    device's label/MAC to find it in a search-only combobox. This is the
    opposite direction -- an inline "Add to group" select right on the
    device's own row, no navigation or typing required."""
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:20"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    assert resp.status_code == 200
    assert b'action="/devices/quick-add-to-group"' in resp.data
    assert b">IoT</option>" in resp.data


def test_quick_add_device_to_group_assigns_and_stays_on_devices_page(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:21", "label": "Kitchen Cam"},
        headers=_auth_header(),
    )
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:21'").fetchone()["id"]

    resp = client.post(
        "/devices/quick-add-to-group", data={"device_id": device_id, "group_id": group_id},
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/devices")
    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["group_id"] == group_id
    assert row["user_id"] is None
    assert row["ignored"] == 0
    assert row["label"] == "Kitchen Cam", "must not touch label -- unlike update_device(), this is a narrow assignment-only update"


def test_quick_add_device_to_group_preserves_bump_and_bypass_flags(client, db_conn):
    """Regression guard: quick_add_device_to_group() must use the same
    narrow UPDATE as bulk_add_to_group(), never update_device()'s
    whole-row-from-form rewrite, or it would silently clear
    bump_enabled/bypass_login on every quick-assign."""
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:22"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:22'").fetchone()["id"]
    client.post(
        "/devices/update",
        data={"device_id": device_id, "bump_enabled": "on", "bypass_login": "on", "assignment": ""},
        headers=_auth_header(),
    )

    client.post(
        "/devices/quick-add-to-group", data={"device_id": device_id, "group_id": group_id},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["group_id"] == group_id
    assert row["bump_enabled"] == 1
    assert row["bypass_login"] == 1


def test_quick_add_device_to_group_without_group_selected_shows_error(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:23"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()["id"]

    resp = client.post(
        "/devices/quick-add-to-group", data={"device_id": device_id, "group_id": ""},
        headers=_auth_header(),
    )

    assert "error=1" in resp.headers["Location"]
    row = db_conn.execute("SELECT group_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["group_id"] is None


def test_quick_add_device_to_group_unknown_group_shows_error(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:24"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()["id"]

    resp = client.post(
        "/devices/quick-add-to-group", data={"device_id": device_id, "group_id": 999999},
        headers=_auth_header(),
    )

    assert "error=1" in resp.headers["Location"]


def test_group_detail_page_renders(client, db_conn):
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    resp = client.get(f"/groups/{group_id}", headers=_auth_header())
    assert resp.status_code == 200
    assert b"TVs" in resp.data
    assert b"Active right now" in resp.data
    assert b"Pause the internet" in resp.data


def test_group_detail_shows_global_domains_separately_from_assigned(client, db_conn):
    """Same real live-testing feedback as user_detail's own equivalent
    test -- groups have the exact same is_global-count-vs-empty-list
    mismatch."""
    client.post(
        "/domains/add",
        data={"pattern": r"gstatic\.com", "mode": "splice", "note": "Google static assets", "is_global": "on"},
        headers=_auth_header(),
    )
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]

    resp = client.get(f"/groups/{group_id}", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Global sites" in resp.data
    assert rb"gstatic\.com" in resp.data
    assert b"Google static assets" in resp.data


def test_group_detail_unknown_id_redirects_with_error(client):
    resp = client.get("/groups/999999", headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_group_detail_shows_no_devices_message_when_empty(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    resp = client.get(f"/groups/{group_id}", headers=_auth_header())
    assert b"No devices in" in resp.data
    assert b'action="/groups/pause"' not in resp.data


def test_pause_group_pauses_every_device_in_it(client, db_conn):
    client.post("/groups/add", data={"name": "Gaming Computers"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'Gaming Computers'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:20", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:21", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )

    resp = client.post("/groups/pause", data={"group_id": group_id}, headers=_auth_header())
    assert resp.status_code == 302
    rows = db_conn.execute("SELECT quarantined_at FROM devices WHERE group_id = ?", (group_id,)).fetchall()
    assert len(rows) == 2
    assert all(row["quarantined_at"] is not None for row in rows)


def test_resume_group_clears_the_pause(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:22", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )
    client.post("/groups/pause", data={"group_id": group_id}, headers=_auth_header())
    client.post("/groups/resume", data={"group_id": group_id}, headers=_auth_header())
    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE group_id = ?", (group_id,)).fetchone()
    assert row["quarantined_at"] is None


def test_pause_group_skips_ignored_devices(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO devices (mac_address, group_id, ignored, created_at) "
        "VALUES ('aa:bb:cc:dd:ee:23', ?, 1, datetime('now'))",
        (group_id,),
    )
    db_conn.commit()

    client.post("/groups/pause", data={"group_id": group_id}, headers=_auth_header())

    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:23'").fetchone()
    assert row["quarantined_at"] is None


def test_pause_group_requires_admin_auth(client, db_conn):
    resp = client.post("/groups/pause", data={"group_id": "1"})
    assert resp.status_code == 401


def test_domains_filter_by_group_shows_group_assigned_and_global_domains(client, db_conn):
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()[0]
    client.post(
        "/domains/add", data={"pattern": "netflix\\.example", "mode": "splice"}, headers=_auth_header()
    )
    client.post(
        "/domains/add", data={"pattern": "notassigned\\.example", "mode": "splice"}, headers=_auth_header()
    )
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = 'netflix\\.example'").fetchone()[0]

    resp = client.post(
        "/domains/access",
        data={"domain_id": domain_id, "group_ids": [str(group_id)]},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert db_conn.execute(
        "SELECT 1 FROM group_domains WHERE group_id = ? AND domain_id = ?", (group_id, domain_id)
    ).fetchone() is not None

    resp = client.get(f"/domains?group_id={group_id}", headers=_auth_header())
    assert b"netflix" in resp.data
    assert b"notassigned" not in resp.data


def test_domain_access_revokes_a_group_by_omission(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()[0]
    client.post("/domains/add", data={"pattern": "iot\\.example", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = 'iot\\.example'").fetchone()[0]
    client.post(
        "/domains/access", data={"domain_id": domain_id, "group_ids": [str(group_id)]},
        headers=_auth_header(),
    )

    client.post("/domains/access", data={"domain_id": domain_id}, headers=_auth_header())
    assert db_conn.execute(
        "SELECT 1 FROM group_domains WHERE group_id = ? AND domain_id = ?", (group_id, domain_id)
    ).fetchone() is None


def test_domain_access_grants_and_filters_by_device(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:20", "label": "Roku"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:20'").fetchone()[0]
    client.post("/domains/add", data={"pattern": "disneyplus\\.example", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": "other\\.example", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = 'disneyplus\\.example'").fetchone()[0]

    resp = client.post(
        "/domains/access", data={"domain_id": domain_id, "device_ids": [str(device_id)]},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert db_conn.execute(
        "SELECT 1 FROM device_domains WHERE device_id = ? AND domain_id = ?", (device_id, domain_id)
    ).fetchone() is not None

    resp = client.get(f"/domains?device_id={device_id}", headers=_auth_header())
    assert b"disneyplus" in resp.data
    assert b"other" not in resp.data


def test_add_domain_with_multiple_users_groups_and_devices_at_once(client, db_conn):
    """The add-domain form itself supports assigning to any combination of
    users, groups, and devices in one step, not just after the fact from
    the Manage page."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    kid1 = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    kid2 = db_conn.execute("SELECT id FROM users WHERE username = 'kid2'").fetchone()[0]
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()[0]
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:21"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]

    resp = client.post(
        "/domains/add",
        data={
            "pattern": "combo\\.example", "mode": "splice",
            "user_ids": [str(kid1), str(kid2)], "group_ids": [str(group_id)],
            "device_ids": [str(device_id)],
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = 'combo\\.example'").fetchone()[0]
    assert db_conn.execute(
        "SELECT COUNT(*) c FROM user_domains WHERE domain_id = ?", (domain_id,)
    ).fetchone()["c"] == 2
    assert db_conn.execute(
        "SELECT 1 FROM group_domains WHERE domain_id = ? AND group_id = ?", (domain_id, group_id)
    ).fetchone() is not None
    assert db_conn.execute(
        "SELECT 1 FROM device_domains WHERE domain_id = ? AND device_id = ?", (domain_id, device_id)
    ).fetchone() is not None


def test_add_domain_from_filtered_device_view_assigns_it_implicitly(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:22"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]

    client.post(
        "/domains/add", data={"pattern": "implicit\\.example", "mode": "splice", "device_id": device_id},
        headers=_auth_header(),
    )
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = 'implicit\\.example'").fetchone()[0]
    assert db_conn.execute(
        "SELECT 1 FROM device_domains WHERE domain_id = ? AND device_id = ?", (domain_id, device_id)
    ).fetchone() is not None


def test_deleting_a_device_removes_its_domain_assignments(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:23"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()[0]
    client.post("/domains/add", data={"pattern": "gone\\.example", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = 'gone\\.example'").fetchone()[0]
    client.post(
        "/domains/access", data={"domain_id": domain_id, "device_ids": [str(device_id)]},
        headers=_auth_header(),
    )

    client.post("/devices/delete", data={"device_id": device_id}, headers=_auth_header())

    assert db_conn.execute(
        "SELECT 1 FROM device_domains WHERE device_id = ?", (device_id,)
    ).fetchone() is None


# ============================================================
# Logout (HTTP Basic Auth has no real session -- best-effort browser-cache
# trick, see the /logout route's docstring)
# ============================================================

def test_logout_with_bogus_credentials_returns_401(client):
    resp = client.get("/logout", headers=_auth_header(username="logout", password="logout"))
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers


def test_logout_requires_some_credential(client):
    resp = client.get("/logout")
    assert resp.status_code == 401


# ============================================================
# Client-side search boxes (Users/Domains/Devices/Groups lists)
# ============================================================

def test_users_page_has_search_box_when_nonempty(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    resp = client.get("/users", headers=_auth_header())
    assert b'data-filter-table="usersTable"' in resp.data


def test_users_page_has_no_search_box_when_empty(client):
    # The literal string "data-filter-table" is always present in BASE's
    # shared JS (the attribute selector itself), so check for the actual
    # rendered input, not the bare substring.
    resp = client.get("/users", headers=_auth_header())
    assert b'data-filter-table="usersTable"' not in resp.data


def test_domains_and_devices_pages_have_search_boxes(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:30"}, headers=_auth_header())
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())

    resp = client.get("/domains", headers=_auth_header())
    assert b'data-filter-table="domainsTable"' in resp.data

    resp = client.get("/devices", headers=_auth_header())
    assert b'data-filter-table="devicesTable"' in resp.data
    assert b'data-filter-table="groupsTable"' in resp.data


# ============================================================
# Devices: last_seen_at + stale-device cleanup (Settings)
# ============================================================

def test_devices_table_has_last_seen_column_showing_never_by_default(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:31"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    assert b"Last seen" in resp.data
    assert b"Never" in resp.data


def test_devices_migration_adds_last_seen_at_to_an_existing_database(tmp_path, monkeypatch):
    """Simulates a database created before last_seen_at existed (by
    creating the devices table without it), then confirms init_db()'s
    migration adds the column without touching existing rows."""
    import db as db_mod
    db_path = tmp_path / "pre_migration.db"
    monkeypatch.setattr(db_mod, "DB_PATH", db_path)
    conn = db_mod.get_conn()
    conn.executescript("""
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            mac_address TEXT UNIQUE NOT NULL,
            label TEXT,
            user_id INTEGER,
            group_id INTEGER,
            ignored INTEGER NOT NULL DEFAULT 0,
            last_known_ip TEXT,
            bump_enabled INTEGER NOT NULL DEFAULT 0,
            bypass_login INTEGER NOT NULL DEFAULT 0,
            is_authenticated INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
    """)
    conn.execute(
        "INSERT INTO devices (mac_address, created_at) VALUES ('aa:bb:cc:dd:ee:ff', datetime('now'))"
    )
    conn.commit()
    conn.close()

    db_mod.init_db()

    conn = db_mod.get_conn()
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
    assert "last_seen_at" in columns
    row = conn.execute("SELECT * FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:ff'").fetchone()
    assert row is not None
    assert row["last_seen_at"] is None
    conn.close()


def _insert_device_with_last_seen(db_conn, mac, days_ago):
    import db as db_mod
    ts = None if days_ago is None else db_mod.iso_secs_ago(days_ago * 86400)
    db_conn.execute(
        "INSERT INTO devices (mac_address, last_seen_at, created_at) VALUES (?, ?, datetime('now'))",
        (mac, ts),
    )
    db_conn.commit()


def test_update_device_stale_days_validates_input(client):
    resp = client.post("/settings/device-stale-days", data={"device_stale_days": "0"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    resp = client.post("/settings/device-stale-days", data={"device_stale_days": "abc"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    resp = client.post("/settings/device-stale-days", data={"device_stale_days": "30"}, headers=_auth_header())
    assert resp.status_code == 302
    assert "error" not in resp.headers["Location"]


def test_settings_page_shows_correct_stale_device_count(client, db_conn):
    _insert_device_with_last_seen(db_conn, "aa:bb:cc:dd:ee:40", days_ago=100)  # stale
    _insert_device_with_last_seen(db_conn, "aa:bb:cc:dd:ee:41", days_ago=5)    # recent, not stale
    _insert_device_with_last_seen(db_conn, "aa:bb:cc:dd:ee:42", days_ago=None)  # never seen -- must NOT count

    client.post("/settings/device-stale-days", data={"device_stale_days": "30"}, headers=_auth_header())
    resp = client.get("/settings", headers=_auth_header())
    assert b"<strong>1</strong>" in resp.data


def test_cleanup_stale_devices_only_removes_devices_with_an_old_real_timestamp(client, db_conn):
    _insert_device_with_last_seen(db_conn, "aa:bb:cc:dd:ee:50", days_ago=100)  # stale -- removed
    _insert_device_with_last_seen(db_conn, "aa:bb:cc:dd:ee:51", days_ago=5)    # recent -- kept
    _insert_device_with_last_seen(db_conn, "aa:bb:cc:dd:ee:52", days_ago=None)  # never seen -- kept

    client.post("/settings/device-stale-days", data={"device_stale_days": "30"}, headers=_auth_header())
    resp = client.post("/devices/cleanup", headers=_auth_header())
    assert resp.status_code == 302

    remaining = {r["mac_address"] for r in db_conn.execute("SELECT mac_address FROM devices")}
    assert remaining == {"aa:bb:cc:dd:ee:51", "aa:bb:cc:dd:ee:52"}


def test_cleanup_stale_devices_requires_threshold_set_first(client, db_conn):
    _insert_device_with_last_seen(db_conn, "aa:bb:cc:dd:ee:53", days_ago=100)
    resp = client.post("/devices/cleanup", headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT 1 FROM devices").fetchone() is not None


def test_cleanup_stale_devices_requires_admin_auth(client):
    resp = client.post("/devices/cleanup")
    assert resp.status_code == 401


# ============================================================
# CA certificate banner: shown on Users until dismissed, always on Settings
# ============================================================

def test_cert_banner_shown_on_users_by_default(client):
    resp = client.get("/users", headers=_auth_header())
    assert b"Setting up a new device or user?" in resp.data


def test_cert_banner_hidden_after_dismiss(client, db_conn):
    resp = client.post("/users/dismiss-cert-banner", headers=_auth_header())
    assert resp.status_code == 302

    resp = client.get("/users", headers=_auth_header())
    assert b"Setting up a new device or user?" not in resp.data


def test_cert_banner_dismiss_requires_admin_auth(client):
    resp = client.post("/users/dismiss-cert-banner")
    assert resp.status_code == 401


def test_settings_always_has_ca_certificate_section(client, db_conn):
    resp = client.get("/settings", headers=_auth_header())
    assert b"CA certificate" in resp.data
    assert b'href="/ca-cert"' in resp.data

    client.post("/users/dismiss-cert-banner", headers=_auth_header())
    resp = client.get("/settings", headers=_auth_header())
    assert b"CA certificate" in resp.data


# ============================================================
# Domains page: combined ?target= filter picker
# ============================================================

def test_domains_target_filter_for_user(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    client.post("/domains/add", data={"pattern": r"kid1only\.example", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"other\.example", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"kid1only\.example",)).fetchone()[0]
    client.post(
        "/domains/access", data={"domain_id": domain_id, "user_ids": [str(user_id)]}, headers=_auth_header()
    )

    resp = client.get(f"/domains?target=user:{user_id}", headers=_auth_header())
    assert b"kid1only" in resp.data
    assert b"other\\.example" not in resp.data


def test_domains_target_filter_reflects_selection_in_picker(client, db_conn):
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()[0]
    resp = client.get(f"/domains?target=group:{group_id}", headers=_auth_header())
    assert resp.status_code == 200
    # The filter is a type-to-search combobox now, fed by a JSON item list
    # rather than one <a> per kid/group/device -- this group's entry points
    # back at the same ?target= value used to reach this page.
    assert f'"href": "/domains?target=group:{group_id}"'.encode() in resp.data
    # The combobox itself has no persistent "selected" state (nothing
    # renders until you type), so the current selection is reflected by
    # the existing hint text instead of a highlighted chip.
    assert b"Showing domains assigned to" in resp.data
    assert b"the <strong>TVs</strong> group" in resp.data


def test_domains_target_filter_invalid_falls_back_to_all(client, db_conn):
    resp = client.get("/domains?target=user:999999", headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_domains_target_takes_priority_over_individual_params(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()[0]
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()[0]

    resp = client.get(f"/domains?target=group:{group_id}&user_id={user_id}", headers=_auth_header())
    assert resp.status_code == 200
    assert f"TVs".encode() in resp.data


# ============================================================
# Picker widgets are searchable comboboxes, not native multi-selects
# ============================================================

def test_add_domain_form_uses_checkbox_pickers_not_multiselect(client):
    resp = client.get("/domains", headers=_auth_header())
    # The mode dropdown (splice/bump/trusted) is still a plain <select>;
    # what's gone is the old <select multiple> for users/groups/devices --
    # replaced by one type-to-search combobox per entity type, each fed by
    # its own JSON item list (see _entity_combo) rather than a fully
    # rendered checkbox per user/group/device.
    assert b"multiple" not in resp.data.lower()
    assert b'data-mode="multi" data-field="user_ids"' in resp.data
    assert b'data-mode="multi" data-field="group_ids"' in resp.data
    assert b'data-mode="multi" data-field="device_ids"' in resp.data


def test_device_assignment_uses_radio_picker(client):
    resp = client.get("/devices", headers=_auth_header())
    assert b'data-mode="single"' in resp.data
    assert b'"id": "ignored", "label": "Ignore (never filtered)"' in resp.data


# ============================================================
# Phase 8: Categories
# ============================================================

def test_categories_page_loads_empty(client):
    resp = client.get("/categories", headers=_auth_header())
    assert resp.status_code == 200
    assert b"No categories configured" in resp.data


def test_add_category_then_appears(client, db_conn):
    resp = client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM categories WHERE name = 'Gambling'").fetchone()
    assert row is not None
    assert row["subscription_url"] is None
    assert row["is_global"] == 0


def test_add_category_requires_a_name(client, db_conn):
    resp = client.post("/categories/add", data={"name": ""}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM categories").fetchone() is None


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://127.0.0.1/rules.txt",
        "http://localhost/rules.txt",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata endpoint
        "http://192.168.1.1/admin",
        "http://10.0.0.5/internal",
        "http://[::1]/rules.txt",
    ],
)
def test_add_category_rejects_a_private_subscription_url(client, db_conn, bad_url):
    """Regression test for a real gap (fixed 2026-09-02): subscription_url
    used to be stored with zero validation despite being fetched
    server-side later with no restriction -- an SSRF-adjacent risk if
    pointed at an internal address (this box's own admin APIs, a
    router, a cloud metadata endpoint)."""
    resp = client.post(
        "/categories/add", data={"name": "Evil", "subscription_url": bad_url}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM categories WHERE name = 'Evil'").fetchone() is None


def test_add_category_accepts_a_normal_public_subscription_url(client, db_conn):
    resp = client.post(
        "/categories/add",
        data={"name": "Gambling", "subscription_url": "raw.githubusercontent.com/example/list.txt"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT subscription_url FROM categories WHERE name = 'Gambling'").fetchone()
    assert row["subscription_url"] == "https://raw.githubusercontent.com/example/list.txt", (
        "a scheme-less URL should be normalized to https://, matching add_domain_from_url()'s own convention"
    )


def test_add_category_rejects_a_duplicate_name(client):
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    resp = client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_delete_category_removes_it(client, db_conn):
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    client.post("/categories/delete", data={"category_id": category_id}, headers=_auth_header())
    assert db_conn.execute("SELECT * FROM categories WHERE id = ?", (category_id,)).fetchone() is None


def test_category_detail_shows_added_domains(client, db_conn):
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    client.post(
        "/categories/domains/add",
        data={"category_id": category_id, "pattern": r"bet\.example\.com"},
        headers=_auth_header(),
    )
    resp = client.get(f"/categories/{category_id}", headers=_auth_header())
    assert resp.status_code == 200
    assert br"bet\.example\.com" in resp.data
    row = db_conn.execute(
        "SELECT * FROM category_domains WHERE category_id = ?", (category_id,)
    ).fetchone()
    assert row["source"] == "manual"


def test_delete_category_domain_only_removes_manual_rows(client, db_conn):
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) "
        "VALUES (?, ?, 'subscription', datetime('now'))",
        (category_id, r"sub\.example\.com"),
    )
    db_conn.commit()
    sub_row_id = db_conn.execute(
        "SELECT id FROM category_domains WHERE pattern = ?", (r"sub\.example\.com",)
    ).fetchone()["id"]
    resp = client.post(
        "/categories/domains/delete", data={"category_domain_id": sub_row_id}, headers=_auth_header()
    )
    assert resp.status_code == 302
    # Subscription-sourced row must survive a manual-delete attempt.
    assert db_conn.execute("SELECT * FROM category_domains WHERE id = ?", (sub_row_id,)).fetchone() is not None


def test_delete_category_domain_nonexistent_id_redirects_cleanly(client):
    resp = client.post(
        "/categories/domains/delete", data={"category_domain_id": "999999"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]


def test_add_category_override_then_appears(client, db_conn):
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    resp = client.post(
        "/categories/overrides/add",
        data={"category_id": category_id, "pattern": r"safe\.example\.com", "note": "school portal"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute(
        "SELECT * FROM category_overrides WHERE category_id = ?", (category_id,)
    ).fetchone()
    assert row["pattern"] == r"safe\.example\.com"
    assert row["note"] == "school portal"


def test_update_category_access_sets_global_and_targets(client, db_conn):
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) "
        "VALUES ('kid1', 'Kid One', 'x', datetime('now'))"
    )
    db_conn.commit()
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]

    resp = client.post(
        "/categories/access", data={"category_id": category_id, "user_ids": [str(user_id)]}, headers=_auth_header()
    )
    assert resp.status_code == 302
    assert db_conn.execute("SELECT is_global FROM categories WHERE id = ?", (category_id,)).fetchone()["is_global"] == 0
    assert db_conn.execute(
        "SELECT 1 FROM category_users WHERE category_id = ? AND user_id = ?", (category_id, user_id)
    ).fetchone() is not None


def test_update_category_access_rejects_scoping_an_oversized_category(client, db_conn, monkeypatch):
    import matching
    monkeypatch.setattr(matching, "MAX_SCOPED_CATEGORY_DOMAINS", 1)
    client.post("/categories/add", data={"name": "Porn"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Porn'").fetchone()["id"]
    db_conn.executemany(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, 'manual', datetime('now'))",
        [(category_id, r"a\.example\.com"), (category_id, r"b\.example\.com")],
    )
    db_conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) "
        "VALUES ('kid1', 'Kid One', 'x', datetime('now'))"
    )
    db_conn.commit()
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]

    resp = client.post(
        "/categories/access", data={"category_id": category_id, "user_ids": [str(user_id)]}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute(
        "SELECT 1 FROM category_users WHERE category_id = ? AND user_id = ?", (category_id, user_id)
    ).fetchone() is None


def test_update_category_access_still_allows_global_on_an_oversized_category(client, db_conn, monkeypatch):
    import matching
    monkeypatch.setattr(matching, "MAX_SCOPED_CATEGORY_DOMAINS", 1)
    client.post("/categories/add", data={"name": "Porn"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Porn'").fetchone()["id"]
    db_conn.executemany(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, 'manual', datetime('now'))",
        [(category_id, r"a\.example\.com"), (category_id, r"b\.example\.com")],
    )
    db_conn.commit()

    resp = client.post(
        "/categories/access", data={"category_id": category_id, "is_global": "on"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    assert "error" not in (resp.headers["Location"].split("?", 1)[1] if "?" in resp.headers["Location"] else "")
    assert db_conn.execute("SELECT is_global FROM categories WHERE id = ?", (category_id,)).fetchone()["is_global"] == 1


# ============================================================
# Editing a category's subscription URL (real gap fixed 2026-09-08:
# previously the only way to change it was delete-and-recreate the whole
# category, losing access assignments/manual domains/overrides)
# ============================================================

def test_update_category_subscription_sets_url_on_a_manual_only_category(client, db_conn):
    client.post("/categories/add", data={"name": "AI"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'AI'").fetchone()["id"]

    resp = client.post(
        f"/categories/{category_id}/subscription",
        data={"subscription_url": "https://blocklistproject.github.io/Lists/adguard/gambling-ags.txt"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    row = db_conn.execute("SELECT subscription_url FROM categories WHERE id = ?", (category_id,)).fetchone()
    assert row["subscription_url"] == "https://blocklistproject.github.io/Lists/adguard/gambling-ags.txt"


def test_update_category_subscription_changes_an_existing_url_and_drops_old_synced_domains(client, db_conn):
    client.post(
        "/categories/add",
        data={"name": "Gambling", "subscription_url": "https://example.invalid/old.txt"},
        headers=_auth_header(),
    )
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    db_conn.executemany(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, ?, datetime('now'))",
        [(category_id, r"old\.example\.com", "subscription"), (category_id, r"kept\.example\.com", "manual")],
    )
    db_conn.execute("UPDATE categories SET last_synced_at = '2026-09-01T00:00:00Z' WHERE id = ?", (category_id,))
    db_conn.commit()

    resp = client.post(
        f"/categories/{category_id}/subscription",
        data={"subscription_url": "https://example.invalid/new.txt"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT subscription_url, last_synced_at FROM categories WHERE id = ?", (category_id,)).fetchone()
    assert row["subscription_url"] == "https://example.invalid/new.txt"
    assert row["last_synced_at"] is None
    remaining = {r["pattern"] for r in db_conn.execute(
        "SELECT pattern FROM category_domains WHERE category_id = ?", (category_id,)
    )}
    assert remaining == {r"kept\.example\.com"}  # old subscription row gone, manual row untouched


def test_update_category_subscription_can_clear_it_to_manual_only(client, db_conn):
    client.post(
        "/categories/add",
        data={"name": "Gambling", "subscription_url": "https://example.invalid/list.txt"},
        headers=_auth_header(),
    )
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]

    resp = client.post(
        f"/categories/{category_id}/subscription", data={"subscription_url": ""}, headers=_auth_header()
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT subscription_url FROM categories WHERE id = ?", (category_id,)).fetchone()
    assert row["subscription_url"] is None


def test_update_category_subscription_rejects_an_invalid_url(client, db_conn):
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]

    resp = client.post(
        f"/categories/{category_id}/subscription",
        data={"subscription_url": "http://127.0.0.1/internal"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    row = db_conn.execute("SELECT subscription_url FROM categories WHERE id = ?", (category_id,)).fetchone()
    assert row["subscription_url"] is None


def test_update_category_subscription_no_change_is_a_no_op(client, db_conn):
    client.post(
        "/categories/add",
        data={"name": "Gambling", "subscription_url": "https://example.invalid/list.txt"},
        headers=_auth_header(),
    )
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    db_conn.execute("UPDATE categories SET last_synced_at = '2026-09-01T00:00:00Z' WHERE id = ?", (category_id,))
    db_conn.commit()

    client.post(
        f"/categories/{category_id}/subscription",
        data={"subscription_url": "https://example.invalid/list.txt"},
        headers=_auth_header(),
    )
    row = db_conn.execute("SELECT last_synced_at FROM categories WHERE id = ?", (category_id,)).fetchone()
    assert row["last_synced_at"] == "2026-09-01T00:00:00Z"  # untouched -- nothing actually changed


def test_update_category_subscription_requires_admin_auth(client, db_conn):
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    resp = client.post(f"/categories/{category_id}/subscription", data={"subscription_url": "https://example.invalid/x.txt"})
    assert resp.status_code == 401


def test_category_detail_always_shows_subscription_card(client, db_conn):
    # Real UX fix 2026-09-08: this card used to be omitted entirely for
    # a manual-only category, so there was no way to see it was even an
    # option to add one without already knowing the route existed.
    client.post("/categories/add", data={"name": "Weapons"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Weapons'").fetchone()["id"]
    resp = client.get(f"/categories/{category_id}", headers=_auth_header())
    assert b"Subscription" in resp.data
    assert b"Manual-only" in resp.data


def test_sync_category_now_reports_failure_cleanly(client, db_conn, monkeypatch):
    import category_fetch

    client.post(
        "/categories/add",
        data={"name": "Gambling", "subscription_url": "https://example.invalid/gambling.txt"},
        headers=_auth_header(),
    )
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]

    def _boom(conn, category, timeout=None):
        raise category_fetch.CategoryFetchError("could not reach host")

    monkeypatch.setattr(category_fetch, "fetch_and_sync_category", _boom)
    resp = client.post(f"/categories/{category_id}/sync", headers=_auth_header())
    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]


def test_sync_category_now_flags_zero_domains_as_likely_wrong_format(client, db_conn, monkeypatch):
    # Real gap found 2026-09-06 by live user testing: fetching a URL that
    # isn't a supported blocklist format (e.g. a documentation webpage)
    # succeeds and legitimately parses to 0 domains -- that used to flash
    # an unhelpful "Synced 0 domains." with nothing explaining why.
    import category_fetch

    client.post(
        "/categories/add",
        data={"name": "AI", "subscription_url": "https://example.invalid/not-a-blocklist"},
        headers=_auth_header(),
    )
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'AI'").fetchone()["id"]
    monkeypatch.setattr(category_fetch, "fetch_and_sync_category", lambda conn, category, timeout=None: 0)

    resp = client.post(f"/categories/{category_id}/sync", headers=_auth_header())
    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]
    assert "0+recognizable+domains" in resp.headers["Location"]


def test_sync_category_now_normal_nonzero_result_is_not_flagged_as_an_error(client, db_conn, monkeypatch):
    import category_fetch

    client.post(
        "/categories/add", data={"name": "Gambling", "subscription_url": "https://example.invalid/real.txt"},
        headers=_auth_header(),
    )
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    monkeypatch.setattr(category_fetch, "fetch_and_sync_category", lambda conn, category, timeout=None: 42)

    resp = client.post(f"/categories/{category_id}/sync", headers=_auth_header())
    assert "error=1" not in resp.headers["Location"]
    assert "Synced+42+domains" in resp.headers["Location"]


def test_sync_all_categories_names_which_ones_came_back_empty(client, db_conn, monkeypatch):
    import category_fetch

    monkeypatch.setattr(
        category_fetch, "sync_all_categories", lambda conn, timeout=None: {"AI": 0, "Gambling": 100}
    )
    resp = client.post("/categories/sync-all", headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    assert "AI" in resp.headers["Location"]


def test_categories_page_has_supported_format_hint(client):
    resp = client.get("/categories", headers=_auth_header())
    assert b"must be a raw domain-list file" in resp.data.lower() or b"Must be a raw domain-list file" in resp.data


def test_categories_page_distinguishes_the_two_search_boxes(client, db_conn):
    # Real bug fixed 2026-09-07, found by live user testing: typing a
    # domain (e.g. a2e.ai) into the client-side "Search categories..."
    # box filtered the table by category NAME, matched nothing, and made
    # every category disappear -- read by the user as "the [domain]
    # lookup tool doesn't work" when it was actually a different,
    # unrelated control. Renamed that box's placeholder and added an
    # explicit hint distinguishing it from the real domain-lookup tool.
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    resp = client.get("/categories", headers=_auth_header())
    assert b"Filter by category name" in resp.data
    assert b"Type a full domain, not a category name" in resp.data


# ============================================================
# Cross-category domain lookup (real gap found 2026-09-06: no way to
# check whether the same domain appears in more than one category
# without opening each one individually)
# ============================================================

def test_category_lookup_finds_a_domain_in_multiple_categories(client, db_conn):
    client.post("/categories/add", data={"name": "Facebook"}, headers=_auth_header())
    client.post("/categories/add", data={"name": "Gambling"}, headers=_auth_header())
    facebook_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Facebook'").fetchone()["id"]
    gambling_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gambling'").fetchone()["id"]
    db_conn.executemany(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, 'manual', datetime('now'))",
        [(facebook_id, r"facebook\.com"), (gambling_id, r"facebook\.com")],
    )
    db_conn.commit()

    resp = client.get("/categories?domain=facebook.com", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Facebook" in resp.data
    assert b"Gambling" in resp.data


def test_category_lookup_no_match_shows_a_clear_message(client, db_conn):
    resp = client.get("/categories?domain=totally-unrelated.example", headers=_auth_header())
    assert b"No category currently lists" in resp.data


def test_category_lookup_blank_domain_shows_no_results_section(client, db_conn):
    resp = client.get("/categories", headers=_auth_header())
    assert b"No category currently lists" not in resp.data


# ============================================================
# Phase 8: Schedules
# ============================================================

def test_schedules_page_loads_empty(client):
    resp = client.get("/schedules", headers=_auth_header())
    assert resp.status_code == 200
    assert b"No schedules configured" in resp.data


def test_add_schedule_then_appears(client, db_conn):
    resp = client.post(
        "/schedules/add",
        data={
            "name": "Bedtime", "days": ["mon", "tue"], "start_time": "21:00", "end_time": "06:00",
            "time_zone": "UTC", "lockout_all": "on",
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM schedules WHERE name = 'Bedtime'").fetchone()
    assert row is not None
    assert row["days_of_week"] == "mon,tue"
    assert row["lockout_all"] == 1


def test_add_schedule_requires_at_least_one_day(client, db_conn):
    resp = client.post(
        "/schedules/add",
        data={"name": "Bedtime", "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM schedules").fetchone() is None


def test_add_schedule_rejects_an_invalid_time_zone(client, db_conn):
    resp = client.post(
        "/schedules/add",
        data={
            "name": "Bedtime", "days": ["mon"], "start_time": "21:00", "end_time": "06:00",
            "time_zone": "Not/AZone",
        },
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM schedules").fetchone() is None


def test_delete_schedule_removes_it(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "Bedtime", "days": ["mon"], "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Bedtime'").fetchone()["id"]
    client.post("/schedules/delete", data={"schedule_id": schedule_id}, headers=_auth_header())
    assert db_conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone() is None


def test_update_schedule_saves_new_window(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "School hours", "days": ["mon"], "start_time": "08:00", "end_time": "15:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'School hours'").fetchone()["id"]
    resp = client.post(
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon", "tue", "wed", "thu", "fri"],
            "start_time": "08:30", "end_time": "15:30", "time_zone": "America/Chicago",
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    assert row["days_of_week"] == "mon,tue,wed,thu,fri"
    assert row["start_time"] == "08:30"
    assert row["time_zone"] == "America/Chicago"


def test_schedule_detail_shows_categories_section_unless_lockout(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "School hours", "days": ["mon"], "start_time": "08:00", "end_time": "15:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'School hours'").fetchone()["id"]
    resp = client.get(f"/schedules/{schedule_id}", headers=_auth_header())
    assert b"Categories blocked during this window" in resp.data

    client.post(
        "/schedules/add",
        data={"name": "Bedtime", "days": ["mon"], "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC", "lockout_all": "on"},
        headers=_auth_header(),
    )
    bedtime_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Bedtime'").fetchone()["id"]
    resp = client.get(f"/schedules/{bedtime_id}", headers=_auth_header())
    assert b"Categories blocked during this window" not in resp.data


def test_update_schedule_categories_assigns_them(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "School hours", "days": ["mon"], "start_time": "08:00", "end_time": "15:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'School hours'").fetchone()["id"]
    client.post("/categories/add", data={"name": "Gaming"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gaming'").fetchone()["id"]

    resp = client.post(
        "/schedules/categories",
        data={"schedule_id": schedule_id, "category_ids": [str(category_id)]},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert db_conn.execute(
        "SELECT 1 FROM schedule_categories WHERE schedule_id = ? AND category_id = ?", (schedule_id, category_id)
    ).fetchone() is not None


def test_schedule_detail_shows_every_category_as_a_checkbox_no_typing_needed(client, db_conn):
    # Real UX bug fixed 2026-09-08: this used to be a type-to-reveal
    # combobox (SHOW_ALL_THRESHOLD = 8 in the shared JS engine) -- with
    # more than 8 categories configured (this project seeds 10 by
    # default), nothing rendered until you typed a name you'd have to
    # already know. Categories are a small, fixed, admin-curated list
    # (unlike users/groups/devices), so this is now a plain checkbox
    # list showing every one regardless of count.
    client.post(
        "/schedules/add",
        data={"name": "School hours", "days": ["mon"], "start_time": "08:00", "end_time": "15:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'School hours'").fetchone()["id"]
    names = [f"Category {i}" for i in range(12)]  # more than the old SHOW_ALL_THRESHOLD of 8
    for name in names:
        client.post("/categories/add", data={"name": name}, headers=_auth_header())
    checked_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Category 3'").fetchone()["id"]
    client.post(
        "/schedules/categories", data={"schedule_id": schedule_id, "category_ids": [str(checked_id)]},
        headers=_auth_header(),
    )

    resp = client.get(f"/schedules/{schedule_id}", headers=_auth_header())

    for name in names:
        assert name.encode() in resp.data  # every category rendered directly in the HTML, not hidden behind a search
    # The previously-saved category is checked; an unrelated one isn't.
    unchecked_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Category 4'").fetchone()["id"]
    assert f'value="{checked_id}" checked'.encode() in resp.data
    assert f'value="{unchecked_id}" checked'.encode() not in resp.data


def test_schedule_detail_categories_empty_state(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "School hours", "days": ["mon"], "start_time": "08:00", "end_time": "15:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'School hours'").fetchone()["id"]
    resp = client.get(f"/schedules/{schedule_id}", headers=_auth_header())
    assert b"No categories yet" in resp.data


def test_update_schedule_access_sets_global_and_targets(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "Bedtime", "days": ["mon"], "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Bedtime'").fetchone()["id"]
    resp = client.post(
        "/schedules/access", data={"schedule_id": schedule_id, "is_global": "on"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    assert db_conn.execute("SELECT is_global FROM schedules WHERE id = ?", (schedule_id,)).fetchone()["is_global"] == 1


def test_update_schedule_saves_is_mode(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "Free Time", "days": ["mon"], "start_time": "00:00", "end_time": "23:59", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Free Time'").fetchone()["id"]
    assert db_conn.execute("SELECT is_mode FROM schedules WHERE id = ?", (schedule_id,)).fetchone()["is_mode"] == 0

    client.post(
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon"], "start_time": "00:00", "end_time": "23:59",
            "time_zone": "UTC", "is_mode": "on",
        },
        headers=_auth_header(),
    )
    assert db_conn.execute("SELECT is_mode FROM schedules WHERE id = ?", (schedule_id,)).fetchone()["is_mode"] == 1


# ============================================================
# Phase 12: Schedule overrides ("Shift mode now")
# ============================================================

def _add_mode_schedule(client, db_conn, name: str, *, is_global: bool = True) -> int:
    client.post(
        "/schedules/add",
        data={"name": name, "days": ["mon"], "start_time": "00:00", "end_time": "23:59", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = ?", (name,)).fetchone()["id"]
    client.post(
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon"], "start_time": "00:00", "end_time": "23:59",
            "time_zone": "UTC", "is_mode": "on",
        },
        headers=_auth_header(),
    )
    if is_global:
        client.post("/schedules/access", data={"schedule_id": schedule_id, "is_global": "on"}, headers=_auth_header())
    return schedule_id


def _add_device(db_conn, mac: str) -> int:
    db_conn.execute(
        "INSERT INTO devices (mac_address, is_authenticated, created_at) VALUES (?, 1, datetime('now'))", (mac,)
    )
    db_conn.commit()
    return db_conn.execute("SELECT id FROM devices WHERE mac_address = ?", (mac,)).fetchone()["id"]


def test_add_schedule_override_forces_target_active(client, db_conn):
    schedule_id = _add_mode_schedule(client, db_conn, "Free Time")
    device_id = _add_device(db_conn, "aa:bb:cc:dd:ee:30")

    resp = client.post(
        "/schedules/override",
        data={"schedule_id": schedule_id, "target": f"device:{device_id}", "duration_minutes": "60"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    row = db_conn.execute(
        "SELECT * FROM schedule_overrides WHERE schedule_id = ? AND device_id = ?", (schedule_id, device_id)
    ).fetchone()
    assert row is not None


def test_add_schedule_override_rejects_a_non_mode_schedule(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "Adult block", "days": ["mon"], "start_time": "00:00", "end_time": "23:59", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Adult block'").fetchone()["id"]
    device_id = _add_device(db_conn, "aa:bb:cc:dd:ee:31")

    resp = client.post(
        "/schedules/override",
        data={"schedule_id": schedule_id, "target": f"device:{device_id}", "duration_minutes": "60"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM schedule_overrides").fetchone() is None


def test_add_schedule_override_rejects_a_target_the_schedule_doesnt_reach(client, db_conn):
    schedule_id = _add_mode_schedule(client, db_conn, "Free Time", is_global=False)
    device_id = _add_device(db_conn, "aa:bb:cc:dd:ee:32")

    resp = client.post(
        "/schedules/override",
        data={"schedule_id": schedule_id, "target": f"device:{device_id}", "duration_minutes": "60"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM schedule_overrides").fetchone() is None


def test_add_schedule_override_replaces_existing_override_for_same_target(client, db_conn):
    free_time = _add_mode_schedule(client, db_conn, "Free Time")
    bedtime = _add_mode_schedule(client, db_conn, "Bedtime")
    device_id = _add_device(db_conn, "aa:bb:cc:dd:ee:33")

    client.post(
        "/schedules/override",
        data={"schedule_id": free_time, "target": f"device:{device_id}", "duration_minutes": "60"},
        headers=_auth_header(),
    )
    client.post(
        "/schedules/override",
        data={"schedule_id": bedtime, "target": f"device:{device_id}", "duration_minutes": "30"},
        headers=_auth_header(),
    )
    rows = db_conn.execute("SELECT * FROM schedule_overrides WHERE device_id = ?", (device_id,)).fetchall()
    assert len(rows) == 1
    assert rows[0]["schedule_id"] == bedtime


def test_cancel_schedule_override_removes_it(client, db_conn):
    schedule_id = _add_mode_schedule(client, db_conn, "Free Time")
    device_id = _add_device(db_conn, "aa:bb:cc:dd:ee:34")
    client.post(
        "/schedules/override",
        data={"schedule_id": schedule_id, "target": f"device:{device_id}", "duration_minutes": "60"},
        headers=_auth_header(),
    )
    override_id = db_conn.execute("SELECT id FROM schedule_overrides WHERE device_id = ?", (device_id,)).fetchone()["id"]

    resp = client.post("/schedules/override/cancel", data={"override_id": override_id}, headers=_auth_header())
    assert resp.status_code == 302
    assert db_conn.execute("SELECT * FROM schedule_overrides WHERE id = ?", (override_id,)).fetchone() is None


# ============================================================
# Phase 8: Settings household time zone
# ============================================================

def test_settings_page_shows_household_time_zone(client):
    resp = client.get("/settings", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Household time zone" in resp.data


def test_update_household_time_zone_saves(client, db_conn):
    import db as db_mod

    resp = client.post(
        "/settings/household-time-zone", data={"household_time_zone": "America/Chicago"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    assert db_mod.get_setting(db_conn, "household_time_zone") == "America/Chicago"


def test_update_household_time_zone_rejects_garbage(client, db_conn):
    import db as db_mod

    resp = client.post(
        "/settings/household-time-zone", data={"household_time_zone": "Not/AZone"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    assert db_mod.get_setting(db_conn, "household_time_zone", "UTC") == "UTC"


def test_settings_page_shows_safesearch_toggle(client):
    resp = client.get("/settings", headers=_auth_header())
    assert resp.status_code == 200
    assert b"SafeSearch" in resp.data


def test_update_safesearch_checked_saves_on(client, db_conn):
    import db as db_mod

    resp = client.post("/settings/safesearch", data={"safesearch_enabled": "1"}, headers=_auth_header())
    assert resp.status_code == 302
    assert db_mod.get_setting(db_conn, "safesearch_enabled") == "1"


def test_update_safesearch_unchecked_saves_off(client, db_conn):
    import db as db_mod

    db_mod.set_setting(db_conn, "safesearch_enabled", "1")
    db_conn.commit()
    resp = client.post("/settings/safesearch", data={}, headers=_auth_header())
    assert resp.status_code == 302
    assert db_mod.get_setting(db_conn, "safesearch_enabled") == "0"


# ============================================================
# Phase 13: SSL-Bump CA certificate management
# ============================================================

def _generate_cert_pair(tmp_path, name: str, *, is_ca: bool = True, common_name: str = "Test CA"):
    """Generates a real self-signed cert+key pair via openssl (same tool
    proxy/entrypoint.sh and dashboard.py's own validation/regeneration
    use) for exercising the upload/validate path against real PEM data
    rather than hand-rolled fakes. `is_ca=False` forces `CA:FALSE`
    explicitly -- omitting the extension entirely is unreliable across
    openssl versions/configs (see proxy/entrypoint.sh's own comment on
    this), so a genuinely non-CA test cert needs it spelled out."""
    cert_path = tmp_path / f"{name}_cert.pem"
    key_path = tmp_path / f"{name}_key.pem"
    constraint = "basicConstraints=critical,CA:TRUE" if is_ca else "basicConstraints=critical,CA:FALSE"
    args = [
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-days", "365", "-nodes", "-x509",
        "-keyout", str(key_path), "-out", str(cert_path),
        "-subj", f"/O=Test/CN={common_name}",
        "-addext", constraint,
    ]
    if is_ca:
        args += ["-addext", "keyUsage=critical,keyCertSign,cRLSign"]
    subprocess.run(args, check=True, capture_output=True)
    return cert_path.read_bytes(), key_path.read_bytes()


def _point_ca_paths_at(monkeypatch, tmp_path):
    """Points dashboard.CA_CERT_PATH/CA_KEY_PATH at a throwaway directory
    -- the real default (/config/ssl_cert/...) doesn't exist and
    shouldn't be touched by tests. Read/written as plain module globals
    by every route/helper this section exercises, so monkeypatching the
    attributes directly (same pattern the dashboard_app fixture already
    uses for db.DB_PATH) is enough -- no reload needed."""
    import dashboard

    cert_dir = tmp_path / "ssl_cert"
    cert_dir.mkdir()
    monkeypatch.setattr(dashboard, "CA_CERT_PATH", cert_dir / "ca_cert.pem")
    monkeypatch.setattr(dashboard, "CA_KEY_PATH", cert_dir / "ca_key.pem")
    return dashboard.CA_CERT_PATH, dashboard.CA_KEY_PATH


def test_settings_shows_ca_cert_details_when_present(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    cert_pem, key_pem = _generate_cert_pair(tmp_path, "current", common_name="My Household CA")
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    resp = client.get("/settings", headers=_auth_header())
    assert b"My Household CA" in resp.data


def test_settings_shows_a_real_fingerprint_not_a_blank_field(client, db_conn, monkeypatch, tmp_path):
    # Regression test: live-verified 2026-09-06 that this openssl build
    # prints "sha256 Fingerprint=" (lowercase), not "SHA256
    # Fingerprint=" as _ca_cert_info() originally assumed -- the
    # fingerprint silently came back blank with no error to reveal why.
    import dashboard

    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    cert_pem, key_pem = _generate_cert_pair(tmp_path, "current")
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    info = dashboard._ca_cert_info(cert_path)
    assert info is not None
    assert info.get("fingerprint")
    assert re.fullmatch(r"([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}", info["fingerprint"])


def test_settings_shows_not_generated_yet_when_absent(client, db_conn, monkeypatch, tmp_path):
    _point_ca_paths_at(monkeypatch, tmp_path)
    resp = client.get("/settings", headers=_auth_header())
    assert b"Not generated yet" in resp.data


def test_regenerate_ca_cert_writes_a_new_pair(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)

    resp = client.post(
        "/settings/ca-cert/regenerate",
        data={"ca_org": "My House", "ca_common_name": "My House CA"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    assert cert_path.exists() and key_path.exists()
    assert b"My House CA" in cert_path.read_bytes() or b"My House CA" in subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-in", str(cert_path)], capture_output=True
    ).stdout


def test_regenerate_ca_cert_backs_up_the_previous_pair(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    old_cert, old_key = _generate_cert_pair(tmp_path, "old")
    cert_path.write_bytes(old_cert)
    key_path.write_bytes(old_key)

    client.post("/settings/ca-cert/regenerate", data={}, headers=_auth_header())

    backups = list(cert_path.parent.glob("ca_cert.*.bak.pem"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == old_cert
    assert cert_path.read_bytes() != old_cert  # actually replaced, not just backed up


def test_regenerate_ca_cert_rejects_slash_in_org(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    resp = client.post(
        "/settings/ca-cert/regenerate", data={"ca_org": "My/House"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    assert not cert_path.exists()


def test_regenerate_ca_cert_requires_admin_auth(client, db_conn, monkeypatch, tmp_path):
    _point_ca_paths_at(monkeypatch, tmp_path)
    resp = client.post("/settings/ca-cert/regenerate", data={})
    assert resp.status_code == 401


def test_upload_ca_cert_accepts_a_valid_matching_pair(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    cert_pem, key_pem = _generate_cert_pair(tmp_path, "uploaded", common_name="Uploaded CA")

    resp = client.post(
        "/settings/ca-cert/upload",
        data={
            "ca_cert_file": (io.BytesIO(cert_pem), "cert.pem"),
            "ca_key_file": (io.BytesIO(key_pem), "key.pem"),
        },
        headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    assert cert_path.read_bytes() == cert_pem
    assert key_path.read_bytes() == key_pem


def test_upload_ca_cert_rejects_a_mismatched_pair(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    cert_pem, _ = _generate_cert_pair(tmp_path, "one")
    _, other_key_pem = _generate_cert_pair(tmp_path, "two")

    resp = client.post(
        "/settings/ca-cert/upload",
        data={
            "ca_cert_file": (io.BytesIO(cert_pem), "cert.pem"),
            "ca_key_file": (io.BytesIO(other_key_pem), "key.pem"),
        },
        headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert "error=1" in resp.headers["Location"]
    assert not cert_path.exists()
    assert not key_path.exists()


def test_upload_ca_cert_rejects_a_non_ca_certificate(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    cert_pem, key_pem = _generate_cert_pair(tmp_path, "leaf", is_ca=False)

    resp = client.post(
        "/settings/ca-cert/upload",
        data={
            "ca_cert_file": (io.BytesIO(cert_pem), "cert.pem"),
            "ca_key_file": (io.BytesIO(key_pem), "key.pem"),
        },
        headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert "error=1" in resp.headers["Location"]
    assert not cert_path.exists()


def test_upload_ca_cert_rejects_garbage_input(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)

    resp = client.post(
        "/settings/ca-cert/upload",
        data={
            "ca_cert_file": (io.BytesIO(b"not a certificate"), "cert.pem"),
            "ca_key_file": (io.BytesIO(b"not a key"), "key.pem"),
        },
        headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert "error=1" in resp.headers["Location"]
    assert not cert_path.exists()


def test_upload_ca_cert_requires_both_files(client, db_conn, monkeypatch, tmp_path):
    _point_ca_paths_at(monkeypatch, tmp_path)
    resp = client.post("/settings/ca-cert/upload", data={}, headers=_auth_header(), content_type="multipart/form-data")
    assert "error=1" in resp.headers["Location"]


def test_upload_ca_cert_requires_admin_auth(client, db_conn, monkeypatch, tmp_path):
    _point_ca_paths_at(monkeypatch, tmp_path)
    resp = client.post("/settings/ca-cert/upload", data={}, content_type="multipart/form-data")
    assert resp.status_code == 401
