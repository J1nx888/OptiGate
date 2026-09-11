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
import json
import re
import subprocess
import zipfile

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


# ============================================================
# Domains toolbar: Download/Delete/Manage access (Entra-style buttons,
# added 2026-09-07 -- closing the last gap in the toolbar redesign already
# applied to Devices/Users/Categories/Schedules; RoadMap.md's dated entry)
# ============================================================

def test_domains_page_has_toolbar_with_download_delete_and_manage_access(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    resp = client.get("/domains", headers=_auth_header())
    assert resp.status_code == 200
    assert b'id="domainBulkToolbar"' in resp.data
    assert b'href="/domains/export"' in resp.data
    assert b'action="/domains/bulk-delete"' in resp.data
    assert b'id="domainBulkManageToggle"' in resp.data
    # The old <details> disclosure this replaced should be gone.
    assert b'<details id="domainBulkAccess">' not in resp.data


def test_bulk_delete_domains_removes_every_selected_domain(client, db_conn):
    client.post("/domains/add", data={"pattern": r"a\.example\.com", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"b\.example\.com", "mode": "splice"}, headers=_auth_header())
    client.post("/domains/add", data={"pattern": r"c\.example\.com", "mode": "splice"}, headers=_auth_header())
    to_delete = [
        r["id"] for r in db_conn.execute(
            "SELECT id FROM domains WHERE pattern IN (?, ?)", (r"a\.example\.com", r"b\.example\.com")
        )
    ]

    resp = client.post(
        "/domains/bulk-delete", data={"domain_ids": [str(i) for i in to_delete]}, headers=_auth_header()
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/domains")
    remaining = {r["pattern"] for r in db_conn.execute("SELECT pattern FROM domains")}
    assert remaining == {r"c\.example\.com"}


def test_bulk_delete_domains_without_selection_shows_error(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())

    resp = client.post("/domains/bulk-delete", data={}, headers=_auth_header())

    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT COUNT(*) c FROM domains").fetchone()["c"] == 1


def test_bulk_delete_domains_skips_builtin_crunchyroll_domain(client, db_conn):
    db_conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, note, created_at) "
        "VALUES ('crunchyroll\\.com', 'bump', 'crunchyroll', 1, NULL, datetime('now'))"
    )
    db_conn.commit()
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    ids = [r["id"] for r in db_conn.execute("SELECT id FROM domains")]

    resp = client.post("/domains/bulk-delete", data={"domain_ids": [str(i) for i in ids]}, headers=_auth_header())

    assert resp.status_code == 302
    remaining = db_conn.execute("SELECT kind FROM domains").fetchall()
    assert [r["kind"] for r in remaining] == ["crunchyroll"]


def test_export_domains_csv_includes_every_domain_and_key_fields(client, db_conn):
    client.post(
        "/domains/add",
        data={"pattern": r"example\.com", "mode": "bump", "note": "family site", "is_global": "on"},
        headers=_auth_header(),
    )

    resp = client.get("/domains/export", headers=_auth_header())

    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in resp.headers["Content-Disposition"]
    body = resp.data.decode()
    assert r"example\.com" in body
    assert "bump" in body
    assert "Everyone" in body
    assert "family site" in body


def test_export_domains_csv_requires_admin_auth(client):
    resp = client.get("/domains/export")
    assert resp.status_code == 401


def test_add_path_and_delete_path(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "bump"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    client.post(
        "/domains/paths/add", data={"domain_id": domain_id, "pattern": "/ok"}, headers=_auth_header()
    )
    path_row = db_conn.execute("SELECT * FROM domain_paths WHERE domain_id = ?", (domain_id,)).fetchone()
    assert path_row is not None

    client.post("/domains/paths/delete", data={"path_id": path_row["id"]}, headers=_auth_header())
    assert db_conn.execute("SELECT * FROM domain_paths WHERE id = ?", (path_row["id"],)).fetchone() is None


# ============================================================
# add_path(): plain path/URL input, not hand-written regex (changed
# 2026-09-07, RoadMap.md's dated entry -- "the admin can just paste the
# URL and everything after what is pasted is allowed")
# ============================================================

def test_extract_path_from_a_bare_path():
    import dashboard
    assert dashboard._extract_path("/comics/foo") == "/comics/foo"


def test_extract_path_from_a_full_url():
    import dashboard
    assert dashboard._extract_path("https://example.com/comics/foo") == "/comics/foo"


def test_extract_path_from_a_schemeless_host_and_path():
    import dashboard
    assert dashboard._extract_path("example.com/comics/foo") == "/comics/foo"


def test_extract_path_strips_query_string_via_path_to_pattern():
    import dashboard
    assert dashboard._extract_path("/comics/foo?ref=1") == "/comics/foo"


def test_add_path_accepts_a_plain_path_and_matches_it_and_anything_after(client, db_conn):
    """The project owner's own example: pasting a path allows that exact
    path, a real subpath under it, AND a different literal path that
    merely shares the same string prefix (not just a "/" boundary)."""
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "bump"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    client.post(
        "/domains/paths/add",
        data={"domain_id": domain_id, "pattern": "/comics/surviving-the-game-as-a-barbarian"},
        headers=_auth_header(),
    )

    import matching
    assert matching.path_allowed(db_conn, domain_id, "/comics/surviving-the-game-as-a-barbarian") is True
    assert matching.path_allowed(db_conn, domain_id, "/comics/surviving-the-game-as-a-barbarian/what") is True
    assert matching.path_allowed(db_conn, domain_id, "/comics/surviving-the-game-as-a-barbarian-adfasdfasdf") is True
    assert matching.path_allowed(db_conn, domain_id, "/comics/something-else") is False


def test_add_path_accepts_a_full_url_and_extracts_just_the_path(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "bump"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    client.post(
        "/domains/paths/add",
        data={"domain_id": domain_id, "pattern": "https://example.com/discover?ref=homepage"},
        headers=_auth_header(),
    )

    import matching
    assert matching.path_allowed(db_conn, domain_id, "/discover") is True


def test_add_path_escapes_regex_metacharacters_in_the_pasted_path(client, db_conn):
    """A literal dot in a real path (e.g. a filename) must match only
    that literal character, not "any character" -- proves the input is
    actually re.escape()d, not inserted as raw regex."""
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "bump"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    client.post(
        "/domains/paths/add", data={"domain_id": domain_id, "pattern": "/file.json"}, headers=_auth_header()
    )

    import matching
    assert matching.path_allowed(db_conn, domain_id, "/file.json") is True
    assert matching.path_allowed(db_conn, domain_id, "/fileXjson") is False


def test_add_path_blank_input_rejected(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "bump"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"example\.com",)).fetchone()[0]

    resp = client.post(
        "/domains/paths/add", data={"domain_id": domain_id, "pattern": ""}, headers=_auth_header()
    )

    assert "error=1" in resp.headers["Location"]


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
    # RoadMap finding #5 (2026-09-10): the Report page had a Status/Result
    # column all along; the owner's browser was serving a stale cached
    # copy. Every HTML page is now sent no-store so that can't happen.
    assert "no-store" in resp.headers.get("Cache-Control", "")
    assert b"<th>Result</th>" in resp.data


def test_report_times_are_shown_in_the_configured_household_timezone(client, db_conn):
    """Owner bug 2026-09-11: the Report page rendered stored UTC
    timestamps verbatim while Settings had the household on US/Eastern.
    Now the activity table + pending card localise to
    `household_time_zone` and the column header names the zone."""
    import datetime as _dt
    import zoneinfo as _zi
    import db as db_mod

    db_mod.set_setting(db_conn, "household_time_zone", "America/New_York")
    ny = _zi.ZoneInfo("America/New_York")
    utc_dt = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=3)).replace(microsecond=0)
    stored = utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    local = utc_dt.astimezone(ny)

    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) VALUES (?, NULL, 'kid1', 'tzcheck.example', '/', 1, 'global_domain')",
        (stored,),
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert f"Time ({local.strftime('%Z')})" in body       # header names the zone (EST/EDT)
    assert "Time (UTC)" not in body
    assert local.strftime("%H:%M:%S") in body              # localised wall time is rendered
    assert local.strftime("%Y-%m-%d") in body


def test_report_falls_back_to_utc_for_a_bad_timezone_value(client, db_conn):
    import db as db_mod
    db_mod.set_setting(db_conn, "household_time_zone", "Not/ARealZone")
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kid1', 'tzfallback.example', '/', 1, 'global_domain')"
    )
    db_conn.commit()
    resp = client.get("/report", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Time (UTC)" in resp.data  # unrecognised zone -> UTC, page still renders
    assert b"tzfallback.example" in resp.data


def test_html_pages_are_sent_no_store_but_static_assets_are_not(client):
    for path in ("/report", "/devices", "/users", "/settings"):
        cc = client.get(path, headers=_auth_header()).headers.get("Cache-Control", "")
        assert "no-store" in cc, f"{path} should be no-store, got {cc!r}"
    css = client.get("/static/css/app.css")
    assert "no-store" not in css.headers.get("Cache-Control", "")


def test_service_worker_is_revalidated_and_never_caches_navigations(client):
    resp = client.get("/sw.js")
    assert resp.status_code == 200
    assert "no-cache" in resp.headers.get("Cache-Control", "")
    body = resp.get_data(as_text=True)
    # bumped cache version so browsers force-update off any older revision
    assert 'CACHE = "pp-static-v3"' in body
    # the fetch handler must only ever respondWith for /static/ -- a
    # blanket cache-first would let a stale page (finding #5) persist
    assert 'url.pathname.startsWith("/static/")' in body
    assert body.count("event.respondWith") == 1


def test_report_page_shows_which_device_a_blocked_row_came_from(client, db_conn):
    """Real live-testing feedback (RoadMap.md's dated entry): a blocked
    row for an unauthenticated device showed "(unauthenticated)" as its
    User with no way to tell which physical device that actually was --
    access_log.device_id was already there (see log_identity_fields()'s
    own docstring), just never surfaced on this page."""
    device_id = _insert_device(db_conn, "aa:bb:cc:dd:ee:60", label="Kitchen Tablet")
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason, device_id) "
        "VALUES (datetime('now'), NULL, '(unauthenticated)', 'example.com', NULL, 0, 'dns_tier_denied', ?)",
        (device_id,),
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Kitchen Tablet" in resp.data
    assert b"aa:bb:cc:dd:ee:60" in resp.data
    assert f'href="/devices/{device_id}"'.encode() in resp.data


def test_report_page_falls_back_to_raw_ip_for_a_never_recognized_device(client, db_conn):
    """Same live-testing feedback as the test above -- the OTHER half:
    when device_id is NULL (never resolved to any devices row at all,
    not just a deleted one), the raw source IP (RoadMap.md's dated
    entry, access_log.ip_address) is the only thing left to track the
    device down by."""
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason, ip_address) "
        "VALUES (datetime('now'), NULL, '(unauthenticated)', 'netflix.com', NULL, 0, 'dns_tier_denied', ?)",
        ("192.168.1.77",),
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())

    assert resp.status_code == 200
    assert b"192.168.1.77" in resp.data


def test_report_page_explains_why_a_blocked_row_was_blocked(client, db_conn):
    """Real gap found live (RoadMap.md's dated entry, project owner's
    own example: speedtest.net blocked on Matthew's device with no
    indication why). access_log.reason was already populated with a
    real value for essentially every allow/deny decision this project
    makes -- the bug was that the Activity table only ever rendered a
    bare "blocked" badge and never looked at row.reason at all."""
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, '(unauthenticated)', 'netflix.com', NULL, 0, 'unknown_domain')"
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())

    assert resp.status_code == 200
    assert b"not a domain configured anywhere in this system" in resp.data


def test_report_shows_the_show_name_next_to_the_id_from_user_shows(client, db_conn):
    """Owner request 2026-09-11: a blocked Crunchyroll row only carried
    the raw series id (`GRE50KV36`). If ANY user has that show approved,
    its title is already on file in user_shows -- surface it, and
    back-fill the access_log row so it's a one-time lookup."""
    client.post("/users/add", data={"username": "kidA", "password": "pw"}, headers=_auth_header())
    uid = db_conn.execute("SELECT id FROM users WHERE username = 'kidA'").fetchone()[0]
    db_conn.execute(
        "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?, 'GRE50KV36', 'Black Clover')",
        (uid,),
    )
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, series_id, series_name, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kidB', 'www.crunchyroll.com', '/playback/v3/x/web/chrome/play', "
        "'GRE50KV36', NULL, 0, 'show_not_approved')"
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Black Clover" in resp.data
    assert b"GRE50KV36" in resp.data  # id still shown alongside the name
    backfilled = db_conn.execute(
        "SELECT series_name FROM access_log WHERE series_id = 'GRE50KV36'"
    ).fetchone()[0]
    assert backfilled == "Black Clover"


def test_report_resolves_a_show_name_via_cr_api_when_nobody_approved_it(client, db_conn, monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard.cr_api, "series_title", lambda sid, timeout=5.0: "Solo Leveling")
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, series_id, series_name, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kidC', 'www.crunchyroll.com', '/playback/v3/y/web/chrome/play', "
        "'GXYZ12345', NULL, 0, 'show_not_approved')"
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Solo Leveling" in resp.data
    assert db_conn.execute(
        "SELECT series_name FROM access_log WHERE series_id = 'GXYZ12345'"
    ).fetchone()[0] == "Solo Leveling"


def test_report_series_name_lookup_survives_a_cr_api_failure(client, db_conn, monkeypatch):
    import dashboard

    def boom(sid, timeout=5.0):
        raise RuntimeError("CR API down")

    monkeypatch.setattr(dashboard.cr_api, "series_title", boom)
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, series_id, series_name, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kidD', 'www.crunchyroll.com', '/watch/z', 'GNOPE00000', NULL, 0, 'show_not_approved')"
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())
    assert resp.status_code == 200
    assert b"GNOPE00000" in resp.data  # falls back to the bare id, page still renders


def test_report_page_shows_the_raw_reason_code_for_an_unrecognized_value(client, db_conn):
    """_reason_label() falls back to the raw code rather than silently
    hiding an unmapped value -- e.g. a future reason this label map
    hasn't been updated for yet should still show SOMETHING, not
    nothing."""
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, '(unauthenticated)', 'example.com', NULL, 0, 'brand_new_reason_code')"
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())

    assert resp.status_code == 200
    assert b"brand_new_reason_code" in resp.data


def test_report_page_shows_dash_for_a_row_with_no_device(client, db_conn):
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kid1', 'example.com', '/', 1, 'global_domain')"
    )
    db_conn.commit()
    resp = client.get("/report", headers=_auth_header())
    assert resp.status_code == 200


# ============================================================
# Report: routine DNS-tier activity is hidden unless asked for
# (RoadMap.md finding #9, 2026-09-10)
# ============================================================

def test_report_hides_dns_tier_allowed_rows_by_default(client, db_conn):
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kid1', 'routine-site.example', NULL, 1, 'dns_tier_allowed')"
    )
    db_conn.commit()

    resp = client.get("/report", headers=_auth_header())

    assert resp.status_code == 200
    assert b"routine-site.example" not in resp.data


def test_report_show_routine_checkbox_reveals_dns_tier_allowed_rows(client, db_conn):
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kid1', 'routine-site.example', NULL, 1, 'dns_tier_allowed')"
    )
    db_conn.commit()

    resp = client.get("/report?show_routine=1", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "routine-site.example" in body
    assert "routine DNS-tier activity, sampled" in body  # _reason_label() text


def test_report_show_routine_does_not_leak_into_other_status_filters_unexpectedly(client, db_conn):
    """A dns_tier_allowed row is allowed=1 -- confirms it still respects
    the ordinary Blocked/Allowed status filter once revealed, it isn't a
    special third bucket outside that filter."""
    db_conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, path, allowed, reason) "
        "VALUES (datetime('now'), NULL, 'kid1', 'routine-site.example', NULL, 1, 'dns_tier_allowed')"
    )
    db_conn.commit()

    resp = client.get("/report?show_routine=1&status=blocked", headers=_auth_header())

    assert resp.status_code == 200
    assert b"routine-site.example" not in resp.data


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


# ============================================================
# User detail "Assigned sites" pagination -- added 2026-09-07, project
# owner's explicit request: "This includes managing the domains assigned
# to users in the user section too" -- same page-size-picker + Prev/Next
# pattern as Categories/Devices/Domains the same day.
# ============================================================

def test_user_detail_assigned_sites_paginates_with_a_default_page_size(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    for i in range(60):
        client.post(
            "/domains/add", data={"pattern": f"site{i:04d}\\.example", "mode": "splice"}, headers=_auth_header()
        )
    domain_ids = [r["id"] for r in db_conn.execute("SELECT id FROM domains")]
    client.post(
        "/domains/bulk-access",
        data={"domain_ids": [str(i) for i in domain_ids], "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Assigned sites (60)" in body
    assert "Page 1 of 2" in body
    assert "showing 1-50 of 60" in body


def test_user_detail_assigned_sites_second_page_shows_the_rest(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    for i in range(60):
        client.post(
            "/domains/add", data={"pattern": f"site{i:04d}\\.example", "mode": "splice"}, headers=_auth_header()
        )
    domain_ids = [r["id"] for r in db_conn.execute("SELECT id FROM domains")]
    client.post(
        "/domains/bulk-access",
        data={"domain_ids": [str(i) for i in domain_ids], "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )

    resp = client.get(f"/users/{user_id}?page=2", headers=_auth_header())

    assert resp.status_code == 200
    assert "Page 2 of 2" in resp.data.decode()


def test_user_detail_assigned_sites_small_list_shows_no_pagination_controls(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains").fetchone()["id"]
    client.post(
        "/domains/access", data={"domain_id": domain_id, "user_ids": [str(user_id)]}, headers=_auth_header()
    )

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Page 1 of" not in resp.data


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


def test_user_detail_lists_shows_approved_for_other_users_as_pickable(client, db_conn):
    """Real live-testing feedback (RoadMap.md's dated entry): approving a
    show for a second kid meant re-pasting/re-resolving the exact same
    Crunchyroll URL a first kid had already been approved for."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    kid1 = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    kid2 = db_conn.execute("SELECT id FROM users WHERE username = 'kid2'").fetchone()["id"]
    client.post(
        "/shows/add",
        data={"user_id": kid1, "url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney", "name": "Ace Attorney"},
        headers=_auth_header(),
    )

    resp = client.get(f"/users/{kid2}", headers=_auth_header())
    assert b"Ace Attorney" in resp.data
    assert b"GYE5K0XVR" in resp.data

    # kid1's own page must NOT offer their own already-approved show back
    # to themselves as a "pick an existing one" option -- with no OTHER
    # user's show to offer, the picker doesn't render at all (still shows
    # GYE5K0XVR in their OWN approved-shows table above, just not as a
    # pickable combobox item).
    resp = client.get(f"/users/{kid1}", headers=_auth_header())
    assert b"Already approved for someone else" not in resp.data


def test_add_show_via_existing_series_id_skips_url_parsing_entirely(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    kid1 = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    kid2 = db_conn.execute("SELECT id FROM users WHERE username = 'kid2'").fetchone()["id"]
    client.post(
        "/shows/add",
        data={"user_id": kid1, "url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney", "name": "Ace Attorney"},
        headers=_auth_header(),
    )

    resp = client.post(
        "/shows/add", data={"user_id": kid2, "existing_series_id": "GYE5K0XVR"}, headers=_auth_header()
    )

    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (kid2,)).fetchone()
    assert row["series_id"] == "GYE5K0XVR"
    assert row["series_name"] == "Ace Attorney"


def test_add_show_existing_series_id_wins_over_a_submitted_url(client, db_conn):
    """Real UX guard: if both fields somehow arrive together, the exact
    already-known match wins -- no ambiguity about which one "really"
    got approved."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    kid1 = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    kid2 = db_conn.execute("SELECT id FROM users WHERE username = 'kid2'").fetchone()["id"]
    client.post(
        "/shows/add",
        data={"user_id": kid1, "url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney", "name": "Ace Attorney"},
        headers=_auth_header(),
    )

    client.post(
        "/shows/add",
        data={
            "user_id": kid2, "existing_series_id": "GYE5K0XVR",
            "url": "https://www.crunchyroll.com/series/ZZZZZZZZ/some-other-show",
        },
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (kid2,)).fetchone()
    assert row["series_id"] == "GYE5K0XVR"


def test_add_show_unknown_existing_series_id_shows_error(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]

    resp = client.post(
        "/shows/add", data={"user_id": user_id, "existing_series_id": "NOTREAL1"}, headers=_auth_header()
    )

    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT * FROM user_shows WHERE user_id = ?", (user_id,)).fetchone() is None


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
# Integrations page -- Crunchyroll cross-user management (2026-09-10)
# ============================================================

def _mk_kids(client, db_conn, *names):
    ids = {}
    for n in names:
        client.post("/users/add", data={"username": n, "password": "pw"}, headers=_auth_header())
        ids[n] = db_conn.execute("SELECT id FROM users WHERE username = ?", (n,)).fetchone()[0]
    return ids


def _approve_direct(db_conn, user_id, series_id="GYE5K0XVR", name="Ace Attorney"):
    db_conn.execute(
        "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?,?,?)",
        (user_id, series_id, name),
    )
    db_conn.commit()


def test_integrations_nav_is_a_collapsible_group(client):
    resp = client.get("/integrations/crunchyroll", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # sidebar group with the three service sub-links
    assert "data-sidebar-group" in body
    assert 'href="/integrations/crunchyroll"' in body
    assert 'href="/integrations/youtube"' in body
    assert 'href="/integrations/discord"' in body
    # active child pre-opens the group
    assert 'class="sidebar-group open"' in body


def test_integrations_index_redirects_to_crunchyroll(client):
    resp = client.get("/integrations", headers=_auth_header())
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/integrations/crunchyroll")


def test_integrations_youtube_and_discord_are_planned_placeholders(client):
    for path in ("/integrations/youtube", "/integrations/discord"):
        body = client.get(path, headers=_auth_header()).get_data(as_text=True)
        assert "Planned" in body
        assert "No Crunchyroll shows" not in body  # Crunchyroll content stays on its own page


def test_integrations_requires_admin(client):
    assert client.get("/integrations").status_code == 401
    assert client.get("/integrations/crunchyroll").status_code == 401
    assert client.get("/integrations/youtube").status_code == 401
    assert client.get("/integrations/discord").status_code == 401
    assert client.post("/integrations/crunchyroll/approve", data={}).status_code == 401
    assert client.post("/integrations/crunchyroll/remove_all", data={}).status_code == 401
    assert client.post("/integrations/crunchyroll/remove_one", data={}).status_code == 401


def test_integrations_empty_state(client, db_conn):
    resp = client.get("/integrations/crunchyroll", headers=_auth_header())
    assert "No Crunchyroll shows approved for anyone yet." in resp.get_data(as_text=True)


def test_integrations_lists_every_series_with_all_its_users(client, db_conn):
    kids = _mk_kids(client, db_conn, "kid1", "kid2", "kid3")
    _approve_direct(db_conn, kids["kid1"], "GYE5K0XVR", "Ace Attorney")
    _approve_direct(db_conn, kids["kid2"], "GYE5K0XVR", "Ace Attorney")
    _approve_direct(db_conn, kids["kid3"], "G6M0K1P2Q", "Naruto")

    body = client.get("/integrations/crunchyroll", headers=_auth_header()).get_data(as_text=True)
    assert "Ace Attorney" in body and "GYE5K0XVR" in body
    assert "Naruto" in body and "G6M0K1P2Q" in body
    # kid1 + kid2 both shown against Ace Attorney
    ace_cell = body.split("GYE5K0XVR", 1)[1].split("Remove from everyone", 1)[0]
    assert "kid1" in ace_cell and "kid2" in ace_cell and "kid3" not in ace_cell


def test_approve_show_for_multiple_users_via_existing_series_id(client, db_conn):
    kids = _mk_kids(client, db_conn, "kid1", "kid2", "kid3")
    _approve_direct(db_conn, kids["kid1"], "GYE5K0XVR", "Ace Attorney")

    resp = client.post(
        "/integrations/crunchyroll/approve",
        data={"existing_series_id": "GYE5K0XVR", "user_ids": [str(kids["kid2"]), str(kids["kid3"])]},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    got = {
        r["user_id"]
        for r in db_conn.execute("SELECT user_id FROM user_shows WHERE series_id = 'GYE5K0XVR'").fetchall()
    }
    assert got == {kids["kid1"], kids["kid2"], kids["kid3"]}


def test_approve_show_for_users_via_pasted_url_and_name(client, db_conn):
    kids = _mk_kids(client, db_conn, "kid1", "kid2")
    resp = client.post(
        "/integrations/crunchyroll/approve",
        data={
            "url": "https://www.crunchyroll.com/series/GABC12345/some-show",
            "name": "Custom Name",
            "user_ids": [str(kids["kid1"]), str(kids["kid2"])],
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    rows = db_conn.execute(
        "SELECT series_id, series_name FROM user_shows WHERE series_id = 'GABC12345'"
    ).fetchall()
    assert len(rows) == 2
    assert {r["series_name"] for r in rows} == {"Custom Name"}


def test_approve_show_with_no_users_selected_is_rejected(client, db_conn):
    _mk_kids(client, db_conn, "kid1")
    resp = client.post(
        "/integrations/crunchyroll/approve",
        data={"existing_series_id": "GYE5K0XVR"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT COUNT(*) c FROM user_shows").fetchone()["c"] == 0


def test_approve_show_with_invalid_url_is_rejected(client, db_conn):
    kids = _mk_kids(client, db_conn, "kid1")
    resp = client.post(
        "/integrations/crunchyroll/approve",
        data={"url": "https://example.com/nope", "user_ids": [str(kids["kid1"])]},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT COUNT(*) c FROM user_shows").fetchone()["c"] == 0


def test_approve_show_ignores_a_nonexistent_user_id(client, db_conn):
    kids = _mk_kids(client, db_conn, "kid1")
    resp = client.post(
        "/integrations/crunchyroll/approve",
        data={"url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney",
              "name": "Ace Attorney", "user_ids": [str(kids["kid1"]), "9999"]},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    rows = db_conn.execute("SELECT user_id FROM user_shows").fetchall()
    assert [r["user_id"] for r in rows] == [kids["kid1"]]


def test_remove_show_from_all_users(client, db_conn):
    kids = _mk_kids(client, db_conn, "kid1", "kid2", "kid3")
    for k in ("kid1", "kid2"):
        _approve_direct(db_conn, kids[k], "GYE5K0XVR", "Ace Attorney")
    _approve_direct(db_conn, kids["kid3"], "GOTHER123", "Other Show")

    resp = client.post(
        "/integrations/crunchyroll/remove_all",
        data={"series_id": "GYE5K0XVR"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    remaining = db_conn.execute("SELECT series_id FROM user_shows").fetchall()
    assert [r["series_id"] for r in remaining] == ["GOTHER123"]


def test_remove_show_from_all_users_when_nobody_had_it(client, db_conn):
    resp = client.post(
        "/integrations/crunchyroll/remove_all",
        data={"series_id": "GNOBODY00"},
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]


def test_remove_show_from_one_user_only(client, db_conn):
    kids = _mk_kids(client, db_conn, "kid1", "kid2")
    _approve_direct(db_conn, kids["kid1"], "GYE5K0XVR", "Ace Attorney")
    _approve_direct(db_conn, kids["kid2"], "GYE5K0XVR", "Ace Attorney")

    resp = client.post(
        "/integrations/crunchyroll/remove_one",
        data={"series_id": "GYE5K0XVR", "user_id": str(kids["kid1"])},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    rows = db_conn.execute("SELECT user_id FROM user_shows WHERE series_id = 'GYE5K0XVR'").fetchall()
    assert [r["user_id"] for r in rows] == [kids["kid2"]]


def test_approve_show_refreshes_stored_name_without_erroring(client, db_conn):
    kids = _mk_kids(client, db_conn, "kid1")
    _approve_direct(db_conn, kids["kid1"], "GYE5K0XVR", "Old Name")
    resp = client.post(
        "/integrations/crunchyroll/approve",
        data={"url": "https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney",
              "name": "New Name", "user_ids": [str(kids["kid1"])]},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute(
        "SELECT series_name FROM user_shows WHERE user_id = ? AND series_id = 'GYE5K0XVR'", (kids["kid1"],)
    ).fetchone()
    assert row["series_name"] == "New Name"


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
        "/settings/network",
        data={"local_network": "10.0.0.0/8", "network_sweep_interval_minutes": "60"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    import db
    assert db.get_setting(db_conn, "local_network") == "10.0.0.0/8"


def test_update_local_network_blank_disables_check(client, db_conn):
    client.post(
        "/settings/network",
        data={"local_network": "", "network_sweep_interval_minutes": "60"},
        headers=_auth_header(),
    )
    import db
    assert db.get_setting(db_conn, "local_network") == ""
    import matching
    assert matching.ip_in_configured_lan(db_conn, "8.8.8.8") is True


def test_settings_page_shows_the_default_optigate_hostname(client):
    resp = client.get("/settings", headers=_auth_header())
    assert b"optigate.home" in resp.data


def test_settings_page_shows_network_sweep_card(client):
    resp = client.get("/settings", headers=_auth_header())
    assert b"Network discovery sweep" in resp.data
    assert b"never run yet" in resp.data


def test_settings_page_shows_last_sweep_status(client, db_conn):
    import db
    db.set_setting(db_conn, "network_sweep_last_run_at", "2026-09-09T03:00:00Z")
    db.set_setting(db_conn, "network_sweep_last_host_count", "254")
    db_conn.commit()

    resp = client.get("/settings", headers=_auth_header())

    assert b"2026-09-09T03:00:00Z" in resp.data
    assert b"254 addresses probed" in resp.data


def test_update_network_sweep_saves_enabled_and_interval(client, db_conn):
    import db
    resp = client.post(
        "/settings/network",
        data={"local_network": "", "network_sweep_enabled": "1", "network_sweep_interval_minutes": "30"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert db.get_setting(db_conn, "network_sweep_enabled") == "1"
    assert db.get_setting(db_conn, "network_sweep_interval_minutes") == "30"


def test_update_network_sweep_unchecked_box_disables(client, db_conn):
    """An unchecked HTML checkbox submits no field at all -- must be
    read as disabled, not crash on a missing form key."""
    import db
    resp = client.post(
        "/settings/network",
        data={"local_network": "", "network_sweep_interval_minutes": "60"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert db.get_setting(db_conn, "network_sweep_enabled") == "0"


def test_update_network_sweep_rejects_non_numeric_interval(client, db_conn):
    import db
    resp = client.post(
        "/settings/network",
        data={"local_network": "", "network_sweep_enabled": "1", "network_sweep_interval_minutes": "not-a-number"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert db.get_setting(db_conn, "network_sweep_interval_minutes", "") == "", \
        "a rejected save must not overwrite the existing setting"


def test_update_network_sweep_rejects_zero_or_negative_interval(client, db_conn):
    import db
    resp = client.post(
        "/settings/network",
        data={"local_network": "", "network_sweep_enabled": "1", "network_sweep_interval_minutes": "0"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert db.get_setting(db_conn, "network_sweep_interval_minutes", "") == ""


def test_update_network_settings_rejected_interval_leaves_local_network_unchanged_too(client, db_conn):
    """Atomicity check for the merged Network section (RoadMap.md item
    3): a bad interval must leave the WHOLE save rejected, not just the
    interval -- a local_network change submitted in the same request
    must not silently go through."""
    import db
    db.set_setting(db_conn, "local_network", "192.168.1.0/24")
    db_conn.commit()
    resp = client.post(
        "/settings/network",
        data={"local_network": "10.0.0.0/8", "network_sweep_interval_minutes": "not-a-number"},
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    assert db.get_setting(db_conn, "local_network") == "192.168.1.0/24"


def test_run_network_sweep_now_sets_the_request_timestamp(client, db_conn):
    import db
    assert db.get_setting(db_conn, "network_sweep_run_now_requested_at", "") == ""

    resp = client.post("/settings/network-sweep/run-now", headers=_auth_header())

    assert resp.status_code == 302
    assert db.get_setting(db_conn, "network_sweep_run_now_requested_at", "") != ""


def test_run_network_sweep_now_works_even_when_disabled(client, db_conn):
    """An explicit one-off "Run now" click must not be silently ignored
    just because the automatic schedule toggle is off."""
    import db
    db.set_setting(db_conn, "network_sweep_enabled", "0")
    db_conn.commit()

    resp = client.post("/settings/network-sweep/run-now", headers=_auth_header())

    assert resp.status_code == 302
    assert db.get_setting(db_conn, "network_sweep_run_now_requested_at", "") != ""


def test_settings_page_shows_the_run_now_button(client):
    resp = client.get("/settings", headers=_auth_header())
    assert b"Run now" in resp.data


def test_run_network_sweep_now_warns_when_controller_is_not_running(client, db_conn):
    """Real gap found live 2026-09-09, project owner's own words: "we
    can't just let it go off into nothingness." No interception_runtime
    row at all (a fresh install, or -- the actual live case -- the
    interception profile simply isn't running) must produce an honest
    warning, not the generic "will run" message that implies success
    it can't back up. The request is still queued regardless (see the
    next test)."""
    resp = client.post("/settings/network-sweep/run-now", headers=_auth_header(), follow_redirects=True)
    assert b"interception profile isn&#39;t running" in resp.data or b"interception profile isn't running" in resp.data


def test_run_network_sweep_now_still_queues_the_request_when_controller_is_down(client, db_conn):
    """The honest warning doesn't mean giving up on the request -- if
    the profile starts moments later, controller's own next check tick
    should still pick this exact request up."""
    import db
    client.post("/settings/network-sweep/run-now", headers=_auth_header())
    assert db.get_setting(db_conn, "network_sweep_run_now_requested_at", "") != ""


def test_run_network_sweep_now_gives_the_normal_message_when_controller_is_up(client, db_conn):
    import db
    _insert_runtime_row(db_conn, mode="running", last_healthy_at=db.now_iso())

    resp = client.post("/settings/network-sweep/run-now", headers=_auth_header(), follow_redirects=True)

    assert b"Requested -- will run within about 30 seconds." in resp.data


def test_run_network_sweep_now_warns_when_controller_reports_stale(client, db_conn):
    """A stopped/crashed controller leaves interception_runtime frozen
    at whatever mode it last reported -- staleness on last_healthy_at,
    not just the mode column, is what actually catches that (same
    reasoning as _subsystem_stale()'s own docstring)."""
    import db
    _insert_runtime_row(db_conn, mode="running", last_healthy_at=db.iso_secs_ago(120))

    resp = client.post("/settings/network-sweep/run-now", headers=_auth_header(), follow_redirects=True)

    assert b"interception profile isn&#39;t running" in resp.data or b"interception profile isn't running" in resp.data


def test_settings_page_shows_live_interception_status_for_the_sweep(client, db_conn):
    import db
    resp = client.get("/settings", headers=_auth_header())
    assert b"interception profile: not running" in resp.data

    _insert_runtime_row(db_conn, mode="running", last_healthy_at=db.now_iso())
    resp = client.get("/settings", headers=_auth_header())
    assert b"interception profile: running" in resp.data


def test_update_optigate_hostname_saves_lowercased_value(client, db_conn):
    resp = client.post(
        "/settings/household", data={"optigate_hostname_prefix": "MyNetwork"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    import db
    assert db.get_setting(db_conn, "optigate_hostname_prefix") == "mynetwork"


def test_update_optigate_hostname_blank_falls_back_to_default(client, db_conn):
    client.post("/settings/household", data={"optigate_hostname_prefix": ""}, headers=_auth_header())
    import db
    assert db.get_setting(db_conn, "optigate_hostname_prefix") == db.DEFAULT_OPTIGATE_HOSTNAME_PREFIX


def test_update_optigate_hostname_rejects_a_dot(client, db_conn):
    """The project owner's own words: "force the use of .home so the
    administrator can only change the first part of the URL" -- a
    prefix containing its own dot could otherwise smuggle in a
    different, unintended suffix."""
    resp = client.post(
        "/settings/household", data={"optigate_hostname_prefix": "evil.example"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    import db
    assert db.get_setting(db_conn, "optigate_hostname_prefix") is None


def test_update_optigate_hostname_rejects_invalid_characters(client, db_conn):
    resp = client.post(
        "/settings/household", data={"optigate_hostname_prefix": "not valid!"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]


def test_update_optigate_hostname_rejects_leading_or_trailing_hyphen(client, db_conn):
    resp = client.post(
        "/settings/household", data={"optigate_hostname_prefix": "-bad"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]


# ============================================================
# optigate.home rewrite pushed directly by the dashboard (2026-09-08) --
# real gap found live: this used to be pushed ONLY by controller's
# periodic cycle (the interception profile, off by default for most
# installs), so the feature silently never worked at all without it,
# with "Saved. The address is now X.home." implying otherwise.
# ============================================================

def test_update_optigate_hostname_without_dashboard_url_explains_why(client, db_conn):
    """DASHBOARD_URL is unset in the test environment (as it would be on
    a fresh install that hasn't configured it yet) -- the save must
    still succeed (the setting itself is real), but say plainly why the
    address isn't live yet, not claim success it can't back up."""
    resp = client.post(
        "/settings/household", data={"optigate_hostname_prefix": "myhouse"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]
    assert "DASHBOARD_URL" in resp.headers["Location"]
    import db
    assert db.get_setting(db_conn, "optigate_hostname_prefix") == "myhouse"


def test_update_optigate_hostname_pushes_to_adguard_when_configured(client, db_conn, monkeypatch):
    import dashboard

    monkeypatch.setenv("DASHBOARD_URL", "http://192.168.1.50:8787")
    client.post(
        "/settings/filtering",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "admin", "adguard_password": "hunter2"},
        headers=_auth_header(),
    )
    client.post(
        "/settings/admin", data={"admin_username": "admin", "admin_password": "hunter2"}, headers=_auth_header(),
    )

    captured = {}

    def fake_sync(conn, url, username, password, block_page_ip):
        captured["args"] = (url, username, password, block_page_ip)

    monkeypatch.setattr(dashboard.optigate_rewrite, "sync_optigate_rewrite", fake_sync)

    resp = client.post(
        "/settings/household",
        data={"optigate_hostname_prefix": "myhouse"},
        headers=_auth_header(username="admin", password="hunter2"),
    )

    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    assert "pushed+to+AdGuard" in resp.headers["Location"]
    assert captured["args"] == ("http://127.0.0.1:3000", "admin", "hunter2", "192.168.1.50")


def test_update_optigate_hostname_reports_an_adguard_error_without_crashing(client, db_conn, monkeypatch):
    import dashboard

    monkeypatch.setenv("DASHBOARD_URL", "http://192.168.1.50:8787")
    client.post(
        "/settings/filtering", data={"adguard_url": "http://127.0.0.1:3000"}, headers=_auth_header(),
    )
    client.post(
        "/settings/admin", data={"admin_username": "admin", "admin_password": "hunter2"}, headers=_auth_header(),
    )

    def fake_sync(*a, **kw):
        raise dashboard.adguard_client.AdGuardError("connection refused")

    monkeypatch.setattr(dashboard.optigate_rewrite, "sync_optigate_rewrite", fake_sync)

    resp = client.post(
        "/settings/household",
        data={"optigate_hostname_prefix": "myhouse"},
        headers=_auth_header(username="admin", password="hunter2"),
    )

    assert resp.status_code == 302
    assert "error=1" in resp.headers["Location"]
    assert "connection+refused" in resp.headers["Location"]


def test_settings_page_shows_not_active_status_by_default(client, db_conn):
    """No DASHBOARD_URL, no AdGuard configured -- the default state on a
    fresh install. Must say so plainly, not silently look identical to
    a working setup (the exact gap that prompted this fix)."""
    resp = client.get("/settings", headers=_auth_header())
    assert b"not active" in resp.data


def test_settings_page_shows_live_status_when_rewrite_confirmed(client, db_conn, monkeypatch):
    import dashboard

    monkeypatch.setenv("DASHBOARD_URL", "http://192.168.1.50:8787")
    client.post(
        "/settings/filtering", data={"adguard_url": "http://127.0.0.1:3000"}, headers=_auth_header(),
    )
    client.post(
        "/settings/admin", data={"admin_username": "admin", "admin_password": "hunter2"}, headers=_auth_header(),
    )

    def fake_get_rewrites(*a, **kw):
        return [{"domain": "optigate.home", "answer": "192.168.1.50", "enabled": True}]

    monkeypatch.setattr(dashboard.optigate_rewrite.adguard_client, "get_rewrites", fake_get_rewrites)

    resp = client.get("/settings", headers=_auth_header(username="admin", password="hunter2"))

    assert b"live -- resolves to 192.168.1.50" in resp.data


def test_settings_page_status_check_survives_adguard_being_unreachable(client, db_conn, monkeypatch):
    import dashboard

    monkeypatch.setenv("DASHBOARD_URL", "http://192.168.1.50:8787")
    client.post(
        "/settings/filtering", data={"adguard_url": "http://127.0.0.1:3000"}, headers=_auth_header(),
    )
    client.post(
        "/settings/admin", data={"admin_username": "admin", "admin_password": "hunter2"}, headers=_auth_header(),
    )

    def fake_get_rewrites(*a, **kw):
        raise dashboard.adguard_client.AdGuardError("connection refused")

    monkeypatch.setattr(dashboard.optigate_rewrite.adguard_client, "get_rewrites", fake_get_rewrites)

    resp = client.get("/settings", headers=_auth_header(username="admin", password="hunter2"))

    assert resp.status_code == 200
    assert b"couldn" in resp.data  # "couldn't check -- AdGuard isn't reachable right now"


def test_settings_page_distinguishes_stale_credentials_from_adguard_being_down(client, db_conn, monkeypatch):
    """Real gap found 2026-09-08 investigating an "AdGuard username/
    password not synced" report: a 401 (AdGuard is up, but rejects the
    stored login -- exactly what happens after an admin password
    change until someone restarts the adguard container) used to show
    the identical "isn't reachable right now" message as AdGuard being
    genuinely offline, pointing troubleshooting in the wrong direction
    entirely."""
    import dashboard

    monkeypatch.setenv("DASHBOARD_URL", "http://192.168.1.50:8787")
    client.post(
        "/settings/filtering", data={"adguard_url": "http://127.0.0.1:3000"}, headers=_auth_header(),
    )
    client.post(
        "/settings/admin", data={"admin_username": "admin", "admin_password": "hunter2"}, headers=_auth_header(),
    )

    def fake_get_rewrites(*a, **kw):
        raise dashboard.adguard_client.AdGuardError("HTTP 401 from x: unauthorized", status_code=401)

    monkeypatch.setattr(dashboard.optigate_rewrite.adguard_client, "get_rewrites", fake_get_rewrites)

    resp = client.get("/settings", headers=_auth_header(username="admin", password="hunter2"))

    assert resp.status_code == 200
    assert b"rejected this login" in resp.data
    assert b"docker compose restart adguard" in resp.data


def test_refresh_adguard_filters_also_retries_the_optigate_rewrite(client, db_conn, monkeypatch):
    """The "Check for filter updates now" button doubles as a manual
    fallback for the rewrite too -- for the case where AdGuard was reset
    or reconfigured independently of this dashboard, with nothing else
    prompting a re-push."""
    import dashboard

    monkeypatch.setenv("DASHBOARD_URL", "http://192.168.1.50:8787")
    client.post(
        "/settings/filtering", data={"adguard_url": "http://127.0.0.1:3000"}, headers=_auth_header(),
    )
    client.post(
        "/settings/admin", data={"admin_username": "admin", "admin_password": "hunter2"}, headers=_auth_header(),
    )
    monkeypatch.setattr(dashboard.adguard_client, "refresh_filters", lambda *a, **kw: 0)

    calls = []
    monkeypatch.setattr(
        dashboard.optigate_rewrite, "sync_optigate_rewrite",
        lambda conn, url, username, password, ip: calls.append(ip),
    )

    resp = client.post("/settings/adguard/refresh", headers=_auth_header(username="admin", password="hunter2"))

    assert resp.status_code == 302
    assert calls == ["192.168.1.50"]


def test_update_block_page_mode_valid_value_saved(client, db_conn):
    resp = client.post(
        "/settings/filtering", data={"block_page_mode": "redirect"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    import db
    assert db.get_setting(db_conn, "block_page_mode") == "redirect"


def test_update_block_page_mode_invalid_value_rejected(client, db_conn):
    resp = client.post(
        "/settings/filtering", data={"block_page_mode": "not-a-mode"}, headers=_auth_header()
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


# ============================================================
# Health page "run this command" toggle -- added 2026-09-07, project
# owner's explicit request in place of a dashboard-driven start/stop
# control (granting the dashboard container Docker socket access to
# actually flip these containers was explicitly declined the same day)
# ============================================================

def test_health_page_shows_stop_commands_when_running(client, db_conn):
    import db
    _insert_runtime_row(db_conn, last_healthy_at=db.now_iso(), nft_last_healthy_at=db.now_iso())
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"docker compose stop controller arp-worker" in resp.data
    assert b"docker compose stop nftables-manager" in resp.data
    assert b"docker compose up -d controller arp-worker" not in resp.data
    assert b"docker compose up -d nftables-manager" not in resp.data


def test_health_page_shows_start_commands_when_stale(client, db_conn):
    import db
    _insert_runtime_row(db_conn, last_healthy_at=db.iso_secs_ago(60), nft_last_healthy_at=db.iso_secs_ago(60))
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"docker compose up -d controller arp-worker" in resp.data
    assert b"docker compose up -d nftables-manager" in resp.data


def test_health_page_shows_stop_command_even_when_fail_open(client, db_conn):
    """fail_open still means the process IS running (it's actively
    self-reporting the failure) -- the toggle command is about container
    up/down state, not health, so it should still offer to stop it."""
    import db
    _insert_runtime_row(db_conn, mode="fail_open", last_healthy_at=db.now_iso())
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"docker compose stop controller arp-worker" in resp.data


def test_health_page_shows_combined_start_command_when_never_run(client):
    resp = client.get("/health", headers=_auth_header())
    assert resp.status_code == 200
    assert b"docker compose --profile interception up -d" in resp.data


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
# Real AdGuard/dashboard credential unification (2026-09-07, RoadMap.md's
# dated entry) -- replaces the earlier "show the plaintext AdGuard
# password on screen" approach, correctly flagged as insecure. Changing
# the dashboard's own admin password is now the ONLY way to change
# AdGuard's login too; see dashboard/adguard_config_sync.py for the
# actual file-write half of this (its own tests cover that in isolation).
# ============================================================

def test_update_admin_password_change_syncs_adguard_settings(client, db_conn, monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard.adguard_config_sync, "sync_adguard_credentials", lambda *a, **kw: None)

    client.post(
        "/settings/admin", data={"admin_username": "newadmin", "admin_password": "newpassword123"},
        headers=_auth_header(),
    )

    import db as db_mod
    assert db_mod.get_setting(db_conn, "adguard_username") == "newadmin"
    assert db_mod.get_setting(db_conn, "adguard_password") == "newpassword123"


def test_update_admin_password_change_calls_the_real_config_sync(client, db_conn, monkeypatch):
    import dashboard
    captured = {}
    monkeypatch.setattr(
        dashboard.adguard_config_sync, "sync_adguard_credentials",
        lambda username, password: captured.update(username=username, password=password),
    )

    resp = client.post(
        "/settings/admin", data={"admin_username": "newadmin", "admin_password": "newpassword123"},
        headers=_auth_header(),
    )

    assert captured == {"username": "newadmin", "password": "newpassword123"}
    assert "restart" in resp.headers["Location"]


def test_update_admin_username_only_change_does_not_touch_adguard(client, db_conn, monkeypatch):
    """Blank password means "keep current" -- there's no current
    plaintext password to re-sync with, so this must not call the sync
    at all (it would otherwise need to hash an empty string)."""
    import dashboard
    called = []
    monkeypatch.setattr(
        dashboard.adguard_config_sync, "sync_adguard_credentials",
        lambda *a, **kw: called.append(True),
    )

    client.post(
        "/settings/admin", data={"admin_username": "renamed-only", "admin_password": ""},
        headers=_auth_header(),
    )

    assert called == []


def test_update_admin_password_change_survives_adguard_sync_failure(client, db_conn, monkeypatch):
    """The dashboard's OWN password change must still succeed even if
    writing AdGuard's config fails (volume not mounted on an existing
    install that hasn't recreated its container yet, disk error,
    whatever) -- never let a best-effort integration block the primary
    action."""
    import dashboard
    def boom(username, password):
        raise dashboard.adguard_config_sync.AdGuardConfigSyncError("simulated failure")
    monkeypatch.setattr(dashboard.adguard_config_sync, "sync_adguard_credentials", boom)

    resp = client.post(
        "/settings/admin", data={"admin_username": "newadmin", "admin_password": "newpassword123"},
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert client.get("/users", headers=_auth_header(username="newadmin", password="newpassword123")).status_code == 200


def test_settings_page_never_shows_a_plaintext_adguard_password(client, db_conn):
    """Regression guard for the exact insecure behavior the project
    owner flagged and asked to have removed, not just hidden better."""
    import db as db_mod
    db_mod.set_setting(db_conn, "adguard_url", "http://127.0.0.1:3000")
    db_mod.set_setting(db_conn, "adguard_password", "s3cr3t-pw")
    db_conn.commit()

    resp = client.get("/settings", headers=_auth_header())

    assert b"s3cr3t-pw" not in resp.data


def test_settings_page_has_no_separate_adguard_username_or_password_input(client, db_conn):
    resp = client.get("/settings", headers=_auth_header())
    assert b'name="adguard_username"' not in resp.data
    assert b'name="adguard_password"' not in resp.data


# ============================================================
# /settings/filtering: AdGuard connection ADDRESS (username/password
# moved to /settings/admin above), SafeSearch, and blocked-site
# experience -- merged into one atomic Save 2026-09-09 (RoadMap.md item
# 3). Plus "check for updates now" (its own separate one-off action).
# ============================================================

def test_update_adguard_settings_saves_only_the_url(client, db_conn):
    resp = client.post(
        "/settings/filtering", data={"adguard_url": "http://127.0.0.1:3000"}, headers=_auth_header(),
    )
    assert resp.status_code == 302
    import db as db_mod
    assert db_mod.get_setting(db_conn, "adguard_url") == "http://127.0.0.1:3000"


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
        "/settings/filtering",
        data={"adguard_url": "http://127.0.0.1:3000", "adguard_username": "admin", "adguard_password": "x"},
        headers=_auth_header(),
    )
    resp = client.get("/settings", headers=_auth_header())
    assert b'href="http://localhost:3000"' in resp.data
    assert b"ADGUARD_WEB_BIND" in resp.data  # the reachability caveat is explained, not just linked


def test_adguard_ui_link_uses_a_different_configured_port(client, db_conn):
    client.post(
        "/settings/filtering",
        data={"adguard_url": "http://127.0.0.1:4000", "adguard_username": "admin", "adguard_password": "x"},
        headers=_auth_header(),
    )
    resp = client.get("/settings", headers=_auth_header())
    assert b'href="http://localhost:4000"' in resp.data


def test_refresh_adguard_filters_calls_the_real_client_and_reports_the_count(client, db_conn, monkeypatch):
    import dashboard
    monkeypatch.setattr(dashboard.adguard_config_sync, "sync_adguard_credentials", lambda *a, **kw: None)
    client.post("/settings/filtering", data={"adguard_url": "http://127.0.0.1:3000"}, headers=_auth_header())
    # Username/password now come from the dashboard's own admin login
    # (update_admin()), not a separate AdGuard-only form -- see this
    # module's own dated entry.
    client.post(
        "/settings/admin", data={"admin_username": "admin", "admin_password": "hunter2"}, headers=_auth_header(),
    )

    captured = {}

    def fake_refresh(base_url, username, password, timeout=None):
        captured["args"] = (base_url, username, password)
        return 2

    monkeypatch.setattr(dashboard.adguard_client, "refresh_filters", fake_refresh)

    resp = client.post(
        "/settings/adguard/refresh", headers=_auth_header(username="admin", password="hunter2")
    )

    assert "error=1" not in resp.headers["Location"]
    assert captured["args"] == ("http://127.0.0.1:3000", "admin", "hunter2")


def test_refresh_adguard_filters_reports_adguard_errors_without_crashing(client, db_conn, monkeypatch):
    client.post(
        "/settings/filtering",
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


def test_events_page_shows_info_severity_with_its_own_badge(client, db_conn):
    """Added 2026-09-09 alongside the 'info' severity itself -- must
    render with a distinct badge, not crash on a severity value that
    predates this page's original two-value ternary."""
    import system_events

    system_events.log_event(db_conn, "network_sweep", "info", "Manual sweep complete: probed 2 address(es).")
    resp = client.get("/events", headers=_auth_header())
    assert resp.status_code == 200
    assert b"info" in resp.data
    assert b'class="badge pending"' in resp.data
    assert b"Manual sweep complete" in resp.data


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


def test_update_device_assigning_to_a_user_authenticates_a_preauth_device(client, db_conn):
    """2026-09-11, project owner's explicit request: assigning a PREAUTH
    device to a kid from the Manage page is the same vouching act as
    add_device()'s own manually-typed-MAC case -- it must clear the
    captive-portal gate, not just set the assignment."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:70")

    client.post(
        "/devices/update",
        data={"device_id": device_id, "label": "", "assignment": f"user:{user_id}"},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1


def test_update_device_assigning_to_a_group_authenticates_a_preauth_device(client, db_conn):
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:71")

    client.post(
        "/devices/update",
        data={"device_id": device_id, "label": "", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1


def test_update_device_leaving_unassigned_does_not_authenticate_a_preauth_device(client, db_conn):
    """Unassigning/leaving unassigned is not a vouching act -- must not
    silently authenticate a device nobody has actually claimed."""
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:72")

    client.post(
        "/devices/update",
        data={"device_id": device_id, "label": "renamed only", "assignment": ""},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 0


def test_update_device_ignoring_does_not_authenticate_a_preauth_device(client, db_conn):
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:73")

    client.post(
        "/devices/update",
        data={"device_id": device_id, "label": "", "assignment": "ignored"},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 0


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


def test_pending_devices_show_manufacturer_from_mac_prefix(client, db_conn):
    # RoadMap.md 2026-09-11: project owner's request to see device type
    # on this card. Manufacturer is a pure MAC-prefix lookup (no
    # device_bindings row needed at all) -- 84:28:59 is a real
    # Amazon-registered OUI (see common/data/oui_prefixes.tsv).
    _add_pending_device(db_conn, "84:28:59:aa:bb:cc")

    resp = client.get("/devices", headers=_auth_header())

    assert b"Amazon Technologies Inc." in resp.data


def test_pending_devices_show_unknown_manufacturer_as_a_dash(client, db_conn):
    # 02:00:00 is the classic locally-administered test prefix -- never
    # a real IEEE assignment, so the lookup must fail soft rather than
    # show a wrong/blank cell.
    _add_pending_device(db_conn, "02:00:00:aa:bb:cc")

    resp = client.get("/devices", headers=_auth_header())

    assert b"Devices awaiting login (1)" in resp.data
    assert b"&mdash;" in resp.data


def test_pending_devices_show_resolved_mdns_hostname(client, db_conn):
    # controller/mdns_lookup.py writes this onto the device's current
    # (most-recently-seen) device_bindings row -- same subquery
    # current_ip/binding_source already use.
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:60")
    db_conn.execute(
        "INSERT INTO device_bindings (device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, "
        "source, active, hostname) SELECT id, mac_address, '192.168.1.88', '2026-09-11T00:00:00Z', "
        "'2026-09-11T12:00:00Z', 'rtnetlink', 1, 'Kids-Tablet' FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:60'"
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())

    assert b"Kids-Tablet" in resp.data


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


def _bind(db_conn, mac, ip, last_seen="2026-09-10T12:00:00Z"):
    db_conn.execute(
        "INSERT INTO device_bindings (device_id, mac_address, ipv4_address, first_seen_at, "
        "last_seen_at, source, active) SELECT id, mac_address, ?, ?, ?, 'snapshot', 1 "
        "FROM devices WHERE mac_address = ?",
        (ip, last_seen, last_seen, mac),
    )
    db_conn.commit()


def test_devices_roster_shows_the_current_ip_column(client, db_conn):
    # RoadMap 2026-09-10 finding #1: the roster had no IP column, so a
    # device could only be found by MAC/label.
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:70"}, headers=_auth_header())
    _bind(db_conn, "aa:bb:cc:dd:ee:70", "192.168.1.123")
    body = client.get("/devices", headers=_auth_header()).data.decode()
    assert "Current IP" in body
    assert "192.168.1.123" in body


def test_devices_search_matches_on_ip(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:71"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:72"}, headers=_auth_header())
    _bind(db_conn, "aa:bb:cc:dd:ee:71", "192.168.1.201")
    _bind(db_conn, "aa:bb:cc:dd:ee:72", "192.168.1.202")
    body = client.get("/devices?q=192.168.1.201", headers=_auth_header()).data.decode()
    assert "aa:bb:cc:dd:ee:71" in body
    assert "aa:bb:cc:dd:ee:72" not in body


def test_devices_roster_and_pending_tables_are_sortable(client, db_conn):
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:73")
    body = client.get("/devices", headers=_auth_header()).data.decode()
    assert body.count("data-sortable") >= 2
    assert 'data-sort="ip"' in body


def test_devices_off_lan_docker_bridge_ip_is_hidden(client, db_conn):
    # RoadMap 2026-09-10 finding #3: the controller's discovery loop
    # recorded 172.17.x Docker-bridge addresses as devices. Until the
    # controller-side fix, the dashboard hides any device whose only
    # bindings are outside the configured local_network.
    client.post("/devices/add", data={"mac_address": "02:42:AC:11:00:02"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:74"}, headers=_auth_header())
    _bind(db_conn, "02:42:ac:11:00:02", "172.17.0.2")
    _bind(db_conn, "aa:bb:cc:dd:ee:74", "192.168.1.130")
    body = client.get("/devices", headers=_auth_header()).data.decode()
    assert "aa:bb:cc:dd:ee:74" in body
    assert "02:42:ac:11:00:02" not in body
    assert "172.17.0.2" not in body


def test_devices_with_no_binding_at_all_still_show(client, db_conn):
    # A manually-added device that has never been seen on the network has
    # no bindings -- the off-LAN filter must not hide it.
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:75"}, headers=_auth_header())
    body = client.get("/devices", headers=_auth_header()).data.decode()
    assert "aa:bb:cc:dd:ee:75" in body


def test_devices_page_does_not_treat_a_group_ignored_device_as_pending(client, db_conn):
    """Real bug found live 2026-09-08 (RoadMap.md's dated entry): the
    pending check only ever looked at d.ignored, not at the device's
    GROUP being in Ignore mode -- a device that's effectively ignored
    only via group membership (same as the group_ignored/
    effective_ignored handling already used for the Status column's
    "Ignored" badge) still showed up in "Devices awaiting login" and
    still got the "Awaiting login" badge, even though every other part
    of the UI already treated it as ignored."""
    db_conn.execute("INSERT INTO groups (name, ignored, created_at) VALUES ('TVs', 1, datetime('now'))")
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO devices (mac_address, is_authenticated, ignored, group_id, created_at) "
        "VALUES ('aa:bb:cc:dd:ee:51', 0, 0, ?, '2026-08-31T00:00:00Z')",
        (group_id,),
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())

    assert b"Devices awaiting login" not in resp.data
    assert b"Awaiting login" not in resp.data


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


def test_dismiss_pending_hides_the_device_from_the_card(client, db_conn):
    """2026-09-08, project owner's explicit request: "I need a 'dismiss'
    option ... I don't want it to do anything but clear the device
    showing as awaiting logon.\""""
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:52")

    resp = client.post("/devices/dismiss_pending", data={"device_id": device_id}, headers=_auth_header())
    assert resp.status_code == 302

    resp = client.get("/devices", headers=_auth_header())
    # The card itself (heading + table) only renders at all when
    # pending_devices is non-empty -- its absence here is the proof the
    # dismissed device dropped out of that query. It still legitimately
    # appears in the separate main-roster table below (see
    # test_dismiss_pending_does_not_hide_the_device_from_the_main_roster),
    # so asserting the MAC is absent from the whole page would be wrong.
    assert b"Devices awaiting login" not in resp.data


def test_dismiss_pending_does_not_touch_any_real_policy_field(client, db_conn):
    """The whole point: purely a display suppression, never a policy
    change -- unlike Bypass, which sets bypass_login=1."""
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:53")

    client.post("/devices/dismiss_pending", data={"device_id": device_id}, headers=_auth_header())

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["ignored"] == 0
    assert row["bypass_login"] == 0
    assert row["is_authenticated"] == 0
    assert row["pending_dismissed_at"] is not None


def test_dismiss_pending_reappears_after_a_new_network_sighting(client, db_conn):
    """Self-expiring, not permanent: a fresh device_bindings row dated
    AFTER the dismissal means the device is genuinely active again, so
    it must come back on its own -- no separate "un-dismiss" action
    exists or is needed."""
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:54")
    db_conn.execute(
        "UPDATE devices SET pending_dismissed_at = '2026-09-08T10:00:00Z' WHERE id = ?", (device_id,)
    )
    db_conn.execute(
        "INSERT INTO device_bindings (device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, "
        "source, active) VALUES (?, 'aa:bb:cc:dd:ee:54', '192.168.1.80', "
        "'2026-09-08T11:00:00Z', '2026-09-08T11:00:00Z', 'rtnetlink', 1)",
        (device_id,),
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())
    assert b"Devices awaiting login" in resp.data
    assert b"aa:bb:cc:dd:ee:54" in resp.data


def test_dismiss_pending_reappears_after_a_new_login_attempt(client, db_conn):
    """Same self-expiring rule, via the other real "it's active again"
    signal: a fresh captive-portal login attempt dated after the
    dismissal, even with no new device_bindings row."""
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:55")
    db_conn.execute(
        "UPDATE devices SET pending_dismissed_at = '2026-09-08T10:00:00Z' WHERE id = ?", (device_id,)
    )
    db_conn.execute(
        "INSERT INTO system_events (ts, source, severity, message, detail) VALUES "
        "('2026-09-08T11:00:00Z', 'captive_portal_login', 'error', 'x', 'aa:bb:cc:dd:ee:55')"
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())
    assert b"Devices awaiting login" in resp.data
    assert b"aa:bb:cc:dd:ee:55" in resp.data


def test_dismiss_pending_stays_hidden_when_only_stale_activity_predates_it(client, db_conn):
    """The inverse of the two tests above: a device_bindings row or
    login attempt from BEFORE the dismissal must not un-hide it -- only
    activity strictly newer than pending_dismissed_at counts."""
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:56")
    db_conn.execute(
        "INSERT INTO device_bindings (device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, "
        "source, active) VALUES (?, 'aa:bb:cc:dd:ee:56', '192.168.1.81', "
        "'2026-09-08T09:00:00Z', '2026-09-08T09:00:00Z', 'rtnetlink', 1)",
        (device_id,),
    )
    db_conn.execute(
        "UPDATE devices SET pending_dismissed_at = '2026-09-08T10:00:00Z' WHERE id = ?", (device_id,)
    )
    db_conn.commit()

    resp = client.get("/devices", headers=_auth_header())
    assert b"Devices awaiting login" not in resp.data


def test_dismiss_pending_does_not_hide_the_device_from_the_main_roster(client, db_conn):
    """Dismissal only declutters the summary card -- the main device
    table (a different query, no dismissal awareness at all) must keep
    showing the device and its real "Awaiting login" status."""
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:57")
    client.post("/devices/dismiss_pending", data={"device_id": device_id}, headers=_auth_header())

    resp = client.get("/devices", headers=_auth_header())
    text = resp.data.decode()
    assert "aa:bb:cc:dd:ee:57" in text
    assert "Awaiting login" in text


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


# ============================================================
# User-detail "Devices" card (2026-09-08) -- real live-testing feedback:
# no way to see which devices are assigned to a user on this page at
# all, had to search for the username on the Devices page instead.
# Mirrors group_detail()'s own pre-existing "Devices in this group" card.
# ============================================================

def test_user_detail_shows_its_assigned_devices(client, db_conn):
    client.post("/users/add", data={"username": "kid5", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid5'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO devices (mac_address, label, user_id, created_at) "
        "VALUES ('aa:bb:cc:dd:ee:72', 'Kid5 Tablet', ?, datetime('now'))",
        (user_id,),
    )
    db_conn.commit()

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Devices (1)" in body
    assert "aa:bb:cc:dd:ee:72" in body
    assert "Kid5 Tablet" in body
    assert "Active" in body


def test_user_detail_devices_card_shows_no_devices_message_when_empty(client, db_conn):
    client.post("/users/add", data={"username": "kid6", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid6'").fetchone()["id"]

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Devices (0)" in resp.data
    assert b"No devices assigned." in resp.data


def test_user_detail_devices_card_shows_paused_and_ignored_status(client, db_conn):
    client.post("/users/add", data={"username": "kid7", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid7'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO devices (mac_address, user_id, quarantined_at, created_at) "
        "VALUES ('aa:bb:cc:dd:ee:73', ?, datetime('now'), datetime('now'))",
        (user_id,),
    )
    db_conn.execute(
        "INSERT INTO devices (mac_address, user_id, ignored, created_at) "
        "VALUES ('aa:bb:cc:dd:ee:74', ?, 1, datetime('now'))",
        (user_id,),
    )
    db_conn.commit()

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Devices (2)" in body
    assert "Paused" in body
    assert "Ignored" in body


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
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
            "start_time": "00:00", "end_time": "23:59", "time_zone": "UTC", "lockout_all": "on",
            "user_ids": [str(user_id)],
        },
        headers=_auth_header(),
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

def test_devices_page_lists_bulk_action_form_and_row_checkboxes(client, db_conn):
    """Real live-testing feedback 2026-09-07 (RoadMap.md's dated entry):
    the devices table was "getting really clunky" and needed real bulk
    actions (assign/delete several at once) instead of one-row-at-a-
    time. Supersedes the same-day per-row quick-add-to-group select,
    which added exactly the clutter this was meant to fix."""
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:20"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    assert resp.status_code == 200
    assert b'action="/devices/bulk-assign-group"' in resp.data
    assert b'action="/devices/bulk-delete"' in resp.data
    assert b'class="bulk-device-check"' in resp.data
    assert b'id="deviceSelectAll"' in resp.data
    assert b">IoT</option>" in resp.data
    assert b'action="/devices/quick-add-to-group"' not in resp.data


def test_devices_page_toolbar_matches_the_entra_style_button_set(client, db_conn):
    """Real follow-up feedback (RoadMap.md's dated entry): "instead of
    the weird dropdown, can you use the buttons like Entra has" --
    Download/Enable/Disable/Delete/Manage, not a bare group-select
    sitting in the toolbar by default."""
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:21"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    assert resp.status_code == 200
    assert b'href="/devices/export"' in resp.data
    assert b"Download devices" in resp.data
    assert b'action="/devices/bulk-resume"' in resp.data
    assert b'action="/devices/bulk-pause"' in resp.data
    assert b'id="deviceBulkManageToggle"' in resp.data
    assert b'id="deviceBulkManagePanel"' in resp.data


def test_bulk_assign_devices_to_group_applies_to_every_selected_device(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:21", "label": "Kitchen Cam"},
        headers=_auth_header(),
    )
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:22"}, headers=_auth_header())
    device_ids = [
        r["id"] for r in db_conn.execute(
            "SELECT id FROM devices WHERE mac_address IN (?, ?)", ("aa:bb:cc:dd:ee:21", "aa:bb:cc:dd:ee:22")
        )
    ]
    assert len(device_ids) == 2

    resp = client.post(
        "/devices/bulk-assign-group",
        data={"group_id": group_id, "device_ids": [str(i) for i in device_ids]},
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/devices")
    for device_id in device_ids:
        row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        assert row["group_id"] == group_id
        assert row["user_id"] is None
        assert row["ignored"] == 0
    kitchen_cam = db_conn.execute("SELECT label FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:21'").fetchone()
    assert kitchen_cam["label"] == "Kitchen Cam", "must not touch label -- narrow assignment-only update"


def test_bulk_assign_devices_to_group_authenticates_preauth_devices(client, db_conn):
    """2026-09-11, project owner's explicit request: same vouching-act
    reasoning as update_device()'s own single-device version -- a bulk
    group assignment from the Devices list must clear the captive-portal
    gate too, not just apply to devices already authenticated."""
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:74")

    client.post(
        "/devices/bulk-assign-group",
        data={"group_id": group_id, "device_ids": [str(device_id)]},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1


def test_bulk_add_to_group_authenticates_preauth_devices(client, db_conn):
    """/groups/add-devices shares _batch_assign_devices_to_group() with
    /devices/bulk-assign-group -- same vouching-act fix applies here."""
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:75")

    client.post(
        "/groups/add-devices",
        data={"group_id": group_id, "device_ids": [str(device_id)]},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1


def test_bulk_assign_devices_to_group_preserves_bump_and_bypass_flags(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:23"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:23'").fetchone()["id"]
    client.post(
        "/devices/update",
        data={"device_id": device_id, "bump_enabled": "on", "bypass_login": "on", "assignment": ""},
        headers=_auth_header(),
    )

    client.post(
        "/devices/bulk-assign-group", data={"group_id": group_id, "device_ids": [str(device_id)]},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["group_id"] == group_id
    assert row["bump_enabled"] == 1
    assert row["bypass_login"] == 1


def test_bulk_assign_devices_to_group_without_group_selected_shows_error(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:24"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()["id"]

    resp = client.post(
        "/devices/bulk-assign-group", data={"group_id": "", "device_ids": [str(device_id)]},
        headers=_auth_header(),
    )

    assert "error=1" in resp.headers["Location"]
    row = db_conn.execute("SELECT group_id FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["group_id"] is None


def test_bulk_assign_devices_to_group_unknown_group_shows_error(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:25"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()["id"]

    resp = client.post(
        "/devices/bulk-assign-group", data={"group_id": 999999, "device_ids": [str(device_id)]},
        headers=_auth_header(),
    )

    assert "error=1" in resp.headers["Location"]


def test_bulk_assign_devices_to_group_without_devices_selected_shows_error(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]

    resp = client.post("/devices/bulk-assign-group", data={"group_id": group_id}, headers=_auth_header())

    assert "error=1" in resp.headers["Location"]


def test_bulk_delete_devices_removes_every_selected_device(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:26"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:27"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:28"}, headers=_auth_header())
    to_delete = [
        r["id"] for r in db_conn.execute(
            "SELECT id FROM devices WHERE mac_address IN (?, ?)", ("aa:bb:cc:dd:ee:26", "aa:bb:cc:dd:ee:27")
        )
    ]
    keep_mac = "aa:bb:cc:dd:ee:28"

    resp = client.post(
        "/devices/bulk-delete", data={"device_ids": [str(i) for i in to_delete]}, headers=_auth_header()
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/devices")
    remaining = {r["mac_address"] for r in db_conn.execute("SELECT mac_address FROM devices")}
    assert remaining == {keep_mac}


def test_bulk_delete_devices_without_selection_shows_error(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:29"}, headers=_auth_header())

    resp = client.post("/devices/bulk-delete", data={}, headers=_auth_header())

    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"] == 1


# ============================================================
# Devices toolbar: Enable/Disable/Download (Entra-style buttons, real
# follow-up feedback -- RoadMap.md's dated entry)
# ============================================================

def test_bulk_pause_devices_pauses_every_selected_device(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:30"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:31"}, headers=_auth_header())
    ids = [r["id"] for r in db_conn.execute("SELECT id FROM devices")]

    resp = client.post("/devices/bulk-pause", data={"device_ids": [str(i) for i in ids]}, headers=_auth_header())

    assert resp.status_code == 302
    rows = db_conn.execute("SELECT quarantined_at FROM devices").fetchall()
    assert all(r["quarantined_at"] is not None for r in rows)


def test_bulk_pause_devices_skips_ignored_devices(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:32"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()["id"]
    db_conn.execute("UPDATE devices SET ignored = 1 WHERE id = ?", (device_id,))
    db_conn.commit()

    client.post("/devices/bulk-pause", data={"device_ids": [str(device_id)]}, headers=_auth_header())

    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["quarantined_at"] is None


def test_bulk_pause_devices_without_selection_shows_error(client, db_conn):
    resp = client.post("/devices/bulk-pause", data={}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_bulk_resume_devices_resumes_every_selected_paused_device(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:33"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()["id"]
    client.post("/devices/pause", data={"device_id": device_id}, headers=_auth_header())

    resp = client.post("/devices/bulk-resume", data={"device_ids": [str(device_id)]}, headers=_auth_header())

    assert resp.status_code == 302
    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["quarantined_at"] is None


def test_bulk_resume_devices_without_selection_shows_error(client, db_conn):
    resp = client.post("/devices/bulk-resume", data={}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_export_devices_csv_includes_every_device_and_key_fields(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post(
        "/devices/add",
        data={"mac_address": "AA:BB:CC:DD:EE:34", "label": "Kitchen Cam", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )

    resp = client.get("/devices/export", headers=_auth_header())

    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in resp.headers["Content-Disposition"]
    body = resp.data.decode()
    assert "aa:bb:cc:dd:ee:34" in body
    assert "Kitchen Cam" in body
    assert "IoT" in body


def test_export_devices_csv_marks_an_ignored_device_clearly(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:35", "assignment": "ignored"}, headers=_auth_header())

    resp = client.get("/devices/export", headers=_auth_header())

    body = resp.data.decode()
    assert "Ignored" in body


def test_export_devices_csv_requires_admin_auth(client):
    resp = client.get("/devices/export")
    assert resp.status_code == 401


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


def test_group_detail_assigned_sites_paginates_with_a_default_page_size(client, db_conn):
    """Added 2026-09-08, natural follow-up to user_detail's identical
    "Assigned sites" pagination the day before -- same shape, same
    reasoning: a heavily-assigned group's own site list only ever
    grows."""
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    for i in range(60):
        client.post(
            "/domains/add", data={"pattern": f"site{i:04d}\\.example", "mode": "splice"}, headers=_auth_header()
        )
    domain_ids = [r["id"] for r in db_conn.execute("SELECT id FROM domains")]
    client.post(
        "/domains/bulk-access",
        data={"domain_ids": [str(i) for i in domain_ids], "group_ids": [str(group_id)]},
        headers=_auth_header(),
    )

    resp = client.get(f"/groups/{group_id}", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Assigned sites (60)" in body
    assert "Page 1 of 2" in body
    assert "showing 1-50 of 60" in body


def test_group_detail_assigned_sites_second_page_shows_the_rest(client, db_conn):
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    for i in range(60):
        client.post(
            "/domains/add", data={"pattern": f"site{i:04d}\\.example", "mode": "splice"}, headers=_auth_header()
        )
    domain_ids = [r["id"] for r in db_conn.execute("SELECT id FROM domains")]
    client.post(
        "/domains/bulk-access",
        data={"domain_ids": [str(i) for i in domain_ids], "group_ids": [str(group_id)]},
        headers=_auth_header(),
    )

    resp = client.get(f"/groups/{group_id}?page=2", headers=_auth_header())

    assert resp.status_code == 200
    assert "Page 2 of 2" in resp.data.decode()


def test_group_detail_assigned_sites_small_list_shows_no_pagination_controls(client, db_conn):
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    domain_id = db_conn.execute("SELECT id FROM domains").fetchone()["id"]
    client.post(
        "/domains/access", data={"domain_id": domain_id, "group_ids": [str(group_id)]}, headers=_auth_header()
    )

    resp = client.get(f"/groups/{group_id}", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Page 1 of" not in resp.data


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


# ============================================================
# Group "Ignore mode" (added 2026-09-07, project owner's explicit
# request: "For Device groups, I need to be able to enable 'ignore
# mode' for specific device groups")
# ============================================================

def test_update_group_ignored_turns_it_on_and_off(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]

    resp = client.post("/groups/ignored", data={"group_id": group_id, "ignored": "1"}, headers=_auth_header())
    assert resp.status_code == 302
    assert db_conn.execute("SELECT ignored FROM groups WHERE id = ?", (group_id,)).fetchone()["ignored"] == 1

    client.post("/groups/ignored", data={"group_id": group_id}, headers=_auth_header())
    assert db_conn.execute("SELECT ignored FROM groups WHERE id = ?", (group_id,)).fetchone()["ignored"] == 0


def test_update_group_ignored_requires_admin_auth(client):
    resp = client.post("/groups/ignored", data={"group_id": "1", "ignored": "1"})
    assert resp.status_code == 401


def test_group_detail_shows_ignore_mode_badge_and_toggle(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post("/groups/ignored", data={"group_id": group_id, "ignored": "1"}, headers=_auth_header())

    resp = client.get(f"/groups/{group_id}", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Ignore mode" in resp.data
    assert b'action="/groups/ignored"' in resp.data


def test_pause_group_refuses_when_group_itself_is_ignored(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:60", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )
    client.post("/groups/ignored", data={"group_id": group_id, "ignored": "1"}, headers=_auth_header())

    resp = client.post("/groups/pause", data={"group_id": group_id}, headers=_auth_header())

    assert "error=1" in resp.headers["Location"]
    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:60'").fetchone()
    assert row["quarantined_at"] is None


def test_pause_all_devices_skips_devices_in_an_ignored_group(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:61", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )
    client.post("/groups/ignored", data={"group_id": group_id, "ignored": "1"}, headers=_auth_header())

    client.post("/devices/pause-all", data={}, headers=_auth_header())

    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:61'").fetchone()
    assert row["quarantined_at"] is None


def test_devices_page_shows_ignored_badge_for_a_device_in_an_ignored_group(client, db_conn):
    client.post("/groups/add", data={"name": "IoT"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:62", "label": "Fridge", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )
    client.post("/groups/ignored", data={"group_id": group_id, "ignored": "1"}, headers=_auth_header())

    resp = client.get("/devices", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    fridge_row_start = body.index("Fridge")
    assert "Ignored" in body[fridge_row_start:fridge_row_start + 400]


# ============================================================
# Devices bulk "Ignore" action (added 2026-09-07, project owner's
# explicit request: "The bulk add to group exists, but the bulk add to
# ignore does not.")
# ============================================================

def test_bulk_set_ignored_devices_sets_ignore_and_clears_assignment(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:63", "assignment": f"user:{user_id}"},
        headers=_auth_header(),
    )
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:64"}, headers=_auth_header())
    ids = [r["id"] for r in db_conn.execute("SELECT id FROM devices")]

    resp = client.post(
        "/devices/bulk-ignore", data={"device_ids": [str(i) for i in ids], "ignored": "1"}, headers=_auth_header()
    )

    assert resp.status_code == 302
    rows = db_conn.execute("SELECT ignored, user_id, group_id FROM devices").fetchall()
    assert all(r["ignored"] == 1 for r in rows)
    assert all(r["user_id"] is None for r in rows)
    assert all(r["group_id"] is None for r in rows)


def test_bulk_set_ignored_devices_can_remove_ignore(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:65", "assignment": "ignored"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()["id"]

    resp = client.post("/devices/bulk-ignore", data={"device_ids": [str(device_id)]}, headers=_auth_header())

    assert resp.status_code == 302
    row = db_conn.execute("SELECT ignored FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["ignored"] == 0


def test_bulk_set_ignored_devices_without_selection_shows_error(client, db_conn):
    resp = client.post("/devices/bulk-ignore", data={"ignored": "1"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_bulk_set_ignored_devices_requires_admin_auth(client):
    resp = client.post("/devices/bulk-ignore", data={"device_ids": ["1"], "ignored": "1"})
    assert resp.status_code == 401


def test_devices_page_manage_panel_has_ignore_bulk_buttons(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:66"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    assert resp.status_code == 200
    assert b'action="/devices/bulk-ignore"' in resp.data
    assert b'id="bulkDeviceIgnoreForm"' in resp.data
    assert b'id="bulkDeviceUnignoreForm"' in resp.data


# ============================================================
# RoadMap.md item 23 (2026-09-09, project owner's explicit request: "I
# realized I want to add an 'Add to ignore' option on the devices main
# page without having to directly open the individual device. I want
# that option for bulk settings too."): a per-row quick Ignore/Un-ignore
# action (previously only reachable by opening a device's own detail
# page), and the bulk Ignore/Un-ignore buttons promoted from the
# collapsed "Manage" panel to the main toolbar row, alongside
# Enable/Disable/Delete.
# ============================================================

def test_bulk_ignore_buttons_are_in_the_main_toolbar_not_the_manage_panel(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:70"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    body = resp.data.decode()
    toolbar = body[body.index('id="deviceBulkToolbar"'):body.index('id="deviceBulkManagePanel"')]
    assert 'id="bulkDeviceIgnoreForm"' in toolbar
    assert 'id="bulkDeviceUnignoreForm"' in toolbar


def test_devices_table_row_shows_a_quick_ignore_button_for_an_unassigned_device(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:71"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    body = resp.data.decode()
    row_start = body.index("aa:bb:cc:dd:ee:71")
    row = body[row_start:body.index("</tr>", row_start)]
    assert ">Ignore<" in row


def test_devices_table_quick_ignore_button_actually_ignores_the_device(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:72"}, headers=_auth_header())
    device_id = db_conn.execute("SELECT id FROM devices").fetchone()["id"]

    resp = client.post(
        "/devices/bulk-ignore", data={"device_ids": [str(device_id)], "ignored": "1"}, headers=_auth_header()
    )

    assert resp.status_code == 302
    assert db_conn.execute("SELECT ignored FROM devices WHERE id = ?", (device_id,)).fetchone()["ignored"] == 1


def test_devices_table_row_shows_un_ignore_for_an_already_ignored_device(client, db_conn):
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:73", "assignment": "ignored"}, headers=_auth_header()
    )
    resp = client.get("/devices", headers=_auth_header())
    body = resp.data.decode()
    row_start = body.index("aa:bb:cc:dd:ee:73")
    row = body[row_start:body.index("</tr>", row_start)]
    assert ">Un-ignore<" in row


def test_devices_table_row_hides_the_quick_toggle_for_a_group_ignored_device(client, db_conn):
    """A device that's only effectively ignored because its GROUP is in
    Ignore mode (devices.ignored itself still 0) must not show a
    misleading per-row "Ignore" button that would look actionable but
    change nothing real -- see common/policy_class.py's own distinction
    between a device's own `ignored` flag and its group's."""
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    client.post(
        "/groups/ignored", data={"group_id": group_id, "ignored": "1"}, headers=_auth_header()
    )
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:74", "assignment": f"group:{group_id}"},
        headers=_auth_header(),
    )

    resp = client.get("/devices", headers=_auth_header())
    body = resp.data.decode()
    # ">Ignore<"/">Un-ignore<" also appear in the page's own bulk-toolbar
    # buttons regardless of any row's state -- isolate this device's own
    # table row before asserting, rather than searching the whole page.
    row_start = body.index("aa:bb:cc:dd:ee:74")
    row = body[row_start:body.index("</tr>", row_start)]
    assert ">Ignore<" not in row
    assert ">Un-ignore<" not in row


def test_pending_devices_card_shows_a_quick_ignore_button(client, db_conn):
    _add_pending_device(db_conn, "aa:bb:cc:dd:ee:75")
    resp = client.get("/devices", headers=_auth_header())
    body = resp.data.decode()
    assert "Devices awaiting login" in body
    # Scope to the pending-devices card itself (up to the next top-level
    # card, "Groups") -- the main Devices table's own toolbar further
    # down the page also always has an "Ignore" button, regardless of
    # this device.
    card = body[body.index("Devices awaiting login"):body.index('<h2>Groups')]
    assert ">Ignore<" in card


def test_pending_devices_card_quick_ignore_button_actually_ignores_it(client, db_conn):
    device_id = _add_pending_device(db_conn, "aa:bb:cc:dd:ee:76")

    resp = client.post(
        "/devices/bulk-ignore", data={"device_ids": [str(device_id)], "ignored": "1"}, headers=_auth_header()
    )

    assert resp.status_code == 302
    assert db_conn.execute("SELECT ignored FROM devices WHERE id = ?", (device_id,)).fetchone()["ignored"] == 1


# ============================================================
# Devices page pagination -- added 2026-09-07, project owner's explicit
# request ("check the devices... page for the same issues... use the
# page-size picker with the prev/next configuration"), same reasoning as
# the Categories domain-list pagination the same day: these lists can
# grow extensively with time.
# ============================================================

def _add_devices(client, count, prefix="aa:bb:cc:dd"):
    for i in range(count):
        client.post(
            "/devices/add", data={"mac_address": f"{prefix}:{i // 256:02x}:{i % 256:02x}"},
            headers=_auth_header(),
        )


def test_devices_page_paginates_with_a_default_page_size(client, db_conn):
    _add_devices(client, 60)
    resp = client.get("/devices", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Page 1 of 2" in body
    assert "showing 1-50 of 60" in body


def test_devices_page_second_page_shows_the_remaining_devices(client, db_conn):
    _add_devices(client, 60)
    resp = client.get("/devices?page=2", headers=_auth_header())
    assert resp.status_code == 200
    assert "Page 2 of 2" in resp.data.decode()


def test_devices_page_pending_card_is_not_limited_by_pagination(client, db_conn):
    """The "awaiting login" card must show every pending device regardless
    of which page of the full roster is showing -- it's a separate query
    now, not a Jinja filter over the (paginated) main list."""
    import identity

    # 55 ordinary devices (more than one page at the default size) plus
    # one genuinely pending one (auto-created via record_binding(), same
    # as a real never-seen MAC would be).
    _add_devices(client, 55)
    identity.record_binding(db_conn, "11:22:33:44:55:66", "192.168.1.99", source="rtnetlink")

    resp = client.get("/devices?per_page=25", headers=_auth_header())

    assert resp.status_code == 200
    assert b"11:22:33:44:55:66" in resp.data
    assert b"Devices awaiting login (1)" in resp.data


def test_devices_page_small_list_shows_no_pagination_controls(client, db_conn):
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:01"}, headers=_auth_header())
    resp = client.get("/devices", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Page 1 of" not in resp.data


def test_devices_page_rejects_an_arbitrary_per_page_value(client, db_conn):
    _add_devices(client, 60)
    resp = client.get("/devices?per_page=999999", headers=_auth_header())
    body = resp.data.decode()
    assert "Page 1 of 2" in body  # fell back to the default page size, not one giant page


def test_devices_page_search_filters_by_label_or_mac(client, db_conn):
    """Added 2026-09-08, project owner's explicit follow-up request:
    once the main roster paginates, the old client-side search box would
    have only searched whichever page was on screen -- this is now a
    real server-side search across the whole table."""
    _add_devices(client, 5)
    client.post(
        "/devices/add", data={"mac_address": "11:22:33:44:55:66", "label": "Kitchen TV"},
        headers=_auth_header(),
    )

    resp = client.get("/devices?q=Kitchen", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "11:22:33:44:55:66" in body
    assert "aa:bb:cc:dd:00:00" not in body
    assert "showing 1-1 of 1" in body


def test_devices_page_search_does_not_limit_the_pending_card(client, db_conn):
    """The "awaiting login" card is intentionally NOT filtered by the
    main roster's search box -- it always lists every pending device."""
    import identity

    _add_devices(client, 5)
    identity.record_binding(db_conn, "11:22:33:44:55:66", "192.168.1.99", source="rtnetlink")

    resp = client.get("/devices?q=nonexistent-search-term", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Devices awaiting login (1)" in resp.data
    assert b"11:22:33:44:55:66" in resp.data


def test_devices_page_search_with_no_matches_still_shows_the_search_box(client, db_conn):
    _add_devices(client, 3)
    resp = client.get("/devices?q=nonexistent-search-term", headers=_auth_header())
    body = resp.data.decode()
    assert resp.status_code == 200
    assert 'name="q"' in body
    assert "No devices match" in body


def test_devices_page_search_is_carried_across_pagination_links(client, db_conn):
    _add_devices(client, 60, prefix="aa:aa:aa:aa")  # all share a common prefix to match on
    resp = client.get("/devices?q=aa:aa:aa:aa&per_page=25", headers=_auth_header())
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "Page 1 of 3" in body
    assert "q=aa" in body  # carried into the Next link's href


# ============================================================
# Domains page pagination -- same request/reasoning as Devices above
# ============================================================

def _add_domains(client, count):
    for i in range(count):
        client.post(
            "/domains/add", data={"pattern": f"site{i:04d}\\.example", "mode": "splice"},
            headers=_auth_header(),
        )


def test_domains_page_paginates_with_a_default_page_size(client, db_conn):
    _add_domains(client, 60)
    resp = client.get("/domains", headers=_auth_header())
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Page 1 of 2" in body
    assert "showing 1-50 of 60" in body


def test_domains_page_second_page_shows_the_remaining_domains(client, db_conn):
    _add_domains(client, 60)
    resp = client.get("/domains?page=2", headers=_auth_header())
    assert resp.status_code == 200
    assert "Page 2 of 2" in resp.data.decode()


def test_domains_page_pagination_preserves_an_active_group_filter(client, db_conn):
    """Clicking Next on a filtered view must not silently drop back to
    the unfiltered full list."""
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())
    group_id = db_conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    _add_domains(client, 60)
    domain_ids = [r["id"] for r in db_conn.execute("SELECT id FROM domains")]
    client.post(
        "/domains/bulk-access",
        data={"domain_ids": [str(i) for i in domain_ids], "group_ids": [str(group_id)]},
        headers=_auth_header(),
    )

    resp = client.get(f"/domains?group_id={group_id}", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert f'name="group_id" value="{group_id}"' in body
    assert f"group_id={group_id}" in body  # carried into the Next link's href too


def test_domains_page_small_list_shows_no_pagination_controls(client, db_conn):
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    resp = client.get("/domains", headers=_auth_header())
    assert resp.status_code == 200
    assert b"Page 1 of" not in resp.data


def test_domains_page_search_filters_by_pattern_or_note(client, db_conn):
    """Added 2026-09-08, project owner's explicit follow-up request --
    same reasoning as Devices' search above."""
    _add_domains(client, 5)
    client.post(
        "/domains/add", data={"pattern": "netflix\\.example", "mode": "splice", "note": "streaming"},
        headers=_auth_header(),
    )

    resp = client.get("/domains?q=netflix", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "netflix" in body
    assert "site0000" not in body
    assert "showing 1-1 of 1" in body

    resp = client.get("/domains?q=streaming", headers=_auth_header())
    assert "netflix" in resp.data.decode()


def test_domains_page_search_with_no_matches_still_shows_the_search_box(client, db_conn):
    _add_domains(client, 3)
    resp = client.get("/domains?q=nonexistent-search-term", headers=_auth_header())
    body = resp.data.decode()
    assert resp.status_code == 200
    assert 'name="q"' in body
    assert "No domains match" in body


def test_domains_page_search_is_carried_across_pagination_links(client, db_conn):
    _add_domains(client, 60)
    resp = client.get("/domains?q=site&per_page=25", headers=_auth_header())
    body = resp.data.decode()
    assert resp.status_code == 200
    assert "Page 1 of 3" in body
    assert "q=site" in body  # carried into the Next link's href


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
# Logout (HTTP Basic Auth has no real server-side session -- rewritten
# 2026-09-09 after a real live lockout, see the /logout route's own
# docstring for the full story: the previous fake-credential URL trick
# caused several browsers to cache "logout" as the username and keep
# resubmitting it on every later login attempt, defeating even a
# correct password.)
# ============================================================

def test_logout_page_reachable_with_no_credentials_at_all(client):
    """Must stay reachable even to someone currently unable to log in --
    unlike every other page in this app, no @require_admin here."""
    resp = client.get("/logout")
    assert resp.status_code == 200
    assert "WWW-Authenticate" not in resp.headers


def test_logout_page_explains_the_real_manual_step(client):
    resp = client.get("/logout")
    body = resp.data.decode()
    assert "close" in body.lower()
    assert "saved password" in body.lower() or "saved login" in body.lower()


def test_logout_page_does_not_prompt_for_or_accept_any_credential_check(client):
    """The old bogus-credential trick actively poisoned some browsers'
    cached username -- confirm this page never even looks at whatever
    Authorization header a browser might still be sending."""
    resp = client.get("/logout", headers=_auth_header(username="logout", password="logout"))
    assert resp.status_code == 200


def test_sidebar_logout_link_has_no_embedded_credentials(client, db_conn):
    """Real regression check for the fix itself: the sidebar link must
    never again embed a username:password@ pair in its href -- that's
    exactly the mechanism that poisoned browsers' cached credentials."""
    resp = client.get("/report", headers=_auth_header())
    assert b"logout:logout@" not in resp.data


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


# ============================================================
# Bulk-actions toolbar extended to Users/Categories/Schedules (RoadMap.md's
# dated entry -- "implement the same design change... to the rest of the
# page such as users, devices, schedules, categories")
# ============================================================

def test_users_page_has_bulk_actions_toolbar(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    resp = client.get("/users", headers=_auth_header())
    assert resp.status_code == 200
    assert b'href="/users/export"' in resp.data
    assert b'action="/users/bulk-resume"' in resp.data
    assert b'action="/users/bulk-pause"' in resp.data
    assert b'action="/users/bulk-delete"' in resp.data
    assert b'class="bulk-user-check"' in resp.data
    assert b'id="userSelectAll"' in resp.data


def test_bulk_delete_users_removes_every_selected_user(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid3", "password": "pw"}, headers=_auth_header())
    to_delete = [r["id"] for r in db_conn.execute("SELECT id FROM users WHERE username IN ('kid1','kid2')")]

    resp = client.post("/users/bulk-delete", data={"user_ids": [str(i) for i in to_delete]}, headers=_auth_header())

    assert resp.status_code == 302
    remaining = {r["username"] for r in db_conn.execute("SELECT username FROM users")}
    assert remaining == {"kid3"}


def test_bulk_delete_users_without_selection_shows_error(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    resp = client.post("/users/bulk-delete", data={}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 1


def test_bulk_pause_users_pauses_every_selected_users_devices(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:40", "assignment": f"user:{user_id}"},
        headers=_auth_header(),
    )

    resp = client.post("/users/bulk-pause", data={"user_ids": [str(user_id)]}, headers=_auth_header())

    assert resp.status_code == 302
    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE user_id = ?", (user_id,)).fetchone()
    assert row["quarantined_at"] is not None


def test_bulk_resume_users_resumes_every_selected_users_devices(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    client.post(
        "/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:41", "assignment": f"user:{user_id}"},
        headers=_auth_header(),
    )
    client.post("/users/pause", data={"user_id": user_id}, headers=_auth_header())

    resp = client.post("/users/bulk-resume", data={"user_ids": [str(user_id)]}, headers=_auth_header())

    assert resp.status_code == 302
    row = db_conn.execute("SELECT quarantined_at FROM devices WHERE user_id = ?", (user_id,)).fetchone()
    assert row["quarantined_at"] is None


def test_bulk_pause_and_resume_users_without_selection_shows_error(client, db_conn):
    resp = client.post("/users/bulk-pause", data={}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    resp = client.post("/users/bulk-resume", data={}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_export_users_csv_includes_every_user_and_key_fields(client, db_conn):
    client.post(
        "/users/add", data={"username": "kid1", "display_name": "Kid One", "password": "pw"},
        headers=_auth_header(),
    )

    resp = client.get("/users/export", headers=_auth_header())

    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in resp.headers["Content-Disposition"]
    body = resp.data.decode()
    assert "kid1" in body
    assert "Kid One" in body


def test_export_users_csv_requires_admin_auth(client):
    resp = client.get("/users/export")
    assert resp.status_code == 401


def test_categories_page_has_bulk_actions_toolbar(client, db_conn):
    client.post("/categories/add", data={"name": "TestCat"}, headers=_auth_header())
    resp = client.get("/categories", headers=_auth_header())
    assert resp.status_code == 200
    assert b'href="/categories/export"' in resp.data
    assert b'action="/categories/bulk-delete"' in resp.data
    assert b'class="bulk-category-check"' in resp.data
    assert b'id="categorySelectAll"' in resp.data


def test_bulk_delete_categories_removes_every_selected_category(client, db_conn):
    client.post("/categories/add", data={"name": "Cat1"}, headers=_auth_header())
    client.post("/categories/add", data={"name": "Cat2"}, headers=_auth_header())
    client.post("/categories/add", data={"name": "Cat3"}, headers=_auth_header())
    to_delete = [r["id"] for r in db_conn.execute("SELECT id FROM categories WHERE name IN ('Cat1','Cat2')")]

    resp = client.post(
        "/categories/bulk-delete", data={"category_ids": [str(i) for i in to_delete]}, headers=_auth_header()
    )

    assert resp.status_code == 302
    remaining = {r["name"] for r in db_conn.execute("SELECT name FROM categories")}
    assert remaining == {"Cat3"}


def test_bulk_delete_categories_without_selection_shows_error(client, db_conn):
    client.post("/categories/add", data={"name": "Cat1"}, headers=_auth_header())
    resp = client.post("/categories/bulk-delete", data={}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT COUNT(*) c FROM categories").fetchone()["c"] == 1


def test_export_categories_csv_includes_every_category_and_key_fields(client, db_conn):
    client.post(
        "/categories/add", data={"name": "TestCat", "subscription_url": "https://example.invalid/list.txt"},
        headers=_auth_header(),
    )

    resp = client.get("/categories/export", headers=_auth_header())

    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")
    body = resp.data.decode()
    assert "TestCat" in body
    assert "https://example.invalid/list.txt" in body


def test_export_categories_csv_requires_admin_auth(client):
    resp = client.get("/categories/export")
    assert resp.status_code == 401


# ============================================================
# Categories toolbar: bulk access assignment + bulk sync (added
# 2026-09-07, project owner's explicit request: "Add the ability for me
# to bulk assign categories to users, groups, or everyone" and "Add the
# ability for me to bulk sync categories")
# ============================================================

def test_categories_page_has_manage_access_and_sync_buttons(client, db_conn):
    client.post("/categories/add", data={"name": "Cat1"}, headers=_auth_header())
    resp = client.get("/categories", headers=_auth_header())
    assert resp.status_code == 200
    assert b'id="categoryBulkManageToggle"' in resp.data
    assert b'action="/categories/bulk-access"' in resp.data
    assert b'action="/categories/bulk-sync"' in resp.data


def test_bulk_update_category_access_applies_to_every_selected_category(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    client.post("/categories/add", data={"name": "Cat1"}, headers=_auth_header())
    client.post("/categories/add", data={"name": "Cat2"}, headers=_auth_header())
    category_ids = [r["id"] for r in db_conn.execute("SELECT id FROM categories WHERE name IN ('Cat1','Cat2')")]

    resp = client.post(
        "/categories/bulk-access",
        data={"category_ids": [str(i) for i in category_ids], "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/categories")
    for category_id in category_ids:
        assert db_conn.execute(
            "SELECT 1 FROM category_users WHERE user_id = ? AND category_id = ?", (user_id, category_id)
        ).fetchone() is not None


def test_bulk_update_category_access_can_set_global(client, db_conn):
    client.post("/categories/add", data={"name": "Cat1"}, headers=_auth_header())
    client.post("/categories/add", data={"name": "Cat2"}, headers=_auth_header())
    category_ids = [r["id"] for r in db_conn.execute("SELECT id FROM categories")]

    client.post(
        "/categories/bulk-access",
        data={"category_ids": [str(i) for i in category_ids], "is_global": "on"},
        headers=_auth_header(),
    )

    rows = db_conn.execute("SELECT is_global FROM categories").fetchall()
    assert all(r["is_global"] == 1 for r in rows)


def test_bulk_update_category_access_skips_oversized_category_requesting_scoped_access(client, db_conn, monkeypatch):
    import matching

    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    client.post("/categories/add", data={"name": "Huge"}, headers=_auth_header())
    client.post("/categories/add", data={"name": "Small"}, headers=_auth_header())
    huge_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Huge'").fetchone()["id"]
    small_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Small'").fetchone()["id"]
    db_conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, 'x', 'manual', datetime('now'))",
        (huge_id,),
    )
    db_conn.commit()
    # Cheaper than inserting 5001 real rows to exceed the real threshold:
    # monkeypatch it down so "Huge"'s one domain already counts as oversized.
    monkeypatch.setattr(matching, "MAX_SCOPED_CATEGORY_DOMAINS", 0)

    resp = client.post(
        "/categories/bulk-access",
        data={"category_ids": [str(huge_id), str(small_id)], "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert "Huge" in resp.headers["Location"]
    assert db_conn.execute(
        "SELECT 1 FROM category_users WHERE user_id = ? AND category_id = ?", (user_id, huge_id)
    ).fetchone() is None
    assert db_conn.execute(
        "SELECT 1 FROM category_users WHERE user_id = ? AND category_id = ?", (user_id, small_id)
    ).fetchone() is not None


def test_bulk_update_category_access_without_selection_shows_error(client, db_conn):
    resp = client.post("/categories/bulk-access", data={"is_global": "on"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_bulk_update_category_access_requires_admin_auth(client):
    resp = client.post("/categories/bulk-access", data={"category_ids": ["1"], "is_global": "on"})
    assert resp.status_code == 401


def _add_schedule(client, name, **overrides):
    data = {
        "name": name, "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
        "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC",
    }
    data.update(overrides)
    client.post("/schedules/add", data=data, headers=_auth_header())


def test_bulk_update_schedule_access_applies_to_every_selected_schedule(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    _add_schedule(client, "Sched1")
    _add_schedule(client, "Sched2")
    schedule_ids = [r["id"] for r in db_conn.execute("SELECT id FROM schedules WHERE name IN ('Sched1','Sched2')")]

    resp = client.post(
        "/schedules/bulk-access",
        data={"schedule_ids": [str(i) for i in schedule_ids], "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].startswith("/schedules")
    for schedule_id in schedule_ids:
        assert db_conn.execute(
            "SELECT 1 FROM schedule_users WHERE user_id = ? AND schedule_id = ?", (user_id, schedule_id)
        ).fetchone() is not None


def test_bulk_update_schedule_access_can_set_global(client, db_conn):
    _add_schedule(client, "Sched1")
    _add_schedule(client, "Sched2")
    schedule_ids = [r["id"] for r in db_conn.execute("SELECT id FROM schedules")]

    client.post(
        "/schedules/bulk-access",
        data={"schedule_ids": [str(i) for i in schedule_ids], "is_global": "on"},
        headers=_auth_header(),
    )

    rows = db_conn.execute("SELECT is_global FROM schedules").fetchall()
    assert all(r["is_global"] == 1 for r in rows)


def test_bulk_update_schedule_access_replaces_rather_than_adds(client, db_conn):
    """Same "grant and revoke are the same action" contract as
    _replace_category_access() -- a schedule previously assigned to one
    user, bulk-assigned to a different user, ends up with ONLY the new
    user, not both."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    client.post("/users/add", data={"username": "kid2", "password": "pw"}, headers=_auth_header())
    kid1_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    kid2_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid2'").fetchone()["id"]
    _add_schedule(client, "Sched1")
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Sched1'").fetchone()["id"]
    db_conn.execute("INSERT INTO schedule_users (schedule_id, user_id) VALUES (?, ?)", (schedule_id, kid1_id))
    db_conn.commit()

    client.post(
        "/schedules/bulk-access",
        data={"schedule_ids": [str(schedule_id)], "user_ids": [str(kid2_id)]},
        headers=_auth_header(),
    )

    targets = {r["user_id"] for r in db_conn.execute(
        "SELECT user_id FROM schedule_users WHERE schedule_id = ?", (schedule_id,)
    )}
    assert targets == {kid2_id}


def test_bulk_update_schedule_access_does_not_touch_what_a_schedule_blocks(client, db_conn):
    """Bulk-assigning targets must leave lockout_all/is_mode/schedule_categories
    completely untouched -- only who the schedule applies to changes."""
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    _add_schedule(client, "Bedtime", lockout_all="on", is_mode="on")
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Bedtime'").fetchone()["id"]

    client.post(
        "/schedules/bulk-access",
        data={"schedule_ids": [str(schedule_id)], "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )

    row = db_conn.execute("SELECT lockout_all, is_mode FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    assert row["lockout_all"] == 1
    assert row["is_mode"] == 1


def test_bulk_update_schedule_access_ignores_a_nonexistent_schedule_id(client, db_conn):
    client.post("/users/add", data={"username": "kid1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    _add_schedule(client, "Sched1")
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Sched1'").fetchone()["id"]

    resp = client.post(
        "/schedules/bulk-access",
        data={"schedule_ids": [str(schedule_id), "999999"], "user_ids": [str(user_id)]},
        headers=_auth_header(),
    )

    assert "error=1" not in resp.headers["Location"]
    assert db_conn.execute(
        "SELECT 1 FROM schedule_users WHERE user_id = ? AND schedule_id = ?", (user_id, schedule_id)
    ).fetchone() is not None


def test_bulk_update_schedule_access_without_selection_shows_error(client, db_conn):
    resp = client.post("/schedules/bulk-access", data={"is_global": "on"}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_bulk_update_schedule_access_requires_admin_auth(client):
    resp = client.post("/schedules/bulk-access", data={"schedule_ids": ["1"], "is_global": "on"})
    assert resp.status_code == 401


def test_schedules_page_shows_bulk_manage_access_toolbar(client, db_conn):
    _add_schedule(client, "Sched1")
    resp = client.get("/schedules", headers=_auth_header())
    body = resp.data.decode()
    assert "scheduleBulkManageToggle" in body
    assert "bulk_update_schedule_access" in body or "/schedules/bulk-access" in body


def test_bulk_sync_categories_syncs_every_selected_subscribed_category(client, db_conn, monkeypatch):
    import category_fetch

    client.post(
        "/categories/add", data={"name": "Cat1", "subscription_url": "https://example.invalid/a.txt"},
        headers=_auth_header(),
    )
    client.post(
        "/categories/add", data={"name": "Cat2", "subscription_url": "https://example.invalid/b.txt"},
        headers=_auth_header(),
    )
    ids = [r["id"] for r in db_conn.execute("SELECT id FROM categories")]
    monkeypatch.setattr(category_fetch, "fetch_and_sync_category", lambda conn, category, timeout=None: 10)

    resp = client.post(
        "/categories/bulk-sync", data={"category_ids": [str(i) for i in ids]}, headers=_auth_header()
    )

    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    assert "20" in resp.headers["Location"]  # 10 + 10 domains total


def test_bulk_sync_categories_skips_manual_only_categories(client, db_conn, monkeypatch):
    import category_fetch

    client.post("/categories/add", data={"name": "ManualOnly"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'ManualOnly'").fetchone()["id"]
    called = []
    monkeypatch.setattr(
        category_fetch, "fetch_and_sync_category",
        lambda conn, category, timeout=None: called.append(category) or 0,
    )

    resp = client.post(
        "/categories/bulk-sync", data={"category_ids": [str(category_id)]}, headers=_auth_header()
    )

    assert resp.status_code == 302
    assert not called
    assert "ManualOnly" in resp.headers["Location"]


def test_bulk_sync_categories_reports_a_failure_without_aborting_the_rest(client, db_conn, monkeypatch):
    import category_fetch

    client.post(
        "/categories/add", data={"name": "Broken", "subscription_url": "https://example.invalid/broken.txt"},
        headers=_auth_header(),
    )
    client.post(
        "/categories/add", data={"name": "Good", "subscription_url": "https://example.invalid/good.txt"},
        headers=_auth_header(),
    )
    ids = {
        r["name"]: r["id"] for r in db_conn.execute("SELECT id, name FROM categories WHERE name IN ('Broken', 'Good')")
    }

    def _fake(conn, category, timeout=None):
        if category["name"] == "Broken":
            raise category_fetch.CategoryFetchError("could not reach host")
        return 5

    monkeypatch.setattr(category_fetch, "fetch_and_sync_category", _fake)

    resp = client.post(
        "/categories/bulk-sync",
        data={"category_ids": [str(ids["Broken"]), str(ids["Good"])]},
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    message = resp.headers["Location"]
    assert "Broken" in message
    assert "could+not+reach+host" in message


def test_bulk_sync_categories_without_selection_shows_error(client, db_conn):
    resp = client.post("/categories/bulk-sync", data={}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]


def test_bulk_sync_categories_requires_admin_auth(client):
    resp = client.post("/categories/bulk-sync", data={"category_ids": ["1"]})
    assert resp.status_code == 401


def test_schedules_page_has_bulk_actions_toolbar(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "Bedtime", "days": ["mon"], "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    resp = client.get("/schedules", headers=_auth_header())
    assert resp.status_code == 200
    assert b'href="/schedules/export"' in resp.data
    assert b'action="/schedules/bulk-delete"' in resp.data
    assert b'class="bulk-schedule-check"' in resp.data
    assert b'id="scheduleSelectAll"' in resp.data


def test_bulk_delete_schedules_removes_every_selected_schedule(client, db_conn):
    for name in ("Sched1", "Sched2", "Sched3"):
        client.post(
            "/schedules/add",
            data={"name": name, "days": ["mon"], "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC"},
            headers=_auth_header(),
        )
    to_delete = [r["id"] for r in db_conn.execute("SELECT id FROM schedules WHERE name IN ('Sched1','Sched2')")]

    resp = client.post(
        "/schedules/bulk-delete", data={"schedule_ids": [str(i) for i in to_delete]}, headers=_auth_header()
    )

    assert resp.status_code == 302
    remaining = {r["name"] for r in db_conn.execute("SELECT name FROM schedules")}
    assert remaining == {"Sched3"}


def test_bulk_delete_schedules_without_selection_shows_error(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "Sched1", "days": ["mon"], "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    resp = client.post("/schedules/bulk-delete", data={}, headers=_auth_header())
    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute("SELECT COUNT(*) c FROM schedules").fetchone()["c"] == 1


def test_export_schedules_csv_includes_every_schedule_and_key_fields(client, db_conn):
    client.post(
        "/schedules/add",
        data={"name": "Bedtime", "days": ["mon"], "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC", "lockout_all": "on"},
        headers=_auth_header(),
    )

    resp = client.get("/schedules/export", headers=_auth_header())

    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("text/csv")
    body = resp.data.decode()
    assert "Bedtime" in body
    assert "Full lockout" in body


def test_export_schedules_csv_requires_admin_auth(client):
    resp = client.get("/schedules/export")
    assert resp.status_code == 401


def test_domains_and_devices_pages_have_search_boxes(client, db_conn):
    # Domains/Devices search server-side (name="q") since both paginate;
    # Groups doesn't paginate so it keeps the old client-side
    # data-filter-table mechanism.
    client.post("/domains/add", data={"pattern": r"example\.com", "mode": "splice"}, headers=_auth_header())
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:30"}, headers=_auth_header())
    client.post("/groups/add", data={"name": "TVs"}, headers=_auth_header())

    resp = client.get("/domains", headers=_auth_header())
    assert b'name="q"' in resp.data

    resp = client.get("/devices", headers=_auth_header())
    assert b'name="q"' in resp.data
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
    """days_ago=None means genuinely never seen -- no device_bindings row
    at all, same as a device added by hand that's never actually shown
    up on the network. Otherwise inserts a real device_bindings row with
    a backdated last_seen_at -- the REAL data source _stale_devices()
    reads (fixed 2026-09-07, RoadMap.md's dated entry): devices.
    last_seen_at itself is never written by anything real, so a test
    that only set THAT column (as this helper used to) would validate a
    scenario that can never actually occur in production."""
    import db as db_mod
    db_conn.execute(
        "INSERT INTO devices (mac_address, created_at) VALUES (?, datetime('now'))", (mac,)
    )
    db_conn.commit()
    if days_ago is not None:
        ts = db_mod.iso_secs_ago(days_ago * 86400)
        db_conn.execute(
            "INSERT INTO device_bindings (mac_address, ipv4_address, first_seen_at, last_seen_at, source) "
            "VALUES (?, ?, ?, ?, 'rtnetlink')",
            (mac, f"192.168.1.{200 + abs(hash(mac)) % 50}", ts, ts),
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


def test_settings_page_shows_a_clickable_table_of_which_devices_are_stale(client, db_conn):
    """Real live-testing feedback (RoadMap.md's dated entry): the old
    card only ever showed a bare count -- no way to see WHICH devices,
    or their MAC/label/assignment, without going elsewhere first."""
    import db as db_mod
    db_conn.execute(
        "INSERT INTO devices (mac_address, label, created_at) VALUES (?, ?, datetime('now'))",
        ("aa:bb:cc:dd:ee:43", "Old Tablet"),
    )
    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:43'").fetchone()["id"]
    ts = db_mod.iso_secs_ago(100 * 86400)
    db_conn.execute(
        "INSERT INTO device_bindings (mac_address, ipv4_address, first_seen_at, last_seen_at, source) "
        "VALUES (?, '192.168.1.99', ?, ?, 'rtnetlink')",
        ("aa:bb:cc:dd:ee:43", ts, ts),
    )
    db_conn.commit()

    client.post("/settings/device-stale-days", data={"device_stale_days": "30"}, headers=_auth_header())
    resp = client.get("/settings", headers=_auth_header())

    assert b"Old Tablet" in resp.data
    assert b"aa:bb:cc:dd:ee:43" in resp.data
    assert f'href="/devices/{device_id}"'.encode() in resp.data


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


# ============================================================
# Category detail domain-list pagination -- added 2026-09-07, project
# owner's explicit request: clicking "Manage" on a large category tried
# to load and render every single domain, which was slow and made the
# "Allow-exceptions" card practically unreachable. Paginated like a
# modern list/detail view instead (page-size picker + Prev/Next).
# ============================================================

def _add_categories_domains(db_conn, category_id, count):
    now_rows = [(category_id, f"site{i:04d}\\.example", "manual") for i in range(count)]
    db_conn.executemany(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, ?, datetime('now'))",
        now_rows,
    )
    db_conn.commit()


def test_category_detail_paginates_domains_with_a_default_page_size(client, db_conn):
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 120)

    resp = client.get(f"/categories/{category_id}", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "site0000\\.example" in body
    assert "site0049\\.example" in body
    assert "site0050\\.example" not in body  # default page size: only the first 50 rows render
    assert "Page 1 of 3" in body
    assert "showing 1-50 of 120" in body


def test_category_detail_second_page_shows_the_next_slice(client, db_conn):
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 120)

    resp = client.get(f"/categories/{category_id}?page=2", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "site0050\\.example" in body
    assert "site0000\\.example" not in body
    assert "Page 2 of 3" in body


def test_category_detail_respects_a_valid_per_page_choice(client, db_conn):
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 120)

    resp = client.get(f"/categories/{category_id}?per_page=25", headers=_auth_header())

    body = resp.data.decode()
    assert "site0024\\.example" in body
    assert "site0025\\.example" not in body
    assert "Page 1 of 5" in body


def test_category_detail_rejects_an_arbitrary_per_page_value(client, db_conn):
    """A hand-edited URL asking for e.g. per_page=999999 must not be able
    to force the page back to rendering everything at once -- only the
    real LIST_PAGE_SIZE_OPTIONS values are honored."""
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 120)

    resp = client.get(f"/categories/{category_id}?per_page=999999", headers=_auth_header())

    body = resp.data.decode()
    assert "site0049\\.example" in body
    assert "site0050\\.example" not in body  # fell back to the default page size


def test_category_detail_clamps_a_page_number_past_the_end(client, db_conn):
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 120)

    resp = client.get(f"/categories/{category_id}?page=999", headers=_auth_header())

    assert resp.status_code == 200
    assert "Page 3 of 3" in resp.data.decode()


def test_category_detail_negative_page_does_not_crash_or_go_negative(client, db_conn):
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 120)

    resp = client.get(f"/categories/{category_id}?page=-5", headers=_auth_header())

    assert resp.status_code == 200
    assert "Page 1 of 3" in resp.data.decode()


def test_category_detail_small_category_shows_no_pagination_controls(client, db_conn):
    client.post("/categories/add", data={"name": "Small"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Small'").fetchone()["id"]
    client.post(
        "/categories/domains/add", data={"category_id": category_id, "pattern": r"example\.com"},
        headers=_auth_header(),
    )

    resp = client.get(f"/categories/{category_id}", headers=_auth_header())

    assert resp.status_code == 200
    assert b"Page 1 of" not in resp.data


def test_category_detail_search_filters_the_domain_list(client, db_conn):
    """Added 2026-09-08, project owner's explicit follow-up request --
    same reasoning as Devices/Domains' server-side search: a category's
    domain list is the one list on this site that can genuinely reach
    the hundreds of thousands of rows, so finding one specific domain by
    paging through by hand doesn't scale."""
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 120)

    resp = client.get(f"/categories/{category_id}?q=site0075", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "site0075\\.example" in body
    assert "site0000\\.example" not in body
    assert "showing 1-1 of 1" in body
    assert "Domains (1 of 120)" in body


def test_category_detail_search_with_no_matches_still_shows_the_search_box(client, db_conn):
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 5)

    resp = client.get(f"/categories/{category_id}?q=nonexistent-search-term", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert 'name="q"' in body
    assert "No domains match" in body


def test_category_detail_search_is_carried_across_pagination_links(client, db_conn):
    client.post("/categories/add", data={"name": "Big"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Big'").fetchone()["id"]
    _add_categories_domains(db_conn, category_id, 120)

    resp = client.get(f"/categories/{category_id}?q=site&per_page=25", headers=_auth_header())

    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Page 1 of 5" in body
    assert "q=site" in body  # carried into the Next link's href


# ============================================================
# Category "Add many domains at once" -- added 2026-09-07 (RoadMap.md's
# dated entry, project owner's explicit request to import a whole list of
# sites as one category in a single paste)
# ============================================================

def test_extract_domain_handles_bare_domain_path_and_full_url():
    import dashboard as dashboard_module
    assert dashboard_module._extract_domain("example.com") == "example.com"
    assert dashboard_module._extract_domain("www.example.com") == "example.com"
    assert dashboard_module._extract_domain("https://www.example.com/some/page") == "example.com"
    assert dashboard_module._extract_domain("example.com/some/page") == "example.com"
    assert dashboard_module._extract_domain("  ") is None
    assert dashboard_module._extract_domain("# a comment") is None


def test_bulk_add_category_domains_accepts_mixed_pasted_lines(client, db_conn):
    client.post("/categories/add", data={"name": "Manga"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Manga'").fetchone()["id"]

    resp = client.post(
        "/categories/domains/bulk-add",
        data={
            "category_id": category_id,
            "patterns": "mangadex.org\nhttps://www.mangakatana.com/\nmangapill.com/some/path\n\n# a comment\n",
        },
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert resp.headers["Location"].startswith(f"/categories/{category_id}")
    patterns = {r["pattern"] for r in db_conn.execute(
        "SELECT pattern FROM category_domains WHERE category_id = ?", (category_id,)
    )}
    assert patterns == {r"mangadex\.org", r"mangakatana\.com", r"mangapill\.com"}
    assert all(r["source"] == "manual" for r in db_conn.execute(
        "SELECT source FROM category_domains WHERE category_id = ?", (category_id,)
    ))


def test_bulk_add_category_domains_dedupes_and_ignores_existing(client, db_conn):
    client.post("/categories/add", data={"name": "Manga"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Manga'").fetchone()["id"]
    client.post(
        "/categories/domains/add", data={"category_id": category_id, "pattern": r"mangadex\.org"},
        headers=_auth_header(),
    )

    client.post(
        "/categories/domains/bulk-add",
        data={"category_id": category_id, "patterns": "mangadex.org\nwww.mangadex.org\nmangadex.org"},
        headers=_auth_header(),
    )

    rows = db_conn.execute("SELECT COUNT(*) c FROM category_domains WHERE category_id = ?", (category_id,)).fetchone()
    assert rows["c"] == 1


def test_bulk_add_category_domains_without_usable_lines_shows_error(client, db_conn):
    client.post("/categories/add", data={"name": "Manga"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Manga'").fetchone()["id"]

    resp = client.post(
        "/categories/domains/bulk-add", data={"category_id": category_id, "patterns": "\n# just a comment\n"},
        headers=_auth_header(),
    )

    assert "error=1" in resp.headers["Location"]
    assert db_conn.execute(
        "SELECT COUNT(*) c FROM category_domains WHERE category_id = ?", (category_id,)
    ).fetchone()["c"] == 0


def test_bulk_add_category_domains_requires_admin_auth(client):
    resp = client.post("/categories/domains/bulk-add", data={"category_id": 1, "patterns": "example.com"})
    assert resp.status_code == 401


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


def test_schedule_detail_renders_exactly_one_save_button(client, db_conn):
    # RoadMap.md item 3: the When / Blocked for / Categories areas used
    # to be three separate <form>s, each with its own Save button.
    client.post(
        "/schedules/add",
        data={"name": "School hours", "days": ["mon"], "start_time": "08:00", "end_time": "15:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'School hours'").fetchone()["id"]
    resp = client.get(f"/schedules/{schedule_id}", headers=_auth_header())
    body = resp.data.decode()
    assert body.count('action="/schedules/update"') == 1
    assert body.count(">Save schedule<") == 1


def test_update_schedule_is_one_atomic_save_across_window_access_and_categories(client, db_conn):
    # RoadMap.md item 3, "one Save button per settings-shaped page, not
    # several": this used to be three independent forms/routes (When /
    # Blocked for / Categories blocked), each saved separately -- merged
    # into one atomic save. Confirms a single submit really does update
    # all three areas together, not just the time-window fields.
    client.post(
        "/schedules/add",
        data={"name": "School hours", "days": ["mon"], "start_time": "08:00", "end_time": "15:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'School hours'").fetchone()["id"]
    client.post("/users/add", data={"username": "kid_atomic", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid_atomic'").fetchone()["id"]
    client.post("/categories/add", data={"name": "Gaming Atomic"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Gaming Atomic'").fetchone()["id"]

    resp = client.post(
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon", "tue"], "start_time": "09:00", "end_time": "16:00",
            "time_zone": "America/Chicago", "user_ids": [str(user_id)],
            "categories_section_present": "1", "category_ids": [str(category_id)],
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 302
    row = db_conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    assert row["days_of_week"] == "mon,tue"
    assert row["start_time"] == "09:00"
    assert db_conn.execute(
        "SELECT 1 FROM schedule_users WHERE schedule_id = ? AND user_id = ?", (schedule_id, user_id)
    ).fetchone() is not None
    assert db_conn.execute(
        "SELECT 1 FROM schedule_categories WHERE schedule_id = ? AND category_id = ?", (schedule_id, category_id)
    ).fetchone() is not None


def test_update_schedule_rejects_whole_save_on_a_bad_time_zone_not_just_the_time_zone(client, db_conn):
    # Atomicity check: a bad value anywhere in the merged form must leave
    # the WHOLE schedule (including access/categories fields submitted in
    # the same request) untouched -- never a partial save.
    client.post(
        "/schedules/add",
        data={"name": "School hours", "days": ["mon"], "start_time": "08:00", "end_time": "15:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'School hours'").fetchone()["id"]
    resp = client.post(
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["tue"], "start_time": "09:00", "end_time": "16:00",
            "time_zone": "Not/AZone", "is_global": "on",
        },
        headers=_auth_header(),
    )
    assert "error=1" in resp.headers["Location"]
    row = db_conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    assert row["days_of_week"] == "mon"
    assert row["start_time"] == "08:00"
    assert row["is_global"] == 0


def test_update_schedule_while_lockout_is_on_does_not_wipe_previously_saved_categories(client, db_conn):
    # Real regression this merge could introduce: SCHEDULE_DETAIL_BODY
    # hides the categories checkbox list entirely while lockout_all is
    # checked, so a lockout schedule's own save never submits
    # category_ids at all. Without the categories_section_present guard,
    # that absence would look identical to "user unchecked everything"
    # and silently delete whatever categories were configured --
    # invisible until lockout was turned back off again.
    client.post(
        "/schedules/add",
        data={"name": "Bedtime", "days": ["mon"], "start_time": "21:00", "end_time": "06:00", "time_zone": "UTC"},
        headers=_auth_header(),
    )
    schedule_id = db_conn.execute("SELECT id FROM schedules WHERE name = 'Bedtime'").fetchone()["id"]
    client.post("/categories/add", data={"name": "Streaming"}, headers=_auth_header())
    category_id = db_conn.execute("SELECT id FROM categories WHERE name = 'Streaming'").fetchone()["id"]
    client.post(
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon"], "start_time": "21:00", "end_time": "06:00",
            "time_zone": "UTC", "categories_section_present": "1", "category_ids": [str(category_id)],
        },
        headers=_auth_header(),
    )

    # Now flip on lockout_all -- the categories section (and its hidden
    # categories_section_present flag) is no longer rendered, so a real
    # browser submit of this same form would omit category_ids entirely.
    client.post(
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon"], "start_time": "21:00", "end_time": "06:00",
            "time_zone": "UTC", "lockout_all": "on",
        },
        headers=_auth_header(),
    )

    assert db_conn.execute(
        "SELECT 1 FROM schedule_categories WHERE schedule_id = ? AND category_id = ?", (schedule_id, category_id)
    ).fetchone() is not None


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
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon"], "start_time": "08:00", "end_time": "15:00",
            "time_zone": "UTC", "categories_section_present": "1", "category_ids": [str(category_id)],
        },
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
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon"], "start_time": "08:00", "end_time": "15:00",
            "time_zone": "UTC", "categories_section_present": "1", "category_ids": [str(checked_id)],
        },
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
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon"], "start_time": "21:00", "end_time": "06:00",
            "time_zone": "UTC", "is_global": "on",
        },
        headers=_auth_header(),
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
    data = {
        "schedule_id": schedule_id, "days": ["mon"], "start_time": "00:00", "end_time": "23:59",
        "time_zone": "UTC", "is_mode": "on",
    }
    if is_global:
        data["is_global"] = "on"
    client.post("/schedules/update", data=data, headers=_auth_header())
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
# RoadMap.md item 24 (2026-09-09, project owner's explicit request: "I
# need the ability to do a shift schedule from the user page (not just
# the schedule page)"): "Shift mode now" reachable directly from a
# User's own detail page.
# ============================================================

def test_user_detail_shows_shift_mode_now_for_a_global_mode_schedule(client, db_conn):
    _add_mode_schedule(client, db_conn, "Free Time")
    client.post("/users/add", data={"username": "kid_shift1", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid_shift1'").fetchone()["id"]

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    # ">Shift mode now<" (the card heading), not the bare phrase -- an
    # unrelated hint on this same page ("...reflects any active 'Shift
    # mode now' override...") always mentions it too, regardless of
    # whether this card renders.
    assert b">Shift mode now<" in resp.data
    assert f'value="user:{user_id}"'.encode() in resp.data


def test_user_detail_omits_shift_mode_now_when_no_mode_schedule_targets_this_user(client, db_conn):
    _add_mode_schedule(client, db_conn, "Free Time", is_global=False)
    client.post("/users/add", data={"username": "kid_shift2", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid_shift2'").fetchone()["id"]

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    assert b">Shift mode now<" not in resp.data


def test_user_detail_offers_a_mode_schedule_explicitly_assigned_to_this_user(client, db_conn):
    schedule_id = _add_mode_schedule(client, db_conn, "Free Time", is_global=False)
    client.post("/users/add", data={"username": "kid_shift3", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid_shift3'").fetchone()["id"]
    client.post(
        "/schedules/update",
        data={
            "schedule_id": schedule_id, "days": ["mon"], "start_time": "00:00", "end_time": "23:59",
            "time_zone": "UTC", "is_mode": "on", "user_ids": [str(user_id)],
        },
        headers=_auth_header(),
    )

    resp = client.get(f"/users/{user_id}", headers=_auth_header())

    assert b">Shift mode now<" in resp.data


def test_shift_mode_now_from_user_page_creates_the_override_and_redirects_back(client, db_conn):
    schedule_id = _add_mode_schedule(client, db_conn, "Free Time")
    client.post("/users/add", data={"username": "kid_shift4", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid_shift4'").fetchone()["id"]

    resp = client.post(
        "/schedules/override",
        data={
            "schedule_id": schedule_id, "target": f"user:{user_id}", "duration_minutes": "60",
            "redirect_to": "user_detail", "user_id": user_id,
        },
        headers=_auth_header(),
    )

    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    assert f"/users/{user_id}" in resp.headers["Location"]
    assert db_conn.execute(
        "SELECT * FROM schedule_overrides WHERE schedule_id = ? AND user_id = ?", (schedule_id, user_id)
    ).fetchone() is not None


def test_shift_mode_now_from_user_page_error_also_redirects_back_not_to_schedules(client, db_conn):
    client.post("/users/add", data={"username": "kid_shift5", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid_shift5'").fetchone()["id"]

    resp = client.post(
        "/schedules/override",
        data={
            "schedule_id": "999999", "target": f"user:{user_id}", "duration_minutes": "60",
            "redirect_to": "user_detail", "user_id": user_id,
        },
        headers=_auth_header(),
    )

    assert "error=1" in resp.headers["Location"]
    assert f"/users/{user_id}" in resp.headers["Location"]


def test_user_detail_shows_active_override_and_lets_it_be_cancelled(client, db_conn):
    schedule_id = _add_mode_schedule(client, db_conn, "Free Time")
    client.post("/users/add", data={"username": "kid_shift6", "password": "pw"}, headers=_auth_header())
    user_id = db_conn.execute("SELECT id FROM users WHERE username = 'kid_shift6'").fetchone()["id"]
    client.post(
        "/schedules/override",
        data={"schedule_id": schedule_id, "target": f"user:{user_id}", "duration_minutes": "60"},
        headers=_auth_header(),
    )
    override_id = db_conn.execute(
        "SELECT id FROM schedule_overrides WHERE schedule_id = ? AND user_id = ?", (schedule_id, user_id)
    ).fetchone()["id"]

    resp = client.get(f"/users/{user_id}", headers=_auth_header())
    assert b"Active override" in resp.data
    assert b"Cancel override" in resp.data
    # The "Shift mode now" form must not ALSO show while an override is
    # already active for this user -- one or the other, never both.
    assert b">Shift mode now<" not in resp.data

    cancel_resp = client.post(
        "/schedules/override/cancel",
        data={"override_id": override_id, "redirect_to": "user_detail", "user_id": user_id},
        headers=_auth_header(),
    )
    assert cancel_resp.status_code == 302
    assert f"/users/{user_id}" in cancel_resp.headers["Location"]
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
        "/settings/household", data={"household_time_zone": "America/Chicago"}, headers=_auth_header()
    )
    assert resp.status_code == 302
    assert db_mod.get_setting(db_conn, "household_time_zone") == "America/Chicago"


def test_update_household_time_zone_rejects_garbage(client, db_conn):
    import db as db_mod

    resp = client.post(
        "/settings/household", data={"household_time_zone": "Not/AZone"}, headers=_auth_header()
    )
    assert "error=1" in resp.headers["Location"]
    assert db_mod.get_setting(db_conn, "household_time_zone", "UTC") == "UTC"


def test_household_time_zone_is_genuinely_unset_on_a_fresh_install(db_conn):
    """Real live-testing feedback (RoadMap.md's dated entry): this used
    to be hardcoded to "UTC" at container boot, which always won over
    the Settings page's own browser-side auto-detect the first time an
    admin ever loaded it -- "default to wherever the admin's device is"
    only means something if the setting is still genuinely absent for
    that first page load to act on."""
    import db as db_mod
    assert db_mod.get_setting(db_conn, "household_time_zone") is None


def test_settings_page_includes_the_auto_detect_script_when_never_configured(client):
    resp = client.get("/settings", headers=_auth_header())
    assert b"Intl.DateTimeFormat" in resp.data
    assert b'id="tzAutoDetectNote"' in resp.data


def test_settings_page_omits_the_auto_detect_script_once_explicitly_saved(client):
    client.post(
        "/settings/household", data={"household_time_zone": "America/Chicago"}, headers=_auth_header()
    )
    resp = client.get("/settings", headers=_auth_header())
    assert b"Intl.DateTimeFormat" not in resp.data


def test_settings_page_shows_safesearch_toggle(client):
    resp = client.get("/settings", headers=_auth_header())
    assert resp.status_code == 200
    assert b"SafeSearch" in resp.data


def test_update_safesearch_checked_saves_on(client, db_conn):
    import db as db_mod

    resp = client.post("/settings/filtering", data={"safesearch_enabled": "1"}, headers=_auth_header())
    assert resp.status_code == 302
    assert db_mod.get_setting(db_conn, "safesearch_enabled") == "1"


def test_update_safesearch_unchecked_saves_off(client, db_conn):
    import db as db_mod

    db_mod.set_setting(db_conn, "safesearch_enabled", "1")
    db_conn.commit()
    resp = client.post("/settings/filtering", data={}, headers=_auth_header())
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


# ============================================================
# Backup/restore (2026-09-08) -- tracked as a deferred item in
# RoadMap.md since before 2026-09-07, revisited by the project owner as
# the actual mechanism for wiping and redeploying the production box
# clean without losing anything or needing to re-trust a new CA
# certificate on every device.
# ============================================================

def test_download_backup_produces_a_zip_with_config_and_ca_files(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    cert_pem, key_pem = _generate_cert_pair(tmp_path, "current", common_name="My Household CA")
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:40", "label": "Roku"}, headers=_auth_header())

    resp = client.get("/settings/backup/download", headers=_auth_header())

    assert resp.status_code == 200
    assert resp.headers["Content-Type"] == "application/zip"
    assert "attachment" in resp.headers["Content-Disposition"]
    assert "optigate-backup-" in resp.headers["Content-Disposition"]
    with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
        names = zf.namelist()
        assert "config.json" in names
        assert "ca_cert.pem" in names
        assert "ca_key.pem" in names
        assert zf.read("ca_cert.pem") == cert_pem
        data = json.loads(zf.read("config.json"))
        assert any(d["mac_address"] == "aa:bb:cc:dd:ee:40" for d in data["devices"])


def test_download_backup_omits_ca_files_when_none_generated_yet(client, db_conn, monkeypatch, tmp_path):
    _point_ca_paths_at(monkeypatch, tmp_path)

    resp = client.get("/settings/backup/download", headers=_auth_header())

    with zipfile.ZipFile(io.BytesIO(resp.data)) as zf:
        names = zf.namelist()
        assert "config.json" in names
        assert "ca_cert.pem" not in names
        assert "ca_key.pem" not in names


def test_download_backup_requires_admin_auth(client, db_conn):
    resp = client.get("/settings/backup/download")
    assert resp.status_code == 401


def _make_backup_zip(config_data, cert_pem=None, key_pem=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config_data))
        if cert_pem is not None:
            zf.writestr("ca_cert.pem", cert_pem)
        if key_pem is not None:
            zf.writestr("ca_key.pem", key_pem)
    buf.seek(0)
    return buf.read()


def _empty_config():
    """A structurally-valid, otherwise-empty backup.RestoreError-passing
    config dict -- every required table present as an empty list."""
    tables = (
        "users", "groups", "devices", "domains", "categories", "schedules",
        "user_domains", "domain_paths", "user_shows", "group_domains", "device_domains",
        "category_domains", "category_overrides", "category_users", "category_groups",
        "category_devices", "schedule_categories", "schedule_users", "schedule_groups",
        "schedule_devices", "schedule_overrides",
    )
    return {"format_version": 1, "settings": {}, **{t: [] for t in tables}}


def test_restore_backup_round_trips_through_the_dashboard(client, db_conn, monkeypatch, tmp_path):
    """Download a real backup, wipe the device, restore it -- the full
    user-facing path, not just common/backup.py's own unit tests."""
    _point_ca_paths_at(monkeypatch, tmp_path)
    client.post("/devices/add", data={"mac_address": "AA:BB:CC:DD:EE:41", "label": "Kitchen TV"}, headers=_auth_header())

    zip_bytes = client.get("/settings/backup/download", headers=_auth_header()).data

    device_id = db_conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:41'").fetchone()["id"]
    client.post("/devices/delete", data={"device_id": device_id}, headers=_auth_header())
    assert db_conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"] == 0

    resp = client.post(
        "/settings/backup/restore",
        data={"backup_file": (io.BytesIO(zip_bytes), "backup.zip")},
        headers=_auth_header(),
        content_type="multipart/form-data",
    )

    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    restored = db_conn.execute("SELECT * FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:41'").fetchone()
    assert restored is not None
    assert restored["label"] == "Kitchen TV"


def test_restore_backup_also_restores_the_ca_certificate(client, db_conn, monkeypatch, tmp_path):
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    cert_pem, key_pem = _generate_cert_pair(tmp_path, "backedup", common_name="Backed Up CA")
    zip_bytes = _make_backup_zip(_empty_config(), cert_pem=cert_pem, key_pem=key_pem)

    resp = client.post(
        "/settings/backup/restore",
        data={"backup_file": (io.BytesIO(zip_bytes), "backup.zip")},
        headers=_auth_header(),
        content_type="multipart/form-data",
    )

    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    assert cert_path.read_bytes() == cert_pem
    assert key_path.read_bytes() == key_pem
    assert "re-trust" in resp.headers["Location"]


def test_restore_backup_does_not_warn_about_re_trust_when_ca_is_unchanged(client, db_conn, monkeypatch, tmp_path):
    """Live-verified bug found 2026-09-08: restoring the SAME backup a
    box's own CA cert came from (the common case, e.g. reverting
    unrelated config on the same install) must not falsely claim every
    device needs to re-trust a certificate that never actually
    changed."""
    cert_path, key_path = _point_ca_paths_at(monkeypatch, tmp_path)
    cert_pem, key_pem = _generate_cert_pair(tmp_path, "current", common_name="Current CA")
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    zip_bytes = _make_backup_zip(_empty_config(), cert_pem=cert_pem, key_pem=key_pem)

    resp = client.post(
        "/settings/backup/restore",
        data={"backup_file": (io.BytesIO(zip_bytes), "backup.zip")},
        headers=_auth_header(),
        content_type="multipart/form-data",
    )

    assert resp.status_code == 302
    assert "error=1" not in resp.headers["Location"]
    assert "unchanged" in resp.headers["Location"]
    assert "re-trust" not in resp.headers["Location"]


def test_restore_backup_rejects_a_non_zip_file(client, db_conn):
    resp = client.post(
        "/settings/backup/restore",
        data={"backup_file": (io.BytesIO(b"not a zip file"), "backup.zip")},
        headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert "error=1" in resp.headers["Location"]


def test_restore_backup_rejects_a_zip_without_config_json(client, db_conn):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("something_else.txt", "not a backup")
    resp = client.post(
        "/settings/backup/restore",
        data={"backup_file": (io.BytesIO(buf.getvalue()), "backup.zip")},
        headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert "error=1" in resp.headers["Location"]


def test_restore_backup_rejects_wrong_format_version(client, db_conn):
    zip_bytes = _make_backup_zip({"format_version": 999, "settings": {}})
    resp = client.post(
        "/settings/backup/restore",
        data={"backup_file": (io.BytesIO(zip_bytes), "backup.zip")},
        headers=_auth_header(),
        content_type="multipart/form-data",
    )
    assert "error=1" in resp.headers["Location"]


def test_restore_backup_requires_a_file(client, db_conn):
    resp = client.post("/settings/backup/restore", data={}, headers=_auth_header(), content_type="multipart/form-data")
    assert "error=1" in resp.headers["Location"]


def test_restore_backup_requires_admin_auth(client, db_conn):
    resp = client.post("/settings/backup/restore", data={}, content_type="multipart/form-data")
    assert resp.status_code == 401


def test_settings_page_has_backup_and_restore_controls(client, db_conn):
    resp = client.get("/settings", headers=_auth_header())
    assert b"Download backup" in resp.data
    assert b"Restore from backup" in resp.data
