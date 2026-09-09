"""common/backup.py: configuration export/import (backup/restore).

Added 2026-09-08 -- tracked as a deferred item in RoadMap.md since
before 2026-09-07, revisited by the project owner as the actual
mechanism for wiping and redeploying the production box clean (e.g. once
the OptiGate rebrand's Phase C infrastructure rename happens) without
losing anything.
"""
from __future__ import annotations

import db
import backup


def _add_user(conn, username="kid1"):
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (username, username.title(), "hash123", db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()["id"]


def _add_domain(conn, pattern="example\\.com", is_global=0):
    conn.execute(
        "INSERT INTO domains (pattern, mode, is_global, created_at) VALUES (?, 'splice', ?, ?)",
        (pattern, is_global, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT id FROM domains WHERE pattern = ?", (pattern,)).fetchone()["id"]


def _add_category(conn, name="Adult", subscription_url=None):
    conn.execute(
        "INSERT INTO categories (name, subscription_url, created_at) VALUES (?, ?, ?)",
        (name, subscription_url, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT id FROM categories WHERE name = ?", (name,)).fetchone()["id"]


# --------------------------------------------------------------- export

def test_export_has_the_expected_top_level_shape(conn):
    data = backup.export_config(conn)
    assert data["format_version"] == backup.FORMAT_VERSION
    assert isinstance(data["settings"], dict)
    for table in ("users", "devices", "domains", "categories", "schedules", "category_domains"):
        assert table in data
        assert isinstance(data[table], list)


def test_export_only_includes_allowlisted_settings(conn):
    db.set_setting(conn, "admin_username", "admin")
    db.set_setting(conn, "secret_key", "super-secret-flask-key")
    db.set_setting(conn, "cr_resolver_last_error", "some diagnostic noise")

    data = backup.export_config(conn)

    assert data["settings"].get("admin_username") == "admin"
    assert "secret_key" not in data["settings"]
    assert "cr_resolver_last_error" not in data["settings"]


def test_export_includes_network_sweep_config_but_not_its_status(conn):
    """network_sweep_enabled/_interval_minutes are real admin
    configuration -- included. network_sweep_last_run_at/
    _last_host_count are controller/network_sweep.py's own diagnostic
    status (for the Settings page's live display) -- excluded, same
    reasoning as cr_resolver_last_error above: restoring a "last ran"
    timestamp from a different box onto a fresh install would just be
    misleading."""
    db.set_setting(conn, "network_sweep_enabled", "0")
    db.set_setting(conn, "network_sweep_interval_minutes", "30")
    db.set_setting(conn, "network_sweep_last_run_at", "2026-09-09T03:00:00Z")
    db.set_setting(conn, "network_sweep_last_host_count", "254")

    data = backup.export_config(conn)

    assert data["settings"].get("network_sweep_enabled") == "0"
    assert data["settings"].get("network_sweep_interval_minutes") == "30"
    assert "network_sweep_last_run_at" not in data["settings"]
    assert "network_sweep_last_host_count" not in data["settings"]


def test_export_includes_manual_category_domains_but_not_subscription(conn):
    category_id = _add_category(conn, subscription_url="https://example.com/list.txt")
    conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, 'manual', ?)",
        (category_id, "manual-added\\.example", db.now_iso()),
    )
    conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, 'subscription', ?)",
        (category_id, "from-subscription\\.example", db.now_iso()),
    )
    conn.commit()

    data = backup.export_config(conn)

    patterns = {row["pattern"] for row in data["category_domains"]}
    assert "manual-added\\.example" in patterns
    assert "from-subscription\\.example" not in patterns


def test_export_excludes_operational_and_historical_tables(conn):
    """access_log/system_events/device_bindings never appear in a
    backup -- they're not configuration (see backup.py's own docstring)."""
    data = backup.export_config(conn)
    for table in ("access_log", "system_events", "device_bindings", "network_events", "series_cache"):
        assert table not in data


# --------------------------------------------------------------- restore

def test_restore_recreates_data_with_foreign_keys_intact(conn):
    user_id = _add_user(conn)
    domain_id = _add_domain(conn)
    conn.execute("INSERT INTO user_domains (user_id, domain_id) VALUES (?, ?)", (user_id, domain_id))
    conn.commit()
    data = backup.export_config(conn)

    # Wipe everything (simulating a fresh install) before restoring.
    for table in ("users", "groups", "devices", "domains", "categories", "schedules"):
        conn.execute(f"DELETE FROM {table}")
    conn.commit()
    assert conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0

    backup.restore_config(conn, data)

    restored_user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    assert restored_user["username"] == "kid1"
    restored_domain = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
    assert restored_domain["pattern"] == "example\\.com"
    link = conn.execute(
        "SELECT * FROM user_domains WHERE user_id = ? AND domain_id = ?", (user_id, domain_id)
    ).fetchone()
    assert link is not None


def test_restore_is_a_full_replace_not_a_merge(conn):
    """Data present on the TARGET but not in the backup must be gone
    afterward -- restore returns to exactly the snapshot, it doesn't
    merge with whatever was already there."""
    data = backup.export_config(conn)  # an empty snapshot

    _add_user(conn, "should-be-wiped")
    assert conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 1

    backup.restore_config(conn, data)

    assert conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0


def test_restore_leaves_operational_tables_untouched(conn):
    user_id = _add_user(conn)
    conn.execute(
        "INSERT INTO access_log (ts, user_id, username, domain, allowed) VALUES (?, ?, 'kid1', 'example.com', 1)",
        (db.now_iso(), user_id),
    )
    conn.execute(
        "INSERT INTO system_events (ts, source, severity, message) VALUES (?, 'test', 'error', 'boom')",
        (db.now_iso(),),
    )
    conn.commit()
    data = backup.export_config(conn)

    backup.restore_config(conn, data)

    assert conn.execute("SELECT COUNT(*) AS c FROM access_log").fetchone()["c"] == 1
    assert conn.execute("SELECT COUNT(*) AS c FROM system_events").fetchone()["c"] == 1


def test_restore_upserts_settings_without_wiping_non_allowlisted_keys(conn):
    db.set_setting(conn, "secret_key", "keep-me")
    data = backup.export_config(conn)  # secret_key never makes it into the export

    backup.restore_config(conn, data)

    assert db.get_setting(conn, "secret_key") == "keep-me"


def test_restore_rejects_wrong_format_version_without_touching_data(conn):
    _add_user(conn, "should-survive")
    bad_data = backup.export_config(conn)
    bad_data["format_version"] = 999

    try:
        backup.restore_config(conn, bad_data)
        assert False, "expected RestoreError"
    except backup.RestoreError:
        pass

    assert conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 1


def test_restore_rejects_a_backup_missing_a_required_table_key(conn):
    data = backup.export_config(conn)
    del data["devices"]

    try:
        backup.restore_config(conn, data)
        assert False, "expected RestoreError"
    except backup.RestoreError:
        pass


def test_restore_rejects_a_non_dict_payload(conn):
    try:
        backup.restore_config(conn, ["not", "a", "dict"])
        assert False, "expected RestoreError"
    except backup.RestoreError:
        pass
