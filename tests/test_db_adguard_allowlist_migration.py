"""common/db.py: the adguard_allowlist table family (adguard_allowlist,
user_adguard_allowlist, group_adguard_allowlist, device_adguard_allowlist)
and access_log's new block_source column -- see adguard_allowlist's own
schema comment for what these are for.
"""
from __future__ import annotations

import db


def _drop_block_source_column(conn) -> None:
    """Simulates a pre-migration database: recreates access_log exactly as
    it looked before the column existed, preserving any rows already
    inserted via the normal (post-migration) schema."""
    conn.execute("ALTER TABLE access_log RENAME TO access_log_new")
    conn.execute(
        """
        CREATE TABLE access_log (
            id          INTEGER PRIMARY KEY,
            ts          TEXT NOT NULL,
            user_id     INTEGER,
            device_id   INTEGER,
            username    TEXT NOT NULL,
            domain      TEXT NOT NULL,
            path        TEXT,
            series_id   TEXT,
            series_name TEXT,
            allowed     INTEGER NOT NULL,
            reason      TEXT,
            approval_requested_at TEXT,
            ip_address  TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO access_log (id, ts, user_id, device_id, username, domain, path, series_id, "
        "series_name, allowed, reason, approval_requested_at, ip_address) "
        "SELECT id, ts, user_id, device_id, username, domain, path, series_id, "
        "series_name, allowed, reason, approval_requested_at, ip_address FROM access_log_new"
    )
    conn.execute("DROP TABLE access_log_new")
    conn.commit()


def test_fresh_database_already_has_the_new_tables_and_column(conn):
    tables = {
        row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {"adguard_allowlist", "user_adguard_allowlist", "group_adguard_allowlist", "device_adguard_allowlist"} <= tables
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(access_log)")}
    assert "block_source" in columns


def test_migrate_adds_block_source_to_a_pre_existing_database_without_losing_data(conn):
    conn.execute(
        "INSERT INTO access_log (ts, username, domain, allowed, reason) "
        "VALUES (?, 'kid1', 'example.com', 1, 'global_domain')",
        (db.now_iso(),),
    )
    conn.commit()
    _drop_block_source_column(conn)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(access_log)")}
    assert "block_source" not in columns

    db._migrate(conn)

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(access_log)")}
    assert "block_source" in columns
    row = conn.execute("SELECT * FROM access_log WHERE domain = 'example.com'").fetchone()
    assert row["username"] == "kid1", "pre-existing row must survive the migration"
    assert row["block_source"] is None


def test_migrate_is_idempotent_across_repeated_calls(conn):
    _drop_block_source_column(conn)

    db._migrate(conn)
    db._migrate(conn)  # a second time, e.g. every container startup -- must not error

    columns = [row["name"] for row in conn.execute("PRAGMA table_info(access_log)")]
    assert columns.count("block_source") == 1


def test_adguard_allowlist_can_be_inserted_and_joined_through_all_three_scope_tables(conn):
    """Sanity check on the new tables' shape -- foreign keys and UNIQUE
    constraints behave the same way domains/user_domains/etc already do."""
    conn.execute("INSERT INTO users (username, display_name, password_hash, created_at) VALUES ('kid1', 'Kid', 'x', datetime('now'))")
    conn.execute("INSERT INTO groups (name, created_at) VALUES ('TVs', datetime('now'))")
    conn.execute("INSERT INTO devices (mac_address, created_at) VALUES ('aa:bb:cc:dd:ee:01', datetime('now'))")
    conn.execute("INSERT INTO adguard_allowlist (pattern, created_at) VALUES ('mobalytics\\.gg', datetime('now'))")
    conn.commit()
    user_id = conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    device_id = conn.execute("SELECT id FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:01'").fetchone()["id"]
    allowlist_id = conn.execute("SELECT id FROM adguard_allowlist WHERE pattern = 'mobalytics\\.gg'").fetchone()["id"]

    conn.execute("INSERT INTO user_adguard_allowlist (user_id, allowlist_id) VALUES (?, ?)", (user_id, allowlist_id))
    conn.execute("INSERT INTO group_adguard_allowlist (group_id, allowlist_id) VALUES (?, ?)", (group_id, allowlist_id))
    conn.execute("INSERT INTO device_adguard_allowlist (device_id, allowlist_id) VALUES (?, ?)", (device_id, allowlist_id))
    conn.commit()

    assert conn.execute(
        "SELECT 1 FROM user_adguard_allowlist WHERE user_id = ? AND allowlist_id = ?", (user_id, allowlist_id)
    ).fetchone() is not None
    assert conn.execute(
        "SELECT 1 FROM group_adguard_allowlist WHERE group_id = ? AND allowlist_id = ?", (group_id, allowlist_id)
    ).fetchone() is not None
    assert conn.execute(
        "SELECT 1 FROM device_adguard_allowlist WHERE device_id = ? AND allowlist_id = ?", (device_id, allowlist_id)
    ).fetchone() is not None

    # Deleting the allowlist row cascades to every scope table -- same
    # ON DELETE CASCADE convention domains/user_domains/etc already use.
    conn.execute("DELETE FROM adguard_allowlist WHERE id = ?", (allowlist_id,))
    conn.commit()
    assert conn.execute("SELECT 1 FROM user_adguard_allowlist WHERE allowlist_id = ?", (allowlist_id,)).fetchone() is None
    assert conn.execute("SELECT 1 FROM group_adguard_allowlist WHERE allowlist_id = ?", (allowlist_id,)).fetchone() is None
    assert conn.execute("SELECT 1 FROM device_adguard_allowlist WHERE allowlist_id = ?", (allowlist_id,)).fetchone() is None
