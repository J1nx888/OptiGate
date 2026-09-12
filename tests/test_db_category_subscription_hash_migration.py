"""common/db.py's _migrate(): adds categories.last_subscription_hash
(2026-09-12, RoadMap.md -- common/category_fetch.py's skip-when-
unchanged fix for fetch_and_sync_category(), so a re-sync can compare
against the previous fetch's content instead of unconditionally
rewriting every category_domains row) to a database that predates the
column, the same idempotent PRAGMA-table_info-then-ALTER-TABLE pattern
_migrate() already uses for every other additive column (see e.g.
device_bindings.hostname).
"""
from __future__ import annotations

import db


def _drop_last_subscription_hash_column(conn) -> None:
    """Simulates a pre-2026-09-12 database: recreates categories exactly
    as it looked before the column existed, preserving any rows already
    inserted via the normal (post-migration) schema."""
    conn.execute("ALTER TABLE categories RENAME TO categories_new")
    conn.execute(
        """
        CREATE TABLE categories (
            id               INTEGER PRIMARY KEY,
            name             TEXT UNIQUE NOT NULL,
            subscription_url TEXT,
            last_synced_at   TEXT,
            is_global        INTEGER NOT NULL DEFAULT 0,
            created_at       TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO categories (id, name, subscription_url, last_synced_at, is_global, created_at) "
        "SELECT id, name, subscription_url, last_synced_at, is_global, created_at FROM categories_new"
    )
    conn.execute("DROP TABLE categories_new")
    conn.commit()


def test_fresh_database_already_has_the_last_subscription_hash_column(conn):
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(categories)")}
    assert "last_subscription_hash" in columns


def test_migrate_adds_last_subscription_hash_to_a_pre_existing_database_without_losing_data(conn):
    conn.execute(
        "INSERT INTO categories (name, subscription_url, is_global, created_at) VALUES (?, ?, 0, ?)",
        ("Gambling", "https://example.invalid/gambling.txt", db.now_iso()),
    )
    conn.commit()
    _drop_last_subscription_hash_column(conn)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(categories)")}
    assert "last_subscription_hash" not in columns

    db._migrate(conn)

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(categories)")}
    assert "last_subscription_hash" in columns
    row = conn.execute("SELECT * FROM categories WHERE name = 'Gambling'").fetchone()
    assert row["subscription_url"] == "https://example.invalid/gambling.txt", "pre-existing row must survive the migration"
    assert row["last_subscription_hash"] is None


def test_migrate_is_idempotent_across_repeated_calls(conn):
    _drop_last_subscription_hash_column(conn)

    db._migrate(conn)
    db._migrate(conn)  # a second time, e.g. every container startup -- must not error

    columns = [row["name"] for row in conn.execute("PRAGMA table_info(categories)")]
    assert columns.count("last_subscription_hash") == 1
