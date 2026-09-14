"""common/db.py's _migrate(): adds domains.protected to a database that
predates the column, the same idempotent PRAGMA-table_info-then-ALTER-TABLE
pattern _migrate() already uses for every other additive column (see e.g.
categories.last_subscription_hash). The column marks rows -- like
infrastructure the Crunchyroll integration depends on -- that shouldn't be
deletable or mixed into the general Domains page.
"""
from __future__ import annotations

import db


def _drop_protected_column(conn) -> None:
    """Simulates a pre-migration database: recreates domains exactly as it
    looked before the column existed, preserving any rows already inserted
    via the normal (post-migration) schema."""
    conn.execute("ALTER TABLE domains RENAME TO domains_new")
    conn.execute(
        """
        CREATE TABLE domains (
            id         INTEGER PRIMARY KEY,
            pattern    TEXT UNIQUE NOT NULL,
            mode       TEXT NOT NULL CHECK (mode IN ('splice', 'bump', 'trusted')),
            kind       TEXT NOT NULL DEFAULT 'generic' CHECK (kind IN ('generic', 'crunchyroll')),
            is_global  INTEGER NOT NULL DEFAULT 0,
            note       TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO domains (id, pattern, mode, kind, is_global, note, created_at) "
        "SELECT id, pattern, mode, kind, is_global, note, created_at FROM domains_new"
    )
    conn.execute("DROP TABLE domains_new")
    conn.commit()


def test_fresh_database_already_has_the_protected_column(conn):
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(domains)")}
    assert "protected" in columns


def test_migrate_adds_protected_to_a_pre_existing_database_without_losing_data(conn):
    conn.execute(
        "INSERT INTO domains (pattern, mode, is_global, note, created_at) VALUES (?, 'splice', 1, 'Google', ?)",
        (r"google\.com", db.now_iso()),
    )
    conn.commit()
    _drop_protected_column(conn)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(domains)")}
    assert "protected" not in columns

    db._migrate(conn)

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(domains)")}
    assert "protected" in columns
    row = conn.execute("SELECT * FROM domains WHERE pattern = ?", (r"google\.com",)).fetchone()
    assert row["note"] == "Google", "pre-existing row must survive the migration"
    assert row["protected"] == 0, "the migration itself only adds the column -- seed_defaults.seed() does the backfill"


def test_migrate_is_idempotent_across_repeated_calls(conn):
    _drop_protected_column(conn)

    db._migrate(conn)
    db._migrate(conn)  # a second time, e.g. every container startup -- must not error

    columns = [row["name"] for row in conn.execute("PRAGMA table_info(domains)")]
    assert columns.count("protected") == 1
