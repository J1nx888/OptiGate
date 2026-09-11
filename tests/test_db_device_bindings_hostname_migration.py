"""common/db.py's _migrate(): adds device_bindings.hostname (2026-09-11,
RoadMap.md -- controller/mdns_lookup.py's best-effort mDNS reverse-PTR
result, feeding the "Devices awaiting login" card's Hostname column) to
a database that predates the column, the same idempotent
PRAGMA-table_info-then-ALTER-TABLE pattern _migrate() already uses for
every other additive column (see e.g. devices.pending_dismissed_at).
"""
from __future__ import annotations

import db


def _drop_hostname_column(conn) -> None:
    """Simulates a pre-2026-09-11 database: recreates device_bindings
    exactly as it looked before the hostname column existed, preserving
    any rows already inserted via the normal (post-migration) schema."""
    conn.execute("ALTER TABLE device_bindings RENAME TO device_bindings_new")
    conn.execute(
        """
        CREATE TABLE device_bindings (
            id            INTEGER PRIMARY KEY,
            device_id     INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            mac_address   TEXT NOT NULL,
            ipv4_address  TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at  TEXT NOT NULL,
            source        TEXT NOT NULL CHECK (source IN ('rtnetlink', 'snapshot', 'adguard', 'bettercap', 'active_scan')),
            confidence    REAL NOT NULL DEFAULT 1.0,
            active        INTEGER NOT NULL DEFAULT 1,
            UNIQUE(mac_address, ipv4_address)
        )
        """
    )
    conn.execute(
        "INSERT INTO device_bindings "
        "(id, device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, source, confidence, active) "
        "SELECT id, device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, source, confidence, active "
        "FROM device_bindings_new"
    )
    conn.execute("DROP TABLE device_bindings_new")
    conn.commit()


def test_fresh_database_already_has_the_hostname_column(conn):
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(device_bindings)")}
    assert "hostname" in columns


def test_migrate_adds_hostname_to_a_pre_existing_database_without_losing_data(conn):
    conn.execute(
        "INSERT INTO device_bindings "
        "(mac_address, ipv4_address, first_seen_at, last_seen_at, source) "
        "VALUES ('aa:bb:cc:dd:ee:01', '192.168.1.50', ?, ?, 'rtnetlink')",
        (db.now_iso(), db.now_iso()),
    )
    conn.commit()
    _drop_hostname_column(conn)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(device_bindings)")}
    assert "hostname" not in columns

    db._migrate(conn)

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(device_bindings)")}
    assert "hostname" in columns
    row = conn.execute(
        "SELECT * FROM device_bindings WHERE mac_address = 'aa:bb:cc:dd:ee:01'"
    ).fetchone()
    assert row["ipv4_address"] == "192.168.1.50", "pre-existing row must survive the migration"
    assert row["hostname"] is None


def test_migrate_is_idempotent_across_repeated_calls(conn):
    _drop_hostname_column(conn)

    db._migrate(conn)
    db._migrate(conn)  # a second time, e.g. every container startup -- must not error

    columns = [row["name"] for row in conn.execute("PRAGMA table_info(device_bindings)")]
    assert columns.count("hostname") == 1
