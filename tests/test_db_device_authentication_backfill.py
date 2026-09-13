"""common/db.py's _migrate(): backfills devices.is_authenticated=1 for any
device already assigned to a user/group (2026-09-13, RoadMap.md -- a real
device found live, assigned to a group with a real label, still stuck
showing on the "Devices awaiting login" card days later).

dashboard.py's update_device()/_batch_assign_devices_to_group() only
started setting is_authenticated=1 on assignment starting 2026-09-11 ("a
vouching act"); any device assigned before that date never got the flag
flipped, since nothing else ever re-checks it. This is a data fix, not a
schema change, so unlike this project's usual ALTER-TABLE migrations there
is no "drop the column first" setup -- these tests seed rows directly in
the shape a pre-fix INSERT would have produced.
"""
from __future__ import annotations

import db


def _insert_device(conn, mac, *, user_id=None, group_id=None, is_authenticated=0, ignored=0, bypass_login=0):
    conn.execute(
        "INSERT INTO devices (mac_address, user_id, group_id, ignored, bypass_login, "
        "is_authenticated, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (mac, user_id, group_id, ignored, bypass_login, is_authenticated, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT id FROM devices WHERE mac_address = ?", (mac,)).fetchone()["id"]


def test_migrate_authenticates_a_device_assigned_to_a_group_before_the_fix(conn):
    conn.execute("INSERT INTO groups (name, created_at) VALUES ('Gaming', ?)", (db.now_iso(),))
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'Gaming'").fetchone()["id"]
    device_id = _insert_device(conn, "38:c1:21:19:97:d1", group_id=group_id, is_authenticated=0)

    db._migrate(conn)

    row = conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1


def test_migrate_authenticates_a_device_assigned_to_a_user_before_the_fix(conn):
    conn.execute(
        "INSERT INTO users (username, password_hash, display_name, created_at) "
        "VALUES ('alex', 'x', 'Alex', ?)", (db.now_iso(),),
    )
    user_id = conn.execute("SELECT id FROM users WHERE username = 'alex'").fetchone()["id"]
    device_id = _insert_device(conn, "aa:bb:cc:dd:ee:80", user_id=user_id, is_authenticated=0)

    db._migrate(conn)

    row = conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1


def test_migrate_leaves_a_genuinely_unassigned_pending_device_alone(conn):
    """The whole point of `pending` is "not yet assigned" -- a real
    PREAUTH device with no user_id/group_id at all must NOT get
    authenticated just because _migrate() ran."""
    device_id = _insert_device(conn, "aa:bb:cc:dd:ee:81", is_authenticated=0)

    db._migrate(conn)

    row = conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 0


def test_migrate_does_not_touch_an_already_authenticated_assigned_device(conn):
    """Not just "ends up 1" -- must not clobber unrelated state on a row
    that was already correct (the common, post-fix case)."""
    conn.execute("INSERT INTO groups (name, created_at) VALUES ('Kitchen', ?)", (db.now_iso(),))
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'Kitchen'").fetchone()["id"]
    device_id = _insert_device(conn, "aa:bb:cc:dd:ee:82", group_id=group_id, is_authenticated=1)

    db._migrate(conn)

    row = conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1


def test_migrate_is_idempotent_across_repeated_calls(conn):
    conn.execute("INSERT INTO groups (name, created_at) VALUES ('Gaming', ?)", (db.now_iso(),))
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'Gaming'").fetchone()["id"]
    device_id = _insert_device(conn, "aa:bb:cc:dd:ee:83", group_id=group_id, is_authenticated=0)

    db._migrate(conn)
    db._migrate(conn)  # a second time, e.g. every container startup -- must not error

    row = conn.execute("SELECT is_authenticated FROM devices WHERE id = ?", (device_id,)).fetchone()
    assert row["is_authenticated"] == 1
