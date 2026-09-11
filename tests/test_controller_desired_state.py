"""controller/desired_state.py: building a real DesiredState from the
devices/device_bindings tables."""
from __future__ import annotations

import db
import identity
from desired_state import db_backed_desired_state
from ipc_client import Target

GATEWAY = Target(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:00")


def _add_device(conn, mac_address, ignored=0):
    conn.execute(
        "INSERT INTO devices (mac_address, ignored, created_at) VALUES (?, ?, ?)",
        (mac_address, ignored, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,)).fetchone()


def test_no_devices_yields_empty_target_list(conn):
    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.gateway == GATEWAY
    assert desired.targets == ()


def test_device_with_active_binding_becomes_a_target(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01")
    identity.record_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21", source="rtnetlink")

    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == (Target(ip="192.168.1.21", mac="aa:bb:cc:dd:ee:01"),)


def test_device_with_no_binding_is_excluded(conn):
    """A known device that hasn't been observed on the network yet (no
    device_bindings row) contributes no target -- there's no IP to
    poison anyone with."""
    _add_device(conn, "aa:bb:cc:dd:ee:01")
    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == ()


def test_ignored_device_is_excluded_even_with_an_active_binding(conn):
    """ignored stands in for the design's bypass_v4 class -- see
    db_backed_desired_state's own doc comment."""
    _add_device(conn, "aa:bb:cc:dd:ee:01", ignored=1)
    identity.record_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21", source="rtnetlink")

    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == ()


def test_device_in_an_ignored_group_is_excluded_even_with_an_active_binding(conn):
    """Group-level ignore (added 2026-09-07, db.py's schema comment on
    groups.ignored) excludes a device the same way its own `ignored` bit
    does, even though the device's own column reads 0."""
    conn.execute("INSERT INTO groups (name, ignored, created_at) VALUES ('IoT', 1, ?)", (db.now_iso(),))
    conn.commit()
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    conn.execute(
        "INSERT INTO devices (mac_address, group_id, ignored, created_at) VALUES (?, ?, 0, ?)",
        ("aa:bb:cc:dd:ee:01", group_id, db.now_iso()),
    )
    conn.commit()
    identity.record_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21", source="rtnetlink")

    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == ()


def test_deactivated_binding_is_excluded(conn):
    """A device whose binding got superseded (see
    identity.record_binding's conflict handling) must not still show up
    as a target using its old, no-longer-valid IP."""
    _add_device(conn, "aa:bb:cc:dd:ee:01")
    identity.record_binding(
        conn, "aa:bb:cc:dd:ee:01", "192.168.1.21", source="rtnetlink", seen_at="2026-08-29T00:00:00Z"
    )
    identity.record_binding(
        conn, "aa:bb:cc:dd:ee:01", "192.168.1.22", source="rtnetlink", seen_at="2026-08-29T01:00:00Z"
    )

    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == (Target(ip="192.168.1.22", mac="aa:bb:cc:dd:ee:01"),)


def test_multiple_devices_all_included(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01")
    _add_device(conn, "aa:bb:cc:dd:ee:02")
    identity.record_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21", source="rtnetlink")
    identity.record_binding(conn, "aa:bb:cc:dd:ee:02", "192.168.1.22", source="rtnetlink")

    desired = db_backed_desired_state(conn, GATEWAY)
    assert set(desired.targets) == {
        Target(ip="192.168.1.21", mac="aa:bb:cc:dd:ee:01"),
        Target(ip="192.168.1.22", mac="aa:bb:cc:dd:ee:02"),
    }


def test_device_with_two_simultaneously_active_bindings_contributes_only_the_freshest(conn):
    """Mirrors test_identity_bindings.py's equivalent case -- a
    theoretical overlap where more than one binding for a device is
    marked active at once must not produce two targets for one MAC."""
    device = _add_device(conn, "aa:bb:cc:dd:ee:01")
    conn.execute(
        "INSERT INTO device_bindings "
        "(device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, source, active) "
        "VALUES (?, 'aa:bb:cc:dd:ee:01', '192.168.1.21', ?, ?, 'snapshot', 1)",
        (device["id"], "2026-08-29T00:00:00Z", "2026-08-29T00:00:00Z"),
    )
    conn.execute(
        "INSERT INTO device_bindings "
        "(device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, source, active) "
        "VALUES (?, 'aa:bb:cc:dd:ee:01', '192.168.1.22', ?, ?, 'snapshot', 1)",
        (device["id"], "2026-08-29T01:00:00Z", "2026-08-29T01:00:00Z"),
    )

    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == (Target(ip="192.168.1.22", mac="aa:bb:cc:dd:ee:01"),)


def test_brand_new_mac_with_no_pre_existing_devices_row_still_becomes_a_target(conn):
    """Regression test for the real gap found scoping Phase 4, 2026-08-31
    (see RoadMap.md and identity.record_binding's own docstring): before
    the auto-create fix, a MAC observed with no devices row ever created
    for it got device_id = NULL, invisible to this module's own JOIN --
    full, unfiltered access, not merely "ungated." record_binding() now
    auto-creates a fresh, unassociated (PREAUTH) devices row the first
    time a MAC is ever seen, which is what makes it show up here at all."""
    identity.record_binding(conn, "aa:bb:cc:dd:ee:99", "192.168.1.99", source="rtnetlink")

    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == (Target(ip="192.168.1.99", mac="aa:bb:cc:dd:ee:99"),)


def test_full_duplex_flag_passed_through(conn):
    desired = db_backed_desired_state(conn, GATEWAY, full_duplex=True)
    assert desired.full_duplex is True


def test_deleting_a_device_does_not_drop_its_active_binding_out_of_scope(conn):
    """Real gap found live 2026-09-11 (see this module's own dated
    comment): deleting a device row used to silently remove it from
    ARP-spoofing scope entirely (device_bindings.device_id -> NULL via
    ON DELETE SET NULL, invisible to the old INNER JOIN) instead of
    falling back to the same safe PREAUTH treatment a genuinely-new
    device gets -- an unconditional bypass for anyone who deletes their
    own device. The orphaned binding must still become a target."""
    device = _add_device(conn, "aa:bb:cc:dd:ee:01")
    identity.record_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21", source="rtnetlink")
    conn.execute("DELETE FROM devices WHERE id = ?", (device["id"],))
    conn.commit()
    assert conn.execute("SELECT device_id FROM device_bindings").fetchone()["device_id"] is None

    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == (Target(ip="192.168.1.21", mac="aa:bb:cc:dd:ee:01"),)


def test_two_orphaned_bindings_from_different_deleted_devices_both_stay_in_scope(conn):
    """Regression guard for a real, adjacent bug this fix could have
    introduced: keying the dedup-by-device set on device_id instead of
    mac_address would make every orphaned binding collide on the same
    NULL, silently dropping all but the first deleted device."""
    device1 = _add_device(conn, "aa:bb:cc:dd:ee:01")
    device2 = _add_device(conn, "aa:bb:cc:dd:ee:02")
    identity.record_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21", source="rtnetlink")
    identity.record_binding(conn, "aa:bb:cc:dd:ee:02", "192.168.1.22", source="rtnetlink")
    conn.execute("DELETE FROM devices WHERE id IN (?, ?)", (device1["id"], device2["id"]))
    conn.commit()

    desired = db_backed_desired_state(conn, GATEWAY)
    assert set(desired.targets) == {
        Target(ip="192.168.1.21", mac="aa:bb:cc:dd:ee:01"),
        Target(ip="192.168.1.22", mac="aa:bb:cc:dd:ee:02"),
    }


def test_orphaned_binding_from_a_previously_ignored_device_is_still_excluded_if_recreated_ignored(conn):
    """Guards the JOIN-direction fix's own COALESCE: an orphaned binding
    has no devices row at all, so it must default to IN-scope (PREAUTH),
    never accidentally excluded by a bare `d.ignored = 0` that would
    silently pass for NULL in a naive rewrite. This pins the opposite,
    still-correct case: a REAL devices row that says ignored=1 keeps
    excluding it, same as before this fix."""
    _add_device(conn, "aa:bb:cc:dd:ee:01", ignored=1)
    identity.record_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21", source="rtnetlink")

    desired = db_backed_desired_state(conn, GATEWAY)
    assert desired.targets == ()
