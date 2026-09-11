"""controller/policy_state.py: computing + persisting the DesiredPolicy
JSON blob that phase3/nftables-manager reads directly from the shared
DB."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import db
import identity
from policy_state import compute_desired_policy, write_desired_policy


def _add_device(
    conn, mac_address, ignored=0, quarantined_at=None, is_authenticated=1, bump_enabled=0, bypass_login=0
):
    conn.execute(
        "INSERT INTO devices "
        "(mac_address, ignored, quarantined_at, is_authenticated, bump_enabled, bypass_login, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (mac_address, ignored, quarantined_at, is_authenticated, bump_enabled, bypass_login, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,)).fetchone()


def _bind(conn, mac_address, ip):
    identity.record_binding(conn, mac_address, ip, source="rtnetlink")


def test_empty_db_yields_all_empty_sets(conn):
    policy = compute_desired_policy(conn)
    assert policy == {
        "authenticated": [],
        "unauthenticated": [],
        "bypass": [],
        "quarantine": [],
        "bump": [],
    }


def test_authenticated_device_goes_in_authenticated_set(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn)
    assert policy["authenticated"] == ["192.168.1.21"]
    assert policy["unauthenticated"] == []
    assert policy["bump"] == []


def test_unauthenticated_device_goes_in_unauthenticated_set(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=0)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn)
    assert policy["unauthenticated"] == ["192.168.1.21"]


def test_bypass_login_device_lands_in_authenticated_set_end_to_end(conn):
    """Regression test for a real bug found 2026-08-31: this query
    never even SELECTed bypass_login, so classify_device() could never
    have honored it regardless of its own logic -- a bypass_login
    device stayed stuck in 'unauthenticated' forever. Full pipeline
    proof, not just the pure classify_device() unit test."""
    _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=0, bypass_login=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn)
    assert policy["authenticated"] == ["192.168.1.21"]
    assert policy["unauthenticated"] == []


def test_ignored_device_goes_in_bypass_set_even_if_unauthenticated(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01", ignored=1, is_authenticated=0)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn)
    assert policy["bypass"] == ["192.168.1.21"]
    assert policy["unauthenticated"] == []


def test_device_in_an_ignored_group_goes_in_bypass_set(conn):
    """Group-level ignore (added 2026-09-07, db.py's schema comment on
    groups.ignored) -- full pipeline proof that the query's new LEFT
    JOIN + group_ignored plumbing actually reaches classify_device(),
    not just the pure unit test in test_policy_class.py."""
    conn.execute("INSERT INTO groups (name, ignored, created_at) VALUES ('IoT', 1, ?)", (db.now_iso(),))
    conn.commit()
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    conn.execute(
        "INSERT INTO devices (mac_address, group_id, ignored, is_authenticated, created_at) "
        "VALUES (?, ?, 0, 0, ?)",
        ("aa:bb:cc:dd:ee:01", group_id, db.now_iso()),
    )
    conn.commit()
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")

    policy = compute_desired_policy(conn)

    assert policy["bypass"] == ["192.168.1.21"]
    assert policy["unauthenticated"] == []


def test_bump_enabled_device_in_an_ignored_group_is_excluded_from_bump(conn):
    conn.execute("INSERT INTO groups (name, ignored, created_at) VALUES ('IoT', 1, ?)", (db.now_iso(),))
    conn.commit()
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'IoT'").fetchone()["id"]
    conn.execute(
        "INSERT INTO devices (mac_address, group_id, ignored, is_authenticated, bump_enabled, created_at) "
        "VALUES (?, ?, 0, 1, 1, ?)",
        ("aa:bb:cc:dd:ee:01", group_id, db.now_iso()),
    )
    conn.commit()
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")

    policy = compute_desired_policy(conn)

    assert policy["bump"] == []
    assert policy["bypass"] == ["192.168.1.21"]


def test_quarantined_device_goes_in_quarantine_set(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01", quarantined_at="2026-08-29T00:00:00Z")
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn)
    assert policy["quarantine"] == ["192.168.1.21"]


def test_bump_enabled_authenticated_device_is_in_both_authenticated_and_bump(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=1, bump_enabled=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn)
    assert policy["authenticated"] == ["192.168.1.21"]
    assert policy["bump"] == ["192.168.1.21"]


def test_bump_enabled_but_unauthenticated_device_is_excluded_from_bump(conn):
    # Hasn't logged in yet -- no DNS-tier access at all, so it can't be
    # bump-eligible either, regardless of the admin's bump_enabled flag.
    _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=0, bump_enabled=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn)
    assert policy["unauthenticated"] == ["192.168.1.21"]
    assert policy["bump"] == []


def test_bump_enabled_but_ignored_device_is_excluded_from_bump(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01", ignored=1, bump_enabled=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn)
    assert policy["bypass"] == ["192.168.1.21"]
    assert policy["bump"] == []


def test_brand_new_mac_with_no_pre_existing_devices_row_lands_in_unauthenticated(conn):
    """End-to-end proof of the Phase 4 gap fix, 2026-08-31: a MAC with
    NO devices row created ahead of time (unlike every other test in
    this file, which pre-creates one via _add_device) still ends up
    gated in the unauthenticated_v4 set on its very first observation,
    since identity.record_binding() now auto-creates a PREAUTH devices
    row for it -- not silently excluded from every set the way a
    device_id = NULL binding used to be."""
    identity.record_binding(conn, "aa:bb:cc:dd:ee:99", "192.168.1.99", source="rtnetlink")
    policy = compute_desired_policy(conn)
    assert policy["unauthenticated"] == ["192.168.1.99"]
    assert policy["authenticated"] == []
    assert policy["bypass"] == []


def test_deleting_a_device_lands_its_orphaned_binding_in_unauthenticated_not_nowhere(conn):
    """Real gap found live 2026-09-11 (see this module's own dated
    comment): deleting a device row used to make its still-active
    binding vanish from every set -- device_bindings.device_id goes
    NULL (ON DELETE SET NULL) and the old INNER JOIN dropped it
    entirely, which functioned as an unconditional bypass (no set
    membership means no nftables rule restricts it at all). It must now
    fall back to the same safe PREAUTH/unauthenticated treatment a
    genuinely-new device gets."""
    device = _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    conn.execute("DELETE FROM devices WHERE id = ?", (device["id"],))
    conn.commit()

    policy = compute_desired_policy(conn)

    assert policy["unauthenticated"] == ["192.168.1.21"]
    assert policy["authenticated"] == []
    assert policy["bypass"] == []
    assert policy["quarantine"] == []
    assert policy["bump"] == []


def test_deleting_a_bump_enabled_device_does_not_leave_it_bump_eligible(conn):
    """A deleted device's orphaned binding must never land in the bump
    set -- bump_eligible() already requires AUTHENTICATED, which an
    orphaned (device_id NULL) row can never be, but this pins the
    specific case where the device was bump_enabled right before
    deletion, guarding against a future regression that special-cases
    bump_enabled ahead of the AUTHENTICATED check."""
    device = _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=1, bump_enabled=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    conn.execute("DELETE FROM devices WHERE id = ?", (device["id"],))
    conn.commit()

    policy = compute_desired_policy(conn)

    assert policy["bump"] == []
    assert policy["unauthenticated"] == ["192.168.1.21"]


def test_orphaned_binding_still_goes_to_quarantine_under_a_global_lockout_schedule(conn):
    """A deleted device has no id/user_id/group_id for a targeted
    schedule to match, but a lockout_all is_global=1 schedule applies to
    everyone regardless -- see matching.schedule_applies_to_target's own
    is_global short-circuit. Confirms the quarantine overlay still
    reaches a fully-NULL device row rather than raising or silently
    skipping it."""
    _add_lockout_schedule(conn)
    device = _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    conn.execute("DELETE FROM devices WHERE id = ?", (device["id"],))
    conn.commit()

    policy = compute_desired_policy(conn, now=_DURING_LOCKOUT)

    assert policy["quarantine"] == ["192.168.1.21"]
    assert policy["unauthenticated"] == []


def test_device_with_no_binding_is_excluded_from_every_set(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01")
    policy = compute_desired_policy(conn)
    assert all(ips == [] for ips in policy.values())


def test_output_is_sorted(conn):
    _add_device(conn, "aa:bb:cc:dd:ee:01")
    _add_device(conn, "aa:bb:cc:dd:ee:02")
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.30")
    _bind(conn, "aa:bb:cc:dd:ee:02", "192.168.1.10")
    policy = compute_desired_policy(conn)
    assert policy["authenticated"] == ["192.168.1.10", "192.168.1.30"]


def test_write_desired_policy_persists_and_upserts(conn):
    policy1 = {"authenticated": ["192.168.1.21"], "unauthenticated": [], "bypass": [], "quarantine": []}
    write_desired_policy(conn, policy1)
    row = conn.execute(
        "SELECT desired_policy_json FROM interception_runtime WHERE singleton_id = 1"
    ).fetchone()
    assert json.loads(row["desired_policy_json"]) == policy1

    policy2 = {"authenticated": [], "unauthenticated": ["192.168.1.99"], "bypass": [], "quarantine": []}
    write_desired_policy(conn, policy2)
    row = conn.execute(
        "SELECT desired_policy_json FROM interception_runtime WHERE singleton_id = 1"
    ).fetchone()
    assert json.loads(row["desired_policy_json"]) == policy2

    count = conn.execute("SELECT COUNT(*) AS c FROM interception_runtime").fetchone()["c"]
    assert count == 1, "expected a single upserted singleton row, not a new row per write"


# --------------------------------------- Phase 8: scheduled full-lockout overlay

def _add_lockout_schedule(conn, name="Bedtime", is_global=1, days="mon", start="21:00", end="06:00"):
    conn.execute(
        "INSERT INTO schedules (name, days_of_week, start_time, end_time, time_zone, "
        "lockout_all, is_global, created_at) VALUES (?, ?, ?, ?, 'UTC', 1, ?, ?)",
        (name, days, start, end, is_global, db.now_iso()),
    )
    conn.commit()


# Monday 2026-08-31 22:00 UTC -- inside the default "mon 21:00-06:00" window.
_DURING_LOCKOUT = datetime(2026, 8, 31, 22, 0, tzinfo=timezone.utc)
# Monday 2026-08-31 12:00 UTC -- outside it.
_OUTSIDE_LOCKOUT = datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc)


def test_device_under_active_global_lockout_schedule_goes_to_quarantine(conn):
    _add_lockout_schedule(conn)
    _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn, now=_DURING_LOCKOUT)
    assert policy["quarantine"] == ["192.168.1.21"]
    assert policy["authenticated"] == []


def test_same_device_outside_the_lockout_window_is_unaffected(conn):
    _add_lockout_schedule(conn)
    _add_device(conn, "aa:bb:cc:dd:ee:01", is_authenticated=1)
    _bind(conn, "aa:bb:cc:dd:ee:01", "192.168.1.21")
    policy = compute_desired_policy(conn, now=_OUTSIDE_LOCKOUT)
    assert policy["authenticated"] == ["192.168.1.21"]
    assert policy["quarantine"] == []


def test_ignored_device_stays_bypass_even_during_an_active_lockout_schedule(conn):
    _add_lockout_schedule(conn)
    _add_device(conn, "aa:bb:cc:dd:ee:02", ignored=1)
    _bind(conn, "aa:bb:cc:dd:ee:02", "192.168.1.22")
    policy = compute_desired_policy(conn, now=_DURING_LOCKOUT)
    assert policy["bypass"] == ["192.168.1.22"]
    assert policy["quarantine"] == []


def test_manually_quarantined_device_is_unaffected_by_schedule_state_either_way(conn):
    # No lockout schedule at all -- a manual quarantine must still hold on
    # its own, independent of Phase 8 ever having been configured.
    _add_device(conn, "aa:bb:cc:dd:ee:03", quarantined_at=db.now_iso())
    _bind(conn, "aa:bb:cc:dd:ee:03", "192.168.1.23")
    policy = compute_desired_policy(conn, now=_OUTSIDE_LOCKOUT)
    assert policy["quarantine"] == ["192.168.1.23"]

    # And an active lockout schedule elsewhere changes nothing about it --
    # still just the one, already-explained reason it's quarantined.
    _add_lockout_schedule(conn)
    policy = compute_desired_policy(conn, now=_DURING_LOCKOUT)
    assert policy["quarantine"] == ["192.168.1.23"]


def test_bump_enabled_device_under_an_active_lockout_is_excluded_from_bump(conn):
    """Regression test for a real bug (fixed 2026-09-02): the bump_v4
    membership check used to be computed from the device's raw
    classify_device() result, blind to the QUARANTINE overlay this
    function applies for an active lockout_all schedule -- so a
    bump-enabled, otherwise-authenticated device caught in a bedtime
    lockout used to land in BOTH the quarantine set AND the bump set at
    once, violating bump_eligible()'s own documented invariant."""
    _add_lockout_schedule(conn)
    _add_device(conn, "aa:bb:cc:dd:ee:06", is_authenticated=1, bump_enabled=1)
    _bind(conn, "aa:bb:cc:dd:ee:06", "192.168.1.26")

    policy = compute_desired_policy(conn, now=_DURING_LOCKOUT)
    assert policy["quarantine"] == ["192.168.1.26"]
    assert policy["bump"] == [], "a quarantined-by-schedule device must never also be in the bump set"

    # Outside the lockout window, the exact same device is bump-eligible
    # again -- confirms this fix didn't just disable bump for it outright.
    policy = compute_desired_policy(conn, now=_OUTSIDE_LOCKOUT)
    assert policy["authenticated"] == ["192.168.1.26"]
    assert policy["bump"] == ["192.168.1.26"]


def test_non_lockout_schedule_never_triggers_the_quarantine_overlay(conn):
    conn.execute(
        "INSERT INTO schedules (name, days_of_week, start_time, end_time, time_zone, "
        "lockout_all, is_global, created_at) VALUES ('School hours', 'mon', '00:00', '23:59', "
        "'UTC', 0, 1, ?)",
        (db.now_iso(),),
    )
    conn.commit()
    _add_device(conn, "aa:bb:cc:dd:ee:04", is_authenticated=1)
    _bind(conn, "aa:bb:cc:dd:ee:04", "192.168.1.24")
    policy = compute_desired_policy(conn, now=_DURING_LOCKOUT)
    assert policy["authenticated"] == ["192.168.1.24"]
    assert policy["quarantine"] == []


def test_defaults_to_real_current_time_when_now_is_omitted(conn):
    # Just confirming the default path doesn't blow up and returns the
    # normal shape -- exact behavior for "right now" isn't asserted since
    # that would make the test's outcome depend on when it happens to run.
    _add_device(conn, "aa:bb:cc:dd:ee:05", is_authenticated=1)
    _bind(conn, "aa:bb:cc:dd:ee:05", "192.168.1.25")
    policy = compute_desired_policy(conn)
    assert "192.168.1.25" in policy["authenticated"] + policy["quarantine"]
