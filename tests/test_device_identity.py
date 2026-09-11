"""common/device_identity.py: source-IP-based identity resolution for
Squid's intercept mode and, since Phase 4 milestone 3, the captive-portal
login server (resolve_device).

resolve_user() (removed 2026-08-31) used to resolve straight from
client_ip to a `users` row in one query -- replaced by resolve_device()
(unchanged) + resolve_user_for_device(), split apart specifically so a
group- or device-only assignment (no `users` row at all) is never
conflated with "no identity resolved at all" -- see
common/matching.py's device_domain_reason() docstring for the bug this
was part of.
"""
from __future__ import annotations

import db
import identity
from device_identity import resolve_device, resolve_user_for_device

MAC_A = "aa:bb:cc:dd:ee:01"
IP_1 = "192.168.1.21"


def _add_user(conn, username="kid1"):
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) VALUES (?,?,?,?)",
        (username, username, "unused-hash", db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


# ============================================================
# resolve_device
# ============================================================

def test_resolve_device_returns_none_with_no_active_binding(conn):
    assert resolve_device(conn, IP_1) is None


def test_resolve_device_returns_the_device_row(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")

    device = resolve_device(conn, IP_1)

    assert device is not None
    assert device["mac_address"] == MAC_A


def test_resolve_device_works_with_no_user_assigned(conn):
    """Unlike resolve_user, this must still find the device even though
    nobody owns it yet -- that's the whole point (the captive-portal
    login is often the FIRST time a device gets a user at all)."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")

    device = resolve_device(conn, IP_1)

    assert device is not None
    assert device["user_id"] is None


def test_resolve_device_ignores_an_inactive_binding(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-30T00:00:00Z")
    identity.record_binding(conn, "aa:bb:cc:dd:ee:02", IP_1, source="rtnetlink", seen_at="2026-08-31T00:00:00Z")

    device = resolve_device(conn, IP_1)

    assert device["mac_address"] == "aa:bb:cc:dd:ee:02"


# ============================================================
# resolve_device: self-healing an orphaned binding (real gap found
# live 2026-09-11, see this function's own dated docstring)
# ============================================================

def test_resolve_device_self_heals_an_orphaned_binding(conn):
    """Deleting a device leaves its device_bindings row orphaned
    (device_id NULL, ON DELETE SET NULL) rather than deleted. Before
    this fix, resolve_device() returned None for it forever -- exactly
    the "we couldn't identify this device on the network yet" dead end
    hit live on production: retrying never helped, since nothing ever
    created the missing devices row. It must now auto-create a fresh
    PREAUTH row and resolve successfully."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    old_device_id = conn.execute(
        "SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)
    ).fetchone()["device_id"]
    conn.execute("DELETE FROM devices WHERE id = ?", (old_device_id,))
    conn.commit()
    assert conn.execute(
        "SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)
    ).fetchone()["device_id"] is None

    device = resolve_device(conn, IP_1)

    assert device is not None
    assert device["mac_address"] == MAC_A
    # Not asserting device["id"] != old_device_id: SQLite reuses a
    # rowid after deleting the only row in an otherwise-empty table, so
    # a genuinely-fresh INSERT can legitimately land on the same
    # numeric id. What actually matters -- a real, fresh row with
    # correct defaults, not the stale deleted one somehow resurrected
    # -- is covered by the assertions below and by the "only heals
    # once" test's own row-count check.
    assert device["is_authenticated"] == 0, "the same PREAUTH default a genuinely-new MAC gets"
    assert device["ignored"] == 0
    assert device["user_id"] is None
    assert device["group_id"] is None


def test_resolve_device_only_self_heals_once(conn):
    """The second call must hit the fast INNER JOIN path directly, not
    create a second devices row for the same MAC -- the binding gets
    repointed at the newly-created device the first time."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    old_device_id = conn.execute(
        "SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)
    ).fetchone()["device_id"]
    conn.execute("DELETE FROM devices WHERE id = ?", (old_device_id,))
    conn.commit()

    first = resolve_device(conn, IP_1)
    second = resolve_device(conn, IP_1)

    assert first["id"] == second["id"]
    count = conn.execute("SELECT COUNT(*) AS c FROM devices WHERE mac_address = ?", (MAC_A,)).fetchone()["c"]
    assert count == 1, "expected exactly one devices row for this MAC after self-healing"
    rebound = conn.execute(
        "SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)
    ).fetchone()["device_id"]
    assert rebound == first["id"], "the binding should now point directly at the healed device"


def test_resolve_device_still_returns_none_for_a_genuinely_unknown_ip(conn):
    """No binding at all for this IP (not even an orphaned one) -- must
    not accidentally create a devices row for it."""
    assert resolve_device(conn, "192.168.1.250") is None
    assert conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"] == 0


# ============================================================
# resolve_user_for_device
# ============================================================

def test_resolve_user_for_device_returns_none_for_none_device(conn):
    assert resolve_user_for_device(conn, None) is None


def test_resolve_user_for_device_returns_none_when_the_device_has_no_user(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    device = resolve_device(conn, IP_1)
    assert resolve_user_for_device(conn, device) is None


def test_resolve_user_for_device_returns_none_for_a_group_assigned_device(conn):
    """The core case resolve_user() used to get wrong: a group-assigned
    device (user_id NULL, group_id set) is a real, resolvable device --
    it just has no *user* of its own."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    device_id = conn.execute("SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)).fetchone()["device_id"]
    conn.execute(
        "INSERT INTO groups (name, created_at) VALUES ('TVs', ?)", (db.now_iso(),)
    )
    group_id = conn.execute("SELECT id FROM groups WHERE name = 'TVs'").fetchone()["id"]
    conn.execute("UPDATE devices SET group_id = ? WHERE id = ?", (group_id, device_id))
    conn.commit()

    device = resolve_device(conn, IP_1)

    assert device["group_id"] == group_id
    assert resolve_user_for_device(conn, device) is None


def test_resolve_user_for_device_returns_the_owning_user(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")
    device_id = conn.execute("SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_1,)).fetchone()["device_id"]
    user = _add_user(conn)
    conn.execute("UPDATE devices SET user_id = ? WHERE id = ?", (user["id"], device_id))
    conn.commit()

    device = resolve_device(conn, IP_1)
    resolved = resolve_user_for_device(conn, device)

    assert resolved["username"] == "kid1"
