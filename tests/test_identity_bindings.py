"""common/identity.py: device_bindings observation recording, MAC/IP
conflict handling, and the network_events log."""
from __future__ import annotations

import json
import threading

import db
import identity

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"
IP_1 = "192.168.1.21"
IP_2 = "192.168.1.22"


def _add_device(conn, mac_address, ignored=0):
    conn.execute(
        "INSERT INTO devices (mac_address, ignored, created_at) VALUES (?, ?, ?)",
        (mac_address, ignored, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,)).fetchone()


def _bindings(conn):
    return conn.execute("SELECT * FROM device_bindings").fetchall()


def _events(conn):
    return conn.execute("SELECT * FROM network_events ORDER BY id").fetchall()


# ------------------------------------------------------------- new bindings

def test_new_mac_auto_creates_a_pending_devices_row_and_event(conn):
    """Phase 4 addition, 2026-08-31: a genuinely brand-new MAC (no
    devices row, no prior device_bindings row at all) gets a fresh,
    unassociated devices row auto-created for it, is_authenticated=0
    (PREAUTH) -- see record_binding's own docstring for why this
    closes a real gap (an unassociated device previously got NO
    interception at all, invisible to desired_state.py's own JOIN)."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")

    rows = _bindings(conn)
    assert len(rows) == 1
    assert rows[0]["device_id"] is not None
    assert rows[0]["mac_address"] == MAC_A
    assert rows[0]["ipv4_address"] == IP_1
    assert rows[0]["first_seen_at"] == "2026-08-29T00:00:00Z"
    assert rows[0]["last_seen_at"] == "2026-08-29T00:00:00Z"
    assert rows[0]["active"] == 1

    device = conn.execute(
        "SELECT * FROM devices WHERE id = ?", (rows[0]["device_id"],)
    ).fetchone()
    assert device["mac_address"] == MAC_A
    assert device["is_authenticated"] == 0, "must override the schema's own default of 1"
    assert device["ignored"] == 0
    assert device["user_id"] is None

    events = _events(conn)
    assert len(events) == 1
    assert events[0]["event_type"] == "device_auto_created"
    assert events[0]["device_id"] == rows[0]["device_id"]
    assert events[0]["mac_address"] == MAC_A


def test_new_mac_auto_create_also_logs_a_system_events_info_row(conn):
    """Fixed 2026-09-09, real gap found live: device_auto_created was
    already recorded in network_events (see the test above), but that
    table has no dashboard page of its own -- an admin had no way to
    see "a new device just showed up" without querying the DB directly.
    Deliberately checks this fires regardless of `source` (not just for
    the network sweep) -- any discovery path finding a genuinely new
    device is equally worth surfacing."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")

    rows = conn.execute("SELECT * FROM system_events").fetchall()
    assert len(rows) == 1
    assert rows[0]["severity"] == "info"
    assert rows[0]["source"] == "device_discovery"
    assert MAC_A in rows[0]["message"]
    assert IP_1 in rows[0]["message"]


def test_a_second_binding_for_an_existing_device_does_not_log_a_system_event(conn):
    """Only the genuinely-new-device case is an 'info'-worthy event --
    every subsequent ordinary binding (a DHCP renewal, a second IP) must
    stay silent, matching system_events.py's own "not a firehose"
    scope."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")
    identity.record_binding(conn, MAC_A, IP_2, source="rtnetlink", seen_at="2026-08-29T00:05:00Z")

    assert conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"] == 1, (
        "only the first, genuinely-new binding should have logged anything"
    )


def test_new_mac_on_a_second_ever_binding_still_does_not_auto_associate(conn):
    """The auto-create only ever fires on a MAC's first-ever binding --
    a second, brand-new binding for an ALREADY-known MAC (e.g. two IPs
    briefly both seen before conflict resolution reconciles them, or a
    caller building rows directly) must reuse the same devices row, not
    create a second one."""
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")
    first_device_id = _bindings(conn)[0]["device_id"]

    identity.record_binding(conn, MAC_A, IP_2, source="rtnetlink", seen_at="2026-08-29T00:05:00Z")

    device_ids = {row["device_id"] for row in _bindings(conn)}
    assert device_ids == {first_device_id}, "must reuse the same auto-created device, not create a second"
    assert conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"] == 1


def test_an_already_known_unassociated_mac_is_never_retroactively_auto_created(conn):
    """Grandfather clause, per the explicit 2026-08-31 product decision
    (no retroactive backfill -- see record_binding's own docstring): a
    MAC that already had a device_bindings row (even an inactive,
    long-superseded one) BEFORE this feature shipped must never get a
    devices row auto-created for it later, even across a normal DHCP
    renewal -- only a MAC with NO prior binding at all qualifies."""
    # Simulates a pre-existing, already-known-but-unassociated binding,
    # as if written by a version of this code before the auto-create
    # fix existed: a real device_bindings row with device_id NULL.
    conn.execute(
        "INSERT INTO device_bindings "
        "(device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, source, active) "
        "VALUES (NULL, ?, ?, '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z', 'snapshot', 0)",
        (MAC_A, IP_1),
    )

    # A later DHCP renewal for the SAME already-known MAC, onto a new IP.
    identity.record_binding(conn, MAC_A, IP_2, source="rtnetlink", seen_at="2026-08-31T00:00:00Z")

    row = conn.execute(
        "SELECT device_id FROM device_bindings WHERE ipv4_address = ?", (IP_2,)
    ).fetchone()
    assert row["device_id"] is None, "a MAC already known before this feature shipped stays unassociated"
    assert conn.execute("SELECT COUNT(*) AS c FROM devices").fetchone()["c"] == 0
    assert {e["event_type"] for e in _events(conn)} == {"binding_pending_association"}


def test_known_mac_associates_device_id_without_a_pending_event(conn):
    device = _add_device(conn, MAC_A)
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink")

    rows = _bindings(conn)
    assert len(rows) == 1
    assert rows[0]["device_id"] == device["id"]
    assert _events(conn) == []  # already associated -- nothing pending to log


def test_repeated_observation_updates_last_seen_only(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")
    identity.record_binding(conn, MAC_A, IP_1, source="snapshot", seen_at="2026-08-29T00:05:00Z")

    rows = _bindings(conn)
    assert len(rows) == 1, "a repeated (mac, ip) observation must not create a second row"
    assert rows[0]["first_seen_at"] == "2026-08-29T00:00:00Z"
    assert rows[0]["last_seen_at"] == "2026-08-29T00:05:00Z"
    assert rows[0]["source"] == "snapshot"


# --------------------------------------------------------- conflict handling

def test_ip_reassigned_deactivates_old_binding_and_logs_event(conn):
    """IP_1 held by MAC_A, then a completely different MAC shows up
    claiming IP_1 (e.g. MAC_A's lease expired and DHCP handed the
    address to a new device)."""
    device_a = _add_device(conn, MAC_A)
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")

    identity.record_binding(conn, MAC_B, IP_1, source="rtnetlink", seen_at="2026-08-29T01:00:00Z")

    rows = {r["mac_address"]: r for r in _bindings(conn)}
    assert rows[MAC_A]["active"] == 0, "the old MAC_A/IP_1 binding must be deactivated"
    assert rows[MAC_B]["active"] == 1
    assert rows[MAC_B]["device_id"] is not None  # MAC_B auto-got a fresh, pending devices row

    # Two events, not one: the conflict itself ("ip_reassigned"), plus
    # MAC_B's own "device_auto_created" since MAC_B has never been seen
    # before -- the two are independent facts about this single
    # observation.
    events = {e["event_type"]: e for e in _events(conn)}
    assert set(events) == {"ip_reassigned", "device_auto_created"}

    reassigned = events["ip_reassigned"]
    assert reassigned["device_id"] == device_a["id"]
    assert reassigned["mac_address"] == MAC_A
    assert reassigned["ipv4_address"] == IP_1
    assert json.loads(reassigned["payload_json"]) == {"new_mac_address": MAC_B}

    auto_created = events["device_auto_created"]
    assert auto_created["device_id"] == rows[MAC_B]["device_id"]
    assert auto_created["mac_address"] == MAC_B
    assert auto_created["ipv4_address"] == IP_1


def test_device_ip_changed_deactivates_old_binding_and_logs_event(conn):
    """Same MAC, new IP -- an ordinary DHCP lease renewal."""
    device = _add_device(conn, MAC_A)
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")

    identity.record_binding(conn, MAC_A, IP_2, source="rtnetlink", seen_at="2026-08-29T02:00:00Z")

    rows = {r["ipv4_address"]: r for r in _bindings(conn)}
    assert rows[IP_1]["active"] == 0
    assert rows[IP_2]["active"] == 1
    assert rows[IP_2]["device_id"] == device["id"], (
        "the new binding must inherit the device_id from the superseded one"
    )

    events = _events(conn)
    assert len(events) == 1
    assert events[0]["event_type"] == "ip_changed"
    assert events[0]["device_id"] == device["id"]
    assert events[0]["ipv4_address"] == IP_1  # the OLD ip, per the event's own semantics
    assert json.loads(events[0]["payload_json"]) == {"new_ipv4_address": IP_2}


def test_both_conflicts_at_once_are_each_handled_independently(conn):
    """MAC_A was on IP_1; MAC_B was on IP_2. Now MAC_A is observed on
    IP_2 -- both MAC_A's old binding and MAC_B's old binding must be
    deactivated, with two separate events."""
    _add_device(conn, MAC_A)
    _add_device(conn, MAC_B)
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")
    identity.record_binding(conn, MAC_B, IP_2, source="rtnetlink", seen_at="2026-08-29T00:01:00Z")

    identity.record_binding(conn, MAC_A, IP_2, source="rtnetlink", seen_at="2026-08-29T03:00:00Z")

    active = {r["mac_address"]: r for r in _bindings(conn) if r["active"] == 1}
    assert set(active) == {MAC_A}
    assert active[MAC_A]["ipv4_address"] == IP_2

    event_types = {e["event_type"] for e in _events(conn)}
    assert event_types == {"ip_reassigned", "ip_changed"}


# ------------------------------------------------------------- active_binding_ip

def test_active_binding_ip_returns_none_when_no_binding(conn):
    device = _add_device(conn, MAC_A)
    assert identity.active_binding_ip(conn, device["id"]) is None


def test_active_binding_ip_returns_the_freshest_active_binding(conn):
    device = _add_device(conn, MAC_A)
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")
    # Manually insert a second (theoretical) simultaneously-active binding
    # with a later last_seen_at, to test the ORDER BY behavior directly
    # rather than relying on record_binding's own conflict handling (which
    # would normally deactivate the older one itself).
    conn.execute(
        "INSERT INTO device_bindings "
        "(device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, source, active) "
        "VALUES (?, ?, ?, ?, ?, 'snapshot', 1)",
        (device["id"], MAC_A, IP_2, "2026-08-29T01:00:00Z", "2026-08-29T01:00:00Z"),
    )

    assert identity.active_binding_ip(conn, device["id"]) == IP_2


# ------------------------------------------------------------- network_events

def test_record_network_event_stores_arbitrary_payload_as_json(conn):
    identity.record_network_event(
        conn,
        "device_seen",
        mac_address=MAC_A,
        ipv4_address=IP_1,
        source="snapshot",
        payload={"band": "5ghz", "attached_to": "satellite-1"},
    )
    row = _events(conn)[0]
    assert row["event_type"] == "device_seen"
    assert json.loads(row["payload_json"]) == {"band": "5ghz", "attached_to": "satellite-1"}


# ------------------------------------------------------------- touch_binding_by_ip
# (Milestone 4's AdGuard query-log discovery source -- see
# controller/adguard_discovery.py, which is the one real caller.)

def test_touch_binding_by_ip_refreshes_last_seen_at_for_an_active_binding(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")

    updated = identity.touch_binding_by_ip(conn, IP_1, "2026-08-29T01:00:00Z")

    assert updated is True
    row = _bindings(conn)[0]
    assert row["last_seen_at"] == "2026-08-29T01:00:00Z"
    assert row["source"] == "adguard"
    assert row["mac_address"] == MAC_A  # unchanged -- this call never touches identity


def test_touch_binding_by_ip_does_not_regress_last_seen_at_backward(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T02:00:00Z")

    updated = identity.touch_binding_by_ip(conn, IP_1, "2026-08-29T01:00:00Z")

    assert updated is False
    row = _bindings(conn)[0]
    assert row["last_seen_at"] == "2026-08-29T02:00:00Z"
    assert row["source"] == "rtnetlink"  # unchanged -- the stale touch never applied


def test_touch_binding_by_ip_is_a_no_op_when_seen_at_is_not_strictly_newer(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")

    updated = identity.touch_binding_by_ip(conn, IP_1, "2026-08-29T00:00:00Z")

    assert updated is False


def test_touch_binding_by_ip_returns_false_when_no_active_binding_exists_for_the_ip(conn):
    assert identity.touch_binding_by_ip(conn, "192.168.1.99", "2026-08-29T00:00:00Z") is False


def test_touch_binding_by_ip_ignores_an_inactive_binding_for_the_same_ip(conn):
    # IP_1 gets reassigned from MAC_A to MAC_B -- record_binding's own
    # conflict handling deactivates MAC_A's binding for IP_1.
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-29T00:00:00Z")
    identity.record_binding(conn, MAC_B, IP_1, source="rtnetlink", seen_at="2026-08-29T01:00:00Z")

    updated = identity.touch_binding_by_ip(conn, IP_1, "2026-08-29T02:00:00Z")

    assert updated is True
    rows = {row["mac_address"]: row for row in _bindings(conn)}
    assert rows[MAC_A]["active"] == 0
    assert rows[MAC_A]["last_seen_at"] == "2026-08-29T00:00:00Z"  # untouched
    assert rows[MAC_B]["active"] == 1
    assert rows[MAC_B]["last_seen_at"] == "2026-08-29T02:00:00Z"  # this is the one that got touched


# ============================================================
# Concurrency -- fixed 2026-09-02, a real race found by code review
# ============================================================

def test_record_binding_never_leaves_two_active_bindings_for_one_ip(conn, monkeypatch):
    """Regression test for a real bug: record_binding()'s conflict
    check (is this IP already actively bound to a DIFFERENT mac?) and
    its own write used to run as separate autocommit statements
    (common/db.py opens with isolation_level=None) with nothing making
    the two atomic. Two near-simultaneous callers observing the SAME IP
    for two DIFFERENT, both-brand-new MACs could each read "no active
    conflict" before either had written its own row, so neither
    deactivated the other -- leaving TWO active=1 device_bindings rows
    for one IP, an invariant nothing else in this codebase expects to
    ever be violated (device_identity.resolve_device()'s `ORDER BY
    last_seen_at DESC LIMIT 1` picks one of the two nondeterministically).

    Deterministic, not a hope-the-scheduler-cooperates race:
    MAC_A's thread is paused (via a monkeypatched
    _existing_device_id_for_mac, the read that runs right after both
    conflict checks and before any write for a brand-new IP with no
    prior bindings) after it has already read "no conflict" but before
    it writes anything. MAC_B's thread is only started once MAC_A is
    confirmed paused there. Pre-fix, nothing stops MAC_B from running
    to completion in the meantime (it also reads "no conflict" and
    writes its own active row) before MAC_A is released to write its
    own -- reproducing the bug on every run. Post-fix, MAC_B blocks
    inside its own BEGIN IMMEDIATE (MAC_A's transaction still holds the
    write lock) until MAC_A is released and commits, at which point
    MAC_B's own (now-unblocked) read correctly sees MAC_A's committed
    row as the real conflict and deactivates it -- no deadlock either
    way, since MAC_B never itself waits on a signal only MAC_A's own
    completion can provide."""
    import identity as identity_module

    mac_a_paused = threading.Event()
    release_mac_a = threading.Event()
    real_lookup = identity_module._existing_device_id_for_mac

    def paused_lookup(conn_arg, mac_address):
        if mac_address == MAC_A:
            mac_a_paused.set()
            release_mac_a.wait(timeout=5)
        return real_lookup(conn_arg, mac_address)

    monkeypatch.setattr(identity_module, "_existing_device_id_for_mac", paused_lookup)

    def call_record_binding(mac):
        own_conn = db.get_conn()  # sqlite3.Connection objects are thread-affined
        try:
            identity.record_binding(own_conn, mac, IP_1, source="rtnetlink")
        finally:
            own_conn.close()

    t1 = threading.Thread(target=call_record_binding, args=(MAC_A,))
    t1.start()
    assert mac_a_paused.wait(timeout=5), "MAC_A's thread never reached the pause point"

    t2 = threading.Thread(target=call_record_binding, args=(MAC_B,))
    t2.start()
    # Deliberately short relative to db.get_conn()'s 5s busy_timeout (common/db.py):
    # pre-fix, an unblocked MAC_B finishes in milliseconds, so 1s is ample margin
    # to observe that. Post-fix, MAC_B is parked inside BEGIN IMMEDIATE behind
    # MAC_A's write lock and is still alive here. Using anything close to 5s would
    # race MAC_B's own busy_timeout against release_mac_a.set() below and could
    # make MAC_B's BEGIN IMMEDIATE time out for real on a loaded machine instead of
    # waiting for MAC_A -- exactly the flake this margin avoids.
    t2.join(timeout=1.0)

    release_mac_a.set()
    t1.join(timeout=10)
    t2.join(timeout=10)  # post-fix, MAC_B can only finish once MAC_A's commit releases the lock

    active = conn.execute(
        "SELECT mac_address FROM device_bindings WHERE ipv4_address = ? AND active = 1", (IP_1,)
    ).fetchall()
    assert len(active) == 1, (
        f"expected exactly one active binding for {IP_1}, got {[r['mac_address'] for r in active]} -- "
        "the conflict-check-then-write sequence let both writers through"
    )


# --------------------------------------------- off-LAN guard (RoadMap #3)

DOCKER_MAC = "02:42:ac:11:00:02"
DOCKER_IP = "172.17.0.2"


def test_record_binding_ignores_an_off_lan_ip(conn):
    """RoadMap 2026-09-10 finding #3: discovery watching docker0 must not
    turn a 172.17.x container address into a devices row."""
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    identity.record_binding(conn, DOCKER_MAC, DOCKER_IP, source="snapshot")
    assert _bindings(conn) == []
    assert conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"] == 0
    assert _events(conn) == []


def test_record_binding_still_records_an_in_lan_ip_with_the_setting_on(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    identity.record_binding(conn, MAC_A, IP_1, source="snapshot")
    assert len(_bindings(conn)) == 1
    assert conn.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"] == 1


def test_record_binding_records_everything_when_local_network_is_unset(conn):
    # No local_network setting -> LAN check disabled -> even 172.17.x is
    # recorded, matching ip_in_configured_lan's documented behaviour.
    identity.record_binding(conn, DOCKER_MAC, DOCKER_IP, source="snapshot")
    assert len(_bindings(conn)) == 1


def test_record_binding_honours_a_multi_cidr_local_network(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24 10.0.0.0/24")
    identity.record_binding(conn, MAC_A, "10.0.0.5", source="rtnetlink")
    identity.record_binding(conn, DOCKER_MAC, DOCKER_IP, source="rtnetlink")
    ips = sorted(b["ipv4_address"] for b in _bindings(conn))
    assert ips == ["10.0.0.5"]
