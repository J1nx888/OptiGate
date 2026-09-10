"""controller/main.py: _purge_offlan_discovery_junk() -- the one-time
cleanup for RoadMap 2026-09-10 finding #3. Before
identity.record_binding() filtered non-LAN IPs, the discovery loop
recorded Docker-bridge (172.17.x) addresses off docker0 as real
`devices` rows. This deletes exactly those, and nothing else.
"""
from __future__ import annotations

import db
from main import _purge_offlan_discovery_junk


def _device(conn, mac, *, label=None, user_id=None, group_id=None, ignored=0):
    conn.execute(
        "INSERT INTO devices (mac_address, label, user_id, group_id, ignored, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (mac, label, user_id, group_id, ignored, db.now_iso()),
    )
    return conn.execute("SELECT id FROM devices WHERE mac_address = ?", (mac,)).fetchone()["id"]


def _bind(conn, did, mac, ip):
    conn.execute(
        "INSERT INTO device_bindings (device_id, mac_address, ipv4_address, first_seen_at, "
        "last_seen_at, source, active) VALUES (?, ?, ?, ?, ?, 'snapshot', 1)",
        (did, mac, ip, db.now_iso(), db.now_iso()),
    )
    conn.commit()


def _mac_addrs(conn):
    return sorted(r["mac_address"] for r in conn.execute("SELECT mac_address FROM devices"))


def test_purges_a_docker_bridge_junk_device(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    jid = _device(conn, "02:42:ac:11:00:02")
    _bind(conn, jid, "02:42:ac:11:00:02", "172.17.0.2")
    real = _device(conn, "aa:bb:cc:dd:ee:01")
    _bind(conn, real, "aa:bb:cc:dd:ee:01", "192.168.1.10")

    removed = _purge_offlan_discovery_junk(conn)
    assert removed == 1
    assert _mac_addrs(conn) == ["aa:bb:cc:dd:ee:01"]
    assert conn.execute("SELECT COUNT(*) c FROM device_bindings WHERE ipv4_address = '172.17.0.2'").fetchone()["c"] == 0


def test_keeps_an_off_lan_device_that_has_human_intent(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    labelled = _device(conn, "02:42:ac:11:00:03", label="my docker thing")
    _bind(conn, labelled, "02:42:ac:11:00:03", "172.17.0.3")
    assigned = _device(conn, "02:42:ac:11:00:04", user_id=None, group_id=None)
    _bind(conn, assigned, "02:42:ac:11:00:04", "172.17.0.4")
    conn.execute("UPDATE devices SET user_id = NULL WHERE id = ?", (assigned,))
    ignored = _device(conn, "02:42:ac:11:00:05", ignored=1)
    _bind(conn, ignored, "02:42:ac:11:00:05", "172.17.0.5")

    removed = _purge_offlan_discovery_junk(conn)
    # only the labelled + ignored ones have human intent here; the third
    # (bare) one IS junk and goes.
    assert "02:42:ac:11:00:03" in _mac_addrs(conn)
    assert "02:42:ac:11:00:05" in _mac_addrs(conn)
    assert "02:42:ac:11:00:04" not in _mac_addrs(conn)
    assert removed == 1


def test_keeps_a_manually_added_device_with_no_bindings(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    _device(conn, "aa:bb:cc:dd:ee:99")  # no bindings at all
    conn.commit()
    assert _purge_offlan_discovery_junk(conn) == 0
    assert _mac_addrs(conn) == ["aa:bb:cc:dd:ee:99"]


def test_keeps_a_device_with_a_mix_of_off_lan_and_in_lan_bindings(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    did = _device(conn, "aa:bb:cc:dd:ee:07")
    _bind(conn, did, "aa:bb:cc:dd:ee:07", "172.17.0.9")
    _bind(conn, did, "aa:bb:cc:dd:ee:07", "192.168.1.55")
    assert _purge_offlan_discovery_junk(conn) == 0
    assert _mac_addrs(conn) == ["aa:bb:cc:dd:ee:07"]


def test_no_op_when_local_network_is_unset(conn):
    did = _device(conn, "02:42:ac:11:00:02")
    _bind(conn, did, "02:42:ac:11:00:02", "172.17.0.2")
    assert _purge_offlan_discovery_junk(conn) == 0
    assert _mac_addrs(conn) == ["02:42:ac:11:00:02"]
