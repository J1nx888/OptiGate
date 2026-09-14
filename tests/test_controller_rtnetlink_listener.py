"""controller/rtnetlink_listener.py: the pure message-filtering logic
(extract_ipv4_binding), tested against real message shapes captured from
a real Linux kernel (see the module's own docstring), plus the
listener's threading/retry wiring, tested against a fake `pyroute2`
module injected via sys.modules -- this project's controller/common code
is otherwise stdlib-only, and pyroute2 is Linux-only (no AF_NETLINK on
Windows), so these tests must not require it to actually be installed.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
import types

import pytest

import rtnetlink_listener

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6
AF_BRIDGE = 7  # not exposed as a socket.AF_* constant on every platform

# ============================================================
# extract_ipv4_binding -- real captured message shapes
# ============================================================

# A real AF_BRIDGE FDB-learning entry (docker0 learning a veth's MAC) --
# NOT an ARP/NDP neighbor at all, must be filtered out. Captured live.
BRIDGE_FDB_NOISE = {
    "event": "RTM_NEWNEIGH",
    "family": AF_BRIDGE,
    "ifindex": 223,
    "ndm_type": 0,
    "state": 128,  # NUD_PERMANENT
    "attrs": [("NDA_LLADDR", "e2:17:be:0d:0a:1a"), ("NDA_MASTER", 4), ("NDA_FLAGS_EXT", 0)],
}

# A real IPv4 ARP neighbor entry -- exactly what this listener exists to
# catch. Captured live (a container pinging its bridge gateway).
REAL_ARP_NEIGHBOR = {
    "event": "RTM_NEWNEIGH",
    "family": AF_INET,
    "ifindex": 4,
    "ndm_type": 1,
    "state": 2,  # NUD_REACHABLE
    "attrs": [
        ("NDA_DST", "172.17.0.2"),
        ("NDA_LLADDR", "F6:D0:02:BC:A7:E7"),
        ("NDA_PROBES", 4),
    ],
}

# A real IPv6 neighbor-discovery entry (solicited-node multicast) -- out
# of scope, this project's device_bindings model is IPv4-only. Captured
# live.
IPV6_NOISE = {
    "event": "RTM_NEWNEIGH",
    "family": AF_INET6,
    "ifindex": 223,
    "ndm_type": 5,
    "state": 64,  # NUD_NOARP
    "attrs": [("NDA_DST", "ff02::16"), ("NDA_LLADDR", "33:33:00:00:00:16")],
}


def test_extracts_a_real_ipv4_arp_neighbor():
    assert rtnetlink_listener.extract_ipv4_binding(REAL_ARP_NEIGHBOR) == ("172.17.0.2", "f6:d0:02:bc:a7:e7")


def test_rejects_af_bridge_fdb_noise():
    assert rtnetlink_listener.extract_ipv4_binding(BRIDGE_FDB_NOISE) is None


def test_rejects_ipv6_neighbors():
    assert rtnetlink_listener.extract_ipv4_binding(IPV6_NOISE) is None


def test_rejects_untrusted_state_incomplete():
    msg = {**REAL_ARP_NEIGHBOR, "state": 0x01}  # NUD_INCOMPLETE
    assert rtnetlink_listener.extract_ipv4_binding(msg) is None


def test_rejects_untrusted_state_failed():
    msg = {**REAL_ARP_NEIGHBOR, "state": 0x20}  # NUD_FAILED
    assert rtnetlink_listener.extract_ipv4_binding(msg) is None


@pytest.mark.parametrize("state", [0x02, 0x04, 0x08, 0x10, 0x40, 0x80])
def test_accepts_every_trusted_state(state):
    msg = {**REAL_ARP_NEIGHBOR, "state": state}
    assert rtnetlink_listener.extract_ipv4_binding(msg) is not None


def test_rejects_missing_lladdr():
    msg = {**REAL_ARP_NEIGHBOR, "attrs": [("NDA_DST", "172.17.0.2")]}
    assert rtnetlink_listener.extract_ipv4_binding(msg) is None


def test_rejects_missing_dst():
    msg = {**REAL_ARP_NEIGHBOR, "attrs": [("NDA_LLADDR", "f6:d0:02:bc:a7:e7")]}
    assert rtnetlink_listener.extract_ipv4_binding(msg) is None


# ============================================================
# RtnetlinkListener / run_loop -- fake pyroute2 injected via sys.modules
# ============================================================

class FakeIPRoute:
    """Stands in for pyroute2.IPRoute: a queue of message batches to
    return from get(), then socket.timeout forever after. Records
    whether bind()/settimeout() were called, matching what a test might
    want to assert on."""

    instances: list["FakeIPRoute"] = []

    def __init__(self, batches=None, raise_on_construct=None):
        if raise_on_construct is not None:
            raise raise_on_construct
        self.batches = list(batches or [])
        self.bound = False
        self.timeout = None
        self.closed = False
        FakeIPRoute.instances.append(self)

    def bind(self):
        self.bound = True

    def settimeout(self, t):
        self.timeout = t

    def get(self):
        if self.batches:
            return self.batches.pop(0)
        raise socket.timeout()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False


@pytest.fixture(autouse=True)
def _reset_fake_instances():
    FakeIPRoute.instances = []
    yield
    FakeIPRoute.instances = []


def _install_fake_pyroute2(monkeypatch, ip_route_factory):
    fake_module = types.ModuleType("pyroute2")
    fake_module.IPRoute = ip_route_factory
    monkeypatch.setitem(sys.modules, "pyroute2", fake_module)


def test_run_loop_records_a_real_binding(conn, monkeypatch):
    _install_fake_pyroute2(monkeypatch, lambda: FakeIPRoute(batches=[[REAL_ARP_NEIGHBOR]]))

    listener = rtnetlink_listener.run_loop()
    try:
        for _ in range(50):
            row = conn.execute(
                "SELECT * FROM device_bindings WHERE ipv4_address = '172.17.0.2'"
            ).fetchone()
            if row is not None:
                break
            time.sleep(0.05)
    finally:
        listener.stop()

    assert row is not None
    assert row["mac_address"] == "f6:d0:02:bc:a7:e7"
    assert row["source"] == "rtnetlink"


def test_run_loop_ignores_delneigh_and_noise(conn, monkeypatch):
    delneigh = {**REAL_ARP_NEIGHBOR, "event": "RTM_DELNEIGH"}
    _install_fake_pyroute2(
        monkeypatch, lambda: FakeIPRoute(batches=[[delneigh, BRIDGE_FDB_NOISE, IPV6_NOISE]])
    )

    listener = rtnetlink_listener.run_loop()
    try:
        time.sleep(0.2)
    finally:
        listener.stop()

    count = conn.execute("SELECT COUNT(*) AS c FROM device_bindings").fetchone()["c"]
    assert count == 0, "RTM_DELNEIGH and non-IPv4-ARP noise must never be recorded"


def test_stop_joins_promptly(conn, monkeypatch):
    _install_fake_pyroute2(monkeypatch, lambda: FakeIPRoute(batches=[]))

    listener = rtnetlink_listener.run_loop()
    time.sleep(0.05)
    started_stop = time.monotonic()
    listener.stop()
    elapsed = time.monotonic() - started_stop
    assert elapsed < 1.0, f"stop() took {elapsed:.3f}s, expected it to return promptly"


def test_a_hard_failure_is_reported_and_retried(conn, monkeypatch):
    calls = {"n": 0}

    def factory():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("permission denied (simulated)")
        return FakeIPRoute(batches=[[REAL_ARP_NEIGHBOR]])

    _install_fake_pyroute2(monkeypatch, factory)

    errors = []
    lock = threading.Lock()

    def on_error(exc):
        with lock:
            errors.append(exc)

    listener = rtnetlink_listener.RtnetlinkListener(on_error=on_error, retry_backoff=0.05)
    listener.start()
    try:
        for _ in range(100):
            row = conn.execute(
                "SELECT * FROM device_bindings WHERE ipv4_address = '172.17.0.2'"
            ).fetchone()
            if row is not None:
                break
            time.sleep(0.02)
    finally:
        listener.stop()

    assert row is not None, "expected the listener to recover after the first construction failure"
    with lock:
        assert len(errors) >= 1
        assert "permission denied" in str(errors[0])
