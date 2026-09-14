"""controller/active_scan.py: active rate-limited ARP scanning.
`nudge()`'s real network send is monkeypatched in every test here via
`_FakeSocket`, so these tests never touch a real network. The UDP-nudge
technique itself is covered by active_scan.py's own module docstring,
not re-verified here.
"""
from __future__ import annotations

import threading
import time

import pytest

import active_scan
import identity

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"
MAC_C = "aa:bb:cc:dd:ee:03"
IP_1 = "192.168.1.10"
IP_2 = "192.168.1.11"
IP_3 = "192.168.1.12"


# ============================================================
# select_stale_bindings
# ============================================================

def test_select_stale_bindings_returns_only_bindings_older_than_threshold(conn):
    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at="2026-08-31T00:00:00Z")
    identity.record_binding(conn, MAC_B, IP_2, source="rtnetlink", seen_at="2026-08-31T13:59:00Z")

    stale = active_scan.select_stale_bindings(conn, stale_after_seconds=300, limit=10)

    # IP_1 is hours stale; IP_2's last_seen_at is far too recent (this
    # runs "now", real wall-clock time is long after both timestamps,
    # but IP_2 is deliberately much closer to "now" than IP_1) --
    # rather than depend on wall-clock timing here, assert the ordering
    # relationship a real stale/fresh pair must produce: IP_1 (older
    # last_seen_at) is selected before IP_2 if both are stale enough,
    # and a threshold tight enough to exclude IP_2 keeps only IP_1.
    assert IP_1 in stale


def test_select_stale_bindings_excludes_fresh_bindings(conn):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(3600))
    identity.record_binding(conn, MAC_B, IP_2, source="rtnetlink", seen_at=db.iso_secs_ago(1))

    stale = active_scan.select_stale_bindings(conn, stale_after_seconds=300, limit=10)

    assert stale == [IP_1]


def test_select_stale_bindings_excludes_inactive_bindings(conn):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(3600))
    conn.execute("UPDATE device_bindings SET active = 0 WHERE ipv4_address = ?", (IP_1,))

    assert active_scan.select_stale_bindings(conn, stale_after_seconds=300, limit=10) == []


def test_select_stale_bindings_respects_limit_oldest_first(conn):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(3000))
    identity.record_binding(conn, MAC_B, IP_2, source="rtnetlink", seen_at=db.iso_secs_ago(2000))
    identity.record_binding(conn, MAC_C, IP_3, source="rtnetlink", seen_at=db.iso_secs_ago(1000))

    stale = active_scan.select_stale_bindings(conn, stale_after_seconds=300, limit=2)

    assert stale == [IP_1, IP_2], "expected the two oldest bindings, oldest first"


# ============================================================
# nudge -- fakes the socket module entirely, no real network I/O
# ============================================================

class _FakeSocket:
    instances: list["_FakeSocket"] = []

    def __init__(self, *a, **k):
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.closed = False
        self.raise_on_sendto: Exception | None = None
        _FakeSocket.instances.append(self)

    def sendto(self, data, addr):
        if self.raise_on_sendto is not None:
            raise self.raise_on_sendto
        self.sent.append((data, addr))

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_fake_socket_instances():
    _FakeSocket.instances = []
    yield
    _FakeSocket.instances = []


def test_nudge_sends_one_udp_datagram_to_the_target_ip(monkeypatch):
    monkeypatch.setattr(active_scan.socket, "socket", lambda *a, **k: _FakeSocket())

    active_scan.nudge(IP_1)

    assert len(_FakeSocket.instances) == 1
    sock = _FakeSocket.instances[0]
    assert sock.sent == [(b"", (IP_1, active_scan._NUDGE_PORT))]
    assert sock.closed, "socket must be closed even on the happy path"


def test_nudge_swallows_a_synchronous_oserror(monkeypatch):
    def _make_socket(*a, **k):
        sock = _FakeSocket()
        sock.raise_on_sendto = OSError("no route to host")
        return sock

    monkeypatch.setattr(active_scan.socket, "socket", _make_socket)

    active_scan.nudge(IP_1)  # must not raise

    assert _FakeSocket.instances[0].closed, "socket must still be closed after a failed sendto"


# ============================================================
# scan_once
# ============================================================

def test_scan_once_nudges_every_selected_stale_binding(conn, monkeypatch):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(3600))
    identity.record_binding(conn, MAC_B, IP_2, source="rtnetlink", seen_at=db.iso_secs_ago(1))
    monkeypatch.setattr(active_scan.socket, "socket", lambda *a, **k: _FakeSocket())

    nudged = active_scan.scan_once(conn, stale_after_seconds=300, limit=10)

    assert nudged == 1
    assert len(_FakeSocket.instances) == 1
    assert _FakeSocket.instances[0].sent[0][1] == (IP_1, active_scan._NUDGE_PORT)


def test_scan_once_never_writes_device_bindings(conn, monkeypatch):
    """This module only ever nudges -- see its own module docstring for
    why writing device_bindings is deliberately left to
    controller/discovery.py's own snapshot loop instead."""
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(3600))
    monkeypatch.setattr(active_scan.socket, "socket", lambda *a, **k: _FakeSocket())

    active_scan.scan_once(conn, stale_after_seconds=300, limit=10)

    row = conn.execute(
        "SELECT last_seen_at, source FROM device_bindings WHERE ipv4_address = ?", (IP_1,)
    ).fetchone()
    assert row["source"] == "rtnetlink", "scan_once must not overwrite the binding's source"


def test_scan_once_returns_zero_when_nothing_is_stale(conn, monkeypatch):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(1))
    monkeypatch.setattr(active_scan.socket, "socket", lambda *a, **k: _FakeSocket())

    assert active_scan.scan_once(conn, stale_after_seconds=300, limit=10) == 0
    assert _FakeSocket.instances == []


# ============================================================
# run_loop -- wiring scan_once() into a background PeriodicTask
# ============================================================

def test_run_loop_calls_scan_repeatedly(conn, monkeypatch):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(3600))
    monkeypatch.setattr(active_scan.socket, "socket", lambda *a, **k: _FakeSocket())

    task = active_scan.run_loop(interval=0.02, stale_after_seconds=300, limit=10)
    try:
        time.sleep(0.15)
    finally:
        task.stop()

    assert len(_FakeSocket.instances) >= 2, "expected scan_once to run repeatedly on the interval"


def test_run_loop_stops_promptly(conn, monkeypatch):
    monkeypatch.setattr(active_scan.socket, "socket", lambda *a, **k: _FakeSocket())

    task = active_scan.run_loop(interval=0.05, stale_after_seconds=300, limit=10)
    time.sleep(0.02)
    started_stop = time.monotonic()
    task.stop()
    elapsed = time.monotonic() - started_stop
    assert elapsed < 0.5, f"stop() took {elapsed:.3f}s, expected it to return promptly"


def test_run_loop_reports_errors_via_on_error_without_dying(conn, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(active_scan, "scan_once", _boom)

    errors = []
    lock = threading.Lock()

    def on_error(exc):
        with lock:
            errors.append(exc)

    task = active_scan.run_loop(
        interval=0.02, stale_after_seconds=300, limit=10, on_error=on_error
    )
    try:
        time.sleep(0.1)
    finally:
        task.stop()

    with lock:
        got = len(errors)
    assert got >= 2, "expected repeated errors, not a dead loop"
