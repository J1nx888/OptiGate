"""controller/main.py: run() end-to-end, including the
reconnect-on-WorkerConnectionError path. Uses a real listening AF_UNIX
socket (not a socketpair) since run() calls WorkerClient.connect(path)
itself, both for the initial connection and for the reconnect attempt --
a socketpair can't be reconnected to by path the way a real
bind()+listen() socket can.

This is a genuine integration test: real signals (run() must be invoked
from the main thread, since signal.signal() only works there), real
threads (the heartbeat pacer running concurrently with the main loop --
see ipc_client.py's own note on why that requires an internal lock),
and a real simulated worker crash-and-restart.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import sys
import threading
import time
import types

import pytest

import discovery
import rtnetlink_listener
from ipc_client import Target
from main import run
from reconcile import DesiredState

af_unix_only = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX not available on this platform"
)
pytestmark = af_unix_only

GATEWAY = Target(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:00")


def _read_line(sock) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("peer closed before a full line arrived")
        buf += chunk
    line, _, _ = buf.partition(b"\n")
    return json.loads(line)


def _send_line(sock, msg: dict) -> None:
    sock.sendall((json.dumps(msg) + "\n").encode())


def _desired_state_provider() -> DesiredState:
    return DesiredState(gateway=GATEWAY, targets=(Target(ip="192.168.1.21", mac="aa:bb:cc:dd:ee:01"),))


@pytest.fixture
def restore_signal_handlers():
    """run() installs its own SIGTERM/SIGINT handlers for the duration
    of the call, which is exactly what it's supposed to do -- but a
    test process shouldn't leave those handlers in place for whatever
    runs after it in the same pytest session."""
    original_term = signal.getsignal(signal.SIGTERM)
    original_int = signal.getsignal(signal.SIGINT)
    yield
    signal.signal(signal.SIGTERM, original_term)
    signal.signal(signal.SIGINT, original_int)


def test_run_reconnects_after_worker_dies_then_shuts_down_cleanly(tmp_path, conn, restore_signal_handlers):
    sock_path = str(tmp_path / "worker.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    server.settimeout(0.5)

    connection_count = 0
    stop_server = threading.Event()

    def serve():
        nonlocal connection_count
        while not stop_server.is_set():
            try:
                conn_sock, _ = server.accept()
            except socket.timeout:
                continue
            connection_count += 1
            first_connection = connection_count == 1
            conn_sock.settimeout(2)
            try:
                if first_connection:
                    # Simulate the worker process crashing: read exactly
                    # one request, then die without ever replying.
                    _read_line(conn_sock)
                else:
                    # Behave normally on the reconnected connection.
                    while True:
                        try:
                            req = _read_line(conn_sock)
                        except (ConnectionError, socket.timeout):
                            break
                        if req["op"] == "replace_targets":
                            _send_line(conn_sock, {
                                "v": 1, "op": "generation_applied",
                                "generation": req["generation"],
                                "target_count": len(req["targets"]),
                                "resolution_failures": [],
                            })
                        elif req["op"] == "heartbeat":
                            _send_line(conn_sock, {
                                "v": 1, "op": "heartbeat_ack",
                                "sequence": req["sequence"], "sent_counters": {},
                            })
                        elif req["op"] == "shutdown":
                            break
            except (ConnectionError, OSError, socket.timeout):
                pass
            finally:
                conn_sock.close()

    server_thread = threading.Thread(target=serve)
    server_thread.start()

    def send_sigterm_after_delay():
        time.sleep(1.2)
        os.kill(os.getpid(), signal.SIGTERM)

    timer_thread = threading.Thread(target=send_sigterm_after_delay)
    timer_thread.start()

    try:
        run(
            sock_path,
            _desired_state_provider,
            heartbeat_interval=0.15,
            poll_interval=0.15,
            health_conn=conn,
            policy_conn=None,
        )
    finally:
        stop_server.set()
        server_thread.join(timeout=3)
        timer_thread.join(timeout=3)
        server.close()

    assert connection_count >= 2, (
        f"expected run() to reconnect after the first connection died, "
        f"saw only {connection_count} connection(s)"
    )

    row = conn.execute("SELECT mode FROM interception_runtime WHERE singleton_id = 1").fetchone()
    assert row is not None
    assert row["mode"] == "running", (
        "expected the reconnected cycle to eventually report healthy again"
    )


def test_run_reconnects_when_only_the_heartbeat_notices_a_dead_worker(
    tmp_path, conn, restore_signal_handlers
):
    """_desired_state_provider() below always returns the SAME
    DesiredState, so after the first successful replace_targets,
    reconcile() correctly returns None on every later cycle (nothing
    changed, nothing to send) -- run_cycle() therefore never touches the
    connection again at all. If the worker dies at that point, only the
    heartbeat pacer -- which touches the connection every single cycle
    regardless of desired state -- can ever notice, so heartbeat failures
    must actively trigger a reconnect, not just get logged.
    """
    sock_path = str(tmp_path / "worker.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    server.settimeout(0.5)

    connection_count = 0
    stop_server = threading.Event()

    def serve():
        nonlocal connection_count
        while not stop_server.is_set():
            try:
                conn_sock, _ = server.accept()
            except socket.timeout:
                continue
            connection_count += 1
            first_connection = connection_count == 1
            conn_sock.settimeout(2)
            heartbeats_answered = 0
            try:
                while True:
                    try:
                        req = _read_line(conn_sock)
                    except (ConnectionError, socket.timeout):
                        break
                    if req["op"] == "replace_targets":
                        _send_line(conn_sock, {
                            "v": 1, "op": "generation_applied",
                            "generation": req["generation"],
                            "target_count": len(req["targets"]),
                            "resolution_failures": [],
                        })
                    elif req["op"] == "heartbeat":
                        if first_connection and heartbeats_answered >= 2:
                            # Simulate the worker dying silently mid-lease,
                            # with desired state never having changed --
                            # no more replace_targets is ever coming, so
                            # this is the ONLY signal a dead worker gets a
                            # chance to produce.
                            break
                        heartbeats_answered += 1
                        _send_line(conn_sock, {
                            "v": 1, "op": "heartbeat_ack",
                            "sequence": req["sequence"], "sent_counters": {},
                        })
                    elif req["op"] == "shutdown":
                        break
            except (ConnectionError, OSError, socket.timeout):
                pass
            finally:
                conn_sock.close()

    server_thread = threading.Thread(target=serve)
    server_thread.start()

    def send_sigterm_after_delay():
        time.sleep(1.5)
        os.kill(os.getpid(), signal.SIGTERM)

    timer_thread = threading.Thread(target=send_sigterm_after_delay)
    timer_thread.start()

    try:
        run(
            sock_path,
            _desired_state_provider,  # always the same DesiredState -- see docstring
            heartbeat_interval=0.1,
            poll_interval=0.15,
            health_conn=conn,
            policy_conn=None,
        )
    finally:
        stop_server.set()
        server_thread.join(timeout=3)
        timer_thread.join(timeout=3)
        server.close()

    assert connection_count >= 2, (
        f"expected the heartbeat failure alone to trigger a reconnect, "
        f"saw only {connection_count} connection(s)"
    )


def test_run_with_discovery_interval_populates_device_bindings_on_a_separate_thread(
    tmp_path, conn, monkeypatch, restore_signal_handlers
):
    """discovery.run_loop wired into run(): a real background thread,
    opening its own sqlite3.Connection internally (see discovery.run_loop's
    own docstring for why it must build that connection itself rather than
    being handed health_conn/policy_conn), running concurrently with the
    main reconcile loop and the heartbeat pacer -- three threads sharing
    one process.
    """
    monkeypatch.setattr(
        discovery, "run_ip_neigh_show",
        lambda: "192.168.1.50 dev eth0 lladdr aa:bb:cc:dd:ee:99 REACHABLE\n",
    )

    sock_path = str(tmp_path / "worker.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    server.settimeout(0.5)
    stop_server = threading.Event()

    def serve():
        while not stop_server.is_set():
            try:
                conn_sock, _ = server.accept()
            except socket.timeout:
                continue
            conn_sock.settimeout(2)
            try:
                while True:
                    try:
                        req = _read_line(conn_sock)
                    except (ConnectionError, socket.timeout):
                        break
                    if req["op"] == "replace_targets":
                        _send_line(conn_sock, {
                            "v": 1, "op": "generation_applied",
                            "generation": req["generation"],
                            "target_count": len(req["targets"]),
                            "resolution_failures": [],
                        })
                    elif req["op"] == "heartbeat":
                        _send_line(conn_sock, {
                            "v": 1, "op": "heartbeat_ack",
                            "sequence": req["sequence"], "sent_counters": {},
                        })
                    elif req["op"] == "shutdown":
                        break
            except (ConnectionError, OSError, socket.timeout):
                pass
            finally:
                conn_sock.close()

    server_thread = threading.Thread(target=serve)
    server_thread.start()

    def send_sigterm_after_delay():
        time.sleep(0.3)
        os.kill(os.getpid(), signal.SIGTERM)

    timer_thread = threading.Thread(target=send_sigterm_after_delay)
    timer_thread.start()

    try:
        run(
            sock_path,
            _desired_state_provider,
            heartbeat_interval=0.05,
            poll_interval=0.05,
            health_conn=conn,
            policy_conn=None,
            discovery_interval=0.02,
        )
    finally:
        stop_server.set()
        server_thread.join(timeout=3)
        timer_thread.join(timeout=3)
        server.close()

    row = conn.execute(
        "SELECT mac_address FROM device_bindings WHERE ipv4_address = ?", ("192.168.1.50",)
    ).fetchone()
    assert row is not None, "expected the discovery loop to have recorded the mocked binding"
    assert row["mac_address"] == "aa:bb:cc:dd:ee:99"


def test_run_with_enable_rtnetlink_populates_device_bindings_on_a_separate_thread(
    tmp_path, conn, monkeypatch, restore_signal_handlers
):
    """Same shape as the discovery test above, but for
    controller/rtnetlink_listener.py's live listener -- a fourth
    concurrent thread (heartbeat pacer, discovery snapshot disabled here
    via discovery_interval=None, rtnetlink listener, main reconcile loop),
    still sharing one process. pyroute2 is faked via sys.modules injection
    since it's Linux-only and this suite also runs on Windows (see
    test_controller_rtnetlink_listener.py's own comment)."""
    fake_module = types.ModuleType("pyroute2")

    class _FakeIPRoute:
        def __init__(self):
            self._sent = False

        def bind(self):
            pass

        def settimeout(self, t):
            pass

        def get(self):
            if not self._sent:
                self._sent = True
                return [{
                    "event": "RTM_NEWNEIGH", "family": socket.AF_INET, "state": 0x02,
                    "attrs": [("NDA_DST", "192.168.1.51"), ("NDA_LLADDR", "aa:bb:cc:dd:ee:88")],
                }]
            raise socket.timeout()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    fake_module.IPRoute = _FakeIPRoute
    monkeypatch.setitem(sys.modules, "pyroute2", fake_module)

    sock_path = str(tmp_path / "worker.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    server.settimeout(0.5)
    stop_server = threading.Event()

    def serve():
        while not stop_server.is_set():
            try:
                conn_sock, _ = server.accept()
            except socket.timeout:
                continue
            conn_sock.settimeout(2)
            try:
                while True:
                    try:
                        req = _read_line(conn_sock)
                    except (ConnectionError, socket.timeout):
                        break
                    if req["op"] == "replace_targets":
                        _send_line(conn_sock, {
                            "v": 1, "op": "generation_applied",
                            "generation": req["generation"],
                            "target_count": len(req["targets"]),
                            "resolution_failures": [],
                        })
                    elif req["op"] == "heartbeat":
                        _send_line(conn_sock, {
                            "v": 1, "op": "heartbeat_ack",
                            "sequence": req["sequence"], "sent_counters": {},
                        })
                    elif req["op"] == "shutdown":
                        break
            except (ConnectionError, OSError, socket.timeout):
                pass
            finally:
                conn_sock.close()

    server_thread = threading.Thread(target=serve)
    server_thread.start()

    def send_sigterm_after_delay():
        time.sleep(0.3)
        os.kill(os.getpid(), signal.SIGTERM)

    timer_thread = threading.Thread(target=send_sigterm_after_delay)
    timer_thread.start()

    try:
        run(
            sock_path,
            _desired_state_provider,
            heartbeat_interval=0.05,
            poll_interval=0.05,
            health_conn=conn,
            policy_conn=None,
            enable_rtnetlink=True,
        )
    finally:
        stop_server.set()
        server_thread.join(timeout=3)
        timer_thread.join(timeout=3)
        server.close()

    row = conn.execute(
        "SELECT mac_address FROM device_bindings WHERE ipv4_address = ?", ("192.168.1.51",)
    ).fetchone()
    assert row is not None, "expected the rtnetlink listener to have recorded the fake binding"
    assert row["mac_address"] == "aa:bb:cc:dd:ee:88"


def test_run_reports_fail_open_when_heartbeat_reports_sustained_arp_send_failures(
    tmp_path, conn, restore_signal_handlers
):
    """End-to-end version of test_controller_run_cycle.py's
    consecutive_send_failures test: this one drives it through the REAL
    heartbeat pacer thread (main.py's arp_send_health dict) into
    run_cycle's reconciliation loop, rather than passing the value
    directly as a parameter, exercising the actual cross-thread wiring.
    The fake worker behaves perfectly normally for replace_targets
    (reconciliation itself succeeds) but reports a high
    consecutive_send_failures on every heartbeat_ack, matching what a
    real worker would report while its bound interface is down.
    """
    sock_path = str(tmp_path / "worker.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    server.settimeout(0.5)

    stop_server = threading.Event()

    def serve():
        try:
            conn_sock, _ = server.accept()
        except socket.timeout:
            return
        conn_sock.settimeout(2)
        try:
            while not stop_server.is_set():
                try:
                    req = _read_line(conn_sock)
                except (ConnectionError, socket.timeout):
                    break
                if req["op"] == "replace_targets":
                    _send_line(conn_sock, {
                        "v": 1, "op": "generation_applied",
                        "generation": req["generation"],
                        "target_count": len(req["targets"]),
                        "resolution_failures": [],
                    })
                elif req["op"] == "heartbeat":
                    _send_line(conn_sock, {
                        "v": 1, "op": "heartbeat_ack",
                        "sequence": req["sequence"], "sent_counters": {},
                        "consecutive_send_failures": 10,
                    })
                elif req["op"] == "shutdown":
                    break
        except (ConnectionError, OSError, socket.timeout):
            pass
        finally:
            conn_sock.close()

    server_thread = threading.Thread(target=serve)
    server_thread.start()

    def send_sigterm_after_delay():
        time.sleep(0.4)
        os.kill(os.getpid(), signal.SIGTERM)

    timer_thread = threading.Thread(target=send_sigterm_after_delay)
    timer_thread.start()

    try:
        run(
            sock_path,
            _desired_state_provider,
            heartbeat_interval=0.05,
            poll_interval=0.05,
            health_conn=conn,
            policy_conn=None,
        )
    finally:
        stop_server.set()
        server_thread.join(timeout=3)
        timer_thread.join(timeout=3)
        server.close()

    row = conn.execute("SELECT mode, fail_open_reason FROM interception_runtime WHERE singleton_id = 1").fetchone()
    assert row is not None
    assert row["mode"] == "fail_open", (
        "expected sustained heartbeat-reported send failures to be visible as fail_open, "
        "even though the controller<->worker socket itself was perfectly healthy throughout"
    )
    assert "consecutive ARP send" in row["fail_open_reason"]
