"""controller/ipc_client.py: the controller-side half of the same wire
protocol implemented on the worker side by
phase3/arp-worker/internal/ipc/protocol.go. Tested against a real
connected Unix socket pair (socket.socketpair) with the "worker" side
driven manually from a background thread -- no real arp-worker process
needed, and this exercises the actual socket/JSON-framing code, not a
mock of it.
"""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from ipc_client import (
    GenerationApplied,
    HeartbeatAck,
    Target,
    WorkerClient,
    WorkerConnectionError,
    WorkerError,
)

# AF_UNIX is the actual deploy-target reality (the worker only ever runs on
# Linux -- see phase3/arp-worker), and is what CI (ubuntu-latest) exercises.
# It's absent on some Windows Python builds, so skip there instead of
# reporting a spurious local failure for something that isn't this module's
# bug.
pytestmark = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX not available on this platform"
)


def _make_pair():
    client_sock, worker_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    return WorkerClient(client_sock), worker_sock


def _read_line(sock) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError("peer closed before sending a full line")
        buf += chunk
    line, _, _ = buf.partition(b"\n")
    return json.loads(line)


def _send_line(sock, msg: dict) -> None:
    sock.sendall((json.dumps(msg) + "\n").encode())


def test_replace_targets_round_trip():
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            req = _read_line(worker_sock)
            assert req["op"] == "replace_targets"
            assert req["generation"] == 43
            assert req["gateway"] == {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01"}
            assert req["targets"] == [{"ip": "192.168.1.21", "mac": "aa:bb:cc:dd:ee:22"}]
            _send_line(worker_sock, {
                "v": 1, "op": "generation_applied", "generation": 43,
                "target_count": 1, "resolution_failures": [],
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        result = client.replace_targets(
            43,
            Target(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01"),
            [Target(ip="192.168.1.21", mac="aa:bb:cc:dd:ee:22")],
        )
        t.join(timeout=2)

        assert result == GenerationApplied(generation=43, target_count=1, resolution_failures=[])
    finally:
        client.close()
        worker_sock.close()


def test_heartbeat_round_trip():
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            req = _read_line(worker_sock)
            assert req == {"v": 1, "op": "heartbeat", "sequence": 8842}
            _send_line(worker_sock, {
                "v": 1, "op": "heartbeat_ack", "sequence": 8842,
                "sent_counters": {"192.168.1.21": 118},
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        result = client.heartbeat(8842)
        t.join(timeout=2)

        assert result == HeartbeatAck(sequence=8842, sent_counters={"192.168.1.21": 118})
    finally:
        client.close()
        worker_sock.close()


def test_heartbeat_parses_consecutive_send_failures():
    # A sustained ARP send failure must be visible to the controller,
    # not silently swallowed.
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "heartbeat_ack", "sequence": 1,
                "sent_counters": {}, "consecutive_send_failures": 7,
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        result = client.heartbeat(1)
        t.join(timeout=2)

        assert result.consecutive_send_failures == 7
    finally:
        client.close()
        worker_sock.close()


def test_heartbeat_defaults_consecutive_send_failures_to_zero_when_absent():
    # An older worker binary that predates this field must not break
    # the controller -- missing key, not a malformed reply.
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            _read_line(worker_sock)
            _send_line(worker_sock, {"v": 1, "op": "heartbeat_ack", "sequence": 1, "sent_counters": {}})

        t = threading.Thread(target=fake_worker)
        t.start()
        result = client.heartbeat(1)
        t.join(timeout=2)

        assert result.consecutive_send_failures == 0
    finally:
        client.close()
        worker_sock.close()


def test_fault_reply_raises_workererror():
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "fault", "reason": "lease_expired",
                "action": "entering_repair_only_mode",
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        with pytest.raises(WorkerError, match="lease_expired"):
            client.heartbeat(1)
        t.join(timeout=2)
    finally:
        client.close()
        worker_sock.close()


def test_unsupported_version_raises_workererror():
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            _read_line(worker_sock)
            _send_line(worker_sock, {"v": 99, "op": "heartbeat_ack", "sequence": 1})

        t = threading.Thread(target=fake_worker)
        t.start()
        with pytest.raises(WorkerError, match="version"):
            client.heartbeat(1)
        t.join(timeout=2)
    finally:
        client.close()
        worker_sock.close()


def test_unexpected_op_raises_workererror():
    """A reply that parses fine and carries the right version but the
    wrong op (e.g. a heartbeat_ack arriving in reply to replace_targets)
    must not be silently accepted as if it matched."""
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            _read_line(worker_sock)
            _send_line(worker_sock, {"v": 1, "op": "heartbeat_ack", "sequence": 1})

        t = threading.Thread(target=fake_worker)
        t.start()
        with pytest.raises(WorkerError, match="generation_applied"):
            client.replace_targets(1, Target(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01"), [])
        t.join(timeout=2)
    finally:
        client.close()
        worker_sock.close()


def test_shutdown_sends_without_waiting_for_reply():
    client, worker_sock = _make_pair()
    try:
        client.shutdown("controller_requested")
        sent = _read_line(worker_sock)
        assert sent == {"v": 1, "op": "shutdown", "reason": "controller_requested"}
    finally:
        client.close()
        worker_sock.close()


def test_worker_closing_connection_mid_request_raises_connection_error():
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            _read_line(worker_sock)
            worker_sock.close()  # close without ever replying

        t = threading.Thread(target=fake_worker)
        t.start()
        with pytest.raises(WorkerConnectionError, match="closed the connection"):
            client.heartbeat(1)
        t.join(timeout=2)
    finally:
        client.close()


def test_fault_and_version_mismatch_are_not_connection_errors():
    """Distinguishing WorkerConnectionError (the socket itself is dead)
    from a plain WorkerError (a healthy connection carrying an
    application-level problem) is what lets controller/main.py decide
    whether reconnecting is warranted -- a fault reply must NOT trigger
    a reconnect, since the connection is fine."""
    client, worker_sock = _make_pair()
    try:
        def fake_worker():
            _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "fault", "reason": "lease_expired",
                "action": "entering_repair_only_mode",
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        try:
            client.heartbeat(1)
        except WorkerConnectionError:
            pytest.fail("a fault reply must raise plain WorkerError, not WorkerConnectionError")
        except WorkerError:
            pass
        t.join(timeout=2)
    finally:
        client.close()


def test_send_on_a_closed_socket_raises_connection_error():
    client, worker_sock = _make_pair()
    client.close()
    worker_sock.close()
    with pytest.raises(WorkerConnectionError):
        client.heartbeat(1)


def test_concurrent_calls_from_multiple_threads_do_not_corrupt_the_stream():
    """WorkerClient is used from two threads in practice -- the heartbeat
    pacer (controller/lease.py) and the main reconciliation loop
    (controller/main.py) -- with no coordination between them beyond
    WorkerClient's own internal lock. Without that lock, two threads
    calling _send()/_read_frame() concurrently could interleave partial
    socket writes or race on the shared read buffer, corrupting the
    JSON stream. This drives real concurrent heartbeat() calls from
    many threads against a real fake-worker socket and confirms every
    reply matches its own request with no corruption or exception."""
    client, worker_sock = _make_pair()
    results: dict[int, int] = {}
    results_lock = threading.Lock()
    errors: list[Exception] = []
    call_count = 40

    def fake_worker():
        for _ in range(call_count):
            req = _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "heartbeat_ack", "sequence": req["sequence"], "sent_counters": {},
            })

    server_thread = threading.Thread(target=fake_worker)
    server_thread.start()

    def caller(n: int) -> None:
        try:
            ack = client.heartbeat(n)
            with results_lock:
                results[n] = ack.sequence
        except Exception as exc:  # noqa: BLE001 -- captured for the assertion, not swallowed
            with results_lock:
                errors.append(exc)

    try:
        callers = [threading.Thread(target=caller, args=(i,)) for i in range(call_count)]
        for t in callers:
            t.start()
        for t in callers:
            t.join(timeout=5)
        server_thread.join(timeout=5)

        assert errors == [], f"concurrent calls raised unexpected errors: {errors}"
        assert results == {i: i for i in range(call_count)}, (
            "every reply must match its own request's sequence -- a mismatch here "
            "means the stream got corrupted/interleaved under concurrency"
        )
    finally:
        client.close()
        worker_sock.close()


def test_close_waits_for_an_in_flight_request_instead_of_racing_it():
    """close() must hold self._lock like every other WorkerClient method,
    so it can't run concurrently with another thread still blocked
    mid-request inside _read_frame()'s socket.recv() -- e.g. run()'s
    _reconnect() closing a client the heartbeat pacer thread is still
    using. Confirms close() BLOCKS until an in-flight request's own lock
    hold ends, rather than returning immediately and racing it."""
    client, worker_sock = _make_pair()
    client._sock.settimeout(0.3)  # short, so the test doesn't wait long
    try:
        blocked_call_done = threading.Event()

        def blocked_heartbeat():
            try:
                client.heartbeat(1)  # worker never replies -- times out
            except Exception:  # noqa: BLE001 -- expected: a timeout-driven WorkerConnectionError
                pass
            blocked_call_done.set()

        t = threading.Thread(target=blocked_heartbeat)
        t.start()
        time.sleep(0.05)  # let the thread actually enter recv() and take the lock first

        started = time.monotonic()
        client.close()
        elapsed = time.monotonic() - started

        assert blocked_call_done.is_set(), (
            "close() returned before the in-flight request finished -- "
            "it is not actually serialized against a concurrent caller"
        )
        assert elapsed >= 0.2, (
            f"close() returned in {elapsed:.3f}s, far faster than the blocked call's own 0.3s "
            "timeout -- it did not actually wait for the lock"
        )
        t.join(timeout=2)
    finally:
        worker_sock.close()
