"""controller/main.py: run_cycle() -- the per-iteration reconcile +
health + policy logic, extracted from run()'s loop specifically so it
can be tested against a fake worker socket without needing real
signal-handling/threading gymnastics (signal.signal() only works from
the main thread in CPython, which run() itself needs)."""
from __future__ import annotations

import json
import socket
import threading

import pytest

from ipc_client import Target, WorkerClient, WorkerConnectionError
from main import run_cycle
from reconcile import DesiredState

af_unix_only = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX not available on this platform"
)
pytestmark = af_unix_only

GATEWAY = Target(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:00")


def _make_client():
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


def _placeholder_desired_state() -> DesiredState:
    return DesiredState(gateway=GATEWAY, targets=(Target(ip="192.168.1.21", mac="aa:bb:cc:dd:ee:01"),))


def _runtime_row(conn):
    return conn.execute("SELECT * FROM interception_runtime WHERE singleton_id = 1").fetchone()


def test_successful_cycle_reports_healthy(conn):
    client, worker_sock = _make_client()
    try:
        def fake_worker():
            req = _read_line(worker_sock)
            assert req["op"] == "replace_targets"
            _send_line(worker_sock, {
                "v": 1, "op": "generation_applied", "generation": req["generation"],
                "target_count": 1, "resolution_failures": [],
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        applied = run_cycle(client, _placeholder_desired_state, None, health_conn=conn, policy_conn=None)
        t.join(timeout=2)

        assert applied is not None
        assert applied.generation == 1

        row = _runtime_row(conn)
        assert row["mode"] == "running"
        assert row["applied_generation"] == 1
        assert row["fail_open_reason"] is None
    finally:
        client.close()
        worker_sock.close()


def test_lease_expired_fault_reports_repair_only_not_fail_open(conn):
    """A lease_expired/entering_repair_only_mode fault is the worker's
    own controlled, self-limiting self-correction (it already restored
    real MACs and stopped poisoning on its own) -- genuinely different
    from a dead/unreachable worker, and the dashboard has a dedicated
    amber badge for exactly this distinction (see
    dashboard/dashboard.py's HEALTH_MODE_BADGE_CLASS)."""
    client, worker_sock = _make_client()
    try:
        def fake_worker():
            _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "fault", "reason": "lease_expired",
                "action": "entering_repair_only_mode",
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        applied = run_cycle(client, _placeholder_desired_state, None, health_conn=conn, policy_conn=None)
        t.join(timeout=2)

        assert applied is None, "a failed cycle must not fabricate an AppliedState"

        row = _runtime_row(conn)
        assert row["mode"] == "repair_only"
        assert "lease_expired" in row["fail_open_reason"]
    finally:
        client.close()
        worker_sock.close()


def test_a_fault_with_a_different_action_still_reports_fail_open(conn):
    """Only the specific, documented entering_repair_only_mode action
    gets the amber repair_only treatment -- every other kind of fault
    (a genuinely unexpected one, or any future fault type that isn't a
    controlled self-correction) still reports the red fail_open state,
    same as before this fix."""
    client, worker_sock = _make_client()
    try:
        def fake_worker():
            _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "fault", "reason": "something_else",
                "action": "connection_closed",
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        applied = run_cycle(client, _placeholder_desired_state, None, health_conn=conn, policy_conn=None)
        t.join(timeout=2)

        assert applied is None

        row = _runtime_row(conn)
        assert row["mode"] == "fail_open"
        assert "something_else" in row["fail_open_reason"]
    finally:
        client.close()
        worker_sock.close()


def test_unchanged_desired_state_still_writes_policy_and_health_but_skips_the_worker(conn):
    """The second cycle's reconcile() call correctly returns None (no
    new generation needed -- see reconcile.py's idempotency
    requirement), but policy/health reporting must still happen every
    cycle regardless -- and the worker must NOT be contacted a second
    time for state it already has."""
    client, worker_sock = _make_client()
    try:
        def fake_worker():
            req = _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "generation_applied", "generation": req["generation"],
                "target_count": 1, "resolution_failures": [],
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        first_applied = run_cycle(client, _placeholder_desired_state, None, health_conn=conn, policy_conn=conn)
        t.join(timeout=2)

        row = _runtime_row(conn)
        assert json.loads(row["desired_policy_json"]) == {
            "authenticated": [], "unauthenticated": [], "bypass": [], "quarantine": [], "bump": [],
        }

        # Second cycle: identical desired state. reconcile() must return
        # None, so no replace_targets call happens -- if it did, this
        # would hang waiting for a reply nothing sends.
        second_applied = run_cycle(
            client, _placeholder_desired_state, first_applied, health_conn=conn, policy_conn=conn
        )
        assert second_applied is first_applied

        row2 = _runtime_row(conn)
        assert row2["mode"] == "running"
        assert row2["applied_generation"] == first_applied.generation
    finally:
        client.close()
        worker_sock.close()


def test_worker_connection_error_propagates_uncaught(conn):
    """run_cycle must NOT swallow WorkerConnectionError -- only run()
    (which owns the WorkerClient variable and can build a replacement)
    is able to actually reconnect; see main.py's own docstrings."""
    client, worker_sock = _make_client()
    try:
        def fake_worker():
            _read_line(worker_sock)
            worker_sock.close()  # closes without ever replying

        t = threading.Thread(target=fake_worker)
        t.start()
        with pytest.raises(WorkerConnectionError):
            run_cycle(client, _placeholder_desired_state, None, health_conn=conn, policy_conn=None)
        t.join(timeout=2)

        # A cycle that propagates never reaches run_cycle's own
        # health-reporting code -- that's run()'s job once it decides
        # how to handle the reconnect, not run_cycle's.
        row = _runtime_row(conn)
        assert row is None
    finally:
        client.close()


def test_sustained_arp_send_failures_report_fail_open_even_though_the_socket_is_fine(conn):
    """A reconcile cycle can succeed completely -- the controller<->worker
    socket is healthy, generation_applied comes back clean -- while the
    worker's actual ARP transmission is failing (the bound interface is
    down). interception_runtime must surface that distinction rather
    than staying "running" throughout a sustained send-failure
    window."""
    from main import ARP_SEND_FAILURE_THRESHOLD

    client, worker_sock = _make_client()
    try:
        def fake_worker():
            req = _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "generation_applied", "generation": req["generation"],
                "target_count": 1, "resolution_failures": [],
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        applied = run_cycle(
            client, _placeholder_desired_state, None, health_conn=conn, policy_conn=None,
            consecutive_send_failures=ARP_SEND_FAILURE_THRESHOLD,
        )
        t.join(timeout=2)

        assert applied is not None, "reconciliation itself still succeeded -- only health reporting changes"
        row = _runtime_row(conn)
        assert row["mode"] == "fail_open"
        assert "consecutive ARP send" in row["fail_open_reason"]
        assert row["applied_generation"] == 1, "the last successfully-applied generation is still true"
    finally:
        client.close()
        worker_sock.close()


def test_below_threshold_arp_send_failures_still_report_healthy(conn):
    """A single transient dropped frame (or a count under the
    threshold) must not flap the pipeline to fail_open."""
    from main import ARP_SEND_FAILURE_THRESHOLD

    client, worker_sock = _make_client()
    try:
        def fake_worker():
            req = _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "generation_applied", "generation": req["generation"],
                "target_count": 1, "resolution_failures": [],
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        run_cycle(
            client, _placeholder_desired_state, None, health_conn=conn, policy_conn=None,
            consecutive_send_failures=ARP_SEND_FAILURE_THRESHOLD - 1,
        )
        t.join(timeout=2)

        row = _runtime_row(conn)
        assert row["mode"] == "running"
        assert row["fail_open_reason"] is None
    finally:
        client.close()
        worker_sock.close()


def test_none_conns_mean_no_db_writes_at_all(conn):
    """health_conn=None and policy_conn=None (run()'s default when no
    --db-path is given) must leave interception_runtime completely
    untouched -- verified against a real conn that run_cycle is simply
    never given."""
    client, worker_sock = _make_client()
    try:
        def fake_worker():
            req = _read_line(worker_sock)
            _send_line(worker_sock, {
                "v": 1, "op": "generation_applied", "generation": req["generation"],
                "target_count": 1, "resolution_failures": [],
            })

        t = threading.Thread(target=fake_worker)
        t.start()
        run_cycle(client, _placeholder_desired_state, None, health_conn=None, policy_conn=None)
        t.join(timeout=2)

        count = conn.execute("SELECT COUNT(*) AS c FROM interception_runtime").fetchone()["c"]
        assert count == 0
    finally:
        client.close()
        worker_sock.close()
