"""controller/readiness.py: startup-readiness gates.

wait_for_worker() is tested against a real listening AF_UNIX socket
(not a socketpair) since it calls WorkerClient.connect(path) itself.
wait_for_adguard() fakes adguard_client, since it has no AF_UNIX
dependency and should run on every platform.

Every test that needs fake timing passes `sleep=`/`now=` EXPLICITLY to
wait_for_worker()/wait_for_adguard() rather than monkeypatching
readiness.time.sleep/readiness.time.monotonic -- those two functions'
own `sleep=time.sleep, now=time.monotonic` defaults are bound to the
real functions at module-IMPORT time (ordinary Python default-argument
binding), so patching the `time` module's attributes afterward has no
effect on a default that already captured the original function object.
"""
from __future__ import annotations

import socket

import pytest

import adguard_client
import readiness
from ipc_client import WorkerClient

af_unix_only = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"), reason="AF_UNIX not available on this platform"
)


# ============================================================
# wait_for_worker
# ============================================================

@af_unix_only
def test_wait_for_worker_succeeds_immediately_when_already_listening(tmp_path):
    sock_path = str(tmp_path / "worker.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_path)
    server.listen(1)
    try:
        client = readiness.wait_for_worker(sock_path, timeout=5.0, poll_interval=0.01)
        assert isinstance(client, WorkerClient)
        client.close()
    finally:
        server.close()


@af_unix_only
def test_wait_for_worker_retries_until_the_socket_appears(tmp_path):
    sock_path = str(tmp_path / "worker.sock")
    fake_time = [0.0]
    sleep_calls = [0]
    server_holder = []

    def fake_now():
        return fake_time[0]

    def fake_sleep(seconds):
        fake_time[0] += seconds
        sleep_calls[0] += 1
        # The socket "appears" after the 2nd failed attempt -- simulates
        # arp-worker creating it a little after the controller starts
        # trying, so the 3rd connect attempt succeeds.
        if sleep_calls[0] == 2:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(sock_path)
            server.listen(1)
            server_holder.append(server)

    client = readiness.wait_for_worker(
        sock_path, timeout=5.0, poll_interval=0.5, sleep=fake_sleep, now=fake_now
    )
    assert isinstance(client, WorkerClient)
    assert sleep_calls[0] == 2
    client.close()
    server_holder[0].close()


@af_unix_only
def test_wait_for_worker_gives_up_and_raises_after_timeout(tmp_path):
    sock_path = str(tmp_path / "never-created.sock")
    fake_time = [0.0]

    def fake_now():
        return fake_time[0]

    def fake_sleep(seconds):
        fake_time[0] += seconds

    with pytest.raises(OSError):
        readiness.wait_for_worker(
            sock_path, timeout=2.0, poll_interval=0.5, sleep=fake_sleep, now=fake_now
        )


# ============================================================
# wait_for_adguard
# ============================================================

def test_wait_for_adguard_returns_true_immediately_when_already_reachable(monkeypatch):
    monkeypatch.setattr(readiness.adguard_client, "get_custom_rules", lambda *a, **k: [])
    assert readiness.wait_for_adguard("http://x", "a", "b", timeout=5.0, poll_interval=0.01) is True


def test_wait_for_adguard_retries_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def flaky(*a, **k):
        calls["n"] += 1
        if calls["n"] < 3:
            raise adguard_client.AdGuardError("connection refused")
        return []

    fake_time = [0.0]
    monkeypatch.setattr(readiness.adguard_client, "get_custom_rules", flaky)

    result = readiness.wait_for_adguard(
        "http://x", "a", "b", timeout=5.0, poll_interval=0.5,
        sleep=lambda s: fake_time.__setitem__(0, fake_time[0] + s),
        now=lambda: fake_time[0],
    )
    assert result is True
    assert calls["n"] == 3


def test_wait_for_adguard_gives_up_and_returns_false_after_timeout_without_raising(monkeypatch):
    def always_fails(*a, **k):
        raise adguard_client.AdGuardError("connection refused")

    fake_time = [0.0]
    monkeypatch.setattr(readiness.adguard_client, "get_custom_rules", always_fails)

    result = readiness.wait_for_adguard(
        "http://x", "a", "b", timeout=2.0, poll_interval=0.5,
        sleep=lambda s: fake_time.__setitem__(0, fake_time[0] + s),
        now=lambda: fake_time[0],
    )
    assert result is False
