#!/usr/bin/env python3
"""Blocks controller startup on its real dependencies actually
answering, not just on their containers having started (`depends_on`
only guarantees the latter).

Two dependencies, two different failure philosophies, matching how the
rest of this codebase already treats each:

- The ARP worker's Unix socket is REQUIRED -- main.py's run() cannot do
  anything without it. wait_for_worker() below retries for a bounded
  time and then re-raises, so a genuinely-broken worker still surfaces
  as a process exit (Docker's `restart: unless-stopped` catches that)
  -- it just turns the ordinary "arp-worker hasn't created its socket
  file yet" startup race into a fast in-process retry instead of a full
  container restart cycle.

- AdGuard is NOT required for the rest of run() to function --
  adguard_sync.py's own periodic run_loop() already retries forever on
  its own schedule and fails soft (logs via on_error, previous rules
  stay in effect). wait_for_adguard() below is a bounded, best-effort
  gate purely so main.py's sdnotify.ready() call means something closer
  to "confirmed reachable" when it can, without blocking startup
  indefinitely -- or crashing it -- over a slow-to-start AdGuard
  instance.
"""
from __future__ import annotations

import logging
import time

import adguard_client
from ipc_client import WorkerClient

log = logging.getLogger("controller.readiness")


def wait_for_worker(
    socket_path: str,
    timeout: float = 30.0,
    poll_interval: float = 0.5,
    connect_timeout: float = 5.0,
    sleep=time.sleep,
    now=time.monotonic,
) -> WorkerClient:
    """Retries WorkerClient.connect(socket_path) until it succeeds or
    `timeout` seconds have elapsed. Raises the last OSError seen
    (FileNotFoundError if the socket doesn't exist yet,
    ConnectionRefusedError if it exists but nothing is listening,
    ...) once the deadline passes -- deliberately not silent about a
    dependency that's still unreachable after 30s of retrying; that is
    a real problem, not an ordinary startup race.

    `sleep`/`now` are injectable purely for fast, deterministic tests --
    every caller besides tests should use the defaults.
    """
    deadline = now() + timeout
    attempt = 0
    while True:
        attempt += 1
        try:
            return WorkerClient.connect(socket_path, timeout=connect_timeout)
        except OSError as exc:
            if now() >= deadline:
                log.warning(
                    "giving up waiting for worker socket %s after %d attempt(s): %s",
                    socket_path, attempt, exc,
                )
                raise
            log.info(
                "worker socket %s not ready yet (attempt %d): %s -- retrying",
                socket_path, attempt, exc,
            )
            sleep(poll_interval)


def wait_for_adguard(
    base_url: str,
    username: str,
    password: str,
    timeout: float = 30.0,
    poll_interval: float = 1.0,
    sleep=time.sleep,
    now=time.monotonic,
) -> bool:
    """Polls AdGuard's `/control/filtering/status` (via
    adguard_client.get_custom_rules -- the exact same call
    adguard_sync.py's own sync_once() makes, reused rather than adding
    a second, slightly-different probe) until it answers or `timeout`
    elapses.

    Returns True if it became reachable in time, False otherwise --
    never raises. main.py proceeds either way (see this module's own
    docstring for why); the return value is purely for logging /
    sdnotify.ready() sequencing at the call site.
    """
    deadline = now() + timeout
    attempt = 0
    while True:
        attempt += 1
        try:
            adguard_client.get_custom_rules(base_url, username, password)
            return True
        except adguard_client.AdGuardError as exc:
            if now() >= deadline:
                log.warning(
                    "AdGuard at %s not reachable after %d attempt(s), proceeding anyway "
                    "-- the periodic sync will keep retrying on its own schedule: %s",
                    base_url, attempt, exc,
                )
                return False
            log.info(
                "AdGuard at %s not ready yet (attempt %d): %s -- retrying",
                base_url, attempt, exc,
            )
            sleep(poll_interval)
