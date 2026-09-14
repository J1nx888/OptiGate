#!/usr/bin/env python3
"""Populates device_bindings from a periodic `ip neigh show` snapshot --
a catch-all discovery source, lower-precedence than
`controller/rtnetlink_listener.py`'s live event listener, for anything
that source misses.

Run via `run_loop()` below, called from `controller/main.py` on its own
background thread and its own DB connection (see `run_loop`'s own
docstring for why a separate connection is required, not just a
separate thread). `device_bindings` freshness -- and therefore Squid's
`common/device_identity.py` identity resolution, and
`controller/policy_state.py`'s nftables policy computation -- depends
on something calling `snapshot_once()` regularly.
"""
from __future__ import annotations

import logging
import re
import sqlite3
import subprocess

import identity
from periodic import PeriodicTask

log = logging.getLogger("controller.discovery")

# Matches a line like:
#   192.168.1.21 dev enp1s0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
# `ip neigh show`'s output format is stable/documented (iproute2's
# `ip-neighbour(8)`), not guessed.
_NEIGH_LINE_RE = re.compile(
    r"^(?P<ip>\S+)\s+dev\s+(?P<dev>\S+)\s+lladdr\s+(?P<mac>[0-9a-fA-F:]+)\s+(?P<state>\S+)\s*$"
)

# States worth trusting as "this binding is currently real."
# FAILED/INCOMPLETE entries have no lladdr at all (the kernel never
# resolved a MAC for them), so they're already excluded by the regex
# not matching -- this set is the second filter, for entries that DO
# have an lladdr but are in a state that doesn't warrant recording
# (there currently are none excluded this way; kept as an explicit
# allowlist rather than a blocklist so a future, unexpected state
# value fails closed -- gets skipped -- rather than silently trusted).
_TRUSTED_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP"}


def parse_ip_neigh_output(output: str) -> list[tuple[str, str, str]]:
    """Parses `ip neigh show` output into (ip, mac, state) tuples,
    skipping lines that don't match the expected shape (e.g. FAILED/
    INCOMPLETE entries, which carry no lladdr at all) or whose state
    isn't in _TRUSTED_STATES.
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _NEIGH_LINE_RE.match(line)
        if not m:
            continue
        state = m.group("state").upper()
        if state not in _TRUSTED_STATES:
            continue
        results.append((m.group("ip"), m.group("mac").lower(), state))
    return results


def run_ip_neigh_show() -> str:
    """Runs the real `ip neigh show` command. Split out from
    parse_ip_neigh_output() specifically so the parsing logic is unit
    testable against fixed sample output without needing to actually
    run a subprocess or depend on the test machine's real neighbor
    table having any particular content.
    """
    result = subprocess.run(
        ["ip", "neigh", "show"], capture_output=True, text=True, timeout=5, check=True
    )
    return result.stdout


def snapshot_once(conn: sqlite3.Connection) -> int:
    """Runs one real `ip neigh show` snapshot and records every
    trusted entry as an observed binding (see
    common/identity.py's record_binding). Returns the number of
    bindings recorded (not necessarily the number of NEW rows --
    record_binding is idempotent for an already-seen (mac, ip) pair).
    """
    entries = parse_ip_neigh_output(run_ip_neigh_show())
    for ip, mac, _state in entries:
        identity.record_binding(conn, mac, ip, source="snapshot")
    return len(entries)


def run_loop(interval: float, on_error=None, on_success=None) -> PeriodicTask:
    """Starts `snapshot_once()` running on a fixed interval, on its own
    background thread, until the returned `PeriodicTask.stop()` is
    called. Mirrors `controller/lease.py`'s `HeartbeatPacer` usage in
    `controller/main.py` -- same "start it, hold onto the handle, stop()
    it in the shutdown path" shape.

    Deliberately does NOT accept a `conn` parameter -- it opens its OWN
    connection internally, lazily, the first time the background thread
    actually runs. `sqlite3.Connection` objects are only usable from the
    thread that *created* them (`check_same_thread=True`, `db.get_conn()`'s
    own default), so handing this loop a connection built on the
    caller's thread (e.g. main.py's own `health_conn`) fails the same
    way a shared connection would; only a connection built ON this
    loop's own background thread works, which means this function has
    to be the one to build it. Callers just need `db.DB_PATH` already
    set correctly before this starts, the same way every other
    component in this codebase (dashboard, the Squid helpers) relies on
    `db.DB_PATH` already being right rather than being told the path
    directly.

    A failed snapshot (the `ip` command missing, a transient subprocess
    error, a malformed line) is reported via `on_error` rather than
    killing the loop -- matching every other periodic task in this
    codebase (`HeartbeatPacer`, `main.py`'s own reconcile-cycle handling)
    in treating one bad cycle as a reason to log and retry next
    interval, not a reason to stop discovering devices entirely.
    """
    state: dict[str, sqlite3.Connection] = {}

    def task() -> None:
        conn = state.get("conn")
        if conn is None:
            import db  # local import: mirrors _build_db_backed_provider's own lazy `import db`

            conn = db.get_conn()
            db.init_db(conn)
            state["conn"] = conn
        snapshot_once(conn)

    pt = PeriodicTask(interval, task, on_error=on_error, on_success=on_success, thread_name="discovery-snapshot")
    pt.start()
    return pt
