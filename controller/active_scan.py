#!/usr/bin/env python3
"""Active, rate-limited ARP scanning -- "only when stale or onboarding
a new device."

Distinct from every other controller/*discovery*.py module in this
codebase: those all passively observe something else's traffic
(discovery.py reads the kernel's own `ip neigh show` state,
adguard_discovery.py reads AdGuard's query log). This module is the
only one that deliberately *provokes* fresh traffic -- nudging the
kernel's own neighbor-resolution state machine for a specific,
already-known-but-stale IP -- rather than just reading in a signal
that already exists on its own.

The controller deliberately holds no CAP_NET_RAW (only phase3/arp-worker
does), so it cannot send a real ARP request itself. It doesn't need to:
opening a plain UDP socket and sendto()-ing a closed port on the target
IP is enough to force the kernel's routing layer to (re)resolve that
destination's link-layer address as a side effect, even though the
"connection" itself always fails (a real ICMP port-unreachable,
delivered asynchronously, never surfaces as a Python exception on this
send). This works for both shapes this module needs: a completely
absent neighbor entry (transitions to INCOMPLETE -- the kernel
attempting a fresh resolution) and an already-stale one (kicks off
re-verification) -- no new op on phase3/arp-worker's IPC protocol
needed, keeping the controller/worker privilege split unchanged.

This module ONLY ever nudges -- it never itself writes
device_bindings. Any resulting resolution (the device is genuinely
still on the LAN) is picked up by controller/discovery.py's own
already-running `ip neigh show` snapshot loop on its next tick,
recorded with source='snapshot' exactly like any other passively
observed entry -- deliberately not duplicated here. This mirrors
adguard_discovery.py's own narrow-scope precedent (one module, one
job, never re-implementing another module's write path); see that
module's docstring for the same reasoning applied to a different
source.

"Onboarding a new device" (the other half of the design doc's phrase)
isn't handled by this module at all: there is no IP to nudge for a
device this table has no binding row for yet -- discovering a
brand-new device is inherently something only a passive/link-layer
source (rtnetlink, the snapshot loop, or the device itself sending
unprompted traffic) can ever do. This module's whole job is refreshing
bindings that already exist but have gone quiet.
"""
from __future__ import annotations

import logging
import socket
import sqlite3

import db
from periodic import PeriodicTask

log = logging.getLogger("controller.active_scan")

# Any closed UDP port works -- nothing is expected to be listening
# there, and the port number itself carries no meaning beyond being
# unprivileged (>1024) and vanishingly unlikely to have a real service
# bound to it on a home LAN device.
_NUDGE_PORT = 39999


def select_stale_bindings(
    conn: sqlite3.Connection, stale_after_seconds: float, limit: int
) -> list[str]:
    """Returns up to `limit` IPv4 addresses from the active
    device_bindings rows whose last_seen_at is older than
    stale_after_seconds ago, oldest-first -- the rate-limiting half of
    "only when stale or onboarding a new device." Deliberately a
    distinct concept from dashboard.py's own HEALTH_STALE_AFTER_SECONDS,
    which is about interception-runtime health, not device freshness --
    they just happen to share the word "stale."

    Ordering oldest-first (rather than e.g. arbitrary DB order) means a
    LAN with more stale devices than `limit` allows still makes
    progress across cycles instead of always nudging the same subset
    while a different subset is permanently starved.
    """
    threshold = db.iso_secs_ago(stale_after_seconds)
    rows = conn.execute(
        "SELECT ipv4_address FROM device_bindings "
        "WHERE active = 1 AND last_seen_at < ? "
        "ORDER BY last_seen_at ASC LIMIT ?",
        (threshold, limit),
    ).fetchall()
    return [row["ipv4_address"] for row in rows]


def nudge(ipv4_address: str) -> None:
    """Sends one UDP datagram to a closed port on `ipv4_address` -- see
    this module's docstring for why this alone is enough to trigger
    real ARP resolution without CAP_NET_RAW. Fire-and-forget: the
    datagram is never expected to reach a real listener, and any
    OSError raised synchronously (e.g. no route to that address at
    all) is swallowed here -- a failed nudge just leaves that IP
    however it already was, the same outcome as never having nudged
    it, not a reason to fail the whole scan cycle over one bad address.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(b"", (ipv4_address, _NUDGE_PORT))
    except OSError as exc:
        log.debug("nudge to %s failed synchronously (ignored): %s", ipv4_address, exc)
    finally:
        sock.close()


def scan_once(conn: sqlite3.Connection, stale_after_seconds: float, limit: int) -> int:
    """One rate-limited scan cycle: nudges at most `limit` stale
    bindings. Returns how many were nudged (0 is a normal, healthy
    result -- every active binding is still fresh, not a failure).
    Any actual resolution is left for controller/discovery.py's own
    snapshot loop to observe and record -- see this module's docstring.
    """
    targets = select_stale_bindings(conn, stale_after_seconds, limit)
    for ip in targets:
        nudge(ip)
    return len(targets)


def run_loop(
    interval: float,
    stale_after_seconds: float,
    limit: int,
    on_error=None,
    on_success=None,
) -> PeriodicTask:
    """Starts `scan_once()` running on a fixed interval, on its own
    background thread, until the returned `PeriodicTask.stop()` is
    called -- same shape as every other controller/*discovery*.py
    run_loop in this codebase, including opening its own DB connection
    lazily on the background thread (see discovery.run_loop's own
    docstring for why that's required, not just a style choice:
    sqlite3.Connection objects are only usable from the thread that
    created them).

    A failed scan cycle (a DB error) is reported via `on_error` rather
    than killing the loop -- this source is purely a freshness nudge,
    never load-bearing for correctness, so a missed cycle just means
    a stale binding stays stale a bit longer until the next cycle
    succeeds.
    """
    state: dict[str, sqlite3.Connection] = {}

    def task() -> None:
        conn = state.get("conn")
        if conn is None:
            conn = db.get_conn()
            db.init_db(conn)
            state["conn"] = conn
        scan_once(conn, stale_after_seconds, limit)

    pt = PeriodicTask(interval, task, on_error=on_error, on_success=on_success, thread_name="active-scan")
    pt.start()
    return pt
