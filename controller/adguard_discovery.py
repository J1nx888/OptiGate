#!/usr/bin/env python3
"""AdGuard query-log observations, used to confirm active IP usage.
Distinct from -- and much narrower than -- adguard_sync.py, which
pushes hard-deny rules TO AdGuard; this module only ever reads FROM it.

AdGuard's query log has no link-layer information (a DNS query carries
a client IP, never a MAC), so this source can never discover a
brand-new device_bindings row on its own -- only refresh last_seen_at
for a binding some other source (rtnetlink, the periodic snapshot)
already created. See common/identity.py's touch_binding_by_ip, the one
write this module ever makes.
"""
from __future__ import annotations

import logging
import sqlite3

import adguard_client
import identity
from periodic import PeriodicTask

log = logging.getLogger("controller.adguard_discovery")


def correlate_once(
    conn: sqlite3.Connection, base_url: str, username: str, password: str, limit: int = 100
) -> int:
    """Fetches the most recent `limit` querylog entries and refreshes
    last_seen_at for whichever ones match an already-active
    device_bindings row -- see this module's own docstring for why it
    can never create a new one. Returns how many bindings were actually
    touched (0 is a normal, healthy result: every querying IP either
    has no active binding yet, or was already up to date), not a
    failure.
    """
    touched = 0
    for entry in adguard_client.get_query_log(base_url, username, password, limit=limit):
        client_ip = entry.get("client")
        raw_time = entry.get("time")
        if not client_ip or not raw_time:
            continue  # malformed/unexpected entry shape -- skip, don't fail the whole batch over one row
        seen_at = adguard_client.normalize_query_log_time(raw_time)
        if identity.touch_binding_by_ip(conn, client_ip, seen_at):
            touched += 1
    return touched


def run_loop(
    interval: float,
    base_url: str,
    username: str,
    password: str,
    on_error=None,
    on_success=None,
) -> PeriodicTask:
    """Starts `correlate_once()` running on a fixed interval, on its own
    background thread, until the returned `PeriodicTask.stop()` is
    called -- same shape as adguard_sync.py's own run_loop (including
    opening its own DB connection lazily on the background thread; see
    that module's docstring for why).

    A failed correlation cycle (AdGuard unreachable, a malformed
    response) is reported via `on_error` rather than killing the loop --
    this source is purely a freshness signal, never load-bearing for
    correctness, so a missed cycle just means slightly staler
    last_seen_at values until the next one succeeds.
    """
    state: dict[str, sqlite3.Connection] = {}

    def task() -> None:
        conn = state.get("conn")
        if conn is None:
            import db  # local import: mirrors adguard_sync.run_loop's own lazy `import db`

            conn = db.get_conn()
            db.init_db(conn)
            state["conn"] = conn
        correlate_once(conn, base_url, username, password)

    pt = PeriodicTask(interval, task, on_error=on_error, on_success=on_success, thread_name="adguard-discovery")
    pt.start()
    return pt
