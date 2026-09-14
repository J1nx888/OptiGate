#!/usr/bin/env python3
"""Records operational failures/recoveries into `system_events`, so an
admin has something to look at from the dashboard's own Events page
instead of needing `docker compose logs` and SSH access.

Every long-running periodic loop in `controller/main.py` (AdGuard sync,
category subscription fetch, active ARP scan, discovery, ...) reports a
failure via `controller/periodic.py`'s `PeriodicTask` `on_error`
callback, and its `on_success` hook reports the failure->success
"recovery" transition. This module gives those a persistent,
dashboard-visible home without inventing a second error-reporting
mechanism to keep in sync with `log.warning` calls -- this is layered
alongside stdlib logging, not instead of it.

Deliberately NOT a firehose: only real failures and the recovery that ends them are
recorded, never a routine successful cycle -- logging every success
would make this table pure noise within hours on a household network
where most cycles succeed. `failure_recovery_callbacks()` below is what
enforces that: it only calls `log_event()` on an actual failure
occurrence, or on the specific transition out of a run of failures back
to success, tracked via a plain closure variable -- there is no
persisted "was this already failing" state, so a container restart
implicitly and correctly ends whatever failure streak it was mid-way
through (a fresh process starting up and immediately succeeding is not,
itself, a notable "recovery" worth a row).

`'info'` severity is deliberately narrow, not a general "log routine
success" escape hatch that would reopen the firehose concern above. Its
callers are all genuinely rare, admin-relevant, one-off events, not a
periodic cycle succeeding: `controller/network_sweep.py`'s manual "Run
now" trigger completing (an explicit admin action, not the automatic
hourly schedule), `common/identity.py`'s `record_binding()` recording a
genuinely brand-new device for the first time (not a routine binding
refresh), and `dashboard/captive_portal_server.py` recording a
successful portal login (the counterpart to the failed-attempt rows
that surface already exists). Requires a real schema migration
(`common/db.py`'s `_migrate()`) since
SQLite's `CHECK` constraints can't be altered in place -- see that
migration's own comment for why this differs from
`interception_runtime.nft_mode`'s own precedent of skipping the CHECK
constraint entirely.
"""
from __future__ import annotations

import logging
import sqlite3
from typing import Callable

import db

log = logging.getLogger(__name__)

_VALID_SEVERITIES = ("error", "recovery", "info")

# dashboard.py/captive_portal_server.py write here for failed login
# attempts (rate-limited but never fully blocked, only throttled), which
# makes this table's writes partly ATTACKER-CONTROLLED: someone who never
# once succeeds can still grow it indefinitely just by repeatedly failing
# a login. EVENT_DISPLAY_LIMIT on the /events page only bounds what's
# DISPLAYED, never what's stored -- this caps the table itself.
_MAX_STORED_EVENTS = 5000


def log_event(
    conn: sqlite3.Connection, source: str, severity: str, message: str, detail: str | None = None
) -> None:
    """Records one operational event. Callers decide WHEN to call this
    (every failure occurrence, or only a state transition) -- this
    function just persists whatever it's given, the same "caller owns
    the state machine, this just records" split `common/identity.py`'s
    `record_binding()` uses for its own event log
    (`network_events`, a different table for a different kind of
    event -- MAC/IP identity changes, not operational failures).

    Prunes back down to `_MAX_STORED_EVENTS` after every insert (see
    that constant's own comment for why this exists at all) -- cheap
    at this table's realistic write rate (rare organic failures, plus a
    rate-limited handful of failed-login rows per minute at worst), and
    simpler to reason about than pruning on a schedule: the cap holds
    after every single write, with no separate periodic job that could
    fall behind or be forgotten."""
    if severity not in _VALID_SEVERITIES:
        raise ValueError(f"severity must be one of {_VALID_SEVERITIES}, got {severity!r}")
    conn.execute(
        "INSERT INTO system_events (ts, source, severity, message, detail) VALUES (?, ?, ?, ?, ?)",
        (db.now_iso(), source, severity, message, detail),
    )
    conn.execute(
        "DELETE FROM system_events WHERE id NOT IN "
        "(SELECT id FROM system_events ORDER BY id DESC LIMIT ?)",
        (_MAX_STORED_EVENTS,),
    )
    conn.commit()


def failure_recovery_callbacks(source: str) -> tuple[Callable[[Exception], None], Callable[[], None]]:
    """Returns a fresh `(on_error, on_success)` pair for one named
    periodic loop, suitable for `PeriodicTask`'s constructor. Each
    occurrence of a failure gets its own `error` row (so an admin can
    see how long something has been broken from consecutive
    timestamps, not just that it once failed); a `recovery` row is
    written only on the specific transition from failing back to
    succeeding, never on an ordinary run of successful cycles.

    Opens its own short-lived DB connection per call rather than
    accepting one from the caller -- these callbacks fire rarely (only
    on failure/recovery, not every cycle) so the extra connection is
    cheap, and it sidesteps needing to plumb a connection through
    `PeriodicTask` itself just for this, matching this project's own
    "open lazily, don't share across threads" precedent for periodic
    loops (see `controller/discovery.py`'s own docstring on why --
    `sqlite3.Connection` objects are only usable from the thread that
    created them, and these callbacks run on the loop's OWN background
    thread, not necessarily the same one that opened whatever
    connection the loop's task body itself uses internally).

    Both callbacks below catch and log via stdlib `logging` (never the
    DB) rather than letting `log_event()`'s own `conn.execute()` raise
    straight through: on a box with several containers hitting the
    shared DB at once, that write can itself fail with
    `sqlite3.OperationalError: database is locked`, and a failure to
    RECORD a failure must never become a second, worse failure that
    kills the whole background thread.
    """
    state = {"failing": False}

    def on_error(exc: Exception) -> None:
        state["failing"] = True
        conn = db.get_conn()
        try:
            log_event(conn, source, "error", f"{source} failed: {exc}")
        except Exception:  # noqa: BLE001 -- deliberately broad, see docstring below
            log.exception("%s: failed to record its own failure event -- swallowed", source)
        finally:
            conn.close()

    def on_success() -> None:
        if not state["failing"]:
            return
        state["failing"] = False
        conn = db.get_conn()
        try:
            log_event(conn, source, "recovery", f"{source} recovered")
        except Exception:  # noqa: BLE001 -- deliberately broad, see docstring below
            log.exception("%s: failed to record its own recovery event -- swallowed", source)
        finally:
            conn.close()

    return on_error, on_success
