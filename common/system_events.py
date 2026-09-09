#!/usr/bin/env python3
"""Records operational failures/recoveries into `system_events`, so an
admin has something to look at from the dashboard's own Events page
instead of needing `docker compose logs` and SSH access.

Added 2026-09-01, ahead of G1 real-network testing: every long-running
periodic loop in `controller/main.py` (AdGuard sync, category
subscription fetch, active ARP scan, discovery, ...) already reports a
failure via `controller/periodic.py`'s `PeriodicTask` `on_error`
callback -- previously that only ever reached Python's own `logging`
(container stdout), invisible from the dashboard entirely. This module
gives the exact same failures (and now, via `PeriodicTask`'s new
`on_success` hook, the failure->success "recovery" transition) a
persistent, dashboard-visible home, without inventing a second
error-reporting mechanism to keep in sync with the first -- `log.warning`
calls stay exactly where they are; this is layered alongside them, not
instead of them.

Deliberately NOT a firehose (project owner's own scope decision,
2026-09-01): only real failures and the recovery that ends them are
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

**`'info'` severity, added 2026-09-09** (real gap found live: clicking
"Run now" on the network discovery sweep visibly did something, but
nothing showed up here at all): deliberately narrow, not a general
"log routine success" escape hatch that would reopen the firehose
question above. Only two callers use it, both genuinely rare,
admin-relevant, one-off events, not a periodic cycle succeeding:
`controller/network_sweep.py`'s manual "Run now" trigger completing
(an explicit admin action, not the automatic hourly schedule), and
`common/identity.py`'s `record_binding()` recording a genuinely
brand-new device for the first time (not a routine binding refresh).
Requires a real schema migration (`common/db.py`'s `_migrate()`) since
SQLite's `CHECK` constraints can't be altered in place -- see that
migration's own comment for why this differs from
`interception_runtime.nft_mode`'s own precedent of skipping the CHECK
constraint entirely.
"""
from __future__ import annotations

import sqlite3
from typing import Callable

import db

_VALID_SEVERITIES = ("error", "recovery", "info")

# Added 2026-09-02, closing a real gap found by code review: this
# table's own original design (see this module's docstring above) was
# "not a firehose" purely by construction -- only real failures and
# their recovery ever get a row, never a routine successful cycle --
# which was a sound bound when every writer was an organic operational
# loop. Once dashboard.py/captive_portal_server.py started also writing
# here for failed login attempts (still rate-limited to a handful per
# minute per surface per IP, but never fully blocked, only throttled),
# this table gained its first ATTACKER-CONTROLLED writer: someone who
# never once succeeds can still grow it indefinitely just by repeatedly
# failing a login. No cap or pruning existed anywhere -- EVENT_DISPLAY_LIMIT
# on the /events page only ever bounded what's DISPLAYED, never what's
# stored. This caps the table itself, independent of who's writing to
# it or why.
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
    """
    state = {"failing": False}

    def on_error(exc: Exception) -> None:
        state["failing"] = True
        conn = db.get_conn()
        try:
            log_event(conn, source, "error", f"{source} failed: {exc}")
        finally:
            conn.close()

    def on_success() -> None:
        if not state["failing"]:
            return
        state["failing"] = False
        conn = db.get_conn()
        try:
            log_event(conn, source, "recovery", f"{source} recovered")
        finally:
            conn.close()

    return on_error, on_success
