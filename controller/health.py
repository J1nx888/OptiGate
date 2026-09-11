#!/usr/bin/env python3
"""Milestone 6: the controller's own health reporting into
interception_runtime -- specifically the mode/last_healthy_at/
fail_open_reason columns tracking the controller<->ARP-worker pipeline,
deliberately separate from phase3/nftables-manager's own nft_mode/
nft_last_healthy_at/nft_fail_reason columns (see common/db.py's schema
comment) so the two subsystems never clobber each other's status in
the shared singleton row.
"""
from __future__ import annotations

import logging
import sqlite3

import db

log = logging.getLogger(__name__)


def _safe_write(conn: sqlite3.Connection, label: str, sql: str, params: tuple) -> None:
    """Runs one health-status INSERT/UPSERT, catching and logging
    (via stdlib `logging`, which never touches the DB) anything it
    raises instead of letting it propagate.

    **Real production incident, 2026-09-11**: every report_*() function
    below used to execute+commit directly. On a real box with several
    containers touching the shared SQLite DB at once, that write can
    itself raise `sqlite3.OperationalError: database is locked` --
    and since these functions are most often called FROM an except
    block already handling some other failure (controller/main.py's
    run_cycle()), that second exception had nowhere to go: it escaped
    uncaught, past the try/except that was already handling the
    original problem, and crashed the entire caller (the main reconcile
    loop itself, in the incident that motivated this fix -- confirmed
    live: one "reconcile cycle failed" warning logged, then the whole
    loop silently died with zero further output, while the container
    kept reporting "Up" and healthy). A failure to WRITE a health
    status is strictly less severe than whatever it was trying to
    report, or than killing the loop that would have retried next
    cycle -- so every function here now goes through this helper
    instead of calling conn.execute()/commit() directly."""
    try:
        conn.execute(sql, params)
        conn.commit()
    except Exception:  # noqa: BLE001 -- deliberately broad, see docstring above
        log.exception("%s: failed to write health status -- swallowed to avoid killing the caller", label)


def report_healthy(conn: sqlite3.Connection, applied_generation: int) -> None:
    """Call this once per successful reconciliation cycle (see
    controller/main.py's run())."""
    now = db.now_iso()
    _safe_write(
        conn,
        "report_healthy",
        "INSERT INTO interception_runtime "
        "(singleton_id, applied_generation, mode, last_healthy_at, fail_open_reason) "
        "VALUES (1, ?, 'running', ?, NULL) "
        "ON CONFLICT(singleton_id) DO UPDATE SET "
        "applied_generation = excluded.applied_generation, mode = 'running', "
        "last_healthy_at = excluded.last_healthy_at, fail_open_reason = NULL",
        (applied_generation, now),
    )


def report_fail_open(
    conn: sqlite3.Connection, reason: str, applied_generation: int | None = None
) -> None:
    """Call this when the pipeline is unhealthy.

    applied_generation defaults to None, leaving the column untouched --
    the right choice when the reconciliation cycle itself is what
    failed (a dead worker connection, an exception mid-cycle): there is
    no fresh confirmation of what's actually applied, so the
    last-known-good value stays meaningful and must not be silently
    reset.

    Pass an explicit value (added 2026-08-31, for
    controller/main.py's new sustained-ARP-send-failure report) when
    the cycle otherwise succeeded -- generation_applied really did come
    back from the worker -- and fail_open is being reported for an
    orthogonal reason (the worker's actual packet transmission, not the
    IPC round-trip, is what's failing). Leaving this at None in that
    case would have let a fresh INSERT default applied_generation to 0,
    understating a real, true value on the very first fail_open cycle
    -- caught by this fix's own test suite, not by inspection."""
    if applied_generation is None:
        _safe_write(
            conn,
            "report_fail_open",
            "INSERT INTO interception_runtime (singleton_id, mode, fail_open_reason) "
            "VALUES (1, 'fail_open', ?) "
            "ON CONFLICT(singleton_id) DO UPDATE SET mode = 'fail_open', "
            "fail_open_reason = excluded.fail_open_reason",
            (reason,),
        )
    else:
        _safe_write(
            conn,
            "report_fail_open",
            "INSERT INTO interception_runtime (singleton_id, applied_generation, mode, fail_open_reason) "
            "VALUES (1, ?, 'fail_open', ?) "
            "ON CONFLICT(singleton_id) DO UPDATE SET "
            "applied_generation = excluded.applied_generation, mode = 'fail_open', "
            "fail_open_reason = excluded.fail_open_reason",
            (applied_generation, reason),
        )


def report_repair_only(conn: sqlite3.Connection, reason: str) -> None:
    """Call this specifically when the worker itself has reported (via
    its own unsolicited "fault" IPC message, reason="lease_expired",
    action="entering_repair_only_mode") that it already sent one
    corrective ARP-restoration round and stopped actively poisoning on
    its own -- a controlled, self-limiting state, genuinely different
    from an outright dead/unreachable worker (report_fail_open, above).

    Added 2026-09-02, closing a real gap found by code review:
    `interception_runtime.mode`'s dedicated 'repair_only' value (with
    its own amber dashboard badge, distinct from fail_open's red one --
    see dashboard/dashboard.py's HEALTH_MODE_BADGE_CLASS) previously had
    no writer anywhere in the codebase; every WorkerError, including
    this exact fault, collapsed into report_fail_open(), so an admin
    could never tell "the worker process crashed" apart from "the
    worker's lease merely expired and it already self-corrected."

    Kept as its own function (not a mode= parameter bolted onto
    report_fail_open) so a future third state is just as easy to add
    without threading a growing enum through one function's signature.
    Deliberately leaves applied_generation untouched, same reasoning as
    report_fail_open's own None-generation case: the worker's own
    internal state changed here, not the IPC round-trip that would
    produce a fresh generation to report."""
    _safe_write(
        conn,
        "report_repair_only",
        "INSERT INTO interception_runtime (singleton_id, mode, fail_open_reason) "
        "VALUES (1, 'repair_only', ?) "
        "ON CONFLICT(singleton_id) DO UPDATE SET mode = 'repair_only', "
        "fail_open_reason = excluded.fail_open_reason",
        (reason,),
    )
