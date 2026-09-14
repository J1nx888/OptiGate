#!/usr/bin/env python3
"""Generic "call this on a fixed interval, in the background, until
stopped" primitive.

Factored out of controller/lease.py's HeartbeatPacer when
controller/discovery.py's discovery loop needed the exact same
thread-lifecycle/error-handling shape: a background thread that must
stop promptly, and that reports -- rather than dies from -- a failing
callback. HeartbeatPacer is now a thin, same-interface subclass of
this; see its own docstring.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable

log = logging.getLogger(__name__)


class PeriodicTask:
    """Calls `task()` on a background thread every `interval` seconds,
    until `stop()` is called.

    `task` is expected to raise on failure -- this class does not retry
    beyond "try again next interval," and does not reconnect/repair
    anything on the caller's behalf. A raised exception is reported via
    `on_error` (if given) rather than propagating, so one bad cycle never
    kills the background thread.

    `on_success` fires after every cycle that does NOT raise --
    including the ordinary case where nothing was ever failing to begin
    with. It's the caller's job (see
    `system_events.failure_recovery_callbacks()`) to decide whether a
    given success is notable; this class makes no judgment about that,
    it just reports every non-raising cycle the same way it reports
    every raising one via `on_error`.

    `_tick()` below wraps both `on_error` and `on_success` in their own
    try/except, logging via the stdlib `logging` module (which never
    touches the DB, so it can't fail the same way) rather than letting
    either one bring the loop down: every real caller's `on_error` (see
    `system_events.failure_recovery_callbacks()`) writes a row to the
    shared SQLite DB, and on a box with several containers touching
    that DB at once, `conn.execute()` can itself raise
    `sqlite3.OperationalError: database is locked` -- an unguarded
    second exception there would kill this task's entire background
    thread outright, the one failure mode this class exists to prevent,
    just one level removed.

    `on_stop` fires exactly once, on this same background thread, right
    before it exits -- whether the final cycle returned cleanly or
    raised. It exists for a `task` that owns a resource only its own
    thread may touch (a `sqlite3.Connection` is thread-affine by
    default, e.g. `controller/rtnetlink_listener.py`'s) and needs a
    guaranteed place to release it on shutdown, regardless of which
    cycle happened to be running when `stop()` was called.
    """

    def __init__(
        self,
        interval: float,
        task: Callable[[], None],
        on_error: Callable[[Exception], None] | None = None,
        on_success: Callable[[], None] | None = None,
        on_stop: Callable[[], None] | None = None,
        *,
        thread_name: str = "periodic-task",
    ) -> None:
        self._interval = interval
        self._task = task
        self._on_error = on_error
        self._on_success = on_success
        self._on_stop = on_stop
        self._thread_name = thread_name
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def stop_requested(self) -> bool:
        """True once stop() has been called. Lets a `task` that polls in
        its own inner loop (rather than returning quickly every cycle --
        e.g. controller/rtnetlink_listener.py's blocking netlink read)
        cooperate with shutdown instead of running until it happens to
        return on its own."""
        return self._stop.is_set()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name=self._thread_name)
        self._thread.start()

    def stop(self) -> None:
        """Signals the task to stop and waits for the background thread
        to actually exit. Safe to call even if start() was never
        called."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval * 5 + 1)

    def _run(self) -> None:
        # Runs once immediately, THEN waits `interval` between every
        # later call -- a naive `while not self._stop.wait(interval):
        # task()` would delay every caller's very first cycle by a full
        # `interval`, which is fatal for a long-interval caller like
        # common/category_fetch.py's 86400s (24h) default: category
        # subscriptions would never populate until the process had been
        # running continuously for a full day. The `_stop.is_set()`
        # guard covers stop() racing in before this thread's first tick
        # (start() returns immediately; nothing otherwise stops a
        # stop-before-first-tick sequence from still running one cycle
        # it shouldn't).
        try:
            if not self._stop.is_set():
                self._tick()
            while not self._stop.wait(self._interval):
                self._tick()
        finally:
            # Runs exactly once, on this same background thread, no
            # matter how the loop above ended -- including when the very
            # last tick raised and stop() was requested during the
            # post-error backoff wait rather than between clean cycles.
            # Exists so a task that owns a thread-affine resource (e.g.
            # rtnetlink_listener.py's sqlite3 connection, which can only
            # be closed from the thread that created it) has a reliable
            # place to release it, instead of every such task
            # reimplementing its own try/finally around the whole loop.
            if self._on_stop is not None:
                self._safe_report(self._on_stop)

    def _tick(self) -> None:
        try:
            self._task()
        except Exception as exc:  # noqa: BLE001 -- deliberately broad: any
            # failure here must not kill the loop silently: it gets
            # reported via on_error and the loop keeps ticking so a
            # transient failure doesn't permanently stop the task.
            if self._on_error is not None:
                self._safe_report(self._on_error, exc)
        else:
            if self._on_success is not None:
                self._safe_report(self._on_success)

    def _safe_report(self, callback: Callable[..., None], *args: object) -> None:
        """Calls `callback` (on_error or on_success), swallowing and
        logging anything IT raises instead of letting that escape --
        see this class's own docstring for the real incident this
        guards against. `callback` failing to report a result is
        strictly less severe than it killing the whole periodic task
        over it."""
        try:
            callback(*args)
        except Exception:  # noqa: BLE001 -- deliberately broad, see above
            log.exception(
                "%s: on_error/on_success callback itself raised -- swallowed to keep the task alive",
                self._thread_name,
            )
