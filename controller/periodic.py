#!/usr/bin/env python3
"""Generic "call this on a fixed interval, in the background, until
stopped" primitive.

Factored out of controller/lease.py's HeartbeatPacer (Milestone 3) when
controller/discovery.py's discovery loop (Milestone 4) needed the exact
same thread-lifecycle/error-handling shape: a background thread that
must stop promptly, and that reports -- rather than dies from -- a
failing callback. HeartbeatPacer is now a thin, same-interface subclass
of this; see its own docstring.
"""
from __future__ import annotations

import threading
from typing import Callable


class PeriodicTask:
    """Calls `task()` on a background thread every `interval` seconds,
    until `stop()` is called.

    `task` is expected to raise on failure -- this class does not retry
    beyond "try again next interval," and does not reconnect/repair
    anything on the caller's behalf. A raised exception is reported via
    `on_error` (if given) rather than propagating, so one bad cycle never
    kills the background thread.

    `on_success` (added 2026-09-01 for `common/system_events.py`'s
    failure->recovery transition tracking) fires after every cycle that
    does NOT raise -- including the ordinary case where nothing was ever
    failing to begin with. It's the caller's job (see
    `system_events.failure_recovery_callbacks()`) to decide whether a
    given success is notable; this class makes no judgment about that,
    it just reports every non-raising cycle the same way it reports
    every raising one via `on_error`.
    """

    def __init__(
        self,
        interval: float,
        task: Callable[[], None],
        on_error: Callable[[Exception], None] | None = None,
        on_success: Callable[[], None] | None = None,
        *,
        thread_name: str = "periodic-task",
    ) -> None:
        self._interval = interval
        self._task = task
        self._on_error = on_error
        self._on_success = on_success
        self._thread_name = thread_name
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

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
        # later call -- fixed 2026-09-07 (RoadMap.md's dated section,
        # "categories not pre-seeded"): every caller of this class used
        # to wait a full `interval` before its very first cycle ever ran
        # (`while not self._stop.wait(interval): task()` never calls
        # task() until the first wait elapses). Harmless at a 5s
        # reconciliation interval, but common/category_fetch.py's own
        # 86400s (24h) default meant category subscriptions could never
        # actually populate until this process had been running
        # continuously for a full day -- something that had never
        # actually happened on the real production box, since every
        # session so far only brought `controller` up for short test
        # windows. The `_stop.is_set()` guard covers stop() racing in
        # before this thread's first tick (start() returns immediately;
        # nothing otherwise stops a stop-before-first-tick sequence from
        # still running one cycle it shouldn't).
        if not self._stop.is_set():
            self._tick()
        while not self._stop.wait(self._interval):
            self._tick()

    def _tick(self) -> None:
        try:
            self._task()
        except Exception as exc:  # noqa: BLE001 -- deliberately broad: any
            # failure here must not kill the loop silently: it gets
            # reported via on_error and the loop keeps ticking so a
            # transient failure doesn't permanently stop the task.
            if self._on_error is not None:
                self._on_error(exc)
        else:
            if self._on_success is not None:
                self._on_success()
