#!/usr/bin/env python3
"""Drives the controller->worker heartbeat on a fixed interval so the
worker's lease (phase3/arp-worker/internal/worker/lease.go) never
expires while the controller is healthy and connected.
"""
from __future__ import annotations

from typing import Callable

from periodic import PeriodicTask


class HeartbeatPacer(PeriodicTask):
    """Calls `send_heartbeat()` on a background thread every `interval`
    seconds, until `stop()` is called.

    `send_heartbeat` is expected to raise on failure (a broken
    connection, a worker fault reply) -- this class does not retry or
    reconnect on its own. Reconnecting needs a fresh generation resend
    via reconcile(), not just a fresh heartbeat, so that's the caller's
    job (main.py), reported here via `on_error`.

    A thin, same-interface subclass of periodic.PeriodicTask, so
    controller/discovery.py's loop doesn't need its own copy of this
    thread-lifecycle logic.
    """

    def __init__(
        self,
        interval: float,
        send_heartbeat: Callable[[], None],
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        super().__init__(interval, send_heartbeat, on_error, thread_name="heartbeat-pacer")
