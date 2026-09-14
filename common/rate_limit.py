#!/usr/bin/env python3
"""A small, in-memory, per-key sliding-window rate limiter for login-style
brute-force protection.

Shared by `dashboard/dashboard.py`'s HTTP-Basic admin login and
`dashboard/captive_portal_server.py`'s kid-login/portal-admin-action
forms, so both reuse the same mechanism instead of separate hand-rolled
copies.

Stdlib-only (`threading` + `time`) -- this module is flat-copied into
every image that copies `common/*.py` (see each Dockerfile's own `COPY`
line), including the `proxy` container, which must never need `pip` (see
`common/auth.py`'s own docstring on the same constraint). Nothing in
`proxy/` currently imports this module, but it must stay stdlib-only
regardless, on the same footing as everything else in `common/`.

In-memory, per-process, deliberately not a new DB table: losing lockout
state across a process restart is an accepted tradeoff for a LAN-only
deployment. Each login surface should hold its OWN module-level `RateLimiter` instance
rather than sharing one between logically different surfaces (unless that
sharing is itself a deliberate choice, as it is between the portal's kid
login and its own admin action -- see that module's docstring) -- state
has to live somewhere that outlives any single request/connection, and a
flood against one surface should never exhaust a different surface's own
budget.
"""
from __future__ import annotations

import threading
import time


class RateLimiter:
    """Tracks failed attempts per key (e.g. a source IP) in a sliding
    window. Thread-safe: Flask's waitress runs multiple worker threads,
    and `captive_portal_server.py`'s `ThreadingHTTPServer` hands each
    connection its own thread -- both can call the same instance's
    methods concurrently.

    Known, accepted tradeoff: a key that is checked but never actually
    fails again (an attacker who gives up, or a legitimate user who
    later logs in successfully via `clear()`) still leaves a tiny empty
    list behind in the internal dict rather than being removed as a key
    entirely -- unbounded in theory over a process's lifetime, but bounded
    in practice by the number of distinct source IPs ever seen, each
    costing a few bytes. Not worth an eviction thread for a household
    LAN's realistic IP churn; revisit if this is ever exposed beyond one.
    """

    def __init__(self, max_attempts: int, window_seconds: float):
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_limited(self, key: str) -> bool:
        """True if `key` has already recorded `max_attempts` failures
        within the current window. Also prunes that key's own
        now-expired timestamps as a side effect, so a key that's well
        under the limit doesn't carry stale entries forever."""
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._attempts.get(key, []) if now - t < self._window_seconds]
            self._attempts[key] = recent
            return len(recent) >= self._max_attempts

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._attempts.setdefault(key, []).append(time.monotonic())

    def clear(self, key: str) -> None:
        """Call on a successful attempt so a legitimate user who
        mistyped a password a few times isn't left one mistake away
        from a lockout on their next, correct, attempt."""
        with self._lock:
            self._attempts.pop(key, None)
