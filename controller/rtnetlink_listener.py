#!/usr/bin/env python3
"""Milestone 4's higher-precedence discovery source (see
docs/design/phase3-technical-design.md's discovery precedence order): a
live rtnetlink listener for `RTM_NEWNEIGH` events, reacting within
however long the kernel takes to deliver the netlink message --
effectively instant, versus `controller/discovery.py`'s periodic
`ip neigh show` snapshot, which can miss a device's new IP for up to a
full `--discovery-interval`. Closes the exact gap that module's own
docstring and `docs/security/overview.md` §3 both flag by name.

Uses `pyroute2` (see `controller/requirements.txt`) -- pure Python, no C
extension needed (confirmed via PyPI metadata), the one deliberate
exception to this project's otherwise-stdlib-only controller/common
code, for the one thing the stdlib genuinely doesn't expose a usable
API for (parsing `RTM_NEWNEIGH` netlink messages -- raw `AF_NETLINK`
sockets ARE available via Python's own `socket` module, but decoding
their contents by hand is squarely what pyroute2 already does well).
Always imported lazily, inside functions, never at module level --
`pyroute2` is Linux-only (no `AF_NETLINK` on Windows), and this module
must stay importable (for tests, and for `controller/main.py` itself)
on this project's Windows dev machine.

Deliberately reacts to `RTM_NEWNEIGH` only, never `RTM_DELNEIGH` --
mirrors `discovery.py`'s own philosophy exactly: a binding goes stale by
being *replaced* (a fresh, conflicting observation -- see
`common/identity.py`'s `record_binding()`), never by the mere absence of
one. A neighbor entry aging out of the kernel's own ARP cache is not
proof a device is gone (could be a completely normal cache timeout for a
device still very much present), so treating a `DELNEIGH` as "deactivate
this binding" would be over-reacting to absence -- exactly the kind of
inference `identity.py`'s own docstring already warns against for a
different case (never auto-associating a MAC from network data alone).

Real message shape confirmed live 2026-08-30 (pyroute2 0.9.6, a real
Linux kernel, real Docker bridge traffic) before writing this, not
assumed from documentation:
- `family` distinguishes real IPv4 ARP neighbors (`socket.AF_INET`, 2)
  from `AF_BRIDGE` FDB-learning noise (7, no `NDA_DST` at all -- these
  dominate event volume on a Docker host and are NOT ARP/NDP entries at
  all) and IPv6 neighbor discovery (`socket.AF_INET6`, 10, out of scope
  -- this project's `device_bindings` model is IPv4-only throughout).
- `state` is an integer `NUD_*` bitmask
  (`include/uapi/linux/neighbour.h`), not the string names
  `ip neigh show`'s text output uses -- observed as always exactly one
  bit set in practice, but checked as a bitmask
  (`state & _TRUSTED_STATE_MASK`) to match the kernel's own field
  definition rather than assume that never changes.
- `attrs` is a list of `(name, value)` tuples; `NDA_DST`/`NDA_LLADDR`
  carry the IP/MAC respectively, and either can be absent (e.g. an
  `INCOMPLETE` entry has no `NDA_LLADDR` yet) -- both are required here.
"""
from __future__ import annotations

import logging
import socket
import threading

import identity

log = logging.getLogger("controller.rtnetlink_listener")

# NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_NOARP | NUD_PERMANENT
# -- the exact same set of states discovery.py's own _TRUSTED_STATES
# trusts from `ip neigh show`'s text output, translated to the kernel's
# real integer bitmask. NUD_INCOMPLETE (0x01) and NUD_FAILED (0x20) are
# deliberately excluded, matching discovery.py excluding the FAILED/
# INCOMPLETE text states (neither carries a usable lladdr anyway).
_TRUSTED_STATE_MASK = 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80

_DEFAULT_POLL_TIMEOUT = 1.0
_DEFAULT_RETRY_BACKOFF = 5.0


def extract_ipv4_binding(message: dict) -> tuple[str, str] | None:
    """Returns `(ip, mac)` for a trusted, real IPv4 ARP neighbor
    `RTM_NEWNEIGH` message, or `None` if this message isn't one -- wrong
    address family (`AF_BRIDGE` FDB noise and IPv6 both arrive on the
    same netlink group and must be filtered out here), an untrusted
    state, or a missing IP/MAC attribute. Pure function, no I/O --
    exactly the piece worth testing thoroughly (mirrors
    `discovery.parse_ip_neigh_output`'s own role relative to
    `discovery.run_ip_neigh_show`).
    """
    if message.get("family") != socket.AF_INET:
        return None
    if not (message.get("state", 0) & _TRUSTED_STATE_MASK):
        return None
    attrs = dict(message.get("attrs") or [])
    ip = attrs.get("NDA_DST")
    mac = attrs.get("NDA_LLADDR")
    if not ip or not mac:
        return None
    return ip, mac.lower()


class RtnetlinkListener:
    """Owns the background thread and the live netlink socket. Started
    via `run_loop()` below; `stop()` joins the thread with a bounded
    timeout, matching `PeriodicTask.stop()`'s own contract elsewhere in
    this package.

    A hard failure while listening (permission denied, the socket
    erroring out, `pyroute2` itself misbehaving) is reported via
    `on_error` and the whole listen loop is retried from scratch after
    `retry_backoff` seconds, rather than letting the background thread
    silently die -- same "one bad cycle is a reason to log and retry,
    never a reason to stop watching for devices entirely" philosophy as
    `discovery.run_loop()` and `HeartbeatPacer`.
    """

    def __init__(
        self,
        on_error=None,
        poll_timeout: float = _DEFAULT_POLL_TIMEOUT,
        retry_backoff: float = _DEFAULT_RETRY_BACKOFF,
    ):
        self._on_error = on_error
        self._poll_timeout = poll_timeout
        self._retry_backoff = retry_backoff
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="rtnetlink-listener", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)

    def _run(self) -> None:
        import db  # local import: mirrors discovery.run_loop's own lazy `import db`

        conn = db.get_conn()
        db.init_db(conn)
        try:
            while not self._stop.is_set():
                try:
                    self._listen_once(conn)
                except Exception as exc:  # noqa: BLE001 -- deliberately broad, see class docstring
                    self._safe_report(exc)
                    self._stop.wait(self._retry_backoff)
        finally:
            conn.close()

    def _safe_report(self, exc: Exception) -> None:
        """Wraps `self._on_error(exc)` in its own try/except -- fixed
        2026-09-11, found by code review, the same bug class as
        `controller/periodic.py`'s own `_safe_report()` fix this same
        session: an unguarded callback invocation meant a SECOND failure
        inside `on_error` itself (e.g. `system_events.py`'s DB write
        hitting `sqlite3.OperationalError: database is locked`) would
        propagate straight out of `_run()`'s except block, silently
        killing this background thread for good instead of just skipping
        this one report and retrying next cycle."""
        if not self._on_error:
            return
        try:
            self._on_error(exc)
        except Exception:
            log.exception("rtnetlink listener's own on_error callback raised -- ignoring, continuing to retry")

    def _listen_once(self, conn) -> None:
        """One full "open a netlink socket, listen until stopped or it
        breaks" cycle. Split out from `_run()` specifically so a single
        socket-level failure re-enters here with a fresh `IPRoute`
        instance on retry, rather than reusing a socket that already
        proved broken."""
        from pyroute2 import IPRoute  # local import: pyroute2 is Linux-only, see module docstring

        with IPRoute() as ipr:
            ipr.bind()
            ipr.settimeout(self._poll_timeout)
            while not self._stop.is_set():
                try:
                    messages = ipr.get()
                except socket.timeout:
                    continue
                for message in messages:
                    if message.get("event") != "RTM_NEWNEIGH":
                        continue
                    binding = extract_ipv4_binding(message)
                    if binding is None:
                        continue
                    ip, mac = binding
                    identity.record_binding(conn, mac, ip, source="rtnetlink")


def run_loop(on_error=None) -> RtnetlinkListener:
    """Starts a live rtnetlink listener on its own background thread,
    recording every trusted `RTM_NEWNEIGH` IPv4 ARP observation via
    `common/identity.py`'s `record_binding()` as it arrives, until the
    returned object's `stop()` is called. Mirrors
    `discovery.run_loop()`'s "open its own DB connection, lazily, on its
    own thread" pattern for the same reason (a `sqlite3.Connection` is
    only usable from the thread that created it).
    """
    listener = RtnetlinkListener(on_error=on_error)
    listener.start()
    return listener
