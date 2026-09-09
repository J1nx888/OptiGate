#!/usr/bin/env python3
"""Active, whole-subnet discovery sweep -- the real fix for a confirmed
architectural gap found live 2026-09-08 (RoadMap.md's dated entry,
project owner's own words: "The entire solution is designed to make
sure no one can avoid it... we need to figure out why some devices
can"): every OTHER discovery source in this project is purely
reactive -- controller/rtnetlink_listener.py only reacts to real-time
kernel neighbor-table changes, controller/discovery.py's own periodic
snapshot only reads whatever the kernel's neighbor table ALREADY has,
and controller/active_scan.py's own docstring says outright it can
only ever refresh an IP that's already known ("there is no IP to nudge
for a device this table has no binding row for yet"). A device that
generates no traffic this box's own kernel happens to independently
observe -- one that joined the LAN before this box's containers last
started, and has simply sat there ever since -- is invisible to every
one of those, indefinitely. For a system whose whole point is that no
device can opt out of it, that's a real gap, not a cosmetic one.

Closes it using the EXACT SAME safe, already-live-verified mechanism
active_scan.py uses to refresh one known-stale IP (see that module's
own docstring for the full verification story against a real kernel):
opening a plain UDP socket and sending a datagram to a closed port on
a target IP forces the kernel's own routing/neighbor-resolution layer
to (re)resolve that address's link-layer info as a side effect, with
no CAP_NET_RAW needed. This module just widens that same trick from
"one specific already-known stale IP" to "every host address in the
configured LAN range(s)" -- reusing active_scan.nudge() directly
rather than re-implementing it, so there is exactly one UDP-nudge
implementation in this codebase, not two that could quietly drift.

Deliberately reuses the SAME `local_network` setting
common/matching.py's ip_in_configured_lan() already reads (a
space-separated CIDR list, e.g. "192.168.1.0/24") rather than adding a
second, possibly-inconsistent subnet setting -- one CIDR list, one
meaning, everywhere in this project. Confirmed with the project owner:
this deployment's actual LAN is 192.168.1.0/24 (254 host addresses),
comfortably inside this module's own sanity cap (see
_MAX_HOSTS_PER_SWEEP below).

Like active_scan.py, this module never itself writes device_bindings --
any resulting resolution is picked up by controller/discovery.py's own
already-running `ip neigh show` snapshot loop on its next tick,
recorded with source='snapshot' exactly like any other passively
observed entry, which is in turn what common/identity.py's
record_binding() uses to auto-create a `devices` row for a genuinely
new MAC (see that function's own 2026-08-31 docstring addition).

Runs once immediately at controller startup (via PeriodicTask's own
"run on start, then on interval" behavior -- see periodic.py), and
every `network_sweep_interval_minutes` minutes afterward (dashboard
Settings page, default 60 -- project owner's explicit request).
Deliberately NOT implemented as a PeriodicTask with that interval
directly: PeriodicTask's own interval is fixed at construction, which
would mean an admin's interval change (or flipping
`network_sweep_enabled` off) only ever took effect after a controller
restart -- the same "settings apply live, no redeploy needed"
expectation every other admin-facing setting in this project already
gets. Instead, the PeriodicTask here ticks on a short, fixed
`_CHECK_INTERVAL_SECONDS` and its own task function re-reads both
settings fresh on every tick, deciding for itself whether a real sweep
is actually due yet -- so a settings change takes effect within one
check tick, not one full sweep interval.
"""
from __future__ import annotations

import ipaddress
import logging
import sqlite3
import time

import active_scan
import db
import system_events
from periodic import PeriodicTask

log = logging.getLogger("controller.network_sweep")

DEFAULT_INTERVAL_MINUTES = 60

# How often the background thread checks whether a real sweep is due --
# independent of the admin-configured sweep interval itself. Short
# enough that an admin's interval/enabled change feels close to
# immediate, long enough not to be a wasted wakeup for a feature whose
# own default cadence is measured in hours.
_CHECK_INTERVAL_SECONDS = 30.0

# A real /24 sweep is 254 addresses (confirmed this deployment's own
# local_network is exactly that). A much larger configured range (e.g.
# a fat-fingered /16) would take a long time and generate a lot of LAN
# traffic for very little benefit on a home network -- capped here,
# not silently allowed to balloon. 4096 comfortably covers up to a
# /20, generously larger than any realistic home LAN, while still
# refusing something clearly wrong rather than hanging or flooding it.
_MAX_HOSTS_PER_SWEEP = 4096


def _configured_hosts(conn: sqlite3.Connection) -> list[str]:
    """Every host address (network/broadcast addresses excluded) across
    every CIDR in the same `local_network` setting
    common/matching.py's ip_in_configured_lan() already uses. Returns
    an empty list (not an error) for an empty/unset setting, matching
    that function's own "LAN check disabled" convention -- nothing
    configured means nothing to sweep, not a failure."""
    raw = (db.get_setting(conn, "local_network") or "").strip()
    if not raw:
        return []
    hosts: list[str] = []
    for cidr in raw.split():
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            log.warning("skipping unparseable local_network entry %r", cidr)
            continue
        for ip in network.hosts():
            hosts.append(str(ip))
            if len(hosts) >= _MAX_HOSTS_PER_SWEEP:
                log.warning(
                    "local_network %r exceeds the %d-host sweep cap -- truncating "
                    "rather than sweeping an unexpectedly huge range",
                    raw, _MAX_HOSTS_PER_SWEEP,
                )
                return hosts
    return hosts


def sweep_once(conn: sqlite3.Connection) -> int:
    """Nudges every host address in the configured LAN range(s) --
    same active_scan.nudge() mechanism used for a single stale IP, just
    applied to the whole range. Returns how many addresses were
    nudged (0 is a legitimate "nothing configured" result, not a
    failure). Records the attempt (address count + timestamp) into
    settings regardless of count, so the Settings page can show real
    status instead of silence -- see dashboard.py's own
    _network_sweep_status()."""
    hosts = _configured_hosts(conn)
    for ip in hosts:
        active_scan.nudge(ip)
    db.set_setting(conn, "network_sweep_last_run_at", db.now_iso())
    db.set_setting(conn, "network_sweep_last_host_count", str(len(hosts)))
    conn.commit()
    return len(hosts)


def _interval_seconds(conn: sqlite3.Connection) -> float:
    raw = db.get_setting(conn, "network_sweep_interval_minutes", str(DEFAULT_INTERVAL_MINUTES))
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        minutes = DEFAULT_INTERVAL_MINUTES
    # A corrupted/zero/negative value falls back to the default rather
    # than producing a zero or negative interval (which would make
    # every single check tick re-sweep, hammering the LAN) -- the
    # dashboard route that writes this setting already validates it,
    # this is defense-in-depth for a value that reached the DB some
    # other way (a stale pre-validation row, direct DB edit, etc.).
    return (minutes if minutes > 0 else DEFAULT_INTERVAL_MINUTES) * 60.0


def _enabled(conn: sqlite3.Connection) -> bool:
    return db.get_setting(conn, "network_sweep_enabled", "1") == "1"


def _run_now_requested(conn: sqlite3.Connection, state: dict[str, object]) -> bool:
    """"Run now" (dashboard Settings page): dashboard.py can't call into
    this process directly -- separate container, separate memory -- so
    it just writes a fresh `network_sweep_run_now_requested_at`
    timestamp and this tick loop notices it, the same "write a
    timestamp, let the other process's own next tick notice it" pattern
    already used for the optigate.home rewrite and the pending-devices
    dismiss feature elsewhere in this project. A request is consumed
    exactly once (compared against the last value THIS process already
    acted on, tracked in-memory in `state`) -- so it fires once per
    button click, not on every tick forever, and correctly fires again
    for a second click even if the first one hasn't produced a new
    timestamp string a naive equality check might miss (it always will,
    since db.now_iso() has second resolution and two real clicks are
    never the same second... but compared as "is it different from what
    we last consumed," not "is it non-empty," specifically so that
    edge case can never cause a second click to be silently ignored).
    Deliberately bypasses BOTH the enabled toggle and the interval
    check below -- an explicit one-off admin action should run
    regardless of whether the automatic schedule is off, the same way
    the Settings page's other "check/refresh now" buttons already work
    independently of their own periodic schedules."""
    requested_at = db.get_setting(conn, "network_sweep_run_now_requested_at", "")
    if not requested_at or requested_at == state.get("last_run_now_consumed"):
        return False
    state["last_run_now_consumed"] = requested_at
    return True


def run_loop(on_error=None, on_success=None) -> PeriodicTask:
    """Starts the check-then-maybe-sweep loop on its own background
    thread, until the returned PeriodicTask.stop() is called -- same
    shape as every other controller/*.py run_loop in this codebase,
    including opening its own DB connection lazily on the background
    thread (sqlite3.Connection objects are only usable from the thread
    that created them -- see discovery.run_loop's own docstring)."""
    state: dict[str, object] = {}

    def task() -> None:
        conn = state.get("conn")
        if conn is None:
            conn = db.get_conn()
            db.init_db(conn)
            state["conn"] = conn

        manual = _run_now_requested(conn, state)
        if not manual:
            if not _enabled(conn):
                return
            now = time.monotonic()
            last_swept = state.get("last_swept_monotonic")
            if last_swept is not None and (now - last_swept) < _interval_seconds(conn):
                return

        swept = sweep_once(conn)
        state["last_swept_monotonic"] = time.monotonic()
        log.info(
            "network sweep: nudged %d address(es)%s", swept, " (manual run-now request)" if manual else ""
        )
        if manual:
            # Fixed 2026-09-09, real gap found live: clicking "Run now"
            # visibly did something (the Settings page's own status line
            # updates), but nothing showed up on the Events page at all
            # -- container stdout (log.info above) was the only place
            # this was visible, same blind spot system_events.py's own
            # docstring describes for the pre-2026-09-01 world. A
            # scheduled/automatic sweep completing does NOT get this --
            # only an explicit admin action, matching the 'info'
            # severity's own narrow scope (see common/db.py's schema
            # comment). Reports what it actually DID (how many addresses
            # it probed, and the range) -- not what it "found": any
            # newly-discovered device is a separate, later event, logged
            # by common/identity.py's record_binding() once
            # discovery.py's own snapshot loop actually observes it.
            local_network = db.get_setting(conn, "local_network", "")
            system_events.log_event(
                conn, "network_sweep", "info",
                f"Manual sweep complete: probed {swept} address(es) in {local_network or '(nothing configured)'}.",
            )

    pt = PeriodicTask(
        _CHECK_INTERVAL_SECONDS, task, on_error=on_error, on_success=on_success,
        thread_name="network-sweep",
    )
    pt.start()
    return pt
