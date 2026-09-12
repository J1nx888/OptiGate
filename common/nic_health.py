#!/usr/bin/env python3
"""Surfaces whether the host's primary network interface has Receive
Packet Steering (RPS) enabled, plus its lifetime hardware-level packet
loss counters -- for the dashboard's Health page (2026-09-12), so a
future deployment on similarly cheap single-queue NIC hardware has
something better than a silent, hard-to-diagnose sustained-upload
failure to go on.

Written after a real production incident (RoadMap.md, "Item 3
revisited"): a Realtek RTL8168h/8111h NIC (driver r8169, single RX
queue, no RSS) had every hardware interrupt landing on ONE CPU core,
confirmed via `/proc/interrupts` + `/proc/net/softnet_stat` + a genuine
nonzero `rx_missed` counter -- and RPS (which spreads packet
*processing*, not the interrupt itself, across every core in software)
was never enabled. `nic-tuning/optigate-nic-tuning.sh` fixes this at
boot going forward; this module is the read side, so an admin can SEE
whether it's actually in effect on their own box rather than trusting
it silently.

Deliberately reads plain sysfs files only (`/proc/net/route`,
`/sys/class/net/<iface>/...`) rather than shelling out to `ip`/`ethtool`
-- no new binary dependency for the dashboard image, and these
particular files are all world-readable (confirmed live: `rps_cpus` is
mode 644 owned by root, no elevated privilege needed just to read it),
unlike the root-only *write* that turns RPS on in the first place.
`rx_missed_errors`/`rx_dropped` come from the exact same underlying
kernel counters `ethtool -S <iface>` reports (confirmed identical
live), exposed generically for every interface via
`/sys/class/net/<iface>/statistics/`, so no ethtool-specific ioctl is
needed either.
"""
from __future__ import annotations

from pathlib import Path

SYS_CLASS_NET = Path("/sys/class/net")
PROC_NET_ROUTE = Path("/proc/net/route")


def detect_primary_interface() -> str | None:
    """The interface carrying the default route (destination
    `0.0.0.0/0`), read directly from `/proc/net/route` -- the same
    interface `nic-tuning/optigate-nic-tuning.sh` tunes at boot (that
    script re-detects it the same way, via `ip route get`, rather than
    either of them hardcoding an interface name that varies across
    hardware/distros).

    Returns `None` if `/proc/net/route` can't be read at all (this
    process isn't running with visibility into the host's network
    namespace -- e.g. no `network_mode: host`) or has no default route
    yet (network not up)."""
    try:
        lines = PROC_NET_ROUTE.read_text().splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 2:
            continue
        iface, destination = fields[0], fields[1]
        if destination == "00000000":
            return iface
    return None


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def rps_enabled(iface: str) -> bool | None:
    """True if ANY RX queue on `iface` has a nonzero `rps_cpus` mask
    (packet processing is being spread across more than whichever one
    core the hardware interrupt happens to land on), False if every
    queue is disabled (the Linux default), or `None` if `iface` has no
    `queues/` directory at all to check (doesn't exist, or this process
    can't see it).

    `rps_cpus` is a bitmask, one hex digit per 4 CPUs, formatted as a
    single hex string on a machine with <=32 CPUs (e.g. `"f"` for all 4
    cores on a 4-core box) or comma-separated 32-bit groups on a larger
    one -- checking for any character outside `"0,"` correctly detects
    "enabled" in both shapes without parsing the mask into an integer.
    """
    queues_dir = SYS_CLASS_NET / iface / "queues"
    try:
        rx_dirs = sorted(p for p in queues_dir.iterdir() if p.name.startswith("rx-"))
    except OSError:
        return None
    if not rx_dirs:
        return None
    for rx_dir in rx_dirs:
        try:
            mask = (rx_dir / "rps_cpus").read_text().strip()
        except OSError:
            continue
        if any(c not in "0," for c in mask):
            return True
    return False


def nic_drop_counters(iface: str) -> dict[str, int] | None:
    """`{"rx_missed_errors", "rx_dropped"}` for `iface`, straight from
    its own sysfs `statistics/` directory -- lifetime counters since the
    driver/interface last reset, NOT since this dashboard process
    started. Returns `None` if `iface` has no `statistics/` directory at
    all (doesn't exist, or not visible to this process)."""
    stats_dir = SYS_CLASS_NET / iface / "statistics"
    if not stats_dir.is_dir():
        return None
    return {
        "rx_missed_errors": _read_int(stats_dir / "rx_missed_errors") or 0,
        "rx_dropped": _read_int(stats_dir / "rx_dropped") or 0,
    }


def nic_load_status(iface: str | None = None) -> dict:
    """Single entry point for the dashboard's Health page. Auto-detects
    the primary interface when `iface` isn't given (tests pass one
    explicitly instead of depending on the test host's own routing
    table). `available` is False when this process can't see host
    networking at all -- e.g. run without `network_mode: host`, or in a
    test/dev environment -- so the page can render a neutral "not
    available" card instead of a misleading "not enabled" one; those
    mean very different things to an admin."""
    if iface is None:
        iface = detect_primary_interface()
    if iface is None:
        return {"available": False, "interface": None}
    rps = rps_enabled(iface)
    if rps is None:
        return {"available": False, "interface": iface}
    counters = nic_drop_counters(iface) or {"rx_missed_errors": 0, "rx_dropped": 0}
    return {
        "available": True,
        "interface": iface,
        "rps_enabled": rps,
        "rx_missed_errors": counters["rx_missed_errors"],
        "rx_dropped": counters["rx_dropped"],
    }


def with_baseline(status: dict, baseline: dict | None) -> dict:
    """Augments a `nic_load_status()` result with "since counters were
    last reset" deltas, added 2026-09-12: `rx_missed_errors`/`rx_dropped`
    are real kernel counters, tied to the NIC driver itself -- they only
    ever reset on an interface down/up cycle or a reboot, never on their
    own and never just because this dashboard restarted. That makes the
    raw lifetime totals nearly useless for "did today's test actually
    cause drops" -- a box that's been up for months could show hundreds
    of missed packets from long before anyone started troubleshooting
    anything. Actually resetting the real counter needs bouncing the
    NIC, which would cut this box's own network connectivity (and thus
    every device behind it) for however long that takes -- not something
    a dashboard button should ever do. This gives the admin the same
    practical result without that risk: a software-side baseline
    (dashboard.py stores one, keyed by interface, in the `settings`
    table) that this function subtracts from the current live reading.

    `status` is a `nic_load_status()` result; `baseline` is `None` (never
    set) or `{"interface", "rx_missed_errors", "rx_dropped", "set_at"}`
    from whenever the admin last clicked "Reset counters". Returns a new
    dict (never mutates `status`) with `baseline_set_at` (`None` if no
    usable baseline applies) and, only when a baseline does apply,
    `rx_missed_errors_since_baseline`/`rx_dropped_since_baseline` plus
    `interface_changed_since_baseline` (the baseline was taken against a
    different interface than the one currently detected -- e.g. a NIC
    swap -- so the comparison is meaningless and is dropped) and
    `counters_reset_since_baseline` (the live value is now LOWER than
    the stored baseline -- the interface itself was reset since, e.g. a
    reboot or `ip link set down/up`, and genuinely restarted counting
    from 0; clamped to 0 rather than shown as a nonsensical negative
    number)."""
    result = dict(status)
    if not status.get("available") or not baseline:
        result["baseline_set_at"] = None
        return result
    if baseline.get("interface") != status.get("interface"):
        result["baseline_set_at"] = None
        result["interface_changed_since_baseline"] = True
        return result
    result["baseline_set_at"] = baseline.get("set_at")
    result["interface_changed_since_baseline"] = False
    missed_delta = status["rx_missed_errors"] - baseline.get("rx_missed_errors", 0)
    dropped_delta = status["rx_dropped"] - baseline.get("rx_dropped", 0)
    result["counters_reset_since_baseline"] = missed_delta < 0 or dropped_delta < 0
    result["rx_missed_errors_since_baseline"] = max(0, missed_delta)
    result["rx_dropped_since_baseline"] = max(0, dropped_delta)
    return result
