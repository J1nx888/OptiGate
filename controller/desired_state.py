#!/usr/bin/env python3
"""Builds a real DesiredState from the devices/device_bindings tables
(Milestone 4) -- the piece controller/main.py's placeholder_desired_state
was explicitly waiting on. This module only reads the DB; recording
observations is common/identity.py's job.
"""
from __future__ import annotations

import sqlite3

from ipc_client import Target
from reconcile import DesiredState


def db_backed_desired_state(
    conn: sqlite3.Connection, gateway: Target, full_duplex: bool = False
) -> DesiredState:
    """Every non-ignored device with a currently-active IPv4 binding
    becomes a poisoning target.

    `devices.is_authenticated` deliberately plays no part here: per
    docs/design/phase3-technical-design.md section 5, interception
    scope and auth/policy scope are different axes -- an authenticated
    or not-yet-authenticated device is poisoned exactly the same way,
    only nftables set membership (not built yet) is meant to vary by
    that flag. `ignored` is the only exclusion here, standing in for
    the design's `bypass_v4` class: it already carries exactly the
    "never touch this device" semantic (the admin's own laptop, a
    guest's phone, or the gateway/Beelink itself entered as an ignored
    device), so this doesn't introduce a second, differently-named
    concept for the same thing. A device sitting in a group whose OWN
    `ignored` flag is set (added 2026-09-07, db.py's own schema comment
    on `groups.ignored`) is excluded the same way, via the LEFT JOIN
    below -- group-level ignore is additive with the device's own bit,
    not a replacement for it. The worker's own ValidateTargets (see
    phase3/arp-worker/internal/worker/safety.go) independently rejects
    the gateway/self/broadcast/multicast regardless of what's sent
    here, as defense in depth -- this function does not duplicate that
    check.

    A device with more than one simultaneously-active binding (see
    common/identity.py's conflict-handling notes for how that can
    briefly happen) contributes only its most-recently-seen one.

    **Real gap found live 2026-09-11**: this used to INNER JOIN
    `devices`, so deleting a device's row (`device_bindings.device_id`
    goes to NULL, `ON DELETE SET NULL` -- see db.py's own schema
    comment on that column) silently dropped it out of ARP-spoofing
    scope entirely rather than falling back to the safe PREAUTH/
    unauthenticated treatment a genuinely-new, never-configured device
    gets. Confirmed live: a deleted-but-still-present device got
    unrestricted, unfiltered internet, indistinguishable from a
    deliberate bypass. Now a LEFT JOIN from `device_bindings`, so an
    orphaned binding (`d.id IS NULL`) still becomes a poisoning target
    -- `COALESCE(d.ignored, 0) = 0` only excludes it if a REAL devices
    row says so, matching classify_device()'s own falsy-default
    treatment of a fully-NULL row in controller/policy_state.py.
    """
    rows = conn.execute(
        """
        SELECT d.id AS device_id, b.mac_address, b.ipv4_address
        FROM device_bindings b
        LEFT JOIN devices d ON d.id = b.device_id
        LEFT JOIN groups g ON g.id = d.group_id
        WHERE b.active = 1 AND COALESCE(d.ignored, 0) = 0 AND COALESCE(g.ignored, 0) = 0
        ORDER BY b.last_seen_at DESC
        """
    ).fetchall()

    seen_macs: set[str] = set()
    targets: list[Target] = []
    for row in rows:
        # mac_address, not device_id -- an orphaned binding (deleted
        # device) has device_id NULL, and several DIFFERENT deleted
        # devices sharing that same NULL would otherwise collide in a
        # device_id-keyed set and wrongly drop all but the first one.
        if row["mac_address"] in seen_macs:
            continue  # already took this MAC's freshest active binding
        seen_macs.add(row["mac_address"])
        targets.append(Target(ip=row["ipv4_address"], mac=row["mac_address"]))

    return DesiredState(gateway=gateway, targets=tuple(targets), full_duplex=full_duplex)
