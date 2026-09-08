#!/usr/bin/env python3
"""Milestone 7: builds the DesiredPolicy JSON blob that
phase3/nftables-manager reads directly from the shared SQLite database
-- following this project's own established "one shared database, live
reads, no separate sync" pattern (see docs/project.md's Key technical
decisions) rather than inventing a new controller<->nftables-manager
IPC protocol.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from policy_class import PolicyClass, bump_eligible, classify_device, to_set_name
from schedule_eval import is_full_lockout_active

# The nftables-manager side's fifth, independent set (policy.SetBump) --
# not one of PolicyClass's four mutually-exclusive values, so it isn't
# in to_set_name()'s table. Kept here, next to the JSON key literals
# this module already owns, rather than in policy_class.py, since
# policy_class.py's to_set_name() contract is specifically "PolicyClass
# -> set name" and bump isn't a PolicyClass.
_BUMP_SET_NAME = "bump"


def compute_desired_policy(
    conn: sqlite3.Connection, now: datetime | None = None
) -> dict[str, list[str]]:
    """One entry per PolicyClass's nftables set name, each holding the
    IPv4 addresses of every device currently classified into it, PLUS
    an independent `"bump"` entry (RoadMap.md's "two independent axes"
    section, locked 2026-08-30) for devices with bump_eligible() true.
    An IP can legitimately appear in both `"authenticated"` and
    `"bump"` at once -- bump is a refinement layered on top of
    authenticated access, not a fifth exclusive class, so it is
    computed independently rather than via classify_device().

    A device with more than one simultaneously-active binding (see
    common/identity.py's own notes on how that can briefly happen)
    contributes each of its active IPs -- unlike
    controller/desired_state.py's ARP-poisoning target list, there's no
    reason to pick only the freshest one here: every IP currently
    routed through this device's identity should get that device's
    policy. Devices with no active binding contribute nothing -- there's
    no IP to add to any set.

    **Phase 8 (2026-08-31)**: `now` (defaults to the current UTC instant;
    tests inject a fixed value) drives a second, independent overlay --
    a device whose classify_device() result ISN'T already BYPASS gets
    reclassified to QUARANTINE if `schedule_eval.is_full_lockout_active()`
    says a `lockout_all` schedule currently targets it. This is a PURE
    computation, same as bump_eligible() above -- it never writes
    `devices.quarantined_at`, so a manual operator quarantine (that
    column) and a scheduled bedtime lockout (this overlay) stay on fully
    independent axes: a device an admin manually quarantined stays
    quarantined regardless of any schedule, and a device under an active
    bedtime schedule returns to its normal classification the moment the
    window ends, with nothing left over to clean up. An already-BYPASS
    (`ignored`) device is never overridden -- "outside the whole system,
    for good" (common/db.py's own words on that column) includes being
    outside schedules too, matching the same baseline-protection rule
    already applied to AdGuard in controller/adguard_sync.py.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    policy: dict[str, list[str]] = {to_set_name(pc): [] for pc in PolicyClass}
    policy[_BUMP_SET_NAME] = []

    rows = conn.execute(
        """
        SELECT d.id, d.user_id, d.group_id, d.ignored, d.quarantined_at, d.is_authenticated,
               d.bump_enabled, d.bypass_login, COALESCE(g.ignored, 0) AS group_ignored,
               b.ipv4_address
        FROM devices d
        JOIN device_bindings b ON b.device_id = d.id AND b.active = 1
        LEFT JOIN groups g ON g.id = d.group_id
        """
    ).fetchall()

    for row in rows:
        group_ignored = bool(row["group_ignored"])
        policy_class = classify_device(row, group_ignored)
        if policy_class != PolicyClass.BYPASS and is_full_lockout_active(conn, row, now):
            policy_class = PolicyClass.QUARANTINE
        policy[to_set_name(policy_class)].append(row["ipv4_address"])
        # Fixed 2026-09-02, a real bug found by code review:
        # bump_eligible(row) re-derives classify_device(row) internally
        # from the RAW row, blind to the QUARANTINE overlay just applied
        # above -- so a bump-enabled, otherwise-AUTHENTICATED device
        # caught in an active lockout_all schedule used to land in BOTH
        # the quarantine set AND the bump set for this cycle, violating
        # bump_eligible()'s own documented invariant ("never true ...
        # for BYPASS, QUARANTINE, or PREAUTH"). phase3/nftables-manager's
        # resolveBump() does drop the conflicting membership before it
        # reaches the kernel (so this was never an actual filter
        # bypass), but it logged a policy-conflict warning every cycle
        # for as long as the window stayed open, and any FUTURE overlay
        # added the same way would hit the identical trap. Gating on the
        # post-overlay policy_class here, not just the row-derived
        # signal bump_eligible() computes internally, is the fix -- in
        # the normal (no-overlay) case this is a no-op, since
        # bump_eligible() already requires classify_device(row) ==
        # AUTHENTICATED internally, which is exactly what policy_class
        # already equals whenever no overlay fired.
        if policy_class == PolicyClass.AUTHENTICATED and bump_eligible(row, group_ignored):
            policy[_BUMP_SET_NAME].append(row["ipv4_address"])

    for ips in policy.values():
        ips.sort()

    return policy


def write_desired_policy(conn: sqlite3.Connection, policy: dict[str, list[str]]) -> None:
    """Persists the computed policy into interception_runtime's
    singleton row (upserting it into existence on first write --
    interception_runtime has no seed row in db.py's SCHEMA)."""
    payload = json.dumps(policy, sort_keys=True)
    conn.execute(
        "INSERT INTO interception_runtime (singleton_id, desired_policy_json) VALUES (1, ?) "
        "ON CONFLICT(singleton_id) DO UPDATE SET desired_policy_json = excluded.desired_policy_json",
        (payload,),
    )
    conn.commit()
