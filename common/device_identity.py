#!/usr/bin/env python3
"""Device-based identity resolution for Squid's intercept mode.

Replaces %LOGIN (Squid's per-request Basic-Auth challenge via
`proxy_auth`) as the identity signal the SNI/authz helper scripts key
their decisions on: an intercepted connection has no CONNECT handshake
for Squid to answer a 407 challenge with, so per-request login is gone
entirely -- the client's own source IP (`%>a`, still available to an
intercepted connection) is the only identity signal left. Resolving it
means reusing the exact same device_bindings data the DNS tier's own
identity model already relies on (see common/identity.py), rather than
inventing a second, proxy-specific identity mechanism.

Used by both proxy/sni_helper.py and proxy/authz_helper.py, replacing
each of their previous `login` parameters.
"""
from __future__ import annotations

import sqlite3

import db
import identity


def resolve_user_for_device(conn: sqlite3.Connection, device: sqlite3.Row | None) -> sqlite3.Row | None:
    """The `users` row for `device`'s own user_id, or None if the device
    itself is None, has no user_id at all (unassigned), or is assigned to
    a group instead of a person -- a group/device-only assignment is still
    a real, enforceable identity (see common/matching.py's
    device_domain_reason()), it just has no single `users` row of its own.

    Callers resolve the *device* first via resolve_device() below (which
    matches on device_bindings alone, with no blind spot for a
    group-assigned device) and pass it here separately, so "no user" and
    "no identity at all" are never conflated: a group/device-only
    assignment must not read as "deny everything" just because there's
    no single `users` row.
    """
    if device is None or device["user_id"] is None:
        return None
    return conn.execute("SELECT * FROM users WHERE id = ?", (device["user_id"],)).fetchone()


def log_identity_fields(
    device: sqlite3.Row | None, user: sqlite3.Row | None
) -> tuple[int | None, str, int | None]:
    """(user_id, username, device_id) for logging_util.log_access(), in
    priority order: a real resolved user; else the device's own label (or
    MAC address if unlabeled, matching how the dashboard's device
    comboboxes already display an unlabeled device -- see dashboard.py's
    _entity_combo) as a synthetic username, with device_id set so the
    Report page can still filter/act on this row by device or group even
    with no user_id; else the pre-existing "(unauthenticated)" placeholder,
    unchanged, for the genuinely-never-seen case (device itself is None --
    no active device_bindings row at all)."""
    if user is not None:
        return user["id"], user["username"], (device["id"] if device is not None else None)
    if device is not None:
        return None, device["label"] or device["mac_address"], device["id"]
    return None, "(unauthenticated)", None


def resolve_device(conn: sqlite3.Connection, client_ip: str) -> sqlite3.Row | None:
    """The `devices` row for whoever currently holds this source IP, or
    None if there's no active device_bindings row for it at all.

    Unlike resolve_user_for_device() above, this resolves straight from
    client_ip (not from an already-resolved device), and returns the
    device itself regardless of whether it has a user_id assigned --
    dashboard/captive_portal_server.py needs the device_id itself to
    actually grant access (flipping is_authenticated), not just
    whichever user, if any, already owns it.

    Self-healing for orphaned bindings: deleting a device leaves its
    `device_bindings` row orphaned (`device_id` NULL via `ON DELETE SET
    NULL`, not deleted -- see db.py's own schema comment), and that
    binding's still-active device can keep generating traffic. An
    orphaned-but-currently-active binding for `client_ip` gets a fresh
    PREAUTH `devices` row via `identity.create_pending_device()` -- the
    exact same defaults a genuinely-new MAC gets -- and every
    `device_bindings` row for that MAC (not just this one IP) is
    repointed at it, so this only happens once per deleted device, not
    on every single request. Deliberately calls
    `create_pending_device()` directly rather than going through
    `record_binding()`'s own `_mac_has_any_prior_binding()` gate: that
    gate exists specifically to block *passive* background binding
    refreshes from reviving a deleted device, which does not describe
    this call site -- reaching here means a real HTTP request (a login
    attempt, an admin action, an intercepted connection) is actively in
    flight for this exact device right now.

    Two near-simultaneous requests for the same orphaned IP (plausible
    -- sni_helper.py/authz_helper.py both resolve identity for one
    connection, and captive_portal_server.py/block_page_server.py do
    too for portal loads) could otherwise both see the same orphaned row
    before either wrote and both call `create_pending_device()`, racing
    an `INSERT` into `devices(mac_address, ...)` (mac_address is
    UNIQUE). `BEGIN IMMEDIATE` acquires SQLite's write lock up front,
    and the healed-row check is repeated once inside it -- a concurrent
    caller that already healed this MAC while we waited for the lock is
    picked up here instead of racing a second INSERT.
    """
    row = conn.execute(
        """
        SELECT d.* FROM device_bindings b
        JOIN devices d ON d.id = b.device_id
        WHERE b.ipv4_address = ? AND b.active = 1
        ORDER BY b.last_seen_at DESC LIMIT 1
        """,
        (client_ip,),
    ).fetchone()
    if row is not None:
        return row

    orphaned = conn.execute(
        "SELECT mac_address FROM device_bindings WHERE ipv4_address = ? AND active = 1 AND device_id IS NULL "
        "ORDER BY last_seen_at DESC LIMIT 1",
        (client_ip,),
    ).fetchone()
    if orphaned is None:
        return None

    conn.execute("BEGIN IMMEDIATE")
    try:
        # Re-check under the write lock: another concurrent caller may
        # have already healed this exact MAC between our unlocked SELECT
        # above and acquiring the lock here.
        healed = conn.execute(
            "SELECT d.* FROM device_bindings b JOIN devices d ON d.id = b.device_id "
            "WHERE b.mac_address = ? AND b.device_id IS NOT NULL LIMIT 1",
            (orphaned["mac_address"],),
        ).fetchone()
        if healed is None:
            device_id = identity.create_pending_device(conn, orphaned["mac_address"], db.now_iso())
            conn.execute(
                "UPDATE device_bindings SET device_id = ? WHERE mac_address = ? AND device_id IS NULL",
                (device_id, orphaned["mac_address"]),
            )
        else:
            device_id = healed["id"]
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()
    return conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
