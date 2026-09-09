#!/usr/bin/env python3
"""Phase 3 identity model (Milestone 4): recording observed MAC<->IPv4
bindings and the network/identity event log that feeds them.

See db.py's device_bindings/network_events schema comments and
docs/design/phase3-technical-design.md section 7 for the design this
implements. This module's own claim used to end here saying "nothing in
the proxy/dashboard enforcement path reads any of this yet" -- corrected
2026-09-09, since that stopped being true a long time ago:
common/device_identity.py's resolve_device()/resolve_user_for_device()
(used by every proxy helper and the dashboard's own Report page) both
read device_bindings directly, and controller/desired_state.py has been
a real, running consumer since the interception profile shipped.
"""
from __future__ import annotations

import json
import sqlite3

import db
import system_events


def record_binding(
    conn: sqlite3.Connection,
    mac_address: str,
    ipv4_address: str,
    source: str,
    seen_at: str | None = None,
    confidence: float = 1.0,
) -> None:
    """Record one MAC<->IP observation.

    Idempotent for a repeated (mac, ip) pair -- just bumps last_seen_at.
    Handles the two conflict shapes the v2 roadmap's "MAC/IP conflict
    handling" requirement calls for, deactivating whichever prior
    binding is now stale and logging a network_events row for each:

      - IP reassigned: this ipv4_address was actively bound to a
        DIFFERENT mac_address (e.g. a departed device's DHCP lease
        reused by a new one).
      - Device moved: this mac_address was actively bound to a
        DIFFERENT ipv4_address (e.g. a normal DHCP lease renewal).

    Reuses whatever device_id (if any) an existing binding for the same
    mac_address already carries, or a `devices` row whose mac_address
    already matches -- this is never a heuristic guess (hostname/vendor
    matching, which the roadmap's "never auto-merge devices solely by
    hostname/vendor" rule forbids), only an exact mac_address match.

    **Phase 4 addition, 2026-08-31**: a MAC this function has genuinely
    NEVER seen before (no `devices` row, and no `device_bindings` row
    of any kind -- active or inactive -- has ever existed for it
    either) gets a brand-new, unassociated `devices` row auto-created
    for it (`is_authenticated = 0`, `ignored = 0`, no `user_id`) rather
    than being left with a dangling `device_id = NULL` binding
    requiring a human to notice and manually associate it. This closes
    a real gap `controller/desired_state.py`'s own docstring didn't
    used to have to think about: a `device_id = NULL` binding is
    invisible to that module's `JOIN`, so a brand-new device previously
    got NO interception of any kind (full, unfiltered access) until
    someone happened to visit the dashboard and create it manually --
    the opposite of Phase 4's "gate any newly-seen MAC by default."
    `is_authenticated = 0` (not the `devices` table's own schema
    default of `1`) is deliberate: that default exists for a device an
    admin creates directly through today's dashboard (an admin manually
    adding a device already implies trust), not for a MAC nobody has
    looked at yet -- see `common/policy_class.py`'s `classify_device()`,
    which puts a device with `is_authenticated = 0` into `PREAUTH`.

    This auto-create only ever fires the FIRST time a given MAC is ever
    recorded -- once any `device_bindings` row exists for a MAC (even
    an inactive, long-superseded one), this function never auto-creates
    a `devices` row for it again, so an already-known-but-unassociated
    device from before this feature shipped is deliberately left alone
    (per an explicit 2026-08-31 product decision: no retroactive
    backfill, only newly-observed MACs going forward) even across a
    later DHCP renewal.
    """
    seen_at = seen_at or db.now_iso()

    # Wrapped in an explicit transaction (fixed 2026-09-02, a real race
    # found by code review): every statement in _record_binding_locked()
    # below used to run as its own independent autocommit (common/db.py
    # opens connections with isolation_level=None), so two
    # near-simultaneous record_binding() calls for the same IP with
    # different MACs (plausible: the rtnetlink listener and a periodic
    # discovery snapshot both observing at once) could each read "no
    # active conflict" before either wrote its own INSERT, leaving TWO
    # active=1 device_bindings rows for the same IP --
    # device_identity.resolve_device()'s `ORDER BY last_seen_at DESC
    # LIMIT 1` would then pick one nondeterministically, attributing
    # traffic to the wrong device. `BEGIN IMMEDIATE` acquires SQLite's
    # write lock up front (not deferred to the first write inside), so
    # a second concurrent caller blocks here for the whole check-then-
    # act sequence rather than racing it -- relying on db.get_conn()'s
    # own `busy_timeout=5000` to wait rather than fail outright.
    conn.execute("BEGIN IMMEDIATE")
    try:
        _record_binding_locked(conn, mac_address, ipv4_address, source, seen_at, confidence)
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def _record_binding_locked(
    conn: sqlite3.Connection,
    mac_address: str,
    ipv4_address: str,
    source: str,
    seen_at: str,
    confidence: float,
) -> None:
    """The actual body of record_binding() -- assumed to already be
    running inside the BEGIN IMMEDIATE transaction that function opens,
    so every early `return` here is safe: the caller commits (or, on an
    exception, rolls back) uniformly regardless of how this exits."""
    existing = conn.execute(
        "SELECT id FROM device_bindings WHERE mac_address = ? AND ipv4_address = ?",
        (mac_address, ipv4_address),
    ).fetchone()
    if existing is not None:
        conn.execute(
            "UPDATE device_bindings SET last_seen_at = ?, source = ?, confidence = ?, active = 1 "
            "WHERE id = ?",
            (seen_at, source, confidence, existing["id"]),
        )
        return

    # Conflict 1: someone else currently holds this IP.
    ip_conflict = conn.execute(
        "SELECT id, mac_address, device_id FROM device_bindings "
        "WHERE ipv4_address = ? AND active = 1",
        (ipv4_address,),
    ).fetchone()
    if ip_conflict is not None:
        conn.execute("UPDATE device_bindings SET active = 0 WHERE id = ?", (ip_conflict["id"],))
        _record_event(
            conn,
            "ip_reassigned",
            device_id=ip_conflict["device_id"],
            mac_address=ip_conflict["mac_address"],
            ipv4_address=ipv4_address,
            source=source,
            observed_at=seen_at,
            payload={"new_mac_address": mac_address},
        )

    # Conflict 2: this MAC currently holds a different IP.
    mac_conflict = conn.execute(
        "SELECT id, ipv4_address, device_id FROM device_bindings "
        "WHERE mac_address = ? AND active = 1",
        (mac_address,),
    ).fetchone()
    device_id = mac_conflict["device_id"] if mac_conflict is not None else None
    if mac_conflict is not None and mac_conflict["ipv4_address"] != ipv4_address:
        conn.execute("UPDATE device_bindings SET active = 0 WHERE id = ?", (mac_conflict["id"],))
        _record_event(
            conn,
            "ip_changed",
            device_id=device_id,
            mac_address=mac_address,
            ipv4_address=mac_conflict["ipv4_address"],
            source=source,
            observed_at=seen_at,
            payload={"new_ipv4_address": ipv4_address},
        )

    if device_id is None:
        device_id = _existing_device_id_for_mac(conn, mac_address)

    auto_created = False
    if device_id is None and not _mac_has_any_prior_binding(conn, mac_address):
        # Genuinely never seen before -- see this function's own
        # docstring for why this is the one case that auto-creates a
        # devices row, and why an already-known-but-unassociated MAC
        # (any prior binding at all, even inactive) deliberately does
        # NOT hit this path.
        device_id = _create_pending_device(conn, mac_address, seen_at)
        auto_created = True

    conn.execute(
        "INSERT INTO device_bindings "
        "(device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, source, confidence, active) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
        (device_id, mac_address, ipv4_address, seen_at, seen_at, source, confidence),
    )
    if auto_created:
        _record_event(
            conn,
            "device_auto_created",
            device_id=device_id,
            mac_address=mac_address,
            ipv4_address=ipv4_address,
            source=source,
            observed_at=seen_at,
            payload=None,
        )
        # Fixed 2026-09-09, real gap found live investigating "why
        # doesn't the network sweep show anything on the Events page":
        # this auto-create was already recorded in network_events (see
        # above), but that table has no dashboard page of its own --
        # only this project's own DB-level tooling ever reads it. A
        # brand-new device appearing for the first time is exactly the
        # kind of rare, admin-relevant moment system_events.py's own
        # 'info' severity exists for (see its docstring) -- and
        # deliberately NOT tied to source == 'sweep' specifically: any
        # discovery path (passive rtnetlink, the periodic snapshot, or
        # the active sweep) finding a genuinely new device is equally
        # worth surfacing, so this fires the same way regardless of
        # which one actually triggered the kernel to notice it.
        system_events.log_event(
            conn, "device_discovery", "info",
            f"New device discovered: {mac_address} ({ipv4_address}), via {source}.",
        )
    elif device_id is None:
        _record_event(
            conn,
            "binding_pending_association",
            device_id=None,
            mac_address=mac_address,
            ipv4_address=ipv4_address,
            source=source,
            observed_at=seen_at,
            payload=None,
        )


def _existing_device_id_for_mac(conn: sqlite3.Connection, mac_address: str) -> int | None:
    row = conn.execute("SELECT id FROM devices WHERE mac_address = ?", (mac_address,)).fetchone()
    return row["id"] if row is not None else None


def _mac_has_any_prior_binding(conn: sqlite3.Connection, mac_address: str) -> bool:
    """Whether ANY device_bindings row -- active or inactive -- has ever
    existed for this mac_address. Deliberately broader than the
    active=1 check record_binding() already does for its own conflict
    handling above: this is what makes the auto-create-a-devices-row
    behavior a one-time, first-observation-only thing rather than
    something that could fire again later (e.g. on a DHCP renewal) for
    a MAC that was already known before this feature shipped, per the
    explicit "new MACs only, no retroactive backfill" product decision.
    """
    return (
        conn.execute(
            "SELECT 1 FROM device_bindings WHERE mac_address = ? LIMIT 1", (mac_address,)
        ).fetchone()
        is not None
    )


def _create_pending_device(conn: sqlite3.Connection, mac_address: str, seen_at: str) -> int:
    """Auto-creates a brand-new, unassociated `devices` row for a MAC
    genuinely never seen before -- see record_binding()'s own docstring
    for the full reasoning. `is_authenticated = 0` deliberately
    overrides the `devices` table's own schema default of `1`.
    """
    cur = conn.execute(
        "INSERT INTO devices (mac_address, is_authenticated, ignored, created_at) "
        "VALUES (?, 0, 0, ?)",
        (mac_address, seen_at),
    )
    return cur.lastrowid


def active_binding_ip(conn: sqlite3.Connection, device_id: int) -> str | None:
    """The most-recently-seen active IPv4 address bound to device_id, or
    None if it has no active binding right now."""
    row = conn.execute(
        "SELECT ipv4_address FROM device_bindings "
        "WHERE device_id = ? AND active = 1 ORDER BY last_seen_at DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    return row["ipv4_address"] if row is not None else None


def touch_binding_by_ip(
    conn: sqlite3.Connection,
    ipv4_address: str,
    seen_at: str,
    source: str = "adguard",
) -> bool:
    """Refreshes last_seen_at for the currently-ACTIVE device_bindings
    row for this IP -- WITHOUT creating a new binding and WITHOUT
    touching its mac_address/device_id/confidence -- for sources that
    only ever observe an IP, never a MAC (AdGuard's query log is the
    only caller today: DNS queries carry no link-layer information), so
    they can never discover a brand-new binding on their own, only
    confirm an already-known one is still actively in use (RoadMap.md's
    discovery precedence: "AdGuard query-log observations (confirms
    active IP usage)"). Contrast with record_binding above, which
    always has a MAC and can create/reassign bindings.

    Only updates if `seen_at` is strictly newer than the binding's
    current last_seen_at -- a page of query-log history can include
    entries a previous poll already accounted for, and this must never
    regress last_seen_at backward. Callers must pass `seen_at` already
    normalized to this project's own db.now_iso() format (see
    common/adguard_client.py's normalize_query_log_time) -- comparing
    differently-shaped ISO8601 timestamps as plain strings is unsafe.

    Returns whether it actually updated anything (no active binding for
    this IP at all, or seen_at wasn't newer, both return False) -- purely
    informational for the caller's own logging/counting, not required
    for correctness.
    """
    row = conn.execute(
        "SELECT id, last_seen_at FROM device_bindings WHERE ipv4_address = ? AND active = 1",
        (ipv4_address,),
    ).fetchone()
    if row is None or seen_at <= row["last_seen_at"]:
        return False
    conn.execute(
        "UPDATE device_bindings SET last_seen_at = ?, source = ? WHERE id = ?",
        (seen_at, source, row["id"]),
    )
    return True


def record_network_event(
    conn: sqlite3.Connection,
    event_type: str,
    *,
    device_id: int | None = None,
    mac_address: str | None = None,
    ipv4_address: str | None = None,
    source: str = "unknown",
    observed_at: str | None = None,
    payload: dict | None = None,
) -> None:
    """Public entry point for callers (e.g. a future discovery daemon)
    to log a network/identity event directly, distinct from the
    conflict events record_binding() logs on its own."""
    _record_event(
        conn,
        event_type,
        device_id=device_id,
        mac_address=mac_address,
        ipv4_address=ipv4_address,
        source=source,
        observed_at=observed_at or db.now_iso(),
        payload=payload,
    )


def _record_event(
    conn: sqlite3.Connection,
    event_type: str,
    *,
    device_id: int | None,
    mac_address: str | None,
    ipv4_address: str | None,
    source: str,
    observed_at: str,
    payload: dict | None,
) -> None:
    conn.execute(
        "INSERT INTO network_events "
        "(event_type, device_id, mac_address, ipv4_address, source, observed_at, payload_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            event_type,
            device_id,
            mac_address,
            ipv4_address,
            source,
            observed_at,
            json.dumps(payload) if payload is not None else None,
        ),
    )
