#!/usr/bin/env python3
"""Reads AdGuard Home's own query log and back-fills the Report page's
`access_log` with the DNS-tier hard-denies that never otherwise reach a
logging call at all.

**The gap this closes (RoadMap.md's dated entry, 2026-09-09):** when
`controller/adguard_sync.py` hard-denies a domain, it does so with an
AdGuard custom rule carrying `$dnsrewrite=NOERROR;A;<block_page_ip>` --
the queried name resolves to this box's own IP so `block_page_server.py`
can show a friendly page. That works for plain HTTP (port 80): the
device's request lands on `block_page_server.py`'s real listener, which
calls `logging_util.log_access()`, and the block shows up on the Report
page. It does NOT work for HTTPS (port 443): nothing listens there by
`block_page_server.py`'s own deliberate design (no cert this project's CA
can present that an arbitrary domain's device already trusts), so the
connection is simply refused -- and since nothing ever accepts it,
nothing ever calls `log_access()`, so the block is invisible on the
Report page even though it worked. That blind spot is the same for every
device, bump-enabled or not.

**The fix, at the layer where the block is actually decided:** AdGuard's
own query log records every DNS query it answers, including the ones it
served from one of this project's own `$dnsrewrite` rules. This module
polls that log, and for every entry whose answer is `block_page_ip` AND
whose queried name is a domain/category this project currently manages
(so an admin's own unrelated AdGuard rewrite to the same IP is never
misattributed), writes one `access_log` "blocked" row via the exact same
`logging_util.log_access()` every other block path already uses -- same
table, same 5-minute dedupe, so the Report page needs no changes at all.

**Why it lives in `dashboard/` (always-on), not `controller/`:**
`controller` only runs under the `interception` profile, which is off
for most of this box's real operating time (Bark Home usually has the
network). The AdGuard rules themselves persist in AdGuard's own config
regardless of whether `controller` is currently running, so the blocks
keep happening -- this poller has to be somewhere that's always up to
observe them. `dashboard` already starts `block_page_server.py` and
`captive_portal_server.py` as background components at boot; this is one
more, gated behind the same `DASHBOARD_URL` check `block_page_server`
already uses (no block-page IP configured -> nothing to correlate).

**The second gap this closes (RoadMap.md finding #9, 2026-09-10):** a
normal authenticated device that is neither SSL-Bump-enabled nor hitting
a blocked category produced ZERO Report rows at all -- Squid only ever
sees `bump_v4` devices, and the hard-deny back-fill above only fires on
an actual block. `correlate_once()` below also back-fills one `allowed`
row per querylog entry that resolves to a device this project tracks,
using the SAME `logging_util.log_access()` 5-minute rolling dedupe every
other writer relies on -- just keyed on a deliberately coarse "site" (see
`_dedupe_site_key()`) rather than the exact queried name, so a page that
fans out to a dozen subdomains of the same site collapses to one row
instead of a dozen. Tagged `reason="dns_tier_allowed"` and hidden by
default on the Report page (a "Show routine DNS-tier activity" toggle
reveals them) since they're expected to vastly outnumber every other
reason code -- they're routine browsing, not something needing review.
`prune_allowed_rows()` deletes them past a 30-day retention window so
this ordinary-traffic sampling doesn't grow `access_log` without bound
the way a real block (rare, and worth keeping indefinitely) should not
be pruned.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time

import adguard_client
import db
import device_identity
import logging_util
import matching

log = logging.getLogger("dashboard.adguard_report_sync")

# The reason string stamped on every hard-deny row this module writes.
# Deliberately distinct from the SNI/authz helpers' own vocabulary
# ("domain_not_assigned", "unconfigured_domain", ...) -- this block
# happened purely at the DNS tier, before (or instead of) Squid ever
# seeing the connection, and the Report page just renders the string.
_REASON = "dns_hard_deny"

# The reason string stamped on every routine-allowed row this module
# writes (finding #9). Distinct from block_page_server.py's
# "dns_tier_denied" and this module's own "dns_hard_deny" above -- this
# is the ALLOWED half of DNS-tier visibility, not a block of any kind.
_ALLOWED_REASON = "dns_tier_allowed"

# How long an allowed-traffic sample row survives before
# prune_allowed_rows() deletes it. Unlike an actual block (rare, and
# worth keeping indefinitely for review), this is routine browsing
# noise sampled purely so the Report page has SOMETHING to show for a
# non-bump device -- unbounded retention would grow access_log forever
# for no benefit past a few weeks of "what has this device been doing"
# review. Chosen 2026-09-10 (RoadMap.md finding #9): the project owner's
# call, weighed against 7/90-day alternatives.
_ALLOWED_RETENTION_DAYS = 30

# prune_allowed_rows() only needs to run occasionally -- access_log has
# no per-row expiry trigger, and a 30-day retention window doesn't need
# sub-hourly enforcement. Checked once per start()-loop iteration against
# a locally-held "last pruned at" wall-clock time (not persisted --
# see start()'s own comment on why that's fine for a best-effort job).
_PRUNE_INTERVAL_SECONDS = 60 * 60

# Setting key holding the newest querylog timestamp already scanned, so a
# restart (or a slow cycle) doesn't re-walk the same entries forever.
# log_access()'s own dedupe would absorb the duplicate writes anyway --
# this is purely to bound the work, same "soft freshness signal" posture
# as controller/adguard_discovery.py's own querylog poll. AdGuard
# timestamps are truncated to whole seconds (normalize_query_log_time),
# so a block sharing its exact second with the previous poll's newest
# entry can be skipped -- an acceptable, rare gap for a best-effort
# Report back-fill, same tolerance adguard_discovery.py documents.
_WATERMARK_SETTING = "adguard_report_sync_watermark"

# One page per poll. Matches adguard_discovery.py's own fixed-page
# approach: missing entries inside a single burst larger than this
# between two polls is an acceptable gap for a best-effort Report
# back-fill, not a correctness hole.
_QUERYLOG_LIMIT = 200

DEFAULT_INTERVAL_SECONDS = 15.0


def _entry_hostname(entry: dict) -> str | None:
    question = entry.get("question")
    if not isinstance(question, dict):
        return None
    name = question.get("name")
    if not isinstance(name, str):
        return None
    name = name.strip().rstrip(".").lower()
    return name or None


def _answer_is_block_page(entry: dict, block_page_ip: str) -> bool:
    """True if any A-record in this entry's answer is `block_page_ip` --
    i.e. AdGuard served this query from a rule pointing at our block
    page. AdGuard's `answer` is a list of {type,value,ttl} dicts (or
    absent/None for NXDOMAIN-style results); anything unexpected is
    treated as "not a block-page answer", never an error."""
    answer = entry.get("answer")
    if not isinstance(answer, list):
        return False
    for record in answer:
        if not isinstance(record, dict):
            continue
        if record.get("type") == "A" and record.get("value") == block_page_ip:
            return True
    return False


def _entry_resolved(entry: dict) -> bool:
    """True if this querylog entry got a real answer back (at least one
    record) -- as opposed to NXDOMAIN/SERVFAIL/an empty response. Used to
    keep the allowed-traffic back-fill to genuine successful lookups, not
    every failed/mistyped query a device happens to make."""
    answer = entry.get("answer")
    return isinstance(answer, list) and len(answer) > 0


def _dedupe_site_key(hostname: str) -> str:
    """Coarse "site" grouping for the allowed-traffic back-fill's dedupe
    key -- deliberately NOT a real public-suffix-aware registrable-domain
    computation (this project has no PSL dependency, and common/ modules
    stay stdlib-only, see common/auth.py's own docstring on why). Takes
    the last two dot-separated labels (`www.crunchyroll.com` ->
    `crunchyroll.com`, `static.cdn.example.org` -> `example.org`), which
    is wrong for a handful of multi-part public suffixes (`foo.co.uk` ->
    `co.uk`) but harmless here: this key only decides how many rows one
    site's traffic can write to a best-effort Report sample within
    log_access()'s existing 5-minute dedupe window, never an enforcement
    decision -- matching.find_domain()'s anchored-suffix regex is what
    actually decides policy, completely unaffected by this."""
    labels = hostname.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname


def _is_managed_hard_deny(conn: sqlite3.Connection, hostname: str) -> bool:
    """Whether `hostname` is something THIS project would currently
    hard-deny -- a `mode='bump'`/`'splice'` domain, or a domain in any
    category. Guards against attributing an admin's own unrelated AdGuard
    Rewrites-list entry (which could point anywhere, including this box's
    own IP) to this project. Deliberately a coarse membership check, not
    a re-derivation of `adguard_sync.py`'s full per-device/per-schedule
    scoping: the querylog answer already IS `block_page_ip` for this
    specific client, which only happens when one of our own
    `$client`-scoped (or global) rules matched it -- this check just
    confirms the domain is ours to claim at all."""
    domain = matching.find_domain(conn, hostname)
    if domain is not None and domain["mode"] in ("bump", "splice"):
        return True
    return bool(matching.find_categories_for_hostname(conn, hostname))


def correlate_once(
    conn: sqlite3.Connection,
    base_url: str,
    username: str,
    password: str,
    block_page_ip: str,
    *,
    limit: int = _QUERYLOG_LIMIT,
) -> int:
    """Scans the most recent querylog page and writes an `access_log` row
    for each entry that's newer than the stored watermark and is either
    one of this project's own DNS-tier hard-denies ("blocked", finding
    #25) or a genuine successful lookup from a device this project
    tracks ("allowed", finding #9 -- see module docstring).

    Returns the number of rows actually written -- 0 is a perfectly
    normal, healthy result when nothing new happened this cycle, and
    `log_access()`'s own 5-minute dedupe legitimately absorbs plenty of
    repeats even when something did. Never raises for a single malformed
    entry; skips it and continues.
    """
    entries = adguard_client.get_query_log(base_url, username, password, limit=limit)
    watermark = db.get_setting(conn, _WATERMARK_SETTING, "")
    newest_seen = watermark
    written = 0

    for entry in entries:
        raw_time = entry.get("time")
        if not isinstance(raw_time, str):
            continue
        try:
            entry_time = adguard_client.normalize_query_log_time(raw_time)
        except adguard_client.AdGuardError:
            continue
        if entry_time > newest_seen:
            newest_seen = entry_time
        if watermark and entry_time <= watermark:
            continue

        hostname = _entry_hostname(entry)
        client_ip = entry.get("client")
        if not hostname or not isinstance(client_ip, str) or not client_ip:
            continue

        if _answer_is_block_page(entry, block_page_ip):
            if not _is_managed_hard_deny(conn, hostname):
                continue
            device = device_identity.resolve_device(conn, client_ip)
            user = device_identity.resolve_user_for_device(conn, device)
            user_id, resolved_username, device_id = device_identity.log_identity_fields(device, user)
            logging_util.log_access(
                conn,
                user_id=user_id,
                username=resolved_username,
                domain=hostname,
                path=None,
                allowed=False,
                reason=_REASON,
                device_id=device_id,
                ip_address=client_ip,
            )
            written += 1
            continue

        # Not one of our own blocks -- only worth a Report row at all if
        # it's a genuine successful lookup (skip NXDOMAIN/SERVFAIL noise)
        # from a device this project actually tracks (skip everything
        # else -- an untracked IP gives an admin nothing to act on here,
        # unlike the hard-deny path above which always has a client_ip to
        # fall back to).
        if not _entry_resolved(entry):
            continue
        device = device_identity.resolve_device(conn, client_ip)
        if device is None:
            continue
        user = device_identity.resolve_user_for_device(conn, device)
        user_id, resolved_username, device_id = device_identity.log_identity_fields(device, user)
        logging_util.log_access(
            conn,
            user_id=user_id,
            username=resolved_username,
            domain=_dedupe_site_key(hostname),
            path=None,
            allowed=True,
            reason=_ALLOWED_REASON,
            device_id=device_id,
            ip_address=client_ip,
        )
        written += 1

    if newest_seen and newest_seen != watermark:
        db.set_setting(conn, _WATERMARK_SETTING, newest_seen)

    return written


def prune_allowed_rows(conn: sqlite3.Connection, *, retention_days: int = _ALLOWED_RETENTION_DAYS) -> int:
    """Deletes `dns_tier_allowed` rows older than `retention_days` --
    keeps the routine-traffic sample from growing access_log without
    bound (see module docstring / RoadMap.md finding #9). Only ever
    touches this module's own `_ALLOWED_REASON` rows -- an actual block
    (dns_hard_deny, dns_tier_denied, or any proxy-tier denial) is never
    pruned by this or anything else. Returns the number of rows deleted.
    """
    cutoff = db.iso_secs_ago(retention_days * 86400)
    cur = conn.execute("DELETE FROM access_log WHERE reason = ? AND ts < ?", (_ALLOWED_REASON, cutoff))
    conn.commit()
    return cur.rowcount


def start(
    interval: float = DEFAULT_INTERVAL_SECONDS,
    stop_event: threading.Event | None = None,
) -> threading.Thread:
    """Starts `correlate_once()` on a fixed interval on its own daemon
    thread, opening its own DB connection lazily on that thread (sqlite3
    connections are single-thread). Returns the thread (already started),
    with the stop `threading.Event` attached as `thread.stop_event` --
    `dashboard.main()` fires and forgets (process lifetime); tests pass
    their own event and set it to end the loop cleanly. Mirrors
    `block_page_server.start()` / `captive_portal_server.start()` in
    shape.

    Resolves AdGuard's URL/credentials fresh from the DB every cycle so an
    admin changing them on the Settings page takes effect without a
    dashboard restart. A cycle that can't reach AdGuard (not up yet on a
    cold boot, credentials not set) is logged and skipped, never fatal --
    this is a best-effort Report back-fill, never load-bearing.

    Also runs prune_allowed_rows() at most once every
    `_PRUNE_INTERVAL_SECONDS`, tracked in a plain local (not persisted to
    the DB) -- a dashboard restart just means the next natural interval
    handles it, which is fine for a 30-day retention window on a
    best-effort sample; not worth a settings row to survive a restart
    that changes nothing about correctness, only which wall-clock minute
    the next prune happens to land on.
    """
    import os

    from optigate_rewrite import parse_block_page_ip

    stop = stop_event or threading.Event()

    def _loop() -> None:
        conn: sqlite3.Connection | None = None
        last_pruned = 0.0
        while not stop.wait(interval):
            try:
                if conn is None:
                    conn = db.get_conn()
                    db.init_db(conn)
                block_page_ip = parse_block_page_ip(os.environ.get("DASHBOARD_URL"))
                if not block_page_ip:
                    continue
                url = db.get_setting(conn, "adguard_url", "")
                username = db.get_setting(conn, "adguard_username", "admin")
                password = db.get_setting(conn, "adguard_password", "")
                if not url or not password:
                    continue
                written = correlate_once(conn, url, username, password, block_page_ip)
                if written:
                    log.info("back-filled %d DNS-tier Report row(s) (blocked + allowed)", written)
                now = time.monotonic()
                if now - last_pruned >= _PRUNE_INTERVAL_SECONDS:
                    pruned = prune_allowed_rows(conn)
                    if pruned:
                        log.info("pruned %d dns_tier_allowed row(s) past the %d-day retention window",
                                  pruned, _ALLOWED_RETENTION_DAYS)
                    last_pruned = now
            except adguard_client.AdGuardError as exc:
                log.info("querylog poll skipped (AdGuard not reachable yet?): %s", exc)
            except Exception:
                log.exception("unexpected error in the AdGuard querylog Report poll -- continuing")

    thread = threading.Thread(target=_loop, name="adguard-report-sync", daemon=True)
    thread.stop_event = stop  # type: ignore[attr-defined]
    thread.start()
    return thread
