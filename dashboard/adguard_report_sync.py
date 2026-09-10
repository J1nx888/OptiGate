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

# The reason string stamped on every row this module writes. Deliberately
# distinct from the SNI/authz helpers' own vocabulary
# ("domain_not_assigned", "unconfigured_domain", ...) -- this block
# happened purely at the DNS tier, before (or instead of) Squid ever
# seeing the connection, and the Report page just renders the string.
_REASON = "dns_hard_deny"

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
    """Scans the most recent querylog page and writes an `access_log`
    "blocked" row for each entry that is one of this project's own
    DNS-tier hard-denies and is newer than the stored watermark.

    Returns the number of rows actually written -- 0 is the normal,
    healthy result (most queries are ordinary allowed lookups, and
    `log_access()`'s own 5-minute dedupe legitimately absorbs repeats of
    a block already logged). Never raises for a single malformed entry;
    skips it and continues.
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
        if not _answer_is_block_page(entry, block_page_ip):
            continue
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

    if newest_seen and newest_seen != watermark:
        db.set_setting(conn, _WATERMARK_SETTING, newest_seen)

    return written


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
    """
    import os

    from optigate_rewrite import parse_block_page_ip

    stop = stop_event or threading.Event()

    def _loop() -> None:
        conn: sqlite3.Connection | None = None
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
                    log.info("back-filled %d DNS-tier hard-deny row(s) into the Report log", written)
            except adguard_client.AdGuardError as exc:
                log.info("querylog poll skipped (AdGuard not reachable yet?): %s", exc)
            except Exception:
                log.exception("unexpected error in the AdGuard querylog Report poll -- continuing")

    thread = threading.Thread(target=_loop, name="adguard-report-sync", daemon=True)
    thread.stop_event = stop  # type: ignore[attr-defined]
    thread.start()
    return thread
