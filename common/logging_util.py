#!/usr/bin/env python3
"""Access-log writer, shared by the SNI and HTTP-layer authz helpers.

Dedupes: the same (username, domain, allowed, series_id, path) combination
is only logged once per DEDUPE_WINDOW_SECONDS, so one browsing session
doesn't produce dozens of near-identical rows (repeated TLS connections,
page assets, polling requests, etc). The reporting page stays readable, and
"who accessed what and when" still reflects genuinely new activity.

`path` is compared with its query string stripped (GH #5): two requests to
the same page that only differ by a cache-busting or session query
parameter count as the same dedupe entry, but two genuinely different
pages on the same domain each get their own row -- previously `path` was
not part of the key at all, so a bump-mode domain visited normally (many
pages within the window, the common case) only ever showed its first page
in the Report. This also means a path-less entry (e.g. the SNI layer,
which never has a path since nothing is decrypted there) and a later
path-bearing entry for what's otherwise the same event are different keys
too, so a richer entry is never hidden behind an earlier, less
informative one for the same window.
"""
from __future__ import annotations

import sqlite3

from db import iso_secs_ago, now_iso

DEDUPE_WINDOW_SECONDS = 5 * 60


def log_access(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    username: str,
    domain: str,
    path: str | None,
    allowed: bool,
    reason: str,
    series_id: str | None = None,
    series_name: str | None = None,
    device_id: int | None = None,
    ip_address: str | None = None,
) -> None:
    """device_id (added 2026-08-31, see RoadMap.md's dated entry): which
    `devices` row made this request, when known -- lets the Report page
    filter/act on a row by device or group even when it has no user_id at
    all (a group- or device-assigned identity, see
    common/matching.py's device_domain_reason()). Deliberately NOT part of
    the dedupe key below -- two devices sharing one username (not possible
    today, but kept simple) or a device's IP moving between requests within
    the dedupe window should still collapse the same way it always has;
    device_id is purely a stored column on whichever row wins the dedupe
    check, not a new dimension of "is this a new event".

    ip_address (added 2026-09-07, RoadMap.md's dated entry): the raw
    source IP, independent of whether device_id resolved to anything --
    real live-testing feedback was that a row for a genuinely never-seen
    device gave an admin nothing to track it down by. Optional and
    defaults to None so every existing caller keeps working unchanged;
    not yet threaded through every call site (see common/db.py's own
    schema comment for which ones currently pass it). Same "descriptive
    metadata on the row, not a new dedupe dimension" treatment as
    device_id -- a device's IP moving between requests within the dedupe
    window still collapses the same way it always has.
    """
    cutoff_iso = iso_secs_ago(DEDUPE_WINDOW_SECONDS)
    # series_id is part of the dedupe key (SQLite's `IS` is null-safe, so two
    # NULLs still match) so two different blocked shows on the same domain
    # each get their own row instead of collapsing into one. `path` is
    # compared query-string-stripped, computed in SQL for the stored value
    # (instr/substr are built into SQLite) and in Python for the incoming
    # one, so both sides normalize the same way.
    normalized_path = path.split("?", 1)[0] if path is not None else None
    recent = conn.execute(
        "SELECT 1 FROM access_log "
        "WHERE username = ? AND domain = ? AND allowed = ? AND ts >= ? "
        "AND series_id IS ? "
        "AND (CASE WHEN instr(path, '?') > 0 THEN substr(path, 1, instr(path, '?') - 1) ELSE path END) IS ? "
        "LIMIT 1",
        (username, domain, 1 if allowed else 0, cutoff_iso, series_id, normalized_path),
    ).fetchone()
    if recent is not None:
        return
    conn.execute(
        "INSERT INTO access_log "
        "(ts, user_id, username, domain, path, series_id, series_name, allowed, reason, device_id, ip_address) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            now_iso(),
            user_id,
            username,
            domain,
            path,
            series_id,
            series_name,
            1 if allowed else 0,
            reason,
            device_id,
            ip_address,
        ),
    )
