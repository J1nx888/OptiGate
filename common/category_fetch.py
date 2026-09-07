#!/usr/bin/env python3
"""Phase 8: fetches each `categories` row's `subscription_url` and
refreshes its `category_domains` rows.

Lives in common/ (not controller/), deliberately -- both
dashboard/dashboard.py's per-category "Sync now" button (an on-demand
call, no background loop) AND controller/main.py's scheduled
`run_loop()` below need this, and the two are separate container images
that each flat-copy common/*.py alongside their own directory's *.py
into ONE shared /app/ (see controller/Dockerfile's own comment on this
layout) -- a same-named file in both common/ and controller/ would
silently collide (whichever COPY ran last would win in each image),
exactly the trap common/adguard_client.py (the REST client, usable from
either image) vs. controller/adguard_sync.py (the scheduling/business
logic on top of it, controller-only since it's the one thing needing
controller/periodic.py) already avoids by the same split. `run_loop()`
below imports `periodic` lazily, INSIDE the function body, not at module
level, for exactly this reason: dashboard.py can safely `import
category_fetch` and call its other functions even though
controller/periodic.py was never copied into the dashboard image --
that import only actually executes if something calls `run_loop()`
itself, which dashboard.py never does.

Own tiny urllib client (`_OPENER`/`_fetch()`), same shape as
common/adguard_client.py's -- deliberately not reusing that module, since
this fetches arbitrary third-party blocklist files (not AdGuard's own
`/control/*` API), a genuinely different concern with its own error type.

Verified live 2026-08-31 that the actual file formats
(common/blocklist_parser.py's own docstring) match what's fetched here.
NOT yet verified: pushing a category's `subscription_url` into AdGuard
Home as one of ITS OWN native filter subscriptions -- see
controller/adguard_sync.py's docstring for why a large category can't go
through this project's own `$client=`-scoped custom rules instead, and
for the caveat on that native-subscription API shape.
"""
from __future__ import annotations

import logging
import re
import sqlite3
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

import db
from blocklist_parser import parse_hostlist

log = logging.getLogger("category_fetch")

DEFAULT_TIMEOUT = 20.0
# Real category lists run large (confirmed live 2026-08-31: the biggest,
# Porn, is ~953K domains / tens of MB as plain text) -- this cap is about
# refusing a runaway/unexpected response, not about the normal case.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024

_OPENER = build_opener(ProxyHandler({}))


class CategoryFetchError(RuntimeError):
    """Raised for any failure fetching or applying a category's
    subscription_url -- unreachable host, non-2xx response, or the size
    cap exceeded. Callers (run_loop below) must treat this the same way
    controller/adguard_sync.py treats an AdGuardError: log it and retry
    next cycle, never crash the process over one bad or slow-to-update
    third-party list."""


def _fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    request = Request(url, headers={"User-Agent": "parental_proxy-category-fetch/1.0"})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            data = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise CategoryFetchError(f"HTTP {exc.code} fetching {url}") from exc
    except URLError as exc:
        raise CategoryFetchError(f"could not reach {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise CategoryFetchError(f"request to {url} timed out") from exc
    if len(data) > MAX_RESPONSE_BYTES:
        raise CategoryFetchError(
            f"{url} exceeded the {MAX_RESPONSE_BYTES}-byte cap -- refusing a possibly-truncated "
            "or unexpectedly huge response"
        )
    return data.decode("utf-8", errors="replace")


def fetch_and_sync_category(conn: sqlite3.Connection, category: sqlite3.Row, timeout: float = DEFAULT_TIMEOUT) -> int:
    """Fetches `category['subscription_url']`, parses it, and replaces
    that category's `source='subscription'` rows with the result --
    `source='manual'` rows are never touched (see common/db.py's
    category_domains comment). Each fetched domain is stored
    `re.escape()`d (see common/blocklist_parser.py's own docstring on why
    that's this caller's job, not the parser's). Returns the number of
    domains fetched. Raises CategoryFetchError if `subscription_url` is
    unset -- callers (run_loop below) should only ever call this for a
    category that has one.
    """
    url = category["subscription_url"]
    if not url:
        raise CategoryFetchError(f"category {category['name']!r} has no subscription_url set")

    text = _fetch(url, timeout=timeout)
    domains = parse_hostlist(text)

    now = db.now_iso()
    # Explicit transaction, fixed 2026-09-07 (RoadMap.md's dated entry) --
    # a real, severe performance bug found live the first time this ever
    # ran against real subscription data at real scale (~953K domains for
    # the largest list): `conn` opens with isolation_level=None
    # (common/db.py), so without this, every single row of the executemany
    # below would autocommit -- and fsync -- individually. What looked
    # like a hang (one sync taking over 20 minutes, then colliding with
    # another writer and raising "database is locked") was actually just
    # hundreds of thousands of separate disk syncs. Same fix shape as
    # common/identity.py's record_binding() -- BEGIN IMMEDIATE acquires
    # the write lock up front rather than deferring to the first write
    # inside, and makes the whole delete+insert+update one atomic unit
    # (a category never ends up with a stale last_synced_at next to a
    # half-replaced domain list if something fails partway through).
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM category_domains WHERE category_id = ? AND source = 'subscription'", (category["id"],))
        conn.executemany(
            "INSERT OR IGNORE INTO category_domains (category_id, pattern, source, created_at) "
            "VALUES (?, ?, 'subscription', ?)",
            [(category["id"], re.escape(domain), now) for domain in domains],
        )
        conn.execute("UPDATE categories SET last_synced_at = ? WHERE id = ?", (now, category["id"]))
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.commit()
    return len(domains)


def sync_all_categories(conn: sqlite3.Connection, timeout: float = DEFAULT_TIMEOUT) -> dict[str, int]:
    """Refreshes every category that has a subscription_url. One
    category's failure (unreachable host, malformed response) is logged
    and skipped -- never aborts the rest, same "one bad source doesn't
    take down the whole cycle" discipline as adguard_sync.py's own
    run_loop. Returns {category_name: domain_count} for the ones that
    succeeded this cycle."""
    results: dict[str, int] = {}
    categories = conn.execute(
        "SELECT * FROM categories WHERE subscription_url IS NOT NULL AND subscription_url != ''"
    ).fetchall()
    for category in categories:
        try:
            results[category["name"]] = fetch_and_sync_category(conn, category, timeout=timeout)
        except CategoryFetchError as exc:
            log.warning("category sync failed for %r: %s", category["name"], exc)
    return results


def run_loop(interval: float, on_error=None, on_success=None):
    """Starts sync_all_categories() running on a fixed interval, on its
    own background thread -- same PeriodicTask shape as
    controller/adguard_sync.py's run_loop() and controller/discovery.py's,
    including the same lazy own-connection-on-the-background-thread
    reasoning (sqlite3.Connection objects are only usable from the thread
    that created them)."""
    from periodic import PeriodicTask

    state: dict[str, sqlite3.Connection] = {}

    def task() -> None:
        conn = state.get("conn")
        if conn is None:
            conn = db.get_conn()
            db.init_db(conn)
            state["conn"] = conn
        sync_all_categories(conn)

    periodic = PeriodicTask(interval, task, on_error=on_error, on_success=on_success, thread_name="category-fetch")
    periodic.start()
    return periodic
