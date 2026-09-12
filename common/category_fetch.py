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

import hashlib
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
    request = Request(url, headers={"User-Agent": "optigate-category-fetch/1.0"})
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


# v2fly/domain-list-community's own "include:<name>" convention (see
# common/blocklist_parser.py's own docstring for the sibling domain:/
# full:/@attribute conventions this shares) -- a line that names another
# file in the SAME directory to pull in wholesale, rather than a domain
# of its own. Confirmed live 2026-09-11: that project's own "category"
# files (e.g. data/category-games, data/category-entertainment) are
# entirely made of these -- zero literal domains -- so fetching one
# directly and handing it straight to parse_hostlist() would silently
# produce zero domains. Deliberately matched generically (not gated on
# the URL being v2fly-specific) since parse_hostlist() already silently
# ignores an include: line either way -- this is a no-op, zero-extra-
# fetch case for any source that never uses the convention.
_INCLUDE_LINE_RE = re.compile(r"^include:(\S+)", re.IGNORECASE)
_INCLUDE_ATTR_RE = re.compile(r"(?:\s+@\S+)+\s*$")

# Refuses to chase an unbounded/malicious include chain -- a category's
# subscription_url is admin-supplied and fetched automatically by an
# unattended background job with no further checks (same SSRF-adjacent
# trust boundary dashboard.py's _validate_subscription_url() already
# documents), so an include graph needs the same "don't trust it to be
# well-behaved" discipline as the response-size cap above. 300
# comfortably covers every real category in v2fly's own catalog (the
# largest confirmed live, category-entertainment, resolves to 156
# files) with headroom, while still refusing a pathological/hostile one.
MAX_INCLUDED_FILES = 300

# Bounds total accumulated text across the WHOLE include chain, not just
# each individual fetch (MAX_RESPONSE_BYTES) or the file count
# (MAX_INCLUDED_FILES) -- found by code review 2026-09-11: those two
# caps alone still allow up to MAX_INCLUDED_FILES * MAX_RESPONSE_BYTES
# (300 * 64 MiB) of Python strings to accumulate in `merged` before
# parse_hostlist() ever runs, risking an OOM kill of the container mid-
# sync. 256 MiB is generous relative to any real category (the biggest
# confirmed live, Porn, is "tens of MB" per this module's own docstring)
# while staying well short of that worst case.
MAX_TOTAL_INCLUDE_BYTES = 256 * 1024 * 1024


def _resolve_includes(
    base_url: str,
    text: str,
    timeout: float,
    _visited: set[str] | None = None,
    _total_bytes: list[int] | None = None,
) -> str:
    """Recursively follows any `include:<name>` lines in `text`,
    fetching each named sibling file (same directory as `base_url`) and
    appending its content, so a caller's later `parse_hostlist()` call
    sees every actual domain line a v2fly-style *category* file's own
    include graph ultimately resolves to -- not just the top-level
    file's own lines (often none at all for one of these).

    `_visited` is a shared set across the whole recursion (seeded with
    `base_url` itself on the outermost call) -- doubles as both the
    cycle guard (a file that includes something already merged in is
    silently skipped, not re-fetched or re-appended) and the
    `MAX_INCLUDED_FILES` accounting. `_total_bytes` is a shared
    one-element mutable list (same "outermost call seeds it" contract
    as `_visited`), tracking bytes accumulated across every fetch in the
    whole recursion tree so far -- see `MAX_TOTAL_INCLUDE_BYTES`'s own
    comment for why the per-file/per-count caps alone aren't enough. An
    include naming an unreachable or malformed file is logged and
    skipped, same "one bad source doesn't abort the whole sync"
    discipline as sync_all_categories() itself -- a partial category
    from a mostly-working include graph is better than none at all.
    """
    if _visited is None:
        _visited = {base_url}
    if _total_bytes is None:
        _total_bytes = [len(text)]
    base_dir = base_url.rsplit("/", 1)[0]
    merged = [text]
    for raw_line in text.splitlines():
        if len(_visited) >= MAX_INCLUDED_FILES:
            log.warning(
                "include chain from %s exceeded the %d-file cap -- stopping early with a partial result",
                base_url, MAX_INCLUDED_FILES,
            )
            break
        if _total_bytes[0] >= MAX_TOTAL_INCLUDE_BYTES:
            log.warning(
                "include chain from %s exceeded the %d-byte aggregate cap -- stopping early with a partial result",
                base_url, MAX_TOTAL_INCLUDE_BYTES,
            )
            break
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        match = _INCLUDE_LINE_RE.match(line)
        if not match:
            continue
        name = _INCLUDE_ATTR_RE.sub("", match.group(1)).strip()
        if not name:
            continue
        sibling_url = f"{base_dir}/{name}"
        if sibling_url in _visited:
            continue
        _visited.add(sibling_url)
        try:
            sibling_text = _fetch(sibling_url, timeout=timeout)
        except CategoryFetchError as exc:
            log.warning("skipping unreachable include %r from %s: %s", name, base_url, exc)
            continue
        _total_bytes[0] += len(sibling_text)
        merged.append(_resolve_includes(sibling_url, sibling_text, timeout, _visited, _total_bytes))
    return "\n".join(merged)


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

    **Skips the actual DELETE+INSERT when nothing changed** (added
    2026-09-12, real gap found by code review): the fetched, parsed
    domain set is hashed (sorted + deduplicated first, so a source that
    just reordered its lines doesn't look "changed") and compared
    against `categories.last_subscription_hash` from the PREVIOUS sync.
    Only a real difference triggers the rewrite -- see
    `category_domains`' own schema comment for why the previous
    always-rewrite behavior was expensive at real scale (the confirmed-
    live "Adult" category alone is ~953K domains). `last_synced_at` is
    still advanced either way: a no-op cycle still successfully checked,
    it just found nothing to apply, and the dashboard's staleness
    display should reflect that this category is actively being kept up
    to date, not that the sync job silently stopped running.
    """
    url = category["subscription_url"]
    if not url:
        raise CategoryFetchError(f"category {category['name']!r} has no subscription_url set")

    text = _fetch(url, timeout=timeout)
    text = _resolve_includes(url, text, timeout=timeout)
    domains = parse_hostlist(text)

    # Sorted + deduplicated -- exactly the set INSERT OR IGNORE ends up
    # storing anyway (category_domains has a UNIQUE(category_id,
    # pattern) constraint), computed once here and reused for both the
    # hash and (below) the actual insert, instead of calling re.escape()
    # a second time per domain.
    patterns = sorted({re.escape(domain) for domain in domains})
    content_hash = hashlib.sha256("\n".join(patterns).encode("utf-8")).hexdigest()

    now = db.now_iso()
    if content_hash == category["last_subscription_hash"]:
        conn.execute("UPDATE categories SET last_synced_at = ? WHERE id = ?", (now, category["id"]))
        conn.commit()
        return len(domains)

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
            [(category["id"], pattern, now) for pattern in patterns],
        )
        conn.execute(
            "UPDATE categories SET last_synced_at = ?, last_subscription_hash = ? WHERE id = ?",
            (now, content_hash, category["id"]),
        )
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
