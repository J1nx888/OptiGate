#!/usr/bin/env python3
"""The Categories page's "Add category from catalog" search picker
(2026-09-11, project owner's explicit request): "so someone could click
'Add' and select a specific category... provide the bulk of the
categories needed." Rather than an admin having to go find a raw
blocklist URL themselves, this maintains a searchable local catalog of
ready-made subscription sources, sourced from
https://github.com/v2fly/domain-list-community's own `data/category-*`
files (118 of them as of 2026-09-11, confirmed via GitHub's git-trees
API -- the plain "contents" API silently truncates a directory listing
past 1000 entries, and this repo's `data/` alone has 1,539 files, so
the trees API's `recursive=1` is required, not just a nicety).

**Why this needs its own fetch logic, not just a URL paste into the
existing subscription_url field**: confirmed live 2026-09-11 that
v2fly's own *category* files (e.g. `data/category-games`) are entirely
made of `include:<name>` lines pointing at other files -- zero literal
domains of their own. Pasting one directly into a category's
subscription_url would fetch successfully and silently produce zero
domains. `common/category_fetch.py`'s `_resolve_includes()` (added the
same day) already recursively follows that include graph at CATEGORY
FETCH time, for any source that happens to use the convention -- this
module is a different concern: which category NAMES to offer for
picking in the first place, and which underlying v2fly file each one
should point at.

Picking a catalog entry never itself becomes a category, is never
assigned to anyone, and is never referenced by category_domains -- it
only pre-fills the ordinary Add-category form's `name` +
`subscription_url`, exactly as if the admin had typed them in by hand.
Everything downstream (fetching, parsing, per-target scoping,
MAX_SCOPED_CATEGORY_DOMAINS) is the same as any other category.

**Region filtering**: v2fly's file-naming convention splits some
categories by region -- `category-games-!cn` (outside mainland China)
vs `category-games-cn` (China only) vs a bare `category-games` (the
union of both, confirmed live by fetching all three: the bare file is
literally `include:category-games-cn` + `include:category-games-!cn`).
For a region-split family, this module's `build_catalog()` keeps the
`-!cn`-style file as the default/global entry (skipping the noisier
bare-union file entirely) and tags the region-specific sibling(s) with
their region code; a family with ONLY a region-specific file (no
global equivalent at all, e.g. Iranian banks) is tagged the same way.
`region IS NULL` entries show in the picker by default; region-tagged
ones are hidden unless the admin turns on the "show region-specific
categories" Settings toggle -- see dashboard.py's own
`category_catalog_combo()`/Settings wiring.

**Bundled fallback + live auto-refresh**, same two-layer shape as
common/oui_lookup.py's IEEE OUI snapshot, just with an actual refresh
loop here instead of a one-off manual regeneration: common/db.py's
`_migrate()` seeds `category_catalog` from
`common/data/v2fly_category_catalog.tsv` only if the table is empty
(a fresh install's day-one bootstrap), and `start()` below re-fetches
and REPLACES the table's live contents automatically afterward, on a
fixed interval, from the dashboard process (always running, unlike
`controller/category_fetch.py`'s own periodic loop -- gated behind the
interception profile -- category browsing/adding has nothing to do
with interception and must work regardless of whether it's on).
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading

import category_fetch
import db

log = logging.getLogger("category_catalog_sync")

DEFAULT_TIMEOUT = 20.0
# Matches controller/main.py's own --category-fetch-interval default --
# a category's own domain list and the catalog of category NAMES both
# change on the same "far less often than AdGuard's bundled ad/tracker
# lists" timescale (category_fetch.py's own reasoning), so there's no
# real justification for a different number here.
DEFAULT_INTERVAL_SECONDS = 86400.0

_TREE_API_URL = "https://api.github.com/repos/v2fly/domain-list-community/git/trees/master?recursive=1"
_RAW_BASE_URL = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data"

_REGION_SUFFIXES = ("cn", "ru", "ir", "jp", "hk", "uk", "mm")
_REGION_LABELS = {
    "cn": "China", "ru": "Russia", "ir": "Iran", "jp": "Japan",
    "hk": "Hong Kong", "uk": "UK", "mm": "Myanmar",
}

# Base names where the FILE'S OWN NAME is a whole country identity
# (confirmed live 2026-09-11 by reading the actual content -- e.g.
# data/category-ir opens "# Iranian websites...") rather than a
# trailing '-xx' suffix the classifier below can detect mechanically.
# 'tm' (Turkmenistan telecom, confirmed by content) is dropped
# entirely -- too niche to model a whole new region code for one file.
_WHOLE_NAME_REGION_OVERRIDE = {"ir": "ir", "ru": "ru", "media-ru-blocked": "ru"}
_WHOLE_NAME_DROP = {"tm"}

# Cosmetic display-name polish for entries a mechanical title-case of
# the hyphenated base name renders awkwardly -- mostly acronyms/
# initialisms a human would never write "Cas" or "Doh" for.
_DISPLAY_NAME_OVERRIDES = {
    "acg": "Anime, Comics & Games",
    "ai": "AI Services",
    "ai-chat": "AI Chat",
    "cas": "Certificate Authorities",
    "cdn": "CDN Infrastructure",
    "ddns": "Dynamic DNS",
    "doh": "DNS-over-HTTPS",
    "ntp": "NTP Time Servers",
    "pt": "Private Trackers",
    "ip-geo-detect": "IP Geolocation Detection",
    "ipfs": "IPFS",
    "stun": "STUN/NAT Traversal",
    "voip": "VoIP",
    "vpnservices": "VPN Services",
    "urlshortner": "URL Shorteners",
    "game-platforms-download": "Game Platform Downloads",
    "android-app-download": "Android App Downloads",
}

_CATEGORY_PREFIX = "category-"


def _titleize(base: str) -> str:
    small = {"in", "of", "the", "and"}
    words = base.replace("-", " ").split()
    out = []
    for i, word in enumerate(words):
        out.append(word.lower() if word.lower() in small and i != 0 else word[:1].upper() + word[1:])
    return " ".join(out)


def _display_name(base: str) -> str:
    return _DISPLAY_NAME_OVERRIDES.get(base, _titleize(base))


def _split_region_suffix(base: str) -> tuple[str, str | None, bool]:
    """Returns (family, region_or_None, is_global_split) for a
    'category-' filename's base name (already stripped of that
    prefix) -- e.g. "games-!cn" -> ("games", None, True) [the explicit
    global/non-China variant of a region-split family], "games-cn" ->
    ("games", "cn", False), "porn" -> ("porn", None, False) [no split
    at all, this IS the only/global file]."""
    for suf in _REGION_SUFFIXES:
        if base.endswith(f"-!{suf}"):
            return base[: -(len(suf) + 2)], None, True
        if base.endswith(f"-{suf}"):
            return base[: -(len(suf) + 1)], suf, False
    return base, None, False


def build_catalog(filenames: list[str]) -> list[dict]:
    """Pure function, no network access (same "text-transform logic
    stays separate from the fetch side" discipline as
    common/blocklist_parser.py) -- given the list of bare
    'category-...' filenames v2fly's own repo currently has, returns
    the curated catalog rows: `[{"slug", "display_name", "file_path",
    "region"}, ...]`. See this module's own docstring for the region-
    split preference (skip the noisy bare-union file when a proper
    '-!cn' split exists) and the whole-name overrides (ir/ru aren't
    named with a detectable suffix, tm is dropped as too niche).
    """
    families: dict[str, list[tuple[str | None, bool, str]]] = {}
    for name in filenames:
        if not name.startswith(_CATEGORY_PREFIX):
            continue
        base = name[len(_CATEGORY_PREFIX):]
        if base in _WHOLE_NAME_DROP:
            continue
        family, region, is_global_split = _split_region_suffix(base)
        families.setdefault(family, []).append((region, is_global_split, name))

    catalog: list[dict] = []
    for family in sorted(families):
        variants = families[family]
        global_splits = [v for v in variants if v[1]]
        region_variants = [v for v in variants if v[0] is not None]
        bare = [v for v in variants if v[0] is None and not v[1]]

        if global_splits:
            _, _, fname = global_splits[0]
            catalog.append({
                "slug": fname[len(_CATEGORY_PREFIX):], "display_name": _display_name(family),
                "file_path": fname, "region": None,
            })
        elif bare:
            _, _, fname = bare[0]
            override_region = _WHOLE_NAME_REGION_OVERRIDE.get(fname[len(_CATEGORY_PREFIX):])
            label = f"{_display_name(family)} ({_REGION_LABELS[override_region]})" if override_region else _display_name(family)
            catalog.append({
                "slug": fname[len(_CATEGORY_PREFIX):], "display_name": label,
                "file_path": fname, "region": override_region,
            })

        for region, _, fname in region_variants:
            catalog.append({
                "slug": fname[len(_CATEGORY_PREFIX):],
                "display_name": f"{_display_name(family)} ({_REGION_LABELS[region]})",
                "file_path": fname, "region": region,
            })

    return catalog


def resolve_subscription_url(file_path: str) -> str:
    """The real raw-content URL for a category_catalog row's file_path
    (e.g. "category-games-!cn") -- what actually gets stored as a new
    category's subscription_url once an admin picks it. A single
    choke point so a future change to v2fly's own repo layout (branch
    rename, etc.) only needs updating here, not in every caller."""
    return f"{_RAW_BASE_URL}/{file_path}"


def _fetch_category_filenames(timeout: float) -> list[str]:
    """Fetches v2fly's own repo tree via GitHub's git-trees API with
    recursive=1 -- the plain "contents" API silently truncates past
    1000 entries and this repo's data/ directory alone has 1,539 files,
    confirmed live 2026-09-11 (contents API returned exactly 1000 with
    no truncation indicator at all; the trees API's own `truncated`
    field is the only reliable signal). Returns the bare 'category-*'
    filenames under data/ (no 'data/' prefix)."""
    text = category_fetch._fetch(_TREE_API_URL, timeout=timeout)
    try:
        payload = json.loads(text)
    except ValueError as exc:
        raise category_fetch.CategoryFetchError(
            f"malformed JSON from {_TREE_API_URL}: {exc}"
        ) from exc
    if payload.get("truncated"):
        log.warning(
            "v2fly repo tree listing reported truncated=true -- this cycle's catalog may be incomplete"
        )
    names = []
    for entry in payload.get("tree", []):
        path = entry.get("path", "")
        if entry.get("type") == "blob" and path.startswith(f"data/{_CATEGORY_PREFIX}"):
            names.append(path[len("data/"):])
    return names


def sync_category_catalog(conn: sqlite3.Connection, timeout: float = DEFAULT_TIMEOUT) -> int:
    """Fetches the current catalog from v2fly and REPLACES
    category_catalog's entire contents with it (same "replace, don't
    diff" discipline as category_fetch.fetch_and_sync_category() itself
    uses for a category's own domain list) -- one atomic transaction, so
    a failure partway through never leaves the table half-updated.
    Raises category_fetch.CategoryFetchError on any fetch/parse
    failure; callers (start() below, and the manual "Refresh catalog
    now" button) are expected to catch it and leave the existing
    catalog untouched rather than let one bad cycle wipe out a working
    one. Returns the number of catalog entries after the refresh."""
    filenames = _fetch_category_filenames(timeout=timeout)
    catalog = build_catalog(filenames)
    now = db.now_iso()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM category_catalog")
        conn.executemany(
            "INSERT INTO category_catalog (slug, display_name, file_path, region, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            [(c["slug"], c["display_name"], c["file_path"], c["region"], now) for c in catalog],
        )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.commit()
    return len(catalog)


def start(
    interval: float = DEFAULT_INTERVAL_SECONDS,
    timeout: float = DEFAULT_TIMEOUT,
    stop_event: threading.Event | None = None,
) -> threading.Thread:
    """Starts sync_category_catalog() running on its own daemon thread,
    ticking immediately on start (not waiting a full `interval` first --
    see controller/periodic.py's own 2026-09-07 fix for exactly this
    class of bug: a long default interval, 86400s here, would otherwise
    mean a database that's never had a successful live sync stays on
    the bundled day-one seed for a full day after every fresh install).
    Opens its own DB connection lazily on that thread (sqlite3
    connections are single-thread). A failed cycle (network, malformed
    JSON) is logged and skipped -- the existing catalog (bundled seed or
    last successful live sync) is left exactly as it was, never a
    reason to crash the dashboard process."""
    stop = stop_event or threading.Event()

    def _loop() -> None:
        conn: sqlite3.Connection | None = None
        while True:
            try:
                if conn is None:
                    conn = db.get_conn()
                    db.init_db(conn)
                count = sync_category_catalog(conn, timeout=timeout)
                log.info("category catalog refreshed: %d entries", count)
            except category_fetch.CategoryFetchError as exc:
                log.info("category catalog refresh skipped (v2fly unreachable?): %s", exc)
            except Exception:
                log.exception("unexpected error refreshing the category catalog -- continuing")
            if stop.wait(interval):
                break

    thread = threading.Thread(target=_loop, name="category-catalog-sync", daemon=True)
    thread.stop_event = stop  # type: ignore[attr-defined]
    thread.start()
    return thread
