#!/usr/bin/env python3
"""Seed the database with sane defaults on first run. Idempotent: every
insert uses INSERT OR IGNORE / set_setting_if_absent, so re-running this
against an already-configured database changes nothing. Anything the admin
has since edited or removed via the dashboard stays as they left it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import db
from ai_sites_seed import AI_SITE_DOMAINS

# Infrastructure Crunchyroll's site depends on -- global, splice mode (never
# decrypted, just a host-level pass-through once allowed). Carried over from
# v1's allowed_sites.txt.
GLOBAL_SPLICE_DOMAINS = [
    ("google\\.com", "Google"),
    ("gstatic\\.com", "Google static assets"),
    ("googleapis\\.com", "Google APIs"),
    ("googleusercontent\\.com", "Google user content"),
    ("ctfassets\\.net", "Crunchyroll CMS assets"),
    ("vimeo\\.com", "Video embeds"),
    ("segment\\.com", "Analytics"),
    ("braze\\.com", "Notifications"),
    ("akamaized\\.net", "CDN"),
    ("auth0\\.com", "Single sign-on"),
    ("firebaseapp\\.com", "Single sign-on"),
    ("ipify\\.org", "Geolocation"),
    ("ipapi\\.co", "Geolocation"),
    ("iplocate\\.io", "Geolocation"),
    ("ipinfo\\.io", "Geolocation"),
    ("bitmovin\\.com", "Video player"),
    ("litix\\.io", "Video player telemetry"),
    ("cookielaw\\.org", "Cookie consent"),
    ("ketchcdn\\.com", "Cookie consent"),
    ("ketchjs\\.com", "Cookie consent"),
    ("jsdelivr\\.net", "Script CDN"),
    ("onetrust\\.com", "Cookie consent"),
    ("datadoghq\\.com", "Telemetry"),
    ("googletagmanager\\.com", "Telemetry"),
]

# Always spliced, never checked or logged -- large binary CDN traffic where
# there's nothing meaningful to authorize per-user (the show-level decision
# already happened at the manifest/playback-token request, which IS bumped).
TRUSTED_DOMAINS = [
    ("gccrunchyroll\\.com", "Crunchyroll raw video CDN"),
    ("crunchyrollcdn\\.com", "Crunchyroll raw video CDN"),
]

# Crunchyroll's own paths -- defense-in-depth for request shapes the
# classifier doesn't specifically recognize. Carried over from v1's
# allowed_paths.txt.
#
# **2026-09-10 (RoadMap.md finding #1d, docs/design/crunchyroll-trace-
# 2026-09-10/ANALYSIS.md item 4): the two blanket rules this list used to
# carry -- `^/playback/v[0-9]+/` and `^/content/v[0-9]+/` -- were removed.**
# Both predated common/cr_urls.py's PLAYBACK/UP_NEXT classifiers and had
# turned into a live security gap: any request under either prefix that
# the classifier didn't specifically recognize fell through to
# proxy/authz_helper.py's OTHER-kind fallback, which consults exactly this
# list -- so an unrecognized (or, before UP_NEXT existed, simply
# unclassified) request under `/content/v.../` was blanket-ALLOWED
# regardless of show ownership, not denied. `/playback/v.../` is fully
# covered by PLAYBACK_URL_RE (the hard gate -- no manifest, no video,
# without passing user_has_show()); `/content/v.../` needs the narrower
# replacements below instead of one blanket allow, so a *future*
# unrecognized shape under either prefix now fails CLOSED (denied,
# `path_not_allowed`) instead of open. Confirmed safe to broaden the
# `discover/` replacement below despite `/content/v.../discover/up_next/`
# living under the same prefix: UP_NEXT_URL_RE intercepts and fully gates
# that shape in common/cr_urls.py's classify() before path rules are ever
# consulted, and `/discover/up_next/` is also in cr_urls.GUARDED_MARKERS
# so even an unrecognized variant of it fails closed rather than falling
# through to this list at all -- the negative lookahead below is a third,
# belt-and-suspenders layer on top of those two.
CRUNCHYROLL_PATHS = [
    r"^/$", r"^/\?",
    r"^/login", r"^/auth", r"^/api",
    r"^/simulcastcalendar", r"^/news",
    r"^/assets", r"^/browser", r"^/build/", r"^/config", r"^/cdn",
    r"^/assets/", r"^/css/", r"^/js/", r"^/images/",
    r"\.(css|js|png|jpg|jpeg|gif|svg|webp|json|woff2?)$",
    r"^/discover",
    r"^/config-delta/",
    r"^/subs/v[0-9]+/",
    r"^/callback",
    r"^/accounts/v[0-9]+/",
    r"^/f/v[0-9]+/",
    # Id-free content API: catalogue browse, watch history, and the
    # personalized/home feed rows all live under this prefix -- but NOT
    # up_next (excluded by name; see the long comment above for why this
    # is safe even though up_next also starts with `discover/`).
    r"^/content/v[0-9]+/discover/(?!up_next/)",
    # accountUuid/watchlist -- carries no series/episode id to check.
    r"^/content/v[0-9]+/[^/]+/watchlist",
    r"^/i18n/", r"^/skip-events/",
    r"^/content/v[0-9]+/.*playheads",
    r"^/v1/track", r"^/v1/p$",
    r"/content-reviews/",
    r"/v1/",
    # "Top 10"-style recommendation rows on the discover/home page (GH #4).
    r"^/personalization/v[0-9]+/",
]


# Phase 8 starter categories. URLs are all from The Block List Project
# (https://github.com/blocklistproject/Lists, MIT, actively maintained) --
# confirmed LIVE 2026-08-31/09-01 (not assumed from its README alone): each
# fetched, format-checked (AdGuard/adblock rule syntax, matching
# common/blocklist_parser.py), and entry-counted. Counts shift as the
# upstream lists update; the ones noted below are what was true when this
# was written, kept only to explain the is_global/scoped split the
# dashboard's category routes actually enforce
# (matching.MAX_SCOPED_CATEGORY_DOMAINS = 5000):
#   - Porn (953,393), Gambling (278,856), Drugs (26,029), Fraud (256,268),
#     Facebook (22,362) are all already over the threshold -- Everyone-only,
#     regardless of what an admin later tries to scope them to.
#   - TikTok (3,725), Twitter/X (1,193), WhatsApp (226) are small enough to
#     scope to a specific kid/device if wanted.
# None are seeded `is_global` by default -- an admin has to actually decide
# to turn a category on (and for whom) from the Categories page; seeding
# the row alone blocks nothing. None have any `category_domains` rows yet
# either -- that only happens once something calls
# `common/category_fetch.py`'s `fetch_and_sync_category()` (the
# controller's own daily background loop, or the dashboard's "Sync now"
# button), same as a freshly-seeded row with no data until its first real
# fetch.
#
# No public blocklist exists for "AI" or "Weapons" (confirmed via research
# the same session) -- both seeded with subscription_url=None,
# manual-curation-only, ready for an admin (or a future pass) to add
# domains to directly from the category's Manage page.
_BLOCKLISTPROJECT_ADGUARD = "https://blocklistproject.github.io/Lists/adguard/{}-ags.txt"

DEFAULT_CATEGORIES = [
    ("Adult", _BLOCKLISTPROJECT_ADGUARD.format("porn")),
    ("Gambling", _BLOCKLISTPROJECT_ADGUARD.format("gambling")),
    ("Drugs", _BLOCKLISTPROJECT_ADGUARD.format("drugs")),
    ("Fraud & Scams", _BLOCKLISTPROJECT_ADGUARD.format("fraud")),
    ("Facebook", _BLOCKLISTPROJECT_ADGUARD.format("facebook")),
    ("TikTok", _BLOCKLISTPROJECT_ADGUARD.format("tiktok")),
    ("Twitter/X", _BLOCKLISTPROJECT_ADGUARD.format("twitter")),
    ("WhatsApp", _BLOCKLISTPROJECT_ADGUARD.format("whatsapp")),
    ("AI", None),
    ("Weapons", None),
]


def seed(conn) -> None:
    for pattern, note in GLOBAL_SPLICE_DOMAINS:
        conn.execute(
            "INSERT OR IGNORE INTO domains (pattern, mode, kind, is_global, note, created_at) "
            "VALUES (?, 'splice', 'generic', 1, ?, ?)",
            (pattern, note, db.now_iso()),
        )

    for pattern, note in TRUSTED_DOMAINS:
        conn.execute(
            "INSERT OR IGNORE INTO domains (pattern, mode, kind, is_global, note, created_at) "
            "VALUES (?, 'trusted', 'generic', 1, ?, ?)",
            (pattern, note, db.now_iso()),
        )

    conn.execute(
        "INSERT OR IGNORE INTO domains (pattern, mode, kind, is_global, note, created_at) "
        "VALUES ('crunchyroll\\.com', 'bump', 'crunchyroll', 1, 'Crunchyroll -- shows approved per-user', ?)",
        (db.now_iso(),),
    )
    # No separate crunchyrollsvc.com playback-service domain: confirmed
    # 2026-08-28 against Crunchyroll's own live webpack bundle that
    # production playback is served from www.crunchyroll.com/playback (the
    # cr-play-service.*.crunchyrollsvc.com host is explicitly dev-only in
    # Crunchyroll's own config, never used by real traffic) -- already
    # covered by the crunchyroll.com domain above. See
    # docs/review-2026-08-28.md item 1.2.
    cr_row = conn.execute(
        "SELECT id FROM domains WHERE pattern = 'crunchyroll\\.com'"
    ).fetchone()
    if cr_row:
        for pattern in CRUNCHYROLL_PATHS:
            conn.execute(
                "INSERT OR IGNORE INTO domain_paths (domain_id, pattern) VALUES (?, ?)",
                (cr_row["id"], pattern),
            )

    for name, subscription_url in DEFAULT_CATEGORIES:
        conn.execute(
            "INSERT OR IGNORE INTO categories (name, subscription_url, is_global, created_at) "
            "VALUES (?, ?, 0, ?)",
            (name, subscription_url, db.now_iso()),
        )

    # AI category starter domains: a one-time manual snapshot (see
    # ai_sites_seed.py's own docstring for provenance/exclusions), tagged
    # source='manual' -- the same tag an admin's own hand-added domain gets,
    # and therefore never touched or duplicated by a re-seed. Not a
    # subscription sync: there is no subscription_url on this category for
    # common/category_fetch.py to fetch from.
    ai_row = conn.execute("SELECT id FROM categories WHERE name = 'AI'").fetchone()
    if ai_row:
        now = db.now_iso()
        conn.executemany(
            "INSERT OR IGNORE INTO category_domains (category_id, pattern, source, created_at) "
            "VALUES (?, ?, 'manual', ?)",
            [(ai_row["id"], re.escape(domain), now) for domain in AI_SITE_DOMAINS],
        )


def main() -> int:
    conn = db.get_conn()
    db.init_db(conn)
    seed(conn)
    conn.commit()
    conn.close()
    print("Seed complete (idempotent -- existing data untouched).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
