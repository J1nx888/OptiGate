"""defaults/seed_defaults.py: idempotent first-run seeding."""
from __future__ import annotations

import re

import db
import seed_defaults
from ai_sites_seed import AI_SITE_DOMAINS


def _counts(conn):
    return {
        "domains": conn.execute("SELECT COUNT(*) c FROM domains").fetchone()["c"],
        "domain_paths": conn.execute("SELECT COUNT(*) c FROM domain_paths").fetchone()["c"],
        "categories": conn.execute("SELECT COUNT(*) c FROM categories").fetchone()["c"],
        "category_domains": conn.execute("SELECT COUNT(*) c FROM category_domains").fetchone()["c"],
    }


def test_seed_is_idempotent_on_row_counts(conn):
    seed_defaults.seed(conn)
    conn.commit()
    first = _counts(conn)

    seed_defaults.seed(conn)
    conn.commit()
    second = _counts(conn)

    assert first == second
    assert first["domains"] > 0
    assert first["domain_paths"] == len(seed_defaults.CRUNCHYROLL_PATHS)
    assert first["categories"] == len(seed_defaults.DEFAULT_CATEGORIES)
    assert first["category_domains"] == len(AI_SITE_DOMAINS)


def test_default_categories_seeded_not_global(conn):
    """Seeding a category row alone blocks nothing -- is_global defaults to
    0 for every starter category, AI included, regardless of whether it has
    domains yet."""
    seed_defaults.seed(conn)
    conn.commit()
    rows = conn.execute("SELECT name, subscription_url, is_global FROM categories ORDER BY name").fetchall()
    assert len(rows) == len(seed_defaults.DEFAULT_CATEGORIES)
    assert all(r["is_global"] == 0 for r in rows)


def test_subscription_categories_have_no_domains_until_first_sync(conn):
    """Every subscription-based starter category gets no category_domains
    rows until something actually calls common/category_fetch.py's
    fetch_and_sync_category() (the controller's own daily loop, or the
    dashboard's "Sync now" button). AI is deliberately excluded from this
    check (unlike before 2026-09-11): it's the one category that carries
    BOTH a real subscription_url (v2fly's AI Services, rebased the same
    day) AND a manual domain snapshot seeded with its domains already in
    place -- see test_ai_category_seeded_with_manual_and_subscription_source
    below for that hybrid case specifically."""
    seed_defaults.seed(conn)
    conn.commit()
    subscribed_ids = [
        r["id"] for r in conn.execute(
            "SELECT id FROM categories WHERE subscription_url IS NOT NULL AND name != 'AI'"
        )
    ]
    assert subscribed_ids, "expected at least one non-AI subscription category to actually check"
    for category_id in subscribed_ids:
        count = conn.execute(
            "SELECT COUNT(*) c FROM category_domains WHERE category_id = ?", (category_id,)
        ).fetchone()["c"]
        assert count == 0


def test_ai_category_seeded_with_manual_and_subscription_source(conn):
    """2026-09-11 (RoadMap.md, project owner's request to rebase the
    default category seed onto the new v2fly catalog): AI was the one
    category with a clean v2fly equivalent (AI Services, category-ai-!cn,
    confirmed live to resolve to 179 real domains) -- it now carries a
    real subscription_url ON TOP OF (not instead of) the pre-existing
    one-time manual snapshot (defaults/ai_sites_seed.py, sourced from
    Microsoft Purview's published AI-sites list), which stays exactly as
    it was: a 'manual' row and a 'subscription' row-to-be coexist fine on
    the same category, same as any other category with both."""
    import category_catalog_sync

    seed_defaults.seed(conn)
    conn.commit()
    ai_row = conn.execute("SELECT id, subscription_url FROM categories WHERE name = 'AI'").fetchone()
    assert ai_row["subscription_url"] == category_catalog_sync.resolve_subscription_url("category-ai-!cn")

    rows = conn.execute(
        "SELECT pattern, source FROM category_domains WHERE category_id = ?", (ai_row["id"],)
    ).fetchall()
    assert len(rows) == len(AI_SITE_DOMAINS)
    assert all(r["source"] == "manual" for r in rows)

    patterns = {r["pattern"] for r in rows}
    for domain in ("chatgpt.com", "claude.ai", "anthropic.com", "character.ai", "midjourney.co"):
        assert re.escape(domain) in patterns


def test_adult_category_deliberately_stays_on_blocklistproject(conn):
    """2026-09-11 explicit decision, not an oversight: v2fly's own Porn
    category resolves to ~99% fewer domains than BlockListProject's
    current Adult list (confirmed live) -- a real coverage regression for
    the single most safety-critical category here, so this one was NOT
    rebased despite AI being rebased the same session. Regression guard
    against someone "finishing the rebase" later without re-checking that
    tradeoff."""
    seed_defaults.seed(conn)
    conn.commit()
    row = conn.execute("SELECT subscription_url FROM categories WHERE name = 'Adult'").fetchone()
    assert "blocklistproject" in row["subscription_url"]
    assert "v2fly" not in row["subscription_url"]


def test_gambling_drugs_fraud_and_weapons_are_not_rebased(conn):
    """2026-09-11 explicit decision: v2fly has no equivalent category for
    any of these four at all -- rebasing would drop real protection with
    nothing to replace it. Weapons keeps subscription_url=None (no public
    list exists for it at all, from either source)."""
    seed_defaults.seed(conn)
    conn.commit()
    for name in ("Gambling", "Drugs", "Fraud & Scams"):
        row = conn.execute("SELECT subscription_url FROM categories WHERE name = ?", (name,)).fetchone()
        assert "blocklistproject" in row["subscription_url"]
    weapons = conn.execute("SELECT subscription_url FROM categories WHERE name = 'Weapons'").fetchone()
    assert weapons["subscription_url"] is None


def test_facebook_tiktok_twitter_whatsapp_stay_separate_not_collapsed(conn):
    """2026-09-11 explicit decision: v2fly only offers one combined
    'Social Media' category -- collapsing these four into it would lose
    per-platform toggling. Each must still exist as its own category on
    its original BlockListProject source (still available manually via
    the Categories page's own "Add from catalog" picker for an admin who
    wants the all-in-one version instead)."""
    seed_defaults.seed(conn)
    conn.commit()
    for name in ("Facebook", "TikTok", "Twitter/X", "WhatsApp"):
        row = conn.execute("SELECT subscription_url FROM categories WHERE name = ?", (name,)).fetchone()
        assert row is not None, f"{name} must still exist as its own category"
        assert "blocklistproject" in row["subscription_url"]


def test_seed_never_overwrites_an_already_existing_categorys_subscription_url(conn):
    """Idempotent contract this whole file's own docstring claims -- an
    admin who already picked a different source for a category (or a
    future version of DEFAULT_CATEGORIES that changes a URL again) must
    never have that silently overwritten by re-seeding."""
    conn.execute(
        "INSERT INTO categories (name, subscription_url, is_global, created_at) VALUES (?, ?, 0, ?)",
        ("AI", "https://example.invalid/admin-picked-this-instead.txt", db.now_iso()),
    )
    conn.commit()

    seed_defaults.seed(conn)
    conn.commit()

    row = conn.execute("SELECT subscription_url FROM categories WHERE name = 'AI'").fetchone()
    assert row["subscription_url"] == "https://example.invalid/admin-picked-this-instead.txt"


def test_ai_category_reseed_preserves_admin_added_domain(conn):
    """Re-running seed() must not disturb a domain an admin added to the AI
    category by hand -- same INSERT OR IGNORE idempotency as everything else
    in this module, keyed on (category_id, pattern). (Note, same as the
    pre-existing GLOBAL_SPLICE_DOMAINS/TRUSTED_DOMAINS seeds: this does NOT
    protect against a *deleted* default reappearing on reseed -- INSERT OR
    IGNORE can't tell "never inserted" from "admin removed it" -- only
    against duplication/data loss for rows the admin adds.)"""
    seed_defaults.seed(conn)
    conn.commit()
    ai_row = conn.execute("SELECT id FROM categories WHERE name = 'AI'").fetchone()

    conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) "
        "VALUES (?, ?, 'manual', ?)",
        (ai_row["id"], re.escape("some-admin-added-ai-site.example"), db.now_iso()),
    )
    conn.commit()

    seed_defaults.seed(conn)
    conn.commit()

    patterns = {
        r["pattern"]
        for r in conn.execute(
            "SELECT pattern FROM category_domains WHERE category_id = ?", (ai_row["id"],)
        )
    }
    assert re.escape("some-admin-added-ai-site.example") in patterns
    assert len(patterns) == len(AI_SITE_DOMAINS) + 1


def test_seed_twice_leaves_a_category_admin_edit_untouched(conn):
    seed_defaults.seed(conn)
    conn.commit()
    conn.execute("UPDATE categories SET is_global = 1 WHERE name = 'Adult'")
    conn.commit()

    seed_defaults.seed(conn)
    conn.commit()

    row = conn.execute("SELECT is_global FROM categories WHERE name = 'Adult'").fetchone()
    assert row["is_global"] == 1


def test_seed_twice_leaves_admin_edits_untouched(conn):
    seed_defaults.seed(conn)
    conn.commit()
    conn.execute("UPDATE domains SET mode = 'bump' WHERE pattern = ?", (r"google\.com",))
    conn.commit()

    seed_defaults.seed(conn)
    conn.commit()

    row = conn.execute("SELECT mode FROM domains WHERE pattern = ?", (r"google\.com",)).fetchone()
    assert row["mode"] == "bump"  # re-seeding must not clobber an admin's change


def test_crunchyrollcdn_is_trusted_not_splice(conn):
    """S2.2: crunchyrollcdn.com must end up 'trusted', not silently dropped
    into 'splice' by being listed in both domain lists."""
    seed_defaults.seed(conn)
    conn.commit()
    row = conn.execute(
        "SELECT mode FROM domains WHERE pattern = ?", (r"crunchyrollcdn\.com",)
    ).fetchone()
    assert row is not None
    assert row["mode"] == "trusted"


def test_crunchyroll_domain_seeded_as_global_bump(conn):
    seed_defaults.seed(conn)
    conn.commit()
    row = conn.execute(
        "SELECT * FROM domains WHERE pattern = ?", (r"crunchyroll\.com",)
    ).fetchone()
    assert row is not None
    assert row["mode"] == "bump"
    assert row["kind"] == "crunchyroll"
    assert row["is_global"] == 1


def test_crunchyrollsvc_playback_host_is_not_seeded(conn):
    """S1.2, resolved 2026-08-28: confirmed against Crunchyroll's own live
    webpack bundle that production playback is served from
    www.crunchyroll.com/playback (already covered by the crunchyroll.com
    domain) -- crunchyrollsvc.com is dev-only in Crunchyroll's own config
    and must NOT be seeded as a separate domain."""
    seed_defaults.seed(conn)
    conn.commit()
    row = conn.execute(
        "SELECT * FROM domains WHERE pattern = ?", (r"crunchyrollsvc\.com",)
    ).fetchone()
    assert row is None


def test_crunchyroll_paths_attached_to_crunchyroll_domain_only(conn):
    seed_defaults.seed(conn)
    conn.commit()
    cr_row = conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"crunchyroll\.com",)).fetchone()
    count = conn.execute(
        "SELECT COUNT(*) c FROM domain_paths WHERE domain_id = ?", (cr_row["id"],)
    ).fetchone()["c"]
    assert count == len(seed_defaults.CRUNCHYROLL_PATHS)


def test_crunchyroll_personalization_path_is_allowed(conn):
    """GH #4: the 'Top 10'-style recommendation API was blocked by the
    path allowlist -- confirmed on a real device -- since it wasn't in
    CRUNCHYROLL_PATHS."""
    import matching

    seed_defaults.seed(conn)
    conn.commit()
    cr_row = conn.execute("SELECT id FROM domains WHERE pattern = ?", (r"crunchyroll\.com",)).fetchone()
    path = (
        "/personalization/v2/personalization?collectionId=Curation_Collections/"
        "Dynamic/Top_10_US&vendor=thinkanalytics&locale=en-US"
    )
    assert matching.path_allowed(conn, cr_row["id"], path) is True


def test_all_seeded_domain_patterns_are_unique(conn):
    seed_defaults.seed(conn)
    conn.commit()
    patterns = [r["pattern"] for r in conn.execute("SELECT pattern FROM domains")]
    assert len(patterns) == len(set(patterns))
