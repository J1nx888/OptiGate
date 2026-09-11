"""common/db.py's _migrate(): removes the two blanket Crunchyroll
domain_paths rules (`^/playback/v[0-9]+/`, `^/content/v[0-9]+/`) that
defaults/seed_defaults.py's CRUNCHYROLL_PATHS stopped seeding 2026-09-10
(RoadMap.md finding #1d) -- see that list's own long comment for why they'd
turned into a live security gap. seed_defaults.seed()'s own INSERT OR
IGNORE is additive-only and isn't even run automatically at startup, so an
existing database (prod's included) needs this data-repair migration to
actually stop carrying the dangerous rows -- _migrate() is the one place
that DOES run automatically on every startup.
"""
from __future__ import annotations

import db


def _add_crunchyroll_domain(conn) -> int:
    conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, created_at) "
        "VALUES ('crunchyroll\\.com', 'bump', 'crunchyroll', 1, ?)",
        (db.now_iso(),),
    )
    conn.commit()
    return conn.execute("SELECT id FROM domains WHERE pattern = 'crunchyroll\\.com'").fetchone()["id"]


def _paths(conn, domain_id) -> set[str]:
    return {
        row["pattern"]
        for row in conn.execute("SELECT pattern FROM domain_paths WHERE domain_id = ?", (domain_id,))
    }


def test_migrate_removes_the_stale_blanket_rules_and_seeds_the_narrow_replacements(conn):
    domain_id = _add_crunchyroll_domain(conn)
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?), (?, ?)",
        (domain_id, r"^/playback/v[0-9]+/", domain_id, r"^/content/v[0-9]+/"),
    )
    conn.commit()

    db._migrate(conn)

    remaining = _paths(conn, domain_id)
    assert r"^/playback/v[0-9]+/" not in remaining
    assert r"^/content/v[0-9]+/" not in remaining
    assert r"^/content/v[0-9]+/discover/(?!up_next/)" in remaining
    assert r"^/content/v[0-9]+/[^/]+/watchlist" in remaining


def test_migrate_never_touches_an_unrelated_domains_paths(conn):
    """Only the Crunchyroll domain (pattern == 'crunchyroll\\.com')
    specifically -- an unrelated bump-mode domain that happens to share
    one of the exact literal patterns must be untouched."""
    conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, created_at) "
        "VALUES ('example\\.com', 'bump', 'generic', 1, ?)",
        (db.now_iso(),),
    )
    conn.commit()
    other_domain_id = conn.execute("SELECT id FROM domains WHERE pattern = 'example\\.com'").fetchone()["id"]
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)",
        (other_domain_id, r"^/content/v[0-9]+/"),
    )
    conn.commit()

    db._migrate(conn)

    assert r"^/content/v[0-9]+/" in _paths(conn, other_domain_id)


def test_migrate_is_idempotent_across_repeated_calls(conn):
    domain_id = _add_crunchyroll_domain(conn)
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?), (?, ?)",
        (domain_id, r"^/playback/v[0-9]+/", domain_id, r"^/content/v[0-9]+/"),
    )
    conn.commit()

    db._migrate(conn)
    db._migrate(conn)  # a second time, e.g. every container startup -- must not duplicate or error

    remaining = list(conn.execute("SELECT pattern FROM domain_paths WHERE domain_id = ?", (domain_id,)))
    patterns = [row["pattern"] for row in remaining]
    assert patterns.count(r"^/content/v[0-9]+/discover/(?!up_next/)") == 1
    assert patterns.count(r"^/content/v[0-9]+/[^/]+/watchlist") == 1


def test_migrate_is_a_no_op_when_no_crunchyroll_domain_exists(conn):
    """A database with no Crunchyroll domain row at all (never seeded, or
    an admin deleted it) -- must not raise, must not create one."""
    db._migrate(conn)
    assert conn.execute("SELECT COUNT(*) c FROM domains WHERE pattern = 'crunchyroll\\.com'").fetchone()["c"] == 0


def test_migrate_preserves_an_admins_own_added_path_rule(conn):
    """A hand-added rule that isn't one of the two exact stale literal
    patterns must survive -- this migration only ever deletes those two
    specific strings, never anything else, even on the same domain."""
    domain_id = _add_crunchyroll_domain(conn)
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?), (?, ?)",
        (domain_id, r"^/playback/v[0-9]+/", domain_id, r"^/my-custom-admin-rule"),
    )
    conn.commit()

    db._migrate(conn)

    assert r"^/my-custom-admin-rule" in _paths(conn, domain_id)
