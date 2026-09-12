"""controller/category_fetch.py: fetching + parsing a category's
subscription_url into category_domains rows. All network access goes
through category_fetch._OPENER.open, which every test here replaces with
a fake -- same pattern as test_adguard_client.py."""
from __future__ import annotations

import db
import pytest

import category_fetch


class FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n: int = -1) -> bytes:
        return self._body if n is None or n < 0 else self._body[:n]

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _insert_category(conn, name, subscription_url=None):
    conn.execute(
        "INSERT INTO categories (name, subscription_url, is_global, created_at) VALUES (?, ?, 0, ?)",
        (name, subscription_url, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM categories WHERE name = ?", (name,)).fetchone()


def test_fetch_and_sync_category_inserts_escaped_domains(monkeypatch, conn):
    category = _insert_category(conn, "Gambling", "https://example.invalid/gambling.txt")
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||bet.example.com^\n||wager.example.org^\n"),
    )

    count = category_fetch.fetch_and_sync_category(conn, category)

    assert count == 2
    rows = conn.execute(
        "SELECT pattern, source FROM category_domains WHERE category_id = ? ORDER BY pattern", (category["id"],)
    ).fetchall()
    assert [r["pattern"] for r in rows] == [r"bet\.example\.com", r"wager\.example\.org"]
    assert all(r["source"] == "subscription" for r in rows)
    assert conn.execute("SELECT last_synced_at FROM categories WHERE id = ?", (category["id"],)).fetchone()[
        "last_synced_at"
    ] is not None


def test_resync_replaces_only_subscription_rows_leaves_manual_untouched(monkeypatch, conn):
    category = _insert_category(conn, "Adult", "https://example.invalid/adult.txt")
    conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, 'manual', ?)",
        (category["id"], r"admin\-added\.example", db.now_iso()),
    )
    conn.commit()

    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||first.example.com^\n"),
    )
    category_fetch.fetch_and_sync_category(conn, category)

    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||second.example.com^\n"),
    )
    category_fetch.fetch_and_sync_category(conn, category)

    rows = {r["pattern"]: r["source"] for r in conn.execute(
        "SELECT pattern, source FROM category_domains WHERE category_id = ?", (category["id"],)
    )}
    assert rows == {
        r"admin\-added\.example": "manual",
        r"second\.example\.com": "subscription",
    }
    assert r"first\.example\.com" not in rows, "stale subscription row from the first sync should be gone"


def test_manual_row_blocks_a_colliding_subscription_pattern(monkeypatch, conn):
    """UNIQUE(category_id, pattern) means INSERT OR IGNORE silently keeps
    the existing manual row rather than duplicating or overwriting it --
    a manual entry always wins for that exact pattern."""
    category = _insert_category(conn, "Social Media", "https://example.invalid/social.txt")
    conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, 'manual', ?)",
        (category["id"], r"tiktok\.com", db.now_iso()),
    )
    conn.commit()
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||tiktok.com^\n"),
    )
    category_fetch.fetch_and_sync_category(conn, category)
    row = conn.execute(
        "SELECT source FROM category_domains WHERE category_id = ? AND pattern = ?",
        (category["id"], r"tiktok\.com"),
    ).fetchone()
    assert row["source"] == "manual"


def test_fetch_and_sync_category_raises_without_subscription_url(conn):
    category = _insert_category(conn, "AI")  # no subscription_url -- manual-only category
    with pytest.raises(category_fetch.CategoryFetchError):
        category_fetch.fetch_and_sync_category(conn, category)


def test_fetch_and_sync_category_skips_rewrite_when_content_is_unchanged(monkeypatch, conn):
    """Regression test for a real gap found by code review 2026-09-11,
    fixed 2026-09-12: this used to unconditionally DELETE+INSERT every
    subscription row on every sync, even when the fetched content was
    identical (post-parse) to what's already stored -- the confirmed-
    live "Adult" category alone is ~953K domains. A second sync with
    byte-for-byte-different-but-semantically-identical content
    (reordered lines) must leave the existing category_domains rows
    completely untouched -- proven here by their row ids staying the
    same, since a real DELETE+INSERT would hand out fresh autoincrement
    ids for the reinserted rows."""
    category = _insert_category(conn, "Gambling", "https://example.invalid/gambling.txt")
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||bet.example.com^\n||wager.example.org^\n"),
    )
    category_fetch.fetch_and_sync_category(conn, category)
    first_ids = {
        r["pattern"]: r["id"]
        for r in conn.execute("SELECT id, pattern FROM category_domains WHERE category_id = ?", (category["id"],))
    }
    first_row = conn.execute("SELECT last_subscription_hash FROM categories WHERE id = ?", (category["id"],)).fetchone()
    assert first_row["last_subscription_hash"] is not None

    # Re-fetch the category row so it carries the hash the first sync
    # just wrote -- every real caller (dashboard.py, controller/
    # adguard_sync.py's own callers) does a fresh SELECT * FROM
    # categories before each sync call, never reuses a stale row across
    # calls.
    category = conn.execute("SELECT * FROM categories WHERE id = ?", (category["id"],)).fetchone()
    # Same two domains, reordered -- a real upstream reordering with no
    # actual content change must still be recognized as "unchanged".
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||wager.example.org^\n||bet.example.com^\n"),
    )
    count = category_fetch.fetch_and_sync_category(conn, category)

    assert count == 2
    second_ids = {
        r["pattern"]: r["id"]
        for r in conn.execute("SELECT id, pattern FROM category_domains WHERE category_id = ?", (category["id"],))
    }
    assert second_ids == first_ids, "rows were rewritten even though the resulting domain set didn't change"
    second_row = conn.execute("SELECT last_synced_at, last_subscription_hash FROM categories WHERE id = ?", (category["id"],)).fetchone()
    assert second_row["last_subscription_hash"] == first_row["last_subscription_hash"]
    assert second_row["last_synced_at"] is not None, "a skipped-rewrite cycle must still advance last_synced_at"


def test_fetch_and_sync_category_still_rewrites_when_content_actually_changes(monkeypatch, conn):
    """Sibling case: a REAL content change must still trigger the
    rewrite -- the skip-when-unchanged fix must not get stuck skipping
    forever once a hash has been recorded."""
    category = _insert_category(conn, "Gambling", "https://example.invalid/gambling.txt")
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||bet.example.com^\n"),
    )
    category_fetch.fetch_and_sync_category(conn, category)

    category = conn.execute("SELECT * FROM categories WHERE id = ?", (category["id"],)).fetchone()
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||bet.example.com^\n||newsite.example.com^\n"),
    )
    count = category_fetch.fetch_and_sync_category(conn, category)

    assert count == 2
    patterns = {
        r["pattern"]
        for r in conn.execute("SELECT pattern FROM category_domains WHERE category_id = ?", (category["id"],))
    }
    assert patterns == {r"bet\.example\.com", r"newsite\.example\.com"}


def test_sync_is_one_atomic_transaction_not_thousands_of_autocommits(monkeypatch, conn):
    """Regression for a real, severe performance bug found live
    2026-09-07 (RoadMap.md's dated entry): `conn` opens with
    isolation_level=None (common/db.py), so without an explicit
    transaction, every row of the executemany INSERT autocommits (and
    fsyncs) individually -- for the real ~953K-domain Adult list, that
    took over 20 minutes and then collided with another writer
    ("database is locked"). Proven here via the rollback path: a
    mid-transaction failure must leave category_domains and
    last_synced_at completely untouched, not partially replaced --
    which is only possible if the delete+insert+update are genuinely
    one atomic unit, not each committing as they go."""
    category = _insert_category(conn, "Gambling", "https://example.invalid/gambling.txt")
    conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, 'subscription', ?)",
        (category["id"], r"old\.example\.com", db.now_iso()),
    )
    conn.commit()

    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||bet.example.com^\n||wager.example.org^\n"),
    )

    # sqlite3.Connection's own methods are read-only on the real C type
    # (can't monkeypatch executemany itself, on the instance or the
    # class) -- failing inside the DELETE-to-INSERT window a different
    # way instead: re.escape() raising partway through building the rows
    # to insert, which happens after the real DELETE has already run
    # (inside the transaction) but before executemany or the UPDATE ever
    # get a chance to.
    def boom(domain):
        raise ValueError("simulated failure mid-transaction")

    monkeypatch.setattr(category_fetch.re, "escape", boom)

    with pytest.raises(ValueError):
        category_fetch.fetch_and_sync_category(conn, category)

    # The DELETE that ran before the simulated failure must have been
    # rolled back too, along with the old row still being there --
    # proving this, not just "the new rows never landed."
    rows = conn.execute(
        "SELECT pattern FROM category_domains WHERE category_id = ?", (category["id"],)
    ).fetchall()
    assert [r["pattern"] for r in rows] == [r"old\.example\.com"]
    assert conn.execute(
        "SELECT last_synced_at FROM categories WHERE id = ?", (category["id"],)
    ).fetchone()["last_synced_at"] is None


def test_size_cap_exceeded_raises(monkeypatch, conn):
    category = _insert_category(conn, "Huge", "https://example.invalid/huge.txt")
    monkeypatch.setattr(category_fetch, "MAX_RESPONSE_BYTES", 10)
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"||this-is-way-too-long-for-the-cap.example^\n"),
    )
    with pytest.raises(category_fetch.CategoryFetchError):
        category_fetch.fetch_and_sync_category(conn, category)


def test_resolve_includes_is_a_no_op_when_no_include_lines_are_present(monkeypatch):
    """No extra fetch at all for the common case -- a source that never
    uses the v2fly include: convention must not pay any extra cost."""
    def _boom(url, timeout=None):
        raise AssertionError(f"must not fetch anything, tried {url!r}")

    monkeypatch.setattr(category_fetch, "_fetch", _boom)

    result = category_fetch._resolve_includes(
        "https://example.invalid/data/category-porn", "||porn.example.com^\n", timeout=5.0
    )

    assert result == "||porn.example.com^\n"


def test_resolve_includes_follows_a_single_include(monkeypatch):
    def fake_fetch(url, timeout=None):
        assert url == "https://example.invalid/data/sibling"
        return "||real.example.com^\n"

    monkeypatch.setattr(category_fetch, "_fetch", fake_fetch)

    result = category_fetch._resolve_includes(
        "https://example.invalid/data/category-games", "include:sibling\n", timeout=5.0
    )

    assert "real.example.com" in result


def test_resolve_includes_follows_nested_includes_recursively(monkeypatch):
    files = {
        "https://example.invalid/data/a": "include:b\n",
        "https://example.invalid/data/b": "include:c\n",
        "https://example.invalid/data/c": "||deeply.nested.example^\n",
    }

    def fake_fetch(url, timeout=None):
        return files[url]

    monkeypatch.setattr(category_fetch, "_fetch", fake_fetch)

    result = category_fetch._resolve_includes(
        "https://example.invalid/data/top", "include:a\n", timeout=5.0
    )

    assert "deeply.nested.example" in result


def test_resolve_includes_strips_trailing_attribute_tags(monkeypatch):
    """v2fly include lines can carry the same trailing ' @attribute'
    tags a domain line can (e.g. 'include:geolocation-cn @cn') -- the
    tag must not become part of the fetched filename."""
    def fake_fetch(url, timeout=None):
        assert url == "https://example.invalid/data/geolocation-cn", url
        return "||tagged.example.com^\n"

    monkeypatch.setattr(category_fetch, "_fetch", fake_fetch)

    result = category_fetch._resolve_includes(
        "https://example.invalid/data/top", "include:geolocation-cn @cn @ads\n", timeout=5.0
    )

    assert "tagged.example.com" in result


def test_resolve_includes_never_refetches_a_cycle(monkeypatch):
    """A includes B, B includes A right back -- must terminate, not
    infinitely recurse or double-fetch."""
    calls = []
    files = {
        "https://example.invalid/data/a": "include:b\n||a.example^\n",
        "https://example.invalid/data/b": "include:a\n||b.example^\n",
    }

    def fake_fetch(url, timeout=None):
        calls.append(url)
        return files[url]

    monkeypatch.setattr(category_fetch, "_fetch", fake_fetch)

    result = category_fetch._resolve_includes(
        "https://example.invalid/data/a", files["https://example.invalid/data/a"], timeout=5.0
    )

    assert calls == ["https://example.invalid/data/b"], "b must be fetched once, a must never be re-fetched"
    assert "a.example" in result and "b.example" in result


def test_resolve_includes_skips_an_unreachable_include_and_keeps_the_rest(monkeypatch):
    def fake_fetch(url, timeout=None):
        if "broken" in url:
            raise category_fetch.CategoryFetchError("simulated failure")
        return "||still.works.example^\n"

    monkeypatch.setattr(category_fetch, "_fetch", fake_fetch)

    result = category_fetch._resolve_includes(
        "https://example.invalid/data/top", "include:broken\ninclude:good\n", timeout=5.0
    )

    assert "still.works.example" in result


def test_resolve_includes_stops_at_the_file_cap(monkeypatch):
    """A pathological/hostile include graph (or a simple off-by-one in a
    legitimate one) must not fetch forever -- this is an unattended
    background job fetching admin-supplied URLs with no further checks."""
    monkeypatch.setattr(category_fetch, "MAX_INCLUDED_FILES", 3)
    fetch_count = [0]

    def fake_fetch(url, timeout=None):
        fetch_count[0] += 1
        n = int(url.rsplit("/", 1)[-1])
        return f"include:{n + 1}\n"

    monkeypatch.setattr(category_fetch, "_fetch", fake_fetch)

    category_fetch._resolve_includes("https://example.invalid/data/0", "include:1\n", timeout=5.0)

    assert fetch_count[0] <= 3


def test_fetch_and_sync_category_resolves_v2fly_style_includes_end_to_end(monkeypatch, conn):
    """The real gap this closes: a v2fly *category* file (e.g.
    data/category-games) is entirely include: lines with zero literal
    domains of its own -- fetching it directly used to silently produce
    zero domains."""
    category = _insert_category(conn, "Gaming", "https://example.invalid/data/category-games")

    def fake_open(request, timeout=None):
        url = request.full_url
        if url == "https://example.invalid/data/category-games":
            return FakeResponse(b"include:category-games-!cn\n")
        if url == "https://example.invalid/data/category-games-!cn":
            return FakeResponse(b"||steampowered.com^\n||epicgames.com^\n")
        raise AssertionError(f"unexpected fetch: {url}")

    monkeypatch.setattr(category_fetch._OPENER, "open", fake_open)

    count = category_fetch.fetch_and_sync_category(conn, category)

    assert count == 2
    patterns = {r["pattern"] for r in conn.execute(
        "SELECT pattern FROM category_domains WHERE category_id = ?", (category["id"],)
    )}
    assert patterns == {r"steampowered\.com", r"epicgames\.com"}


def test_sync_all_categories_skips_a_failing_one_and_still_syncs_the_rest(monkeypatch, conn):
    good = _insert_category(conn, "Gambling", "https://example.invalid/gambling.txt")
    _insert_category(conn, "Broken", "https://example.invalid/broken.txt")
    _insert_category(conn, "AI")  # no subscription_url -- excluded from the query entirely

    def fake_open(request, timeout=None):
        if "broken" in request.full_url:
            raise category_fetch.URLError("connection refused")
        return FakeResponse(b"||bet.example.com^\n")

    monkeypatch.setattr(category_fetch._OPENER, "open", fake_open)

    results = category_fetch.sync_all_categories(conn)

    assert results == {"Gambling": 1}
    assert conn.execute(
        "SELECT COUNT(*) AS c FROM category_domains WHERE category_id = ?", (good["id"],)
    ).fetchone()["c"] == 1
