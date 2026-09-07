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
