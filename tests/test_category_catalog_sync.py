"""common/category_catalog_sync.py: the Categories page's "Add category
from catalog" search picker, sourced from v2fly/domain-list-community.
build_catalog() is pure logic, tested directly against small fake
filename lists (no network) -- sync_category_catalog()/start() network
access goes through category_fetch._fetch, monkeypatched here the same
way test_category_fetch.py already does."""
from __future__ import annotations

import threading
import time

import db
import pytest

import category_catalog_sync as ccs
import category_fetch


# ============================================================
# build_catalog -- pure classification/curation logic
# ============================================================

def test_build_catalog_uses_bare_file_when_no_region_split_exists():
    catalog = ccs.build_catalog(["category-porn"])
    assert catalog == [{"slug": "porn", "display_name": "Porn", "file_path": "category-porn", "region": None}]


def test_build_catalog_prefers_the_global_ex_cn_variant_over_the_bare_union_file():
    """category-games (bare) is the union of category-games-cn and
    category-games-!cn (confirmed live by fetching all three) -- using
    it directly would re-include the China-specific noise the split
    exists to let a caller avoid. The bare file must be skipped
    entirely when a proper split exists."""
    catalog = ccs.build_catalog(["category-games", "category-games-!cn", "category-games-cn"])
    slugs = {c["slug"] for c in catalog}
    assert slugs == {"games-!cn", "games-cn"}
    global_entry = next(c for c in catalog if c["region"] is None)
    assert global_entry["file_path"] == "category-games-!cn"
    assert global_entry["display_name"] == "Games"
    region_entry = next(c for c in catalog if c["region"] == "cn")
    assert region_entry["file_path"] == "category-games-cn"
    assert region_entry["display_name"] == "Games (China)"


def test_build_catalog_tags_a_region_only_family_with_no_global_equivalent():
    """category-automobile only exists as -cn, no bare or -!cn variant
    at all -- must still surface (region-gated), not silently vanish."""
    catalog = ccs.build_catalog(["category-automobile-cn"])
    assert catalog == [{
        "slug": "automobile-cn", "display_name": "Automobile (China)",
        "file_path": "category-automobile-cn", "region": "cn",
    }]


def test_build_catalog_applies_whole_name_region_overrides():
    """category-ir/category-ru are themselves the whole region identity
    (confirmed live by reading their content) -- the suffix classifier
    alone can't detect this, so it needs the explicit override table."""
    catalog = ccs.build_catalog(["category-ir", "category-ru"])
    by_slug = {c["slug"]: c for c in catalog}
    assert by_slug["ir"]["region"] == "ir"
    assert by_slug["ir"]["display_name"] == "Ir (Iran)"
    assert by_slug["ru"]["region"] == "ru"


def test_build_catalog_drops_the_whole_name_drop_list():
    """category-tm (Turkmenistan telecom) is deliberately dropped --
    too niche to justify a whole new region code for one file."""
    catalog = ccs.build_catalog(["category-tm", "category-porn"])
    assert [c["slug"] for c in catalog] == ["porn"]


def test_build_catalog_applies_display_name_overrides_for_acronyms():
    catalog = ccs.build_catalog(["category-doh", "category-vpnservices"])
    by_slug = {c["slug"]: c["display_name"] for c in catalog}
    assert by_slug["doh"] == "DNS-over-HTTPS"
    assert by_slug["vpnservices"] == "VPN Services"


def test_build_catalog_ignores_non_category_files():
    catalog = ccs.build_catalog(["netflix", "category-porn", "geolocation-cn"])
    assert [c["slug"] for c in catalog] == ["porn"]


def test_build_catalog_is_empty_for_an_empty_input():
    assert ccs.build_catalog([]) == []


def test_resolve_subscription_url_points_at_the_raw_v2fly_file():
    url = ccs.resolve_subscription_url("category-entertainment")
    assert url == "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/category-entertainment"


# ============================================================
# sync_category_catalog -- network + DB, mocked HTTP
# ============================================================

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


def _fake_tree_json(paths: list[str]) -> bytes:
    import json as _json
    tree = [{"path": p, "type": "blob"} for p in paths]
    return _json.dumps({"truncated": False, "tree": tree}).encode("utf-8")


def test_sync_category_catalog_replaces_existing_rows(monkeypatch, conn):
    conn.execute(
        "INSERT INTO category_catalog (slug, display_name, file_path, region, updated_at) "
        "VALUES ('stale', 'Stale', 'category-stale', NULL, ?)", (db.now_iso(),),
    )
    conn.commit()
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(_fake_tree_json(["data/category-porn"])),
    )

    count = ccs.sync_category_catalog(conn)

    assert count == 1
    rows = [r["slug"] for r in conn.execute("SELECT slug FROM category_catalog")]
    assert rows == ["porn"], "stale row must be gone, replaced entirely by the new fetch"


def test_sync_category_catalog_only_considers_data_category_files(monkeypatch, conn):
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(
            _fake_tree_json(["data/netflix", "data/category-porn", "readme.md"])
        ),
    )

    count = ccs.sync_category_catalog(conn)

    assert count == 1
    assert conn.execute("SELECT slug FROM category_catalog").fetchone()["slug"] == "porn"


def test_sync_category_catalog_raises_on_malformed_json(monkeypatch, conn):
    monkeypatch.setattr(
        category_fetch._OPENER, "open",
        lambda request, timeout=None: FakeResponse(b"not json"),
    )

    with pytest.raises(category_fetch.CategoryFetchError):
        ccs.sync_category_catalog(conn)


def test_sync_category_catalog_raises_on_unreachable_host(monkeypatch, conn):
    def fake_open(request, timeout=None):
        raise category_fetch.URLError("connection refused")

    monkeypatch.setattr(category_fetch._OPENER, "open", fake_open)

    with pytest.raises(category_fetch.CategoryFetchError):
        ccs.sync_category_catalog(conn)


def test_sync_category_catalog_logs_a_warning_when_the_tree_was_truncated(monkeypatch, conn, caplog):
    import json as _json

    body = _json.dumps({"truncated": True, "tree": [{"path": "data/category-porn", "type": "blob"}]}).encode()
    monkeypatch.setattr(category_fetch._OPENER, "open", lambda request, timeout=None: FakeResponse(body))

    with caplog.at_level("WARNING"):
        ccs.sync_category_catalog(conn)

    assert any("truncated" in r.message for r in caplog.records)


# ============================================================
# start -- wiring sync_category_catalog() into a background thread
# ============================================================

def test_start_ticks_immediately_not_after_a_full_interval(monkeypatch, conn):
    """Same class of bug controller/periodic.py was fixed for
    2026-09-07: with an 86400s default interval, waiting a full
    interval before the first tick would mean a fresh install stays on
    the bundled day-one seed for a full day before ever attempting a
    live refresh."""
    calls = []
    monkeypatch.setattr(ccs, "sync_category_catalog", lambda conn, timeout=20.0: calls.append(1) or 0)

    stop = threading.Event()
    thread = ccs.start(interval=10.0, stop_event=stop)
    try:
        deadline = time.monotonic() + 2.0
        while not calls and time.monotonic() < deadline:
            time.sleep(0.02)
        assert calls, "expected the first sync to fire almost immediately, not after the 10s interval"
    finally:
        stop.set()
        thread.join(timeout=2.0)


def test_start_calls_repeatedly_on_the_interval(monkeypatch):
    calls = []
    monkeypatch.setattr(ccs, "sync_category_catalog", lambda conn, timeout=20.0: calls.append(1) or 0)

    stop = threading.Event()
    thread = ccs.start(interval=0.02, stop_event=stop)
    try:
        time.sleep(0.15)
    finally:
        stop.set()
        thread.join(timeout=2.0)

    assert len(calls) >= 2


def test_start_stops_promptly(monkeypatch):
    monkeypatch.setattr(ccs, "sync_category_catalog", lambda conn, timeout=20.0: 0)

    stop = threading.Event()
    thread = ccs.start(interval=5.0, stop_event=stop)
    time.sleep(0.02)
    started_stop = time.monotonic()
    stop.set()
    thread.join(timeout=2.0)
    elapsed = time.monotonic() - started_stop

    assert elapsed < 1.0, f"stop took {elapsed:.3f}s, expected it to return promptly"


def test_start_survives_a_failed_cycle_and_keeps_ticking(monkeypatch):
    calls = []

    def _boom(conn, timeout=20.0):
        calls.append(1)
        raise category_fetch.CategoryFetchError("simulated failure")

    monkeypatch.setattr(ccs, "sync_category_catalog", _boom)

    stop = threading.Event()
    thread = ccs.start(interval=0.02, stop_event=stop)
    try:
        time.sleep(0.15)
    finally:
        stop.set()
        thread.join(timeout=2.0)

    assert len(calls) >= 2, "a failed cycle must not kill the loop"
