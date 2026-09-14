"""common/series_resolve.py: object-id -> series-id cache, including the
stale-on-error fallback (serve an expired positive cache entry rather
than break playback when Crunchyroll's API is unreachable / the anonymous
client id has been rotated).
"""
from __future__ import annotations

import time

import cr_api
import db
import pytest
import series_resolve


class FakeResolver:
    def __init__(self, mapping: dict | None = None, error: Exception | None = None):
        self.mapping = mapping or {}
        self.error = error
        self.calls: list[tuple[str, ...]] = []

    def resolve(self, object_ids):
        ids = tuple(object_ids)
        self.calls.append(ids)
        if self.error is not None:
            raise self.error
        return {i: self.mapping.get(i) for i in ids}


@pytest.fixture(autouse=True)
def reset_module_singleton():
    series_resolve._resolver = None
    yield
    series_resolve._resolver = None


def _install(monkeypatch, fake: FakeResolver):
    monkeypatch.setattr(series_resolve, "_get_resolver", lambda: fake)
    return fake


def test_resolve_unknown_id_calls_resolver_and_caches(conn, monkeypatch):
    fake = _install(monkeypatch, FakeResolver({"OBJ1": "SER1"}))
    result = series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert result == {"OBJ1": "SER1"}
    assert fake.calls == [("OBJ1",)]

    row = conn.execute("SELECT * FROM series_cache WHERE object_id = 'OBJ1'").fetchone()
    assert row["series_id"] == "SER1"


def test_resolve_second_call_uses_cache_not_resolver(conn, monkeypatch):
    fake = _install(monkeypatch, FakeResolver({"OBJ1": "SER1"}))
    series_resolve.resolve_series_ids(conn, ("OBJ1",))
    result = series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert result == {"OBJ1": "SER1"}
    assert fake.calls == [("OBJ1",)]  # resolver only ever called once


def test_negative_result_is_cached_and_not_re_resolved_within_ttl(conn, monkeypatch):
    fake = _install(monkeypatch, FakeResolver({"OBJ1": None}))
    first = series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert first == {"OBJ1": None}

    second = series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert second == {"OBJ1": None}
    assert fake.calls == [("OBJ1",)]  # negative cache hit, no second call


def test_expired_positive_entry_is_re_resolved_normally(conn, monkeypatch):
    fake = _install(monkeypatch, FakeResolver({"OBJ1": "SER1"}))
    series_resolve.resolve_series_ids(conn, ("OBJ1",))
    conn.execute("UPDATE series_cache SET expires_at = ? WHERE object_id = 'OBJ1'", (time.time() - 1,))
    conn.commit()

    fake.mapping["OBJ1"] = "SER1_UPDATED"
    result = series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert result == {"OBJ1": "SER1_UPDATED"}
    assert len(fake.calls) == 2


def test_expired_negative_entry_is_not_served_stale_and_is_rechecked(conn, monkeypatch):
    """Docstring contract: an expired negative entry is never served stale --
    we re-check instead of blocking a show forever on a lookup that might
    now succeed."""
    fake = _install(monkeypatch, FakeResolver({"OBJ1": None}))
    series_resolve.resolve_series_ids(conn, ("OBJ1",))
    conn.execute("UPDATE series_cache SET expires_at = ? WHERE object_id = 'OBJ1'", (time.time() - 1,))
    conn.commit()

    fake.mapping["OBJ1"] = "SER1"  # now resolvable
    result = series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert result == {"OBJ1": "SER1"}
    assert len(fake.calls) == 2


def test_resolver_failure_with_no_prior_cache_fails_closed(conn, monkeypatch):
    _install(monkeypatch, FakeResolver(error=cr_api.ResolutionError("down")))
    result = series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert result is None


def test_resolver_failure_with_stale_positive_cache_serves_stale(conn, monkeypatch):
    """When the anonymous client id gets rotated / API goes down, a show
    that was already resolved must keep playing, not break."""
    fake = _install(monkeypatch, FakeResolver({"OBJ1": "SER1"}))
    series_resolve.resolve_series_ids(conn, ("OBJ1",))
    conn.execute("UPDATE series_cache SET expires_at = ? WHERE object_id = 'OBJ1'", (time.time() - 1,))
    conn.commit()

    fake.error = cr_api.ResolutionError("client id rotated")
    result = series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert result == {"OBJ1": "SER1"}  # served from stale cache, not None


def test_resolver_failure_records_error_setting(conn, monkeypatch):
    _install(monkeypatch, FakeResolver(error=cr_api.ResolutionError("client id rotated")))
    series_resolve.resolve_series_ids(conn, ("OBJ1",))
    err = db.get_setting(conn, series_resolve._RESOLVER_ERROR_KEY)
    assert err is not None
    assert "client id rotated" in err


def test_successful_resolve_clears_previously_recorded_error(conn, monkeypatch):
    db.set_setting(conn, series_resolve._RESOLVER_ERROR_KEY, "some old error")
    conn.commit()

    _install(monkeypatch, FakeResolver({"OBJ1": "SER1"}))
    series_resolve.resolve_series_ids(conn, ("OBJ1",))
    assert db.get_setting(conn, series_resolve._RESOLVER_ERROR_KEY) is None


def test_mixed_batch_only_resolves_unknown_ids(conn, monkeypatch):
    fake = _install(monkeypatch, FakeResolver({"OBJ1": "SER1", "OBJ2": "SER2"}))
    series_resolve.resolve_series_ids(conn, ("OBJ1",))  # caches OBJ1
    fake.calls.clear()

    result = series_resolve.resolve_series_ids(conn, ("OBJ1", "OBJ2"))
    assert result == {"OBJ1": "SER1", "OBJ2": "SER2"}
    assert fake.calls == [("OBJ2",)]  # only the uncached id was sent


def test_resolve_with_no_object_ids_returns_empty_without_calling_resolver(conn, monkeypatch):
    fake = _install(monkeypatch, FakeResolver())
    assert series_resolve.resolve_series_ids(conn, ()) == {}
    assert fake.calls == []
