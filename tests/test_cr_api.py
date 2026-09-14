"""common/cr_api.py: Crunchyroll CMS API client -- token refresh, retry-on-401,
error wrapping, and series_id_of's fallback branches. All network access goes
through cr_api._OPENER.open, which every test here replaces with a fake.
"""
from __future__ import annotations

import json
import time
from urllib.error import HTTPError, URLError

import pytest

import cr_api


class FakeResponse:
    """Minimal stand-in for the context-manager object urlopen()/opener.open()
    returns -- only `.read(n)` and context-manager protocol are used by
    cr_api._read_json."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self, n: int = -1) -> bytes:
        return self._body if n is None or n < 0 else self._body[:n]

    def close(self) -> None:
        pass  # HTTPError wraps `fp` in addinfourl, which closes it on GC

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _json_response(payload) -> FakeResponse:
    return FakeResponse(json.dumps(payload).encode("utf-8"))


@pytest.fixture(autouse=True)
def reset_shared_resolver():
    """cr_api.series_title() caches a module-global SeriesResolver (with its
    own cached token) -- reset it so tests don't leak state into each other."""
    cr_api._shared_resolver = None
    yield
    cr_api._shared_resolver = None


# ============================================================
# TokenManager
# ============================================================

def test_token_manager_refreshes_and_caches(monkeypatch):
    calls = []

    def fake_open(request, timeout=None):
        calls.append(request.full_url)
        return _json_response({"access_token": "tok-1", "expires_in": 3600})

    monkeypatch.setattr(cr_api._OPENER, "open", fake_open)
    manager = cr_api.TokenManager()

    assert manager.token() == "tok-1"
    assert manager.token() == "tok-1"  # cached, no second HTTP call
    assert len(calls) == 1
    assert calls[0] == cr_api.TOKEN_URL


def test_token_manager_force_refresh_calls_again(monkeypatch):
    tokens = iter(["tok-1", "tok-2"])
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: _json_response({"access_token": next(tokens), "expires_in": 3600}),
    )
    manager = cr_api.TokenManager()
    assert manager.token() == "tok-1"
    assert manager.token(force_refresh=True) == "tok-2"


def test_token_manager_missing_access_token_raises(monkeypatch):
    monkeypatch.setattr(
        cr_api._OPENER, "open", lambda request, timeout=None: _json_response({"expires_in": 3600})
    )
    manager = cr_api.TokenManager()
    with pytest.raises(cr_api.ResolutionError):
        manager.token()


def test_token_manager_non_numeric_expires_in_uses_default_lifetime(monkeypatch):
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: _json_response({"access_token": "tok-1", "expires_in": "not-a-number"}),
    )
    manager = cr_api.TokenManager()
    before = time.monotonic()
    assert manager.token() == "tok-1"
    # default lifetime is 3600s minus the 300s refresh margin
    assert manager._expires_at >= before + 3600 - cr_api.TOKEN_REFRESH_MARGIN - 1


# ============================================================
# _read_json error handling
# ============================================================

def test_read_json_http_error_wrapped(monkeypatch):
    def fake_open(request, timeout=None):
        raise HTTPError(request.full_url, 401, "invalid_client", None, FakeResponse(b"nope"))

    monkeypatch.setattr(cr_api._OPENER, "open", fake_open)
    with pytest.raises(cr_api.ResolutionError, match="HTTP 401"):
        cr_api._read_json(cr_api.Request(cr_api.TOKEN_URL), 1.0)


def test_read_json_url_error_wrapped(monkeypatch):
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: (_ for _ in ()).throw(URLError("dns failure")),
    )
    with pytest.raises(cr_api.ResolutionError, match="could not reach"):
        cr_api._read_json(cr_api.Request(cr_api.TOKEN_URL), 1.0)


def test_read_json_timeout_wrapped(monkeypatch):
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: (_ for _ in ()).throw(TimeoutError()),
    )
    with pytest.raises(cr_api.ResolutionError, match="timed out"):
        cr_api._read_json(cr_api.Request(cr_api.TOKEN_URL), 1.0)


def test_read_json_malformed_json_wrapped(monkeypatch):
    monkeypatch.setattr(cr_api._OPENER, "open", lambda request, timeout=None: FakeResponse(b"{not json"))
    with pytest.raises(cr_api.ResolutionError, match="malformed JSON"):
        cr_api._read_json(cr_api.Request(cr_api.TOKEN_URL), 1.0)


def test_read_json_non_dict_payload_wrapped(monkeypatch):
    monkeypatch.setattr(cr_api._OPENER, "open", lambda request, timeout=None: _json_response([1, 2, 3]))
    with pytest.raises(cr_api.ResolutionError, match="expected a JSON object"):
        cr_api._read_json(cr_api.Request(cr_api.TOKEN_URL), 1.0)


# ============================================================
# SeriesResolver.resolve
# ============================================================

def _stub_token(monkeypatch, resolver):
    """Skip the token dance for tests that only care about the objects call."""
    monkeypatch.setattr(resolver._tokens, "token", lambda force_refresh=False: "tok")


def test_resolve_empty_object_ids_short_circuits(monkeypatch):
    resolver = cr_api.SeriesResolver()

    def fake_open(request, timeout=None):
        pytest.fail("should not make an HTTP call for an empty id list")

    monkeypatch.setattr(cr_api._OPENER, "open", fake_open)
    assert resolver.resolve([]) == {}


def test_resolve_dedupes_and_uppercases_ids(monkeypatch):
    resolver = cr_api.SeriesResolver()
    _stub_token(monkeypatch, resolver)
    seen_urls = []

    def fake_open(request, timeout=None):
        seen_urls.append(request.full_url)
        return _json_response({"data": []})

    monkeypatch.setattr(cr_api._OPENER, "open", fake_open)
    resolver.resolve(["abc123", "ABC123", "def456"])
    assert len(seen_urls) == 1
    assert "ABC123,DEF456" in seen_urls[0]


def test_resolve_happy_path_maps_entries_by_id(monkeypatch):
    resolver = cr_api.SeriesResolver()
    _stub_token(monkeypatch, resolver)
    payload = {
        "data": [
            {"id": "OBJ1", "episode_metadata": {"series_id": "SER1"}},
            {"id": "obj2", "type": "series"},
        ]
    }
    monkeypatch.setattr(cr_api._OPENER, "open", lambda request, timeout=None: _json_response(payload))
    result = resolver.resolve(["OBJ1", "OBJ2", "OBJ3"])
    assert result == {"OBJ1": "SER1", "OBJ2": "OBJ2", "OBJ3": None}


def test_resolve_missing_data_list_raises(monkeypatch):
    resolver = cr_api.SeriesResolver()
    _stub_token(monkeypatch, resolver)
    monkeypatch.setattr(cr_api._OPENER, "open", lambda request, timeout=None: _json_response({"data": "nope"}))
    with pytest.raises(cr_api.ResolutionError, match="no data list"):
        resolver.resolve(["OBJ1"])


def test_get_json_retries_once_on_401_then_succeeds(monkeypatch):
    resolver = cr_api.SeriesResolver()
    tokens_used = []

    def fake_token(force_refresh=False):
        token = "stale" if not force_refresh else "fresh"
        tokens_used.append(token)
        return token

    monkeypatch.setattr(resolver._tokens, "token", fake_token)

    def fake_open(request, timeout=None):
        if request.headers.get("Authorization") == "Bearer stale":
            raise HTTPError(request.full_url, 401, "expired", None, FakeResponse(b"expired"))
        return _json_response({"data": []})

    monkeypatch.setattr(cr_api._OPENER, "open", fake_open)
    result = resolver._get_json("https://example.invalid/x")
    assert result == {"data": []}
    assert tokens_used == ["stale", "fresh"]


def test_get_json_401_twice_raises(monkeypatch):
    resolver = cr_api.SeriesResolver()
    monkeypatch.setattr(resolver._tokens, "token", lambda force_refresh=False: "tok")
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: (_ for _ in ()).throw(
            HTTPError(request.full_url, 401, "still expired", None, FakeResponse(b"x"))
        ),
    )
    with pytest.raises(cr_api.ResolutionError, match="HTTP 401"):
        resolver._get_json("https://example.invalid/x")


def test_get_json_non_401_error_does_not_retry(monkeypatch):
    resolver = cr_api.SeriesResolver()
    calls = []

    def fake_token(force_refresh=False):
        calls.append(force_refresh)
        return "tok"

    monkeypatch.setattr(resolver._tokens, "token", fake_token)
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: (_ for _ in ()).throw(
            HTTPError(request.full_url, 500, "server error", None, FakeResponse(b"x"))
        ),
    )
    with pytest.raises(cr_api.ResolutionError, match="HTTP 500"):
        resolver._get_json("https://example.invalid/x")
    assert calls == [False]  # never retried


# ============================================================
# series_id_of fallback branches
# ============================================================

def test_series_id_of_episode_metadata_branch():
    assert cr_api.series_id_of({"episode_metadata": {"series_id": "abc"}}) == "ABC"


def test_series_id_of_type_series_branch():
    assert cr_api.series_id_of({"type": "series", "id": "abc"}) == "ABC"


def test_series_id_of_top_level_series_id_fallback():
    """Defensive coverage for object types (movie/musicvideo/concert) that
    have never been observed on real episode/season/series data, but cost
    nothing to support if encountered."""
    assert cr_api.series_id_of({"series_id": "abc"}) == "ABC"


def test_series_id_of_prefers_episode_metadata_over_top_level():
    entry = {
        "episode_metadata": {"series_id": "from_episode"},
        "series_id": "from_top_level",
    }
    assert cr_api.series_id_of(entry) == "FROM_EPISODE"


def test_series_id_of_no_match_returns_none():
    assert cr_api.series_id_of({"type": "episode", "id": "abc"}) is None
    assert cr_api.series_id_of({}) is None


def test_series_id_of_real_season_shape_has_no_series_id_field():
    """A season entry's season_metadata has no series_id field at all (the
    parent series only appears inside a pipe-delimited `identifier` string),
    so it must resolve to None rather than crash or match something
    unrelated."""
    real_season_entry = {
        "id": "GR19CPDWM",
        "type": "season",
        "title": "Solo Leveling",
        "season_metadata": {
            "audio_locales": ["ja-JP"],
            "season_display_number": "1",
            "season_sequence_number": 1,
            "identifier": "GDKHZEJ0K|S00320668",
        },
    }
    assert cr_api.series_id_of(real_season_entry) is None


def test_series_id_of_real_series_shape_has_only_id_and_type():
    """A 'series' object entry has no fields beyond id/type, so the
    type=='series' branch using its own id is the only way to resolve it."""
    real_series_entry = {"id": "GDKHZEJ0K", "type": "series"}
    assert cr_api.series_id_of(real_series_entry) == "GDKHZEJ0K"


def test_series_id_of_ignores_non_string_or_empty_values():
    assert cr_api.series_id_of({"episode_metadata": {"series_id": ""}}) is None
    assert cr_api.series_id_of({"episode_metadata": {"series_id": 123}}) is None


# ============================================================
# series_title (display-only helper, must never raise)
# ============================================================
#
# series_title() lazily creates a module-global SeriesResolver and calls its
# _get_json(), which fetches a token *before* the objects request. To
# exercise the id-lookup logic in isolation (rather than accidentally
# testing token-fetch failure, which also happens to return None), these
# tests pre-install a shared resolver with its token call stubbed out, so
# the one _OPENER.open() call each test mocks is unambiguously the objects
# request.

@pytest.fixture
def shared_resolver_stub_token():
    resolver = cr_api.SeriesResolver()
    resolver._tokens.token = lambda force_refresh=False: "tok"
    cr_api._shared_resolver = resolver
    return resolver


def test_series_title_happy_path(shared_resolver_stub_token, monkeypatch):
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: _json_response(
            {"data": [{"id": "GYE5K0XVR", "title": "Ace Attorney"}]}
        ),
    )
    assert cr_api.series_title("gye5k0xvr") == "Ace Attorney"


def test_series_title_returns_none_when_id_not_found(shared_resolver_stub_token, monkeypatch):
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: _json_response({"data": [{"id": "OTHER", "title": "Other"}]}),
    )
    assert cr_api.series_title("GYE5K0XVR") is None


def test_series_title_swallows_any_error_and_returns_none(shared_resolver_stub_token, monkeypatch):
    monkeypatch.setattr(
        cr_api._OPENER, "open",
        lambda request, timeout=None: (_ for _ in ()).throw(URLError("down")),
    )
    assert cr_api.series_title("GYE5K0XVR") is None


def test_series_title_reuses_shared_resolver_across_calls(monkeypatch):
    def fake_open(request, timeout=None):
        if request.full_url == cr_api.TOKEN_URL:
            return _json_response({"access_token": "tok", "expires_in": 3600})
        return _json_response({"data": []})

    monkeypatch.setattr(cr_api._OPENER, "open", fake_open)
    cr_api.series_title("AAA")
    resolver_after_first = cr_api._shared_resolver
    assert resolver_after_first is not None
    cr_api.series_title("BBB")
    assert cr_api._shared_resolver is resolver_after_first
