#!/usr/bin/env python3
"""Resolve Crunchyroll object IDs to parent series IDs via the CMS API.

The helper uses Crunchyroll's anonymous web-client token flow to read metadata.
It does not use the viewer's account credentials and does not grant playback.
"""
from __future__ import annotations

import json
import time
import urllib.parse
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

TOKEN_URL = "https://www.crunchyroll.com/auth/v1/token"
OBJECTS_URL = "https://www.crunchyroll.com/content/v2/cms/objects/{ids}"

# base64("cr_web:"). This is Crunchyroll's public anonymous web client ID with
# an empty secret. If token requests start returning 401 invalid_client, rederive
# the anonymous client ID from the Crunchyroll web app and update this value.
ANON_BASIC_CREDENTIAL = "Y3Jfd2ViOg=="
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT = 5.0
TOKEN_REFRESH_MARGIN = 300.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class ResolutionError(RuntimeError):
    """Raised when a lookup could not be completed. Callers must fail closed."""


# Bypass environment proxy variables. The helper must not call back through the
# same Squid instance that is waiting for the helper's verdict.
_OPENER = build_opener(ProxyHandler({}))


def _read_json(request: Request, timeout: float) -> dict[str, Any]:
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES)
    except HTTPError as exc:
        detail = exc.read(300).decode("utf-8", errors="replace")
        raise ResolutionError(f"HTTP {exc.code} from {request.full_url}: {detail}")
    except URLError as exc:
        raise ResolutionError(f"could not reach {request.full_url}: {exc.reason}")
    except TimeoutError:
        raise ResolutionError(f"request to {request.full_url} timed out")

    try:
        decoded = json.loads(body)
    except ValueError as exc:
        raise ResolutionError(f"malformed JSON from {request.full_url}: {exc}")
    if not isinstance(decoded, dict):
        raise ResolutionError(f"expected a JSON object from {request.full_url}")
    return decoded


class TokenManager:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._token: str | None = None
        self._expires_at = 0.0

    def token(self, force_refresh: bool = False) -> str:
        if force_refresh or self._token is None or time.monotonic() >= self._expires_at:
            self._refresh()
        assert self._token is not None
        return self._token

    def _refresh(self) -> None:
        request = Request(
            TOKEN_URL,
            data=b"grant_type=client_id",
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": f"Basic {ANON_BASIC_CREDENTIAL}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            method="POST",
        )
        payload = _read_json(request, self._timeout)
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ResolutionError("token response contained no access_token")
        expires_in = payload.get("expires_in")
        lifetime = float(expires_in) if isinstance(expires_in, (int, float)) else 3600.0
        self._token = access_token
        self._expires_at = time.monotonic() + max(lifetime - TOKEN_REFRESH_MARGIN, 60.0)


def series_id_of(entry: dict[str, Any]) -> str | None:
    """Return the parent series ID for a CMS object entry, or None if unknown.

    An 'episode' entry has episode_metadata.series_id; a 'series' entry
    has no series_id-shaped field, only its own id. season_metadata has
    no series_id field in the current API -- the parent series is only
    present as the first half of a pipe-delimited `identifier` string
    ("SERIESID|SEASONCODE"), which isn't reliable enough to parse here,
    and isn't needed since series_resolve.py never looks up a season
    object directly (only episode/playback objects). The top-level
    `series_id` fallback covers movie/musicvideo/concert object types
    that could reach this via a playback URL -- costs nothing when
    absent, and avoids silently failing closed on content this hasn't
    been checked against.
    """
    episode_metadata = entry.get("episode_metadata")
    if isinstance(episode_metadata, dict):
        series_id = episode_metadata.get("series_id")
        if isinstance(series_id, str) and series_id:
            return series_id.upper()

    # Cheap fallback for object types not covered above -- see docstring.
    own_parent = entry.get("series_id")
    if isinstance(own_parent, str) and own_parent:
        return own_parent.upper()

    if entry.get("type") == "series":
        own_id = entry.get("id")
        if isinstance(own_id, str) and own_id:
            return own_id.upper()

    return None


class SeriesResolver:
    """Resolve CMS object IDs to parent series IDs, retrying once on stale token."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._tokens = TokenManager(timeout=timeout)

    def resolve(self, object_ids: Iterable[str]) -> dict[str, str | None]:
        wanted = tuple(dict.fromkeys(obj.upper() for obj in object_ids if obj))
        if not wanted:
            return {}
        query = urllib.parse.urlencode({"locale": "en-US", "ratings": "false"})
        payload = self._get_json(OBJECTS_URL.format(ids=",".join(wanted)) + "?" + query)
        resolved: dict[str, str | None] = {object_id: None for object_id in wanted}
        entries = payload.get("data")
        if not isinstance(entries, list):
            raise ResolutionError("objects response contained no data list")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            entry_id = entry.get("id")
            if isinstance(entry_id, str):
                key = entry_id.upper()
                if key in resolved:
                    resolved[key] = series_id_of(entry)
        return resolved

    def _get_json(self, url: str) -> dict[str, Any]:
        for force_refresh in (False, True):
            token = self._tokens.token(force_refresh=force_refresh)
            request = Request(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            )
            try:
                return _read_json(request, self._timeout)
            except ResolutionError as exc:
                if force_refresh or "HTTP 401" not in str(exc):
                    raise
        raise ResolutionError(f"could not fetch {url}")


_shared_resolver: SeriesResolver | None = None


def series_title(series_id: str, timeout: float = DEFAULT_TIMEOUT) -> str | None:
    """Best-effort display title for a series id, via the CMS objects endpoint.
    Returns None if the API is unreachable -- callers fall back to the raw id.
    Used by the dashboard for the "Approve" button and show-add form."""
    global _shared_resolver
    if _shared_resolver is None:
        _shared_resolver = SeriesResolver(timeout=timeout)
    query = urllib.parse.urlencode({"locale": "en-US"})
    try:
        payload = _shared_resolver._get_json(
            OBJECTS_URL.format(ids=series_id.upper()) + "?" + query
        )
    except Exception:  # display-only helper -- never propagate into a request
        return None
    for entry in payload.get("data", []):
        if isinstance(entry, dict) and str(entry.get("id", "")).upper() == series_id.upper():
            title = entry.get("title")
            if isinstance(title, str) and title:
                return title
    return None
