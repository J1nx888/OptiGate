#!/usr/bin/env python3
"""Classify Crunchyroll request URLs for the authz helper.

This module performs no network I/O and stores no state. It only decides
what kind of request a (decrypted, bump-mode) URL is, and whether it carries
one or more Crunchyroll object IDs that need show-level resolution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class RequestKind(Enum):
    SERIES_PAGE = "series_page"
    WATCH_PAGE = "watch_page"
    PLAYBACK = "playback"
    UP_NEXT = "up_next"
    CMS_OBJECTS = "cms_objects"
    BLOCKED_SHAPE = "blocked_shape"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class ClassifiedRequest:
    kind: RequestKind
    ids: tuple[str, ...] = ()


SERIES_URL_RE = re.compile(
    r"^https://www\.crunchyroll\.com/series/([A-Za-z0-9]+)"
    r"(?:/[^?#]*)?(?:\?[^#]*)?(?:#.*)?$",
    re.IGNORECASE,
)

WATCH_URL_RE = re.compile(
    r"^https://www\.crunchyroll\.com/watch/([A-Za-z0-9]+)"
    r"(?:/[^?#]*)?(?:\?[^#]*)?(?:#.*)?$",
    re.IGNORECASE,
)

PLAYBACK_URL_RE = re.compile(
    r"^https://www\.crunchyroll\.com/playback/"
    r"v\d+/"
    r"(?:(?:manifest|token)/)?"
    r"([A-Za-z0-9]+)"
    r"(?:/.*)?$",
    re.IGNORECASE,
)

CMS_OBJECTS_URL_RE = re.compile(
    r"^https://www\.crunchyroll\.com/content/v\d+/cms/objects/"
    r"([A-Za-z0-9]+(?:,[A-Za-z0-9]+)*)(?:\?[^#]*)?(?:#.*)?$",
    re.IGNORECASE,
)

# Added 2026-09-10 (RoadMap.md finding #1d, docs/design/crunchyroll-trace-
# 2026-09-10/ANALYSIS.md item 1): the "continue watching" / "next episode"
# feed for a series page. The series id is already in the URL path (no
# resolver round-trip needed, same direct matching.user_has_show() check
# SERIES_PAGE gets below) -- confirmed live by probe 2026-09-10. Before
# this classifier existed, a request here fell through to OTHER and was
# blanket-allowed by the (now removed, see defaults/seed_defaults.py)
# `^/content/v[0-9]+/` domain_paths rule -- i.e. genuinely unfiltered
# regardless of show ownership. This closes that gap.
UP_NEXT_URL_RE = re.compile(
    r"^https://www\.crunchyroll\.com/content/v\d+/discover/up_next/"
    r"([A-Za-z0-9]+)(?:\?[^#]*)?(?:#.*)?$",
    re.IGNORECASE,
)

GUARDED_MARKERS = (
    "/watch/",
    "/playback/",
    "/cms/objects/",
    "/discover/up_next/",
)


def classify(url: str) -> ClassifiedRequest:
    """Classify one decrypted Crunchyroll-domain request URL.

    Fail-closed rule: if a URL looks like a guarded route but doesn't match
    a supported safe shape, it's BLOCKED_SHAPE instead of OTHER, so an
    unrecognized variant of a sensitive endpoint doesn't slip through as a
    plain page view.
    """
    if not isinstance(url, str) or not url:
        return ClassifiedRequest(RequestKind.BLOCKED_SHAPE)

    match = SERIES_URL_RE.fullmatch(url)
    if match:
        return ClassifiedRequest(RequestKind.SERIES_PAGE, (match.group(1).upper(),))

    match = WATCH_URL_RE.fullmatch(url)
    if match:
        return ClassifiedRequest(RequestKind.WATCH_PAGE, (match.group(1).upper(),))

    match = PLAYBACK_URL_RE.fullmatch(url)
    if match:
        return ClassifiedRequest(RequestKind.PLAYBACK, (match.group(1).upper(),))

    match = UP_NEXT_URL_RE.fullmatch(url)
    if match:
        return ClassifiedRequest(RequestKind.UP_NEXT, (match.group(1).upper(),))

    match = CMS_OBJECTS_URL_RE.fullmatch(url)
    if match:
        ids = tuple(part.upper() for part in match.group(1).split(',') if part)
        if not ids:
            return ClassifiedRequest(RequestKind.BLOCKED_SHAPE)
        return ClassifiedRequest(RequestKind.CMS_OBJECTS, ids)

    lowered = url.casefold()
    if any(marker in lowered for marker in GUARDED_MARKERS):
        return ClassifiedRequest(RequestKind.BLOCKED_SHAPE)

    return ClassifiedRequest(RequestKind.OTHER)
