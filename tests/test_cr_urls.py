"""common/cr_urls.py: classifying decrypted Crunchyroll request URLs."""
from __future__ import annotations

import cr_urls
from cr_urls import RequestKind


def test_series_page_happy_path():
    result = cr_urls.classify("https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney")
    assert result.kind is RequestKind.SERIES_PAGE
    assert result.ids == ("GYE5K0XVR",)


def test_series_page_bare_id_no_slug():
    result = cr_urls.classify("https://www.crunchyroll.com/series/gye5k0xvr")
    assert result.kind is RequestKind.SERIES_PAGE
    assert result.ids == ("GYE5K0XVR",)  # normalized to uppercase


def test_series_page_with_query_and_fragment():
    result = cr_urls.classify("https://www.crunchyroll.com/series/GYE5K0XVR?foo=bar#top")
    assert result.kind is RequestKind.SERIES_PAGE
    assert result.ids == ("GYE5K0XVR",)


def test_watch_page_happy_path():
    result = cr_urls.classify("https://www.crunchyroll.com/watch/G6NQ5DWX6/episode-1")
    assert result.kind is RequestKind.WATCH_PAGE
    assert result.ids == ("G6NQ5DWX6",)


def test_playback_via_main_domain():
    result = cr_urls.classify("https://www.crunchyroll.com/playback/v2/G6NQ5DWX6/session")
    assert result.kind is RequestKind.PLAYBACK
    assert result.ids == ("G6NQ5DWX6",)


def test_playback_via_manifest_prefix():
    result = cr_urls.classify("https://www.crunchyroll.com/playback/v2/manifest/G6NQ5DWX6")
    assert result.kind is RequestKind.PLAYBACK
    assert result.ids == ("G6NQ5DWX6",)


def test_up_next_happy_path():
    """RoadMap.md finding #1d: the "continue watching" feed carries the
    series id directly in the path -- confirmed live 2026-09-10."""
    result = cr_urls.classify("https://www.crunchyroll.com/content/v2/discover/up_next/GYEXQKJG6")
    assert result.kind is RequestKind.UP_NEXT
    assert result.ids == ("GYEXQKJG6",)


def test_up_next_normalizes_id_to_uppercase_and_strips_query():
    result = cr_urls.classify("https://www.crunchyroll.com/content/v2/discover/up_next/gyexqkjg6?locale=en-US")
    assert result.kind is RequestKind.UP_NEXT
    assert result.ids == ("GYEXQKJG6",)


def test_blocked_shape_for_malformed_up_next_url():
    """Contains the guarded '/discover/up_next/' marker but no id follows
    -- must fail closed as BLOCKED_SHAPE, not fall through to OTHER (and
    from there to whatever the domain's own path allowlist permits under
    the broader /content/v.../discover/ prefix)."""
    result = cr_urls.classify("https://www.crunchyroll.com/content/v2/discover/up_next/")
    assert result.kind is RequestKind.BLOCKED_SHAPE


def test_cms_objects_single_id():
    result = cr_urls.classify("https://www.crunchyroll.com/content/v2/cms/objects/GYE5K0XVR")
    assert result.kind is RequestKind.CMS_OBJECTS
    assert result.ids == ("GYE5K0XVR",)


def test_cms_objects_multiple_ids():
    result = cr_urls.classify(
        "https://www.crunchyroll.com/content/v2/cms/objects/AAA111,BBB222?locale=en-US"
    )
    assert result.kind is RequestKind.CMS_OBJECTS
    assert result.ids == ("AAA111", "BBB222")


def test_blocked_shape_for_malformed_watch_url():
    """Contains the guarded '/watch/' marker but the id has an invalid
    character, so it doesn't fullmatch WATCH_URL_RE -- must fail closed as
    BLOCKED_SHAPE, not fall through as a plain OTHER page."""
    result = cr_urls.classify("https://www.crunchyroll.com/watch/abc-def!/extra")
    assert result.kind is RequestKind.BLOCKED_SHAPE


def test_blocked_shape_for_malformed_playback_url():
    """Contains the guarded '/playback/' marker but no id follows -- must
    fail closed as BLOCKED_SHAPE, not fall through as a plain OTHER page."""
    result = cr_urls.classify("https://www.crunchyroll.com/playback/v2/")
    assert result.kind is RequestKind.BLOCKED_SHAPE


def test_blocked_shape_for_cms_objects_with_no_ids():
    result = cr_urls.classify("https://www.crunchyroll.com/content/v2/cms/objects/,,")
    assert result.kind is RequestKind.BLOCKED_SHAPE


def test_blocked_shape_for_non_string_or_empty_input():
    assert cr_urls.classify("").kind is RequestKind.BLOCKED_SHAPE
    assert cr_urls.classify(None).kind is RequestKind.BLOCKED_SHAPE  # type: ignore[arg-type]


def test_other_for_plain_page():
    result = cr_urls.classify("https://www.crunchyroll.com/")
    assert result.kind is RequestKind.OTHER


def test_other_for_unrelated_path():
    result = cr_urls.classify("https://www.crunchyroll.com/news/some-article")
    assert result.kind is RequestKind.OTHER
