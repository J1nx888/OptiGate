"""common/logging_util.py: deduped access-log writer."""
from __future__ import annotations

import db
import logging_util


def _rows(conn):
    return conn.execute("SELECT * FROM access_log ORDER BY id").fetchall()


def test_first_call_inserts_a_row(conn):
    logging_util.log_access(
        conn, user_id=1, username="kid1", domain="crunchyroll.com",
        path=None, allowed=True, reason="global_domain",
    )
    rows = _rows(conn)
    assert len(rows) == 1
    assert rows[0]["username"] == "kid1"
    assert rows[0]["allowed"] == 1


def test_identical_call_within_window_is_suppressed(conn):
    kwargs = dict(
        user_id=1, username="kid1", domain="crunchyroll.com",
        path=None, allowed=False, reason="not_authenticated",
    )
    logging_util.log_access(conn, **kwargs)
    logging_util.log_access(conn, **kwargs)
    logging_util.log_access(conn, **kwargs)
    assert len(_rows(conn)) == 1


def test_different_series_id_is_not_deduped(conn):
    base = dict(user_id=1, username="kid1", domain="crunchyroll.com", path="/watch/x", allowed=False)
    logging_util.log_access(conn, reason="show_not_approved", series_id="AAA111", **base)
    logging_util.log_access(conn, reason="show_not_approved", series_id="BBB222", **base)
    assert len(_rows(conn)) == 2


def test_ip_address_is_stored_when_given(conn):
    """Added 2026-09-07 (RoadMap.md's dated entry): real live-testing
    feedback that a row for a never-recognized device gave nothing to
    track it down by. Optional -- defaults to None, so it's descriptive
    metadata on the row, not a new dedupe dimension (same treatment as
    device_id)."""
    logging_util.log_access(
        conn, user_id=None, username="(unauthenticated)", domain="netflix.com",
        path=None, allowed=False, reason="dns_tier_denied", ip_address="192.168.1.42",
    )
    assert _rows(conn)[0]["ip_address"] == "192.168.1.42"


def test_ip_address_defaults_to_none_and_does_not_affect_dedupe(conn):
    kwargs = dict(
        user_id=1, username="kid1", domain="crunchyroll.com",
        path=None, allowed=False, reason="not_authenticated",
    )
    logging_util.log_access(conn, ip_address="192.168.1.10", **kwargs)
    logging_util.log_access(conn, ip_address="192.168.1.11", **kwargs)  # different IP, same window
    rows = _rows(conn)
    assert len(rows) == 1, "IP is not part of the dedupe key -- a moved IP within the window still collapses"
    assert rows[0]["ip_address"] == "192.168.1.10"


def test_different_series_id_none_vs_value_is_not_deduped(conn):
    base = dict(user_id=1, username="kid1", domain="crunchyroll.com", path="/", allowed=True)
    logging_util.log_access(conn, reason="global_domain", series_id=None, **base)
    logging_util.log_access(conn, reason="show_approved", series_id="AAA111", **base)
    assert len(_rows(conn)) == 2


def test_different_allowed_value_is_not_deduped(conn):
    base = dict(user_id=1, username="kid1", domain="crunchyroll.com", path=None)
    logging_util.log_access(conn, allowed=True, reason="global_domain", **base)
    logging_util.log_access(conn, allowed=False, reason="user_domain", **base)
    assert len(_rows(conn)) == 2


def test_different_path_is_not_deduped(conn):
    """GH #5: path is part of the dedupe key -- browsing multiple different
    pages on the same bump-mode domain within the window must each get
    their own Report row, not collapse into just the first one visited."""
    base = dict(user_id=1, username="kid1", domain="asurascans.example", allowed=True, reason="user_domain")
    logging_util.log_access(conn, path="/comics/series-a", **base)
    logging_util.log_access(conn, path="/comics/series-b", **base)
    rows = _rows(conn)
    assert len(rows) == 2
    assert {r["path"] for r in rows} == {"/comics/series-a", "/comics/series-b"}


def test_path_differing_only_by_query_string_is_deduped(conn):
    """GH #5: the dedupe key normalizes path by stripping the query string,
    so cache-busting/session/tracking params don't create a new Report row
    for what's functionally the same page."""
    base = dict(user_id=1, username="kid1", domain="asurascans.example", allowed=True, reason="user_domain")
    logging_util.log_access(conn, path="/comics/series-a?t=1111", **base)
    logging_util.log_access(conn, path="/comics/series-a?t=2222", **base)
    assert len(_rows(conn)) == 1


def test_path_bearing_call_is_not_suppressed_by_a_prior_path_less_entry(conn):
    """A path-less entry (e.g. sni_helper.py's SNI-layer log, which never
    has a path since nothing is decrypted there) and a later, richer
    path-bearing entry for what's otherwise the same event are different
    dedupe keys under GH #5's path-aware key, so the richer one is never
    hidden behind the earlier, less informative one for the rest of the
    window."""
    base = dict(user_id=1, username="kid1", domain="unknown-site.example", allowed=False, reason="unknown_domain")
    logging_util.log_access(conn, path=None, **base)
    assert len(_rows(conn)) == 1

    logging_util.log_access(conn, path="/watch/some-real-path", **base)
    rows = _rows(conn)
    assert len(rows) == 2
    assert rows[1]["path"] == "/watch/some-real-path"


def test_window_expiry_allows_a_new_row(conn):
    kwargs = dict(
        user_id=1, username="kid1", domain="crunchyroll.com",
        path=None, allowed=False, reason="not_authenticated",
    )
    logging_util.log_access(conn, **kwargs)
    assert len(_rows(conn)) == 1

    # Backdate the existing row past the dedupe window.
    stale_ts = db.iso_secs_ago(logging_util.DEDUPE_WINDOW_SECONDS + 60)
    conn.execute("UPDATE access_log SET ts = ?", (stale_ts,))
    conn.commit()

    logging_util.log_access(conn, **kwargs)
    assert len(_rows(conn)) == 2
