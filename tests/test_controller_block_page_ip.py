"""common/optigate_rewrite.py's parse_block_page_ip: extracting a plain
IPv4 host from a DASHBOARD_URL-shaped value for the $dnsrewrite target.

Moved here from controller/main.py's own private _parse_block_page_ip
2026-09-08, alongside the function itself -- see
common/optigate_rewrite.py's own docstring for why: both
controller/adguard_sync.py's periodic cycle AND dashboard.py's own
direct push (the fix for the feature silently not working when the
interception profile is off) need this, so it moved to common/ the
same way category_fetch.py already did for an analogous "both
containers need this" case."""
from __future__ import annotations

import pytest

from optigate_rewrite import parse_block_page_ip


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://192.168.1.50:8787", "192.168.1.50"),
        ("http://192.168.1.50", "192.168.1.50"),
        ("https://10.0.0.5:8787", "10.0.0.5"),
    ],
)
def test_extracts_a_plain_ipv4_host(url, expected):
    assert parse_block_page_ip(url) == expected


def test_none_when_unset():
    assert parse_block_page_ip(None) is None
    assert parse_block_page_ip("") is None


def test_none_for_a_real_hostname():
    """A hostname needs DNS resolution to become useful, which is
    circular for a rule that exists to REPLACE DNS resolution --
    $dnsrewrite needs a literal IP."""
    assert parse_block_page_ip("http://dashboard.example.com:8787") is None


def test_none_for_an_ipv6_host():
    assert parse_block_page_ip("http://[::1]:8787") is None


def test_none_for_malformed_url():
    assert parse_block_page_ip("not a url at all") is None
    assert parse_block_page_ip("http://") is None
