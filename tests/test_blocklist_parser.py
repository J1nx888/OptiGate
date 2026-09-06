"""Phase 8: common/blocklist_parser.py -- pure text extraction from the
three real formats confirmed live against
https://github.com/blocklistproject/Lists, plus a fourth (full URL per
line, added 2026-09-08) confirmed live against a real social-networking-
sites list of that shape (see that module's docstring)."""
from __future__ import annotations

import blocklist_parser


def test_adguard_format():
    text = "||example.com^\n||sub.example.org^$important\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com", "sub.example.org"]


def test_hosts_format_both_null_route_ips():
    text = "0.0.0.0 example.com\n127.0.0.1 other.example.com\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com", "other.example.com"]


def test_hosts_format_ipv6_null_route():
    text = ":: example.com\n::1 other.example.com\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com", "other.example.com"]


def test_hosts_format_multiple_aliases_on_one_line():
    text = "0.0.0.0 example.com www.example.com\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com", "www.example.com"]


def test_bare_domain_per_line():
    text = "example.com\nanother.example.org\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com", "another.example.org"]


def test_full_line_comments_and_blank_lines_skipped():
    text = "# a comment\n! also a comment\n\n   \nexample.com\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com"]


def test_header_block_like_real_blocklistproject_file():
    text = (
        "! Title: Porn Block List\n"
        "! Description: Adult content domains\n"
        "! Format: AdGuard\n"
        "!\n"
        "||example-adult-site.com^\n"
    )
    assert blocklist_parser.parse_hostlist(text) == ["example-adult-site.com"]


def test_deduplicates_preserving_first_seen_order():
    text = "example.com\n||example.com^\n0.0.0.0 example.com\nzzz.example.com\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com", "zzz.example.com"]


def test_lowercases_and_strips_trailing_dot():
    text = "EXAMPLE.COM.\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com"]


def test_malformed_lines_skipped_not_raised():
    text = (
        "@@||exception.example.com^\n"  # exception rule -- not a form this parser understands
        "not a domain at all!!\n"
        "/some-regex-rule/\n"
        "example.com\n"
    )
    assert blocklist_parser.parse_hostlist(text) == ["example.com"]


def test_empty_input_returns_empty_list():
    assert blocklist_parser.parse_hostlist("") == []


def test_whitespace_only_lines_and_crlf_handled():
    text = "example.com\r\n   \r\nother.example.org\r\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com", "other.example.org"]


# --- full-URL-per-line format (added 2026-09-08) --------------------------

def test_full_url_per_line():
    text = "http://example.com\nhttps://other.example.org\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com", "other.example.org"]


def test_full_url_with_path_and_query_extracts_just_the_host():
    text = "https://example.com/some/path?query=1&other=2\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com"]


def test_full_url_is_case_insensitive_scheme_and_host():
    text = "HTTP://ANobii.com\n"
    assert blocklist_parser.parse_hostlist(text) == ["anobii.com"]


def test_full_url_real_world_edge_cases():
    # Confirmed live 2026-09-08 against the actual file that surfaced this
    # gap: a query string glued directly onto the bare hostname with no
    # "/" separator, and a bare "#" fragment marker with nothing after it.
    text = (
        "http://bebo.com#\n"
        "http://www.bolt.com?p=tgraph&r=home_home\n"
        "http://43things.com\n"
    )
    assert blocklist_parser.parse_hostlist(text) == ["bebo.com", "www.bolt.com", "43things.com"]


def test_full_url_deduplicates_with_other_formats_for_the_same_host():
    text = "http://example.com\nexample.com\n||example.com^\n"
    assert blocklist_parser.parse_hostlist(text) == ["example.com"]
