#!/usr/bin/env python3
"""Phase 8: parses a fetched category blocklist's text into plain domain
names. Pure function, no network access (see controller/category_fetch.py
for the fetch side) -- verified live 2026-08-31 against real files from
https://github.com/blocklistproject/Lists (MIT), which serves three of
the four formats below; the fourth (full-URL-per-line) was added
2026-09-08, verified live against a real list of that shape (see
`parse_hostlist()`'s own docstring).

Returns PLAIN, lowercased domain strings -- NOT regex-escaped. Callers
that store a result into `category_domains.pattern` (matched later via
common/matching.py's `_domain_regex()`-style suffix anchoring, same as
`domains.pattern`) are responsible for `re.escape()`-ing each one first,
same as `defaults/seed_defaults.py` hand-escapes its own seeded patterns
(e.g. `"google\\.com"`) -- kept as a separate step rather than done here,
so this module stays about text extraction only.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

_COMMENT_PREFIXES = ("#", "!")

# Hosts-file style: "<ip> <hostname> [alias...]". Recognizes the null-route
# IPs real blocklists actually use (confirmed live: BlockListProject's own
# `hosts`-format files use 0.0.0.0; the IPv6 forms are included defensively
# for other hosts-style sources that use them).
_HOSTS_IP_PREFIXES = ("0.0.0.0", "127.0.0.1", "::", "::1")

# AdGuard/uBlock style: "||hostname^" optionally followed by more modifiers
# (e.g. "||hostname^$important") -- confirmed live against
# BlockListProject's own `adguard/*-ags.txt` files, which use exactly this
# shape with no other rule forms mixed in.
_ADGUARD_RULE_RE = re.compile(r"^\|\|([^\^$]+)\^?")

# A full URL per line -- e.g. "http://example.com" or
# "http://example.com?p=tgraph&r=home_home" (some real lists in this shape
# glue a query string straight onto the bare hostname with no `/` in
# between, which urlparse() still handles correctly -- confirmed live
# 2026-09-08 against a real list using exactly that pattern). Only the
# scheme is checked here; urlparse() does the actual host extraction.
_URL_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)

# A bare domain-per-line entry: letters/digits/hyphens, dot-separated
# labels. Deliberately conservative -- a line that doesn't look like a
# plausible hostname is skipped rather than guessed at.
_BARE_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")


def _normalize(hostname: str) -> str | None:
    hostname = hostname.strip().rstrip(".").lower()
    if not hostname or not _BARE_DOMAIN_RE.match(hostname):
        return None
    return hostname


def parse_hostlist(text: str) -> list[str]:
    """Parses `text` (a whole fetched list) into a deduplicated list of
    plain domain names, preserving first-seen order. Supports, per line:

      - a full-line comment (`#` or `!` as the first non-whitespace
        character) or a blank line -- skipped.
      - AdGuard/uBlock style: `||example.com^`, with or without trailing
        modifiers (`$important`, etc. -- ignored).
      - hosts-file style: `0.0.0.0 example.com` (and the other
        _HOSTS_IP_PREFIXES) -- every whitespace-separated token after the
        IP is treated as a hostname (some hosts files list aliases on one
        line).
      - a full URL, e.g. `http://example.com` or
        `https://example.com/some/path?query=1` -- the hostname is
        extracted via `urlparse()` (added 2026-09-08, real gap found by
        live user testing: a real list -- a social-networking-sites list
        formatted exactly this way, one full URL per line, including a
        few lines with a query string glued straight onto the bare
        hostname with no `/` -- fetched successfully but produced zero
        domains, since none of the three formats above recognize a URL
        with a scheme). Verified live against that exact file: all ~197
        entries parsed correctly, including the query-glued and
        trailing-`#`-fragment lines.
      - a bare domain on its own line.

    A line matching none of these shapes (malformed, or a rule type this
    parser doesn't understand -- e.g. a regex rule, an exception rule
    starting `@@`) is silently skipped, not raised on -- a category sync is
    a best-effort refresh of a large third-party file; one weird line
    should never abort the whole sync. Skipped-line volume isn't currently
    surfaced anywhere; if a real subscription source turns out to need
    more format coverage than this, that'll show up as a suspiciously
    small resulting category_domains count, worth keeping in mind if a
    future format needs adding here.
    """
    seen: dict[str, None] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue

        match = _ADGUARD_RULE_RE.match(line)
        if match:
            domain = _normalize(match.group(1))
            if domain:
                seen.setdefault(domain, None)
            continue

        parts = line.split()
        if len(parts) >= 2 and parts[0] in _HOSTS_IP_PREFIXES:
            for token in parts[1:]:
                domain = _normalize(token)
                if domain:
                    seen.setdefault(domain, None)
            continue

        if _URL_SCHEME_RE.match(line):
            try:
                hostname = urlparse(line).hostname
            except ValueError:
                hostname = None
            domain = _normalize(hostname) if hostname else None
            if domain:
                seen.setdefault(domain, None)
            continue

        if len(parts) == 1:
            domain = _normalize(parts[0])
            if domain:
                seen.setdefault(domain, None)

    return list(seen.keys())
