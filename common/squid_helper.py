#!/usr/bin/env python3
"""Shared stdin/stdout loop for the Squid helper scripts.

Squid speaks one line protocol to every ``external_acl_type`` helper: one
request per line, fields separated by a single space, reply ``OK`` or
``ERR`` flushed immediately. The two helpers (sni, authz) differ only in
the field count and the decision function -- everything else lived
duplicated in each ``main()`` before this module.

The ``unquote``/``keep_trailing_spaces`` parameters below predate a
removed third helper (basic_auth_helper) that needed different handling:
both current callers always percent-encode (``external_acl_type``'s own
protocol) and need no trailing-space handling, so both now always pass
their defaults -- kept as parameters rather than inlined, since they're
still real, independently testable protocol variations (see
tests/test_helpers_protocol.py's own protocol-level tests), not dead code.
"""
from __future__ import annotations

import sys
import urllib.parse
from typing import Callable

import db


def run(
    name: str,
    field_count: int,
    handler: Callable[..., bool],
    *,
    unquote: bool = True,
    keep_trailing_spaces: bool = False,
) -> int:
    """Drive the Squid helper protocol until stdin closes.

    name                 label used in stderr diagnostics.
    field_count          number of space-separated fields expected per line.
    handler              called as ``handler(conn, *fields) -> bool``.
    unquote              percent-decode each field. ``external_acl_type``
                         always encodes its fields, so both current
                         callers leave this at its default.
    keep_trailing_spaces split into exactly ``field_count`` fields, leaving
                         any further spaces in the final field (a proxy
                         password may legitimately contain spaces).
    """
    conn = db.get_conn()
    db.init_db(conn)

    for line in sys.stdin:
        line = line.rstrip("\n").rstrip("\r")
        if keep_trailing_spaces:
            parts = line.split(" ", field_count - 1)
        else:
            parts = line.split()
        if len(parts) != field_count:
            sys.stdout.write("ERR\n")
            sys.stdout.flush()
            continue
        if unquote:
            parts = [urllib.parse.unquote(p) for p in parts]
        try:
            ok = handler(conn, *parts)
        except Exception as exc:  # one bad line must never kill the helper
            print(f"{name} error: {exc}", file=sys.stderr, flush=True)
            ok = False
        sys.stdout.write("OK\n" if ok else "ERR\n")
        sys.stdout.flush()
    return 0
