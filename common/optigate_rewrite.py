#!/usr/bin/env python3
"""The `optigate.home` memorable-hostname DNS rewrite -- lives in
common/ since both dashboard and controller need it (same reasoning
category_fetch.py's own docstring gives for its module).

Called directly by the dashboard (see dashboard.py's own
`_sync_optigate_rewrite_now()`) rather than only from
controller/adguard_sync.py's periodic sync loop: the `interception`
profile controller runs under is off by default for most installs, so
the rewrite has to work standalone or `update_household_settings()`'s
"Saved. The address is now X.home." message would be untrue for anyone
not running that profile. controller's own periodic call is now just a
second, redundant path for when that profile happens to be running.

Bypass/ignored devices can't reach `optigate.home` -- by design. The
hostname is only ever an AdGuard DNS rewrite, so it resolves only for a
device whose DNS actually goes through AdGuard. A `bypass_login` device gets nftables'
plain `ct mark set 0x1 return` with no `:5354` DNS redirect
(phase3/nftables-manager baselineRules), and an `ignored` device isn't
in any managed set at all -- both resolve `optigate.home` against
whatever upstream resolver they're configured with, which returns
NXDOMAIN. Making it work for them would mean redirecting their DNS to
AdGuard, which is exactly the interception those two modes exist to
opt out of. An unmanaged device has nothing to self-diagnose on the
troubleshooting page anyway; its admin reaches the dashboard by IP.
Surfaced to the operator in the Settings page hint text.
"""
from __future__ import annotations

import ipaddress
import sqlite3
from urllib.parse import urlparse

import adguard_client
import db


def parse_block_page_ip(dashboard_url: str | None) -> str | None:
    """Extracts a plain IPv4 host from a DASHBOARD_URL-shaped value
    (e.g. "http://192.168.1.50:8787" -> "192.168.1.50") -- both this
    module's own sync_optigate_rewrite() and dashboard.py's
    block_page_server.py need a literal IP, not a hostname (a hostname
    would itself need DNS resolution, circular for a rule that exists
    to REPLACE DNS resolution). Returns None for anything that isn't a
    plain IPv4 address (including a genuine hostname, or an unset/
    malformed URL) -- this is a cosmetic enhancement, not something
    worth failing loudly over if misconfigured; a device just keeps
    getting the plain default deny (or, here, no rewrite) instead."""
    if not dashboard_url:
        return None
    host = urlparse(dashboard_url).hostname
    if not host:
        return None
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return None
    return host


def sync_optigate_rewrite(
    conn: sqlite3.Connection,
    base_url: str,
    username: str,
    password: str,
    block_page_ip: str | None,
    timeout: float = adguard_client.DEFAULT_TIMEOUT,
) -> None:
    """Reconciles AdGuard Home's own DNS-rewrite entries against this
    project's single `optigate.home` entry -- same "recompute and
    reconcile every call" discipline controller/adguard_sync.py's other
    sync functions use, so renaming the hostname prefix (Settings page)
    or the box's own LAN IP changing (DASHBOARD_URL) self-heals on the
    next call, no manual step needed.

    Skipped entirely if block_page_ip is None -- same "not configured,
    not an error" treatment every other block_page_ip consumer already
    gives it: there's nowhere to point the rewrite at without it.

    Manages ONLY entries whose domain ends in
    `db.OPTIGATE_HOSTNAME_SUFFIX` (".home") -- that forced suffix exists
    specifically so this project's own managed entry is unambiguous and
    never collides with an admin's own unrelated AdGuard rewrite (a
    completely separate, general-purpose AdGuard feature this project
    doesn't otherwise touch). A stale entry (leftover from an old prefix,
    or an old LAN IP) is deleted before the correct one is (re-)added --
    AdGuard has no update-in-place call for this, only add/delete (see
    common/adguard_client.py's own docstring)."""
    if not block_page_ip:
        return
    desired_domain = db.optigate_hostname(conn)
    current = adguard_client.get_rewrites(base_url, username, password, timeout=timeout)
    ours = [
        r for r in current
        if isinstance(r, dict) and str(r.get("domain", "")).endswith(db.OPTIGATE_HOSTNAME_SUFFIX)
    ]
    already_correct = any(
        r.get("domain") == desired_domain and r.get("answer") == block_page_ip for r in ours
    )
    for stale in ours:
        if stale.get("domain") != desired_domain or stale.get("answer") != block_page_ip:
            adguard_client.delete_rewrite(
                base_url, username, password, stale["domain"], stale["answer"], timeout=timeout
            )
    if not already_correct:
        adguard_client.add_rewrite(base_url, username, password, desired_domain, block_page_ip, timeout=timeout)
