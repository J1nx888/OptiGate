#!/usr/bin/env python3
"""Squid `external_acl_type` helper for ssl_bump step2 decisions.

Invoked four different ways from squid.conf (same script, different mode
argument), each backing one ssl_bump rule, evaluated in this order:

    sni_helper.py trusted     -> OK if mode='trusted' (always spliced, unchecked)
    sni_helper.py bump        -> OK if mode='bump' (always fully decrypted)
    sni_helper.py splice      -> OK if mode='splice' AND this user may access it
    sni_helper.py block_page  -> catch-all for everything else (unrecognized
                                  domain, or a splice-mode domain this user
                                  can't access). OK if the admin's
                                  block_page_mode setting is 'redirect' --
                                  this deliberately bumps (decrypts) just
                                  this one connection so a real HTTP deny
                                  page can be served (via authz_helper.py's
                                  existing deny path) instead of a bare
                                  connection failure. If the setting is
                                  'terminate', always ERR here, so the
                                  connection falls through to squid.conf's
                                  final `ssl_bump splice step2 all` and is
                                  never decrypted at all -- the tradeoff is
                                  a broken-looking connection instead of an
                                  explanation.

Protocol (external_acl_type, format `%>a %ssl::>sni %DATA`): one line per
request, three percent-encoded fields, respond "OK" or "ERR". The trailing
%DATA field is always "-" (no `acl ... external ...` line below passes a
static argument) and is otherwise unused -- it must still be declared and
consumed, because Squid always appends %DATA to an external_acl_type FORMAT
that doesn't already include it (see squid.conf.template's comment).

Updated 2026-08-30 for Squid's intercept mode (RoadMap.md's "Squid:
explicit-proxy-with-login -> transparent intercept" section): %LOGIN is
gone -- an intercepted connection has no CONNECT handshake for Squid to
challenge with a 407, so there is no per-request login at all anymore.
Identity is now resolved from `%>a` (the client's source IP) via
common/device_identity.py's device_bindings-based lookup, the same
identity data the DNS tier already relies on.

'splice' mode logs every decision at this stage -- spliced connections are
never decrypted, so this is the only point that traffic is ever observed at
all. 'bump' mode and the 'block_page' bump-for-denial path both log richly
at the HTTP layer instead (authz_helper.py, once decrypted). 'block_page'
also logs a domain-only entry itself, but *only* for a genuinely
unconfigured domain when not in 'redirect' mode -- otherwise that case
would never be recorded anywhere, since nothing downstream ever runs to
log it either (GH #1). 'trusted' mode is deliberately never logged (see
project README).
"""
from __future__ import annotations

import sqlite3
import sys

sys.path.insert(0, "/opt/optigate")

import db
import device_identity
import logging_util
import matching
import squid_helper


def handle_bump(conn, client_ip: str, sni: str, _data: str = "-") -> bool:
    domain = matching.find_domain(conn, sni)
    return domain is not None and domain["mode"] == "bump"


def handle_trusted(conn, client_ip: str, sni: str, _data: str = "-") -> bool:
    domain = matching.find_domain(conn, sni)
    return domain is not None and domain["mode"] == "trusted"


def _log_denial(
    conn, sni: str, reason: str, device: sqlite3.Row | None = None, user: sqlite3.Row | None = None,
    client_ip: str | None = None,
) -> None:
    """Log a denied SNI-layer decision -- domain only, no path, since
    nothing is decrypted at this layer. Shared by handle_splice and
    handle_block_page so the identity-resolution-for-logging isn't
    duplicated between them."""
    user_id, username, device_id = device_identity.log_identity_fields(device, user)
    logging_util.log_access(
        conn, user_id=user_id, username=username, domain=sni,
        path=None, allowed=False, reason=reason, device_id=device_id, ip_address=client_ip,
    )


def handle_splice(conn, client_ip: str, sni: str, _data: str = "-") -> bool:
    domain = matching.find_domain(conn, sni)
    if domain is not None and domain["mode"] != "splice":
        # Reached only if a race changed this domain's mode between two
        # ssl_bump ACL evaluations for the same connection -- sni_bump
        # already claims every genuine mode='bump' domain earlier in
        # squid.conf's rule order ("first match wins"), so this branch
        # is defensive, not something normal operation reaches.
        return False

    # Network-tier check first: a request whose source IP is not on the
    # configured LAN is refused regardless of whether it maps to a known
    # device. Deliberately BEFORE identity resolution (2026-09-10): since
    # common/identity.record_binding() now rejects off-LAN IPs at
    # discovery time, an off-LAN client no longer has a device_bindings
    # row to resolve -- but it must still be denied and logged here as
    # `outside_lan`, exactly as before, so this check can't depend on a
    # resolved identity.
    if not matching.ip_in_configured_lan(conn, client_ip):
        _log_denial(conn, sni, "outside_lan", client_ip=client_ip)
        return False

    # Resolve the DEVICE first -- see authz_helper.decide()'s own comment
    # on why (a group/device-only assignment has no `users` row at all,
    # but is still a real, enforceable identity).
    device = device_identity.resolve_device(conn, client_ip)
    if device is None:
        _log_denial(conn, sni, "not_authenticated", client_ip=client_ip)
        return False
    user = device_identity.resolve_user_for_device(conn, device)
    user_id, username, device_id = device_identity.log_identity_fields(device, user)

    if domain is None:
        # Fixed 2026-09-08, real gap found live: a domain with no
        # `domains` row at all used to be denied here unconditionally,
        # even though controller/adguard_sync.py's own
        # _build_domain_deny_rules() docstring is explicit that an
        # unconfigured domain is "deliberately still default-allow at
        # the DNS tier." Since a non-bump device's HTTPS traffic never
        # reaches Squid at all (see knftables_adapter.go's baseline
        # rules -- only bump_v4 members' port 443 is redirected here),
        # this mismatch meant turning on SSL-Bump for one device
        # silently switched its ENTIRE traffic from "default-allow,
        # blocked only by category" to "default-deny, allow-list only"
        # -- a real, surprising, unintended side effect (confirmed
        # live: Netflix, never configured anywhere, was blocked
        # specifically because bump was on for the visiting device, not
        # because of anything Netflix-specific). Splicing it through
        # now makes a bump-enabled device's unconfigured-domain
        # experience match a non-bump device's exactly -- Squid becomes
        # a refinement layer for domains that actually need path/show
        # level rules, not a stricter gate than the DNS tier's own
        # already-decided policy.
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=sni, path=None,
            allowed=True, reason="unconfigured_domain", device_id=device_id, ip_address=client_ip,
        )
        return True

    reason = matching.device_domain_reason(conn, device, domain)
    allowed = reason is not None
    logging_util.log_access(
        conn, user_id=user_id, username=username, domain=sni, path=None,
        allowed=allowed, reason=reason or "domain_not_assigned", device_id=device_id, ip_address=client_ip,
    )
    return allowed


def handle_block_page(conn, client_ip: str, sni: str, _data: str = "-") -> bool:
    # Reached only for connections none of the other three rules matched.
    # Fixed 2026-09-08, alongside handle_splice()'s own fix: an
    # unconfigured domain (no `domains` row at all) is now caught and
    # spliced by handle_splice() itself, matching the DNS tier's own
    # "default-allow for unconfigured" policy -- so this handler can no
    # longer be reached by one. The ONLY thing that still falls through
    # to here is a domain that DOES have a `domains` row (mode='splice')
    # but this device/user isn't authorized for it -- already logged by
    # handle_splice() before this rule is ever reached. The only
    # question left is whether we bump it to explain that via a real
    # page, or terminate outright. (No identity/LAN check needed here:
    # authz_helper.py will independently deny this once decrypted
    # regardless.)
    #
    # This used to ALSO be the only place that could ever log a
    # genuinely unconfigured domain (GH #1's fix, so a kid trying a
    # brand-new site wasn't completely invisible on the Report page) --
    # that's no longer needed here since handle_splice() logs an
    # ALLOWED "unconfigured_domain" entry for exactly that case now,
    # which is strictly better visibility (every attempt is logged, not
    # just denied ones, and only when block_page_mode happened to be
    # 'terminate').
    mode = db.get_setting(conn, "block_page_mode", "terminate")
    return mode == "redirect"


HANDLERS = {
    "bump": handle_bump,
    "trusted": handle_trusted,
    "splice": handle_splice,
    "block_page": handle_block_page,
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in HANDLERS:
        print("usage: sni_helper.py {bump|trusted|splice|block_page}", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    return squid_helper.run(f"sni_helper[{mode}]", 3, HANDLERS[mode])


if __name__ == "__main__":
    raise SystemExit(main())
