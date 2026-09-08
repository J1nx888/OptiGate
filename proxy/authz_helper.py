#!/usr/bin/env python3
"""Squid `external_acl_type` helper for the HTTP-layer decision on bump-mode
domains (the ones ssl_bump fully decrypts, per sni_helper.py's 'bump' check).

Protocol (format `%>a %DST %PATH %DATA`): one line per request, four
percent-encoded fields, respond "OK" or "ERR". The trailing %DATA field is
always "-" (the `acl authz_allowed external authz_check` line passes no
static argument) and is otherwise unused -- it must still be declared and
consumed, because Squid always appends %DATA to an external_acl_type FORMAT
that doesn't already include it (see squid.conf.template's comment).

Updated 2026-08-30 for Squid's intercept mode (RoadMap.md's "Squid:
explicit-proxy-with-login -> transparent intercept" section): %LOGIN is
gone -- identity is now resolved from `%>a` (the client's source IP) via
common/device_identity.py's device_bindings-based lookup, same as
sni_helper.py.

Decision order for a bump-mode domain:
  1. Client's IP must resolve to a known device (any device -- a bare
     device_bindings match, not a user), and be inside the configured LAN.
  2. Domain must be globally allowed, or assigned to this device's user,
     its group, or the device itself directly -- see
     common/matching.py's device_domain_reason().
  3. If it's the Crunchyroll domain: resolve watch/playback/series requests
     to their parent show via the CMS API (cached) and check the user's
     show list. CMS metadata-only requests are always allowed (matches v1).
     Requires a resolved user -- user_shows has no group/device
     equivalent, see decide()'s own "show_requires_user" case.
  4. Otherwise: the request's path must match one of the domain's
     configured allowed-paths. **Changed 2026-09-07 (RoadMap.md's dated
     entry, project owner's explicit direction)**: a domain with ZERO
     configured paths used to allow every path by default ("admins only
     need to curate paths for domains where that matters") -- switching a
     domain to bump mode silently opened its entire site until someone
     came back and narrowed it. Now a domain with no path rules allows
     ONLY the bare root ("/") -- see `_path_allowed_or_bare_root()` --
     so bump mode is deny-by-default beyond the homepage until an admin
     deliberately adds path rules for whatever else should be reachable.
     A domain that already has at least one path rule is unaffected --
     only ITS OWN rules ever mattered for it, before or after this
     change.

Every decision is logged (deduped) via logging_util.

**Fixed 2026-08-31**: step 1/2 used to resolve straight to a `users` row
(device_identity.resolve_user()) and only ever check
`is_global or user_has_domain(...)` -- a device assigned to a GROUP (no
user_id) resolved to no identity at all and was denied everything, and
even a user-resolved device could never benefit from a group/device-level
domain grant. See common/matching.py's device_domain_reason() docstring
for the full bug writeup and RoadMap.md's dated entry.
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/opt/optigate")

import cr_urls
import device_identity
import logging_util
import matching
import series_resolve
import squid_helper


def _split_host_port(dst: str) -> str:
    if dst.startswith("["):  # IPv6 literal, rare on a home LAN but be safe
        return dst.split("]")[0].lstrip("[")
    return dst.split(":", 1)[0]


def decide(conn, client_ip: str, dst: str, path: str, _data: str = "-") -> bool:
    hostname = _split_host_port(dst)
    path = path or "/"

    # Resolve the DEVICE first, not the user -- a group- or device-only
    # assignment has no `users` row at all, but is still a real identity
    # (see common/matching.py's device_domain_reason()). Only a source IP
    # with no active device_bindings row at all (never seen, or stale)
    # gets the old "no identity" treatment: deny, unlogged, exactly as
    # before this fix.
    device = device_identity.resolve_device(conn, client_ip)
    if device is None:
        return False

    user = device_identity.resolve_user_for_device(conn, device)
    user_id, username, device_id = device_identity.log_identity_fields(device, user)

    if not matching.ip_in_configured_lan(conn, client_ip):
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=hostname,
            path=path, allowed=False, reason="outside_lan", device_id=device_id,
        )
        return False

    domain = matching.find_domain(conn, hostname)
    if domain is None or domain["mode"] != "bump":
        # Two ways to get here: a genuinely unconfigured domain, or a
        # splice-mode domain this device isn't permitted -- ssl_bump's
        # block_page rule (see sni_helper.py) deliberately bumps both so a
        # real deny page can be served here instead of a bare connection
        # failure. Either way: deny.
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=hostname,
            path=path, allowed=False,
            reason="unknown_domain" if domain is None else "not_bump_mode",
            device_id=device_id,
        )
        return False

    reason = matching.device_domain_reason(conn, device, domain)
    if reason is None:
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=hostname,
            path=path, allowed=False, reason="domain_not_assigned", device_id=device_id,
        )
        return False

    if domain["kind"] == "crunchyroll":
        if user is None:
            # The domain itself is authorized (via group/device), but
            # user_shows is keyed by user_id only -- there's no
            # group/device-level show list to check against. Fails
            # closed rather than either silently allowing every show or
            # crashing on a None user_id below.
            logging_util.log_access(
                conn, user_id=user_id, username=username, domain=hostname,
                path=path, allowed=False, reason="show_requires_user", device_id=device_id,
            )
            return False
        return _decide_crunchyroll(conn, user, hostname, path, domain)

    if not _path_allowed_or_bare_root(conn, domain["id"], path):
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=hostname,
            path=path, allowed=False, reason="path_not_allowed", device_id=device_id,
        )
        return False

    logging_util.log_access(
        conn, user_id=user_id, username=username, domain=hostname,
        path=path, allowed=True, reason=reason, device_id=device_id,
    )
    return True


def _has_any_path_rules(conn, domain_id: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM domain_paths WHERE domain_id = ? LIMIT 1", (domain_id,)
    ).fetchone()
    return row is not None


def _path_allowed_or_bare_root(conn, domain_id: int, path: str) -> bool:
    """Whether `path` is allowed for `domain_id`'s configured path rules,
    for both the generic bump-domain check above and Crunchyroll's own
    "OTHER request shape" fallback below. **Changed 2026-09-07** -- see
    this module's own docstring for the full reasoning: a domain with
    ZERO configured rows in `domain_paths` used to allow every path;
    now it allows only the bare root ("/"), deny-by-default otherwise.
    A domain with at least one rule is unaffected -- delegates entirely
    to `matching.path_allowed()`, same as before this change."""
    if _has_any_path_rules(conn, domain_id):
        return matching.path_allowed(conn, domain_id, path)
    return path == "/"


def _decide_crunchyroll(conn, user, hostname: str, path: str, domain) -> bool:
    username = user["username"]
    url = f"https://{hostname}{path}"
    request = cr_urls.classify(url)

    if request.kind is cr_urls.RequestKind.CMS_OBJECTS:
        return True  # metadata only, matches v1 behavior

    if request.kind is cr_urls.RequestKind.BLOCKED_SHAPE:
        logging_util.log_access(
            conn, user_id=user["id"], username=username, domain=hostname,
            path=path, allowed=False, reason="blocked_shape",
        )
        return False

    if request.kind is cr_urls.RequestKind.OTHER:
        # Not a recognized watch/playback/series/CMS shape. Same
        # defense-in-depth v1 had: fall back to the configured path
        # allowlist for this domain instead of allowing blindly, so an
        # endpoint the classifier doesn't know about isn't automatically
        # open. Same deny-by-default-beyond-root treatment as the generic
        # bump-domain check above (2026-09-07) when zero paths are
        # configured -- for Crunchyroll specifically, defaults.py seeds
        # this domain with a real path list, so that fallback shouldn't
        # normally be reached here at all.
        if _path_allowed_or_bare_root(conn, domain["id"], path):
            return True
        logging_util.log_access(
            conn, user_id=user["id"], username=username, domain=hostname,
            path=path, allowed=False, reason="path_not_allowed",
        )
        return False

    if request.kind is cr_urls.RequestKind.SERIES_PAGE:
        allowed = True
        for series_id in request.ids:
            show_ok = matching.user_has_show(conn, user["id"], series_id)
            logging_util.log_access(
                conn, user_id=user["id"], username=username, domain=hostname,
                path=path, allowed=show_ok,
                reason="show_approved" if show_ok else "show_not_approved",
                series_id=series_id,
            )
            if not show_ok:
                allowed = False
        return allowed

    # WATCH_PAGE / PLAYBACK: resolve object IDs to their parent series first.
    resolved = series_resolve.resolve_series_ids(conn, request.ids)
    if resolved is None:
        logging_util.log_access(
            conn, user_id=user["id"], username=username, domain=hostname,
            path=path, allowed=False, reason="resolution_failed",
        )
        return False

    ok = True
    for object_id in request.ids:
        series_id = resolved.get(object_id)
        show_ok = series_id is not None and matching.user_has_show(conn, user["id"], series_id)
        logging_util.log_access(
            conn, user_id=user["id"], username=username, domain=hostname,
            path=path, allowed=show_ok,
            reason="show_approved" if show_ok else "show_not_approved",
            series_id=series_id,
        )
        if not show_ok:
            ok = False
    return ok


def main() -> int:
    return squid_helper.run("authz_helper", 4, decide)


if __name__ == "__main__":
    raise SystemExit(main())
