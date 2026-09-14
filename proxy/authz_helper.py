#!/usr/bin/env python3
"""Squid `external_acl_type` helper for the HTTP-layer decision on every
request that reaches it -- primarily bump-mode domains (the ones
ssl_bump fully decrypts, per sni_helper.py's 'bump' check), but ALSO
every plain-HTTP request from a bump_v4 device, regardless of that
domain's own mode, since plain HTTP has no SNI/TLS stage for
sni_helper.py's own trusted/bump/splice checks to run against first.

Protocol (format `%>a %DST %PATH %DATA`): one line per request, four
percent-encoded fields, respond "OK" or "ERR". The trailing %DATA field is
always "-" and otherwise unused -- it must still be declared and
consumed, because Squid always appends %DATA to an external_acl_type FORMAT
that doesn't already include it (see squid.conf.template's comment).

Identity is resolved from `%>a` (the client's source IP) via
common/device_identity.py's device_bindings-based lookup, same as
sni_helper.py.

For a plain-HTTP request, an unconfigured or 'trusted' domain is allowed
outright and a 'splice' domain gets the same per-user/group/device check
as sni_helper.py's handle_splice() -- mirroring what would happen over
HTTPS, since plain HTTP never reaches sni_helper.py's own checks. Only
'bump'-mode domains go through the full decision order below:
  1. Client's IP must resolve to a known device (any device -- a bare
     device_bindings match, not a user), and be inside the configured LAN.
  2. Domain must be globally allowed, or assigned to this device's user,
     its group, or the device itself directly -- see
     common/matching.py's device_domain_reason().
  3. If it's the Crunchyroll domain: resolve watch/playback/series requests
     to their parent show via the CMS API (cached) and check the user's
     show list. CMS metadata-only requests are always allowed. Requires a
     resolved user -- user_shows has no group/device equivalent, see
     decide()'s own "show_requires_user" case.
  4. Otherwise: the request's path must match one of the domain's
     configured allowed-paths. A domain with no path rules allows ONLY
     the bare root ("/") -- see `_path_allowed_or_bare_root()` -- so bump
     mode is deny-by-default beyond the homepage until an admin adds
     path rules for whatever else should be reachable. A domain with at
     least one path rule is unaffected -- only its own rules matter.

Every decision is logged (deduped) via logging_util.
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


def _series_name(conn, series_id: str | None) -> str | None:
    """Best-effort human title for a Crunchyroll series id, stored on the
    access_log row so the Report page can show the name next to the id.
    Cheap, indexed, no network: if ANY user has this show approved,
    `user_shows.series_name` already holds its title. A blocked show
    nobody has approved returns None here -- the Report page resolves
    and back-fills that case via cr_api at render time, off the request
    path."""
    if not series_id:
        return None
    row = conn.execute(
        "SELECT series_name FROM user_shows WHERE series_id = ? AND series_name <> '' LIMIT 1",
        (series_id,),
    ).fetchone()
    return row["series_name"] if row else None


def decide(conn, client_ip: str, dst: str, path: str, _data: str = "-") -> bool:
    hostname = _split_host_port(dst)
    path = path or "/"

    # Network-tier check first: a request whose source IP is not on the
    # configured LAN is refused regardless of whether it maps to a known
    # device. Deliberately before identity resolution: since
    # common/identity.record_binding() rejects off-LAN IPs at discovery
    # time, an off-LAN client has no device_bindings row to resolve, but
    # must still be denied and logged as `outside_lan` -- so this check
    # can't depend on a resolved identity.
    if not matching.ip_in_configured_lan(conn, client_ip):
        lan_uid, lan_uname, lan_did = device_identity.log_identity_fields(None, None)
        logging_util.log_access(
            conn, user_id=lan_uid, username=lan_uname, domain=hostname,
            path=path, allowed=False, reason="outside_lan", device_id=lan_did, ip_address=client_ip,
        )
        return False

    # Resolve the DEVICE first, not the user -- a group- or device-only
    # assignment has no `users` row at all, but is still a real identity
    # (see common/matching.py's device_domain_reason()). A source IP
    # with no active device_bindings row (never seen, or stale) is
    # denied, unlogged.
    device = device_identity.resolve_device(conn, client_ip)
    if device is None:
        return False

    user = device_identity.resolve_user_for_device(conn, device)
    user_id, username, device_id = device_identity.log_identity_fields(device, user)

    domain = matching.find_domain(conn, hostname)

    if domain is None:
        # Unconfigured domains are default-allow at the DNS tier -- this
        # plain-HTTP path must not re-deny one just because it isn't
        # mode='bump'.
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=hostname,
            path=path, allowed=True, reason="unconfigured_domain", device_id=device_id, ip_address=client_ip,
        )
        return True

    if domain["mode"] == "trusted":
        # Matches sni_helper.py's handle_trusted()/"trusted mode is
        # deliberately never logged" convention -- always spliced,
        # unchecked, at every layer this project has.
        return True

    if domain["mode"] == "splice":
        # Matches sni_helper.py's handle_splice() exactly -- this is
        # the plain-HTTP version of the same per-user/group/device
        # authorization check, no path/show-level refinement (that's
        # bump-mode-only, below).
        reason = matching.device_domain_reason(conn, device, domain)
        allowed = reason is not None
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=hostname,
            path=path, allowed=allowed, reason=reason or "domain_not_assigned", device_id=device_id, ip_address=client_ip,
        )
        return allowed

    if domain["mode"] != "bump":
        # Unreachable in practice -- domains.mode's own CHECK constraint
        # only allows 'splice'/'bump'/'trusted', all three handled
        # above. Defensive only.
        return False

    reason = matching.device_domain_reason(conn, device, domain)
    if reason is None:
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=hostname,
            path=path, allowed=False, reason="domain_not_assigned", device_id=device_id, ip_address=client_ip,
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
                path=path, allowed=False, reason="show_requires_user", device_id=device_id, ip_address=client_ip,
            )
            return False
        return _decide_crunchyroll(conn, user, hostname, path, domain, client_ip)

    if not _path_allowed_or_bare_root(conn, domain["id"], path):
        logging_util.log_access(
            conn, user_id=user_id, username=username, domain=hostname,
            path=path, allowed=False, reason="path_not_allowed", device_id=device_id, ip_address=client_ip,
        )
        return False

    logging_util.log_access(
        conn, user_id=user_id, username=username, domain=hostname,
        path=path, allowed=True, reason=reason, device_id=device_id, ip_address=client_ip,
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
    "OTHER request shape" fallback below. A domain with zero configured
    rows in `domain_paths` allows only the bare root ("/"),
    deny-by-default otherwise; a domain with at least one rule delegates
    entirely to `matching.path_allowed()`."""
    if _has_any_path_rules(conn, domain_id):
        return matching.path_allowed(conn, domain_id, path)
    return path == "/"


def _decide_crunchyroll(conn, user, hostname: str, path: str, domain, client_ip: str | None = None) -> bool:
    username = user["username"]
    url = f"https://{hostname}{path}"
    request = cr_urls.classify(url)

    if request.kind is cr_urls.RequestKind.CMS_OBJECTS:
        return True  # metadata only, matches v1 behavior

    if request.kind is cr_urls.RequestKind.BLOCKED_SHAPE:
        logging_util.log_access(
            conn, user_id=user["id"], username=username, domain=hostname, ip_address=client_ip,
            path=path, allowed=False, reason="blocked_shape",
        )
        return False

    if request.kind is cr_urls.RequestKind.OTHER:
        # Not a recognized watch/playback/series/CMS shape. Falls back
        # to the configured path allowlist for this domain instead of
        # allowing blindly, so an endpoint the classifier doesn't know
        # about isn't automatically open. defaults.py seeds this domain
        # with a real path list, so this fallback shouldn't normally be
        # reached.
        if _path_allowed_or_bare_root(conn, domain["id"], path):
            return True
        logging_util.log_access(
            conn, user_id=user["id"], username=username, domain=hostname, ip_address=client_ip,
            path=path, allowed=False, reason="path_not_allowed",
        )
        return False

    if request.kind in (cr_urls.RequestKind.SERIES_PAGE, cr_urls.RequestKind.UP_NEXT):
        # UP_NEXT carries a series id directly in the URL, same as
        # SERIES_PAGE -- no series_resolve round-trip needed, just the
        # same direct user_has_show() check.
        allowed = True
        for series_id in request.ids:
            show_ok = matching.user_has_show(conn, user["id"], series_id)
            logging_util.log_access(
                conn, user_id=user["id"], username=username, domain=hostname, ip_address=client_ip,
                path=path, allowed=show_ok,
                reason="show_approved" if show_ok else "show_not_approved",
                series_id=series_id, series_name=_series_name(conn, series_id),
            )
            if not show_ok:
                allowed = False
        return allowed

    # WATCH_PAGE / PLAYBACK: resolve object IDs to their parent series first.
    resolved = series_resolve.resolve_series_ids(conn, request.ids)
    if resolved is None:
        logging_util.log_access(
            conn, user_id=user["id"], username=username, domain=hostname, ip_address=client_ip,
            path=path, allowed=False, reason="resolution_failed",
        )
        return False

    ok = True
    for object_id in request.ids:
        series_id = resolved.get(object_id)
        show_ok = series_id is not None and matching.user_has_show(conn, user["id"], series_id)
        logging_util.log_access(
            conn, user_id=user["id"], username=username, domain=hostname, ip_address=client_ip,
            path=path, allowed=show_ok,
            reason="show_approved" if show_ok else "show_not_approved",
            series_id=series_id, series_name=_series_name(conn, series_id),
        )
        if not show_ok:
            ok = False
    return ok


def main() -> int:
    return squid_helper.run("authz_helper", 4, decide)


if __name__ == "__main__":
    raise SystemExit(main())
