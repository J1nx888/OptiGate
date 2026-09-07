#!/usr/bin/env python3
"""Thin REST client for AdGuard Home's `/control` API.

This is what makes the "two independent axes" hard-deny invariant real
(RoadMap.md, locked 2026-08-30): a domain marked `domains.mode = 'bump'`
must never resolve normally for a device that isn't `bump_enabled` --
nftables has no domain visibility to enforce this itself (see
knftables_adapter.go's own comment), so it has to happen here, at the
DNS tier, before a connection to that domain is even attempted.

Verified live 2026-08-30 against a real AdGuard Home v0.107.79 instance
-- not written from documentation alone, matching this project's own
repeated lesson that a first draft written from memory/docs tends to be
subtly wrong in exactly the way that only shows up against the real
thing (the ARP worker's mdlayher/arp adapter, the nftables adapter's
import path, three separate Squid startup bugs this same session):
- `/control/filtering/set_rules` (POST, body `{"rules": [...]}`) does a
  full replace of AdGuard's custom filtering rules -- no incremental
  add/remove API exists, matching this project's own established
  full-reconcile pattern (phase3/nftables-manager's flush-before-re-add,
  controller's full DesiredPolicy recompute every cycle).
- `/control/filtering/status` (GET) echoes the current list back under
  a `user_rules` key.
- HTTP Basic Auth works directly against `/control/*` for a configured
  instance -- no cookie-based `/control/login` session dance needed.
- The `$client=ip1,ip2` modifier on a custom rule does exactly what it
  says: confirmed with two real client containers against a real
  instance, one resolving a domain normally and the other -- named in
  the rule's $client list -- getting `0.0.0.0` back for the identical
  query.
- `/control/install/configure` (POST) is what the first-run setup
  wizard itself calls -- NOT the bare `/install/configure` path some of
  AdGuard's own generated OpenAPI-doc tooling implies (every route
  lives under `/control`, even before the instance is configured at
  all). It writes a complete, correctly-versioned AdGuardHome.yaml
  itself; see adguard/entrypoint.sh, which calls this once on first
  boot instead of hand-templating that file (confirmed live that a
  hand-authored version, built from the wiki's documented fields alone,
  was missing several fields the real binary always writes --
  `session_ttl` format, `upstream_mode`, `cache_optimistic_*`,
  `doh.routes` -- so letting AdGuard build its own config is both
  simpler and version-correct in a way a template can't be kept in sync
  with automatically).
- `/control/filtering/status`'s `user_rules` key is present but `null`,
  not `[]`, on a freshly-configured instance that has never had a custom
  rule set -- confirmed live 2026-08-30 running the full interception
  stack against a brand-new AdGuard container for the first time ever
  (every earlier live AdGuard test this project ran had already pushed
  at least one custom rule by the time `get_custom_rules` was exercised,
  which is exactly why this hadn't surfaced before). `get_custom_rules`
  below treats that ONE specific shape -- key present, value `null` --
  as "no rules yet" (empty list), same as `[]`. It deliberately does NOT
  extend the same treatment to a missing key or a non-object response:
  an early version of this fix did, and a code review the same day
  caught that this let `sync_once()` silently proceed to a destructive
  full-replace write on what could be a genuinely malformed response
  (wrong endpoint, incompatible AdGuard version) rather than the
  confirmed benign case -- those still raise `AdGuardError` and fail
  closed, exactly as before this fix existed.
- `/control/querylog?limit=N` (GET) returns `{"data": [...], "oldest":
  "<timestamp>"}`, newest-first -- confirmed live 2026-08-31 by
  generating real DNS queries against a running instance and reading
  the response back. Each entry's `client` field is a plain IP string
  (no MAC -- DNS carries no link-layer information) and `time` is
  ISO8601 UTC with variable-precision fractional seconds (commonly
  9-digit/nanosecond, e.g. `"2026-08-31T13:17:13.089285447Z"`) -- see
  `normalize_query_log_time` below for why that can't be compared as a
  plain string against this project's own `db.now_iso()` timestamps.
- `/control/rewrite/list` (GET) / `/control/rewrite/add` (POST) /
  `/control/rewrite/delete` (POST) -- DNS rewrites, a separate feature
  from the custom filtering rules above. Confirmed live 2026-09-07
  against the real production instance for the `optigate.home`
  memorable-URL feature (RoadMap.md's dated entry): `list` returns a
  plain `[]` on a fresh instance (unlike `user_rules`'s `null` quirk
  above); `add`/`delete` both take `{"domain", "answer"}` and return an
  empty 200 body; a rewrite added this way is immediately resolvable --
  confirmed with `dig @127.0.0.1 -p 5353 <domain>` against the real
  resolver in the same session, then confirmed gone after `delete`.

No third-party dependencies -- matches common/cr_api.py's own
urllib-based pattern, mirrored here, rather than adding `requests` to a
package this project otherwise keeps stdlib-only outside dashboard/.
"""
from __future__ import annotations

import base64
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

DEFAULT_TIMEOUT = 5.0
MAX_RESPONSE_BYTES = 1 * 1024 * 1024

# Bypass environment proxy variables -- this client always talks
# directly to AdGuard Home's own control port, never through Squid or
# anything else that might itself depend on AdGuard being reachable.
_OPENER = build_opener(ProxyHandler({}))


class AdGuardError(RuntimeError):
    """Raised for any failure talking to AdGuard Home -- unreachable,
    a non-2xx response, or a malformed body. Callers (adguard_sync.py)
    must treat this the same way controller/discovery.py treats a
    failed snapshot: log it and retry next cycle, never crash the
    process over a transient AdGuard restart or network hiccup."""


def _basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _request(
    url: str,
    *,
    method: str,
    username: str | None = None,
    password: str | None = None,
    json_body: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> bytes:
    headers: dict[str, str] = {}
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if username is not None:
        headers["Authorization"] = _basic_auth_header(username, password or "")

    request = Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            return response.read(MAX_RESPONSE_BYTES)
    except HTTPError as exc:
        detail = exc.read(300).decode("utf-8", errors="replace")
        raise AdGuardError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except URLError as exc:
        raise AdGuardError(f"could not reach {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise AdGuardError(f"request to {url} timed out") from exc


def get_custom_rules(
    base_url: str, username: str, password: str, timeout: float = DEFAULT_TIMEOUT
) -> list[str]:
    """The CURRENT custom filtering rules list, straight from AdGuard --
    never cached, same "always read fresh" discipline as
    policy.ActualPolicy on the nftables side. adguard_sync.py reads this
    first so it can preserve any rules it doesn't manage (an admin's own
    manually-added rule) before overwriting with set_custom_rules."""
    body = _request(
        f"{base_url.rstrip('/')}/control/filtering/status",
        method="GET",
        username=username,
        password=password,
        timeout=timeout,
    )
    try:
        decoded = json.loads(body)
    except ValueError as exc:
        raise AdGuardError(f"malformed JSON from {base_url}/control/filtering/status: {exc}") from exc
    if not isinstance(decoded, dict):
        raise AdGuardError(f"{base_url}/control/filtering/status didn't return a JSON object")
    if "user_rules" not in decoded:
        raise AdGuardError("AdGuard Home's filtering/status response had no 'user_rules' key")
    rules = decoded["user_rules"]
    if rules is None:
        # A freshly-configured instance that's never had a custom rule set
        # reports the KEY PRESENT but `null`, not `[]` -- see this module's
        # docstring. Treat that one specific, confirmed-live shape as an
        # empty list rather than raising, or sync_once() could never
        # complete its very first cycle against a brand-new AdGuard
        # instance (it always reads before it writes). Deliberately narrow:
        # a non-dict response or a missing key entirely is a genuinely
        # different, more anomalous failure (wrong endpoint, incompatible
        # AdGuard version) and should still raise and fail closed --
        # collapsing all three into one silent "no rules yet" used to let
        # sync_once() proceed to a full-replace write on a merely
        # malformed read, silently discarding any admin-added rules that
        # were actually still there (found via code review 2026-08-30).
        rules = []
    if not isinstance(rules, list):
        raise AdGuardError("AdGuard Home's filtering/status response had a non-list 'user_rules'")
    return [str(r) for r in rules]


def set_custom_rules(
    base_url: str, username: str, password: str, rules: list[str], timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Full replace of AdGuard Home's custom filtering rules list -- see
    this module's docstring for why there's no incremental API. Callers
    must pass the COMPLETE desired list (including any preserved
    not-ours rules from get_custom_rules), not just the ones they own."""
    _request(
        f"{base_url.rstrip('/')}/control/filtering/set_rules",
        method="POST",
        username=username,
        password=password,
        json_body={"rules": rules},
        timeout=timeout,
    )


def get_rewrites(
    base_url: str, username: str, password: str, timeout: float = DEFAULT_TIMEOUT
) -> list[dict]:
    """AdGuard Home's own DNS-rewrite entries (`GET /control/rewrite/list`)
    -- a separate feature from the custom filtering rules above (no
    `$dnsrewrite` modifier or block involved, just a plain forced DNS
    answer for a domain). Confirmed live 2026-09-07 against a real
    AdGuard Home instance: returns a plain JSON array (`[]` on a fresh
    instance, not `null` the way `user_rules` is -- this endpoint had no
    equivalent of that quirk), each entry shaped
    `{"domain": ..., "answer": ..., "enabled": true}`. Used by
    controller/adguard_sync.py's `sync_optigate_rewrite()` to find and
    clean up a stale entry (e.g. after the admin renames the
    `optigate.home` hostname prefix from the Settings page) before
    adding the current one."""
    body = _request(
        f"{base_url.rstrip('/')}/control/rewrite/list",
        method="GET",
        username=username,
        password=password,
        timeout=timeout,
    )
    try:
        decoded = json.loads(body)
    except ValueError as exc:
        raise AdGuardError(f"malformed JSON from {base_url}/control/rewrite/list: {exc}") from exc
    if not isinstance(decoded, list):
        raise AdGuardError(f"{base_url}/control/rewrite/list didn't return a JSON array")
    return decoded


def add_rewrite(
    base_url: str, username: str, password: str, domain: str, answer: str, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Adds one DNS-rewrite entry (`POST /control/rewrite/add`, body
    `{"domain", "answer"}`) -- confirmed live 2026-09-07: a plain HTTP
    200 with an empty body on success, and the new entry immediately
    resolvable via AdGuard's own DNS (confirmed with `dig` against port
    5353 the same session). Does not check for an existing entry with
    the same domain first -- callers that need idempotency (
    sync_optigate_rewrite()) should read get_rewrites() and reconcile
    before calling this, same "read fresh, then write" discipline as
    set_custom_rules()."""
    _request(
        f"{base_url.rstrip('/')}/control/rewrite/add",
        method="POST",
        username=username,
        password=password,
        json_body={"domain": domain, "answer": answer},
        timeout=timeout,
    )


def delete_rewrite(
    base_url: str, username: str, password: str, domain: str, answer: str, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Removes one DNS-rewrite entry (`POST /control/rewrite/delete`,
    body `{"domain", "answer"}` -- both fields required; AdGuard matches
    on the exact pair, not the domain alone, confirmed live 2026-09-07).
    """
    _request(
        f"{base_url.rstrip('/')}/control/rewrite/delete",
        method="POST",
        username=username,
        password=password,
        json_body={"domain": domain, "answer": answer},
        timeout=timeout,
    )


def set_filters_update_interval(
    base_url: str, username: str, password: str, interval_hours: int, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Sets how often AdGuard Home ITSELF re-checks every subscribed
    filter list (its own built-in background schedule -- this project
    doesn't reimplement update-checking, just configures AdGuard's real
    one). `adguard/entrypoint.sh` calls this once during first-run
    bootstrap with `interval_hours=168` (one week, matching AdGuard's
    own "Once a week" UI preset) -- confirmed live 2026-08-30 that 168
    is accepted and echoed back exactly by `/control/filtering/status`.
    """
    _request(
        f"{base_url.rstrip('/')}/control/filtering/config",
        method="POST",
        username=username,
        password=password,
        json_body={"enabled": True, "interval": interval_hours},
        timeout=timeout,
    )


def refresh_filters(base_url: str, username: str, password: str, timeout: float = DEFAULT_TIMEOUT) -> int:
    """Forces AdGuard Home to check every subscribed filter list right
    now, instead of waiting for its own update interval -- this is what
    the dashboard's "Check for filter updates now" button calls.
    Confirmed live 2026-08-30 this is safe to call as often as wanted
    (AdGuard's own docs: "ratelimited, so you can call it freely").
    Returns how many lists actually had new content -- 0 is a normal,
    healthy result when nothing has changed upstream since the last
    check, not a failure.
    """
    body = _request(
        f"{base_url.rstrip('/')}/control/filtering/refresh",
        method="POST",
        username=username,
        password=password,
        json_body={"whitelist": False},
        timeout=timeout,
    )
    try:
        decoded = json.loads(body)
    except ValueError as exc:
        raise AdGuardError(f"malformed JSON from {base_url}/control/filtering/refresh: {exc}") from exc
    updated = decoded.get("updated") if isinstance(decoded, dict) else None
    if not isinstance(updated, int):
        raise AdGuardError("AdGuard Home's filtering/refresh response had no 'updated' count")
    return updated


# RoadMap.md's discovery precedence: "AdGuard query-log observations
# (confirms active IP usage)" -- the shape below is confirmed live
# 2026-08-31 against a real AdGuard Home instance (`/control/querylog`),
# not assumed from documentation, matching this module's own established
# discipline.
_QUERYLOG_TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?Z$")


def normalize_query_log_time(raw: str) -> str:
    """AdGuard's querylog `time` field is ISO8601 UTC with variable-
    precision fractional seconds and a bare `Z` suffix -- confirmed
    live 2026-08-31 (e.g. `"2026-08-31T13:17:13.089285447Z"`, 9-digit/
    nanosecond precision). `common/db.py`'s own `now_iso()` never
    carries fractional seconds at all (`"2026-08-31T13:17:13Z"`).
    Comparing the two formats as plain strings is unsafe: ASCII `.`
    (0x2E) sorts before `Z` (0x5A), so a same-second fractional
    timestamp compares as "earlier" than a whole-second one that
    actually occurred first -- e.g. `"...13.5Z" < "...13Z"` as strings,
    backwards from real time. Every AdGuard timestamp is truncated to
    whole seconds through this function before it is ever stored in or
    compared against `last_seen_at`, so the column stays uniformly
    comparable regardless of which discovery source last touched it.

    Raises AdGuardError (not a bare regex/parsing exception) if `raw`
    doesn't match AdGuard's own confirmed shape -- a change to that
    shape should fail loudly here rather than silently corrupt
    last_seen_at ordering.
    """
    match = _QUERYLOG_TIME_RE.match(raw)
    if not match:
        raise AdGuardError(f"unexpected AdGuard querylog timestamp shape: {raw!r}")
    return match.group(1) + "Z"


def get_query_log(
    base_url: str, username: str, password: str, limit: int = 100, timeout: float = DEFAULT_TIMEOUT
) -> list[dict]:
    """The most recent `limit` querylog entries, newest first -- matches
    AdGuard's own confirmed-live ordering (`/control/querylog?limit=N`).
    Returns the raw `data` list as-is (each entry at least has `client`
    -- the querying device's plain IP string, no MAC, since DNS queries
    carry no link-layer information -- and `time`, see
    normalize_query_log_time above); callers needing anything else from
    an entry can read it directly rather than this module re-shaping
    every field AdGuard happens to return.

    Deliberately does NOT support pagination (`older_than`) -- the one
    caller (controller/adguard_discovery.py) only needs "what's new
    since last poll," and a modest, fixed-size page covers normal query
    volume between polls; missing entries within a single burst that
    exceeds `limit` is an acceptable gap for a source whose whole role
    is a soft freshness signal, not primary discovery (RoadMap.md's
    discovery precedence).
    """
    body = _request(
        f"{base_url.rstrip('/')}/control/querylog?limit={int(limit)}",
        method="GET",
        username=username,
        password=password,
        timeout=timeout,
    )
    try:
        decoded = json.loads(body)
    except ValueError as exc:
        raise AdGuardError(f"malformed JSON from {base_url}/control/querylog: {exc}") from exc
    if not isinstance(decoded, dict) or not isinstance(decoded.get("data"), list):
        raise AdGuardError(f"{base_url}/control/querylog didn't return the expected {{'data': [...]}} shape")
    return decoded["data"]


# ==========================================================================
# Phase 8 (2026-08-31): native filter-list subscriptions -- for a `categories`
# row over controller/adguard_sync.py's per-target rule-count threshold
# (confirmed live 2026-08-31: real category lists run up to ~953K domains --
# AdGuard's own team calls per-client scoping of a list that size via custom
# rules "unworkable," see AdguardTeam/AdGuardHome#8103), the category's own
# subscription_url is pushed as one of AdGuard's OWN managed filter lists
# instead -- letting AdGuard's engine (built for exactly this) match it,
# rather than this project expanding it into a `$client=`-scoped custom-rule
# line per domain the way build_category_deny_rules() does for a small,
# per-target category.
#
# **Confirmed live 2026-09-01** against a real running AdGuard Home
# v0.107.79 instance on the smoke-test VM, once it came back up --
# written from openapi.yaml alone originally (no Docker available
# locally at the time; the smoke-test VM was offline), then verified
# with direct curl calls plus a real end-to-end run of
# sync_category_subscriptions() against a scratch 5,001-domain category
# before being trusted the way every other function in this module is.
# All four request/response shapes below turned out correct on the
# first live check -- no surprises, unlike most of this project's other
# from-openapi-alone guesses (see RoadMap.md's dated entry for the full
# verification writeup).
# ==========================================================================

def get_filters_status(
    base_url: str, username: str, password: str, timeout: float = DEFAULT_TIMEOUT
) -> list[dict]:
    """The `filters` array from `/control/filtering/status` -- each entry
    at least `id`/`enabled`/`name`/`url`/`rules_count` per AdGuard's
    openapi.yaml -- confirmed live 2026-09-01, see module note above."""
    body = _request(
        f"{base_url.rstrip('/')}/control/filtering/status",
        method="GET",
        username=username,
        password=password,
        timeout=timeout,
    )
    try:
        decoded = json.loads(body)
    except ValueError as exc:
        raise AdGuardError(f"malformed JSON from {base_url}/control/filtering/status: {exc}") from exc
    filters = decoded.get("filters") if isinstance(decoded, dict) else None
    if not isinstance(filters, list):
        raise AdGuardError(f"{base_url}/control/filtering/status had no 'filters' list")
    return filters


def add_filter_url(
    base_url: str, username: str, password: str, name: str, url: str, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Subscribes AdGuard Home to `url` as a new managed filter list named
    `name` -- per openapi.yaml (confirmed live 2026-09-01, see module
    note above), `POST /control/filtering/add_url` with body
    `{"name", "url", "whitelist": false}`. Behavior when `url` is already
    subscribed is unconfirmed -- callers (adguard_sync.py) should check
    `get_filters_status()` first rather than relying on this being a safe
    no-op if it's already present."""
    _request(
        f"{base_url.rstrip('/')}/control/filtering/add_url",
        method="POST",
        username=username,
        password=password,
        json_body={"name": name, "url": url, "whitelist": False},
        timeout=timeout,
    )


def remove_filter_url(
    base_url: str, username: str, password: str, url: str, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Unsubscribes AdGuard Home from `url` -- `POST
    /control/filtering/remove_url` with body `{"url", "whitelist": false}`
    -- confirmed live 2026-09-01, see module note above."""
    _request(
        f"{base_url.rstrip('/')}/control/filtering/remove_url",
        method="POST",
        username=username,
        password=password,
        json_body={"url": url, "whitelist": False},
        timeout=timeout,
    )


def set_filter_url_enabled(
    base_url: str, username: str, password: str, url: str, name: str, enabled: bool,
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    """Toggles an already-subscribed filter's `enabled` state without
    removing it -- `POST /control/filtering/set_url` with body
    `{"url", "whitelist": false, "data": {"enabled", "name", "url"}}`,
    identified by URL rather than id per openapi.yaml (confirmed live
    2026-09-01, see module note above). This is what lets a schedule-gated
    global category (adguard_sync.py) turn its subscription on/off as the
    schedule's window opens/closes, without adding/removing it from
    AdGuard's filter list entirely each time. `name` must be passed again
    here even though it isn't changing -- per the documented request
    shape, `data` fully replaces the filter's editable fields, not a
    partial patch."""
    _request(
        f"{base_url.rstrip('/')}/control/filtering/set_url",
        method="POST",
        username=username,
        password=password,
        json_body={"url": url, "whitelist": False, "data": {"enabled": enabled, "name": name, "url": url}},
        timeout=timeout,
    )


# ==========================================================================
# G3 (2026-09-01): SafeSearch / YouTube Restricted Mode -- Bark Home parity
# (RoadMap.md's Phase 8 gap-list addendum). AdGuard Home has a genuine
# first-class feature for exactly this, per its own openapi.yaml --
# **confirmed live 2026-09-01** against a real running instance before
# writing controller/adguard_sync.py's caller: `GET
# /control/safesearch/status` returns `{"enabled", "bing", "duckduckgo",
# "ecosia", "google", "pixabay", "yandex", "youtube"}` (all booleans);
# `PUT /control/safesearch/settings` takes the identical shape and
# returns `200 OK` (plain text, not JSON). Confirmed this is a REAL DNS
# rewrite, not just a config flag: with `enabled: true`, `dig
# www.google.com` returned a CNAME to `forcesafesearch.google.com`, and
# `dig www.youtube.com` returned a CNAME to `restrictmoderate.youtube.com`
# (YouTube's own *moderate* restriction level -- AdGuard's toggle has no
# strict/moderate choice, it's whatever Google's own forcesafesearch
# infrastructure applies for that hostname).
#
# This mirrors Bark Home's own behavior exactly: SafeSearch/Restricted
# Mode is a single network-wide toggle there too, not a per-device
# setting -- so unlike the category/schedule machinery elsewhere in this
# project, there is deliberately no `$client=`-scoped equivalent here.
# `openapi.yaml` also lists a legacy `/control/parental/*` "Parental
# Control" endpoint (a third-party adult-content blocklist AdGuard used
# to run server-side) -- NOT used here: that's a different, older
# feature this project's own `categories` table (Phase 8) already covers
# via the "Adult" starter category, and separately, is widely reported
# discontinued in recent AdGuard Home releases since the backend service
# it depended on was shut down -- not verified live one way or the
# other, simply irrelevant to what G3 actually needs.
# ==========================================================================


def get_safesearch_status(
    base_url: str, username: str, password: str, timeout: float = DEFAULT_TIMEOUT
) -> dict:
    """The current SafeSearch config -- confirmed live 2026-09-01, see
    module note above. `adguard_sync.py`'s `sync_safesearch()` reads
    this first so it can preserve whatever an admin has set per-service
    directly in AdGuard's own UI, changing only the master `enabled`
    flag this project owns."""
    body = _request(
        f"{base_url.rstrip('/')}/control/safesearch/status",
        method="GET",
        username=username,
        password=password,
        timeout=timeout,
    )
    try:
        decoded = json.loads(body)
    except ValueError as exc:
        raise AdGuardError(f"malformed JSON from {base_url}/control/safesearch/status: {exc}") from exc
    if not isinstance(decoded, dict) or "enabled" not in decoded:
        raise AdGuardError(f"{base_url}/control/safesearch/status had no 'enabled' field")
    return decoded


def set_safesearch_settings(
    base_url: str, username: str, password: str, config: dict, timeout: float = DEFAULT_TIMEOUT
) -> None:
    """Replaces AdGuard's SafeSearch config wholesale -- `PUT
    /control/safesearch/settings`, confirmed live 2026-09-01 to accept
    and echo back exactly the shape `get_safesearch_status()` returns
    (there is no partial-patch form; every field must be supplied).
    Callers should always start from a fresh `get_safesearch_status()`
    result and only change the one field they mean to, same discipline
    `set_filter_url_enabled()` above follows for filters."""
    _request(
        f"{base_url.rstrip('/')}/control/safesearch/settings",
        method="PUT",
        username=username,
        password=password,
        json_body=config,
        timeout=timeout,
    )
