#!/usr/bin/env python3
"""Pushes two independent sets of DNS-tier enforcement rules to AdGuard
Home, both via its per-client custom filtering rules (see
common/adguard_client.py's docstring for how that's verified to
actually work), both built by the same shared engine
(`_build_domain_deny_rules()`):

1. `build_rules()` -- a domain marked `domains.mode = 'bump'` must NEVER
   be reachable via plain, unrefined DNS-tier access UNLESS the
   requesting device is both currently `bump_eligible()`
   (`common/policy_class.py`) AND that specific domain is actually
   assigned to it (`is_global`, or a user/group/device grant) -- refined
   through Squid, or denied outright, never a silent DNS-tier fallback.
2. `build_splice_deny_rules()` (added 2026-08-31, GH #9) -- enforces the
   same per-user/group/device/everyone domain assignment the dashboard's
   Domains page already manages, for `mode = 'splice'` domains -- the
   tier most devices actually use, since bump is a deliberately small
   curated set. See that function's own docstring for the gap this
   closed (this module used to do ONLY #1).

**Reworked 2026-08-31, per the project owner's explicit design
clarification (RoadMap.md's dated entry, GH #9)**: `build_rules()` used
to ONLY check bump-eligibility, giving any bump-eligible device a free
DNS pass to every `bump`-mode domain and relying entirely on Squid's own
`authz_helper.decide()` to catch a domain that specific device/user
wasn't actually assigned, after decryption. AdGuard now checks the same
assignment before the DNS query even resolves, for both modes -- one
shared engine, `_build_domain_deny_rules()`, that also excludes any
device classified `BYPASS` (`ignored=1`) from every rule it builds, on
either mode ("AdGuard should apply a baseline of protection... unless
the device/user/group is set to bypass/ignore" -- the project owner's
own words). See that function's own docstring for the full algorithm.

nftables has no domain visibility to enforce either of these itself (it
can only redirect by IP+port, see knftables_adapter.go's own comment on
this exact point), so both happen here, at the DNS tier, before a
connection to that domain is even attempted.

Same idempotent-full-reconcile shape as everywhere else in this
codebase (phase3/nftables-manager's flush-before-re-add,
controller/policy_state.py's full DesiredPolicy recompute every cycle):
every sync reads the DB and AdGuard's current rules fresh, computes the
complete desired managed-rules block (both rule sets combined), and
replaces it whole -- no incremental add/remove, no assumption about
what a previous cycle left behind.

**Phase 8 addendum (2026-08-31)**: content-category blocking
(`build_category_deny_rules()`) adds a THIRD rule source to the same
managed block, for categories at or under
`matching.MAX_SCOPED_CATEGORY_DOMAINS` domains. Real category blocklists
(confirmed live: https://github.com/blocklistproject/Lists) range from
tens of domains to ~953K -- scoping a list that size to a subset of
clients via `$client=` is exactly what AdGuard's own team calls
"unworkable" for per-client blocklist assignment
(AdguardTeam/AdGuardHome#8103: "requires maintaining thousands of rules
for each client profile"). A category over that threshold is therefore
`is_global`-only (enforced by the dashboard, not re-checked here) and
handled by an entirely separate mechanism, `sync_category_subscriptions()`
-- pushing the category's own `subscription_url` into AdGuard as one of
ITS OWN native managed filter lists instead of expanding it into custom
rules, letting AdGuard's engine (built for exactly this) match it. See
each function's own docstring.

**Memorable-URL addendum (2026-09-07)**: `sync_optigate_rewrite()` is a
FOURTH, unrelated mechanism living in this same module purely because
it's the same "reconcile every cycle" background loop -- it manages an
AdGuard DNS-rewrite entry (a completely different AdGuard feature from
the custom filtering rules the other three sources feed, see
common/adguard_client.py's own docstring), not a block/allow decision
at all. See that function's own docstring and dashboard/
block_page_server.py for the page it makes reachable.
"""
from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone

import adguard_client
import db
import matching
import schedule_eval
from matching import MAX_SCOPED_CATEGORY_DOMAINS
from periodic import PeriodicTask
from policy_class import PolicyClass, bump_eligible, classify_device

log = logging.getLogger("controller.adguard_sync")

# Bracket this process's own rules within AdGuard's shared custom-rules
# list so a sync can find and replace exactly its own block, leaving
# anything an admin added by hand (directly in AdGuard's own UI)
# completely untouched -- the same "dedicated space, never touch
# anything else on the box" discipline
# phase3/nftables-manager/internal/nft/knftables_adapter.go applies to
# its own nftables table, applied here to AdGuard's rules list instead.
_MARKER_BEGIN = "! === optigate managed rules -- do not edit below this line, see docs/security/overview.md ==="
_MARKER_END = "! === end optigate managed rules ==="


def _domain_rule(pattern: str, client_ips: list[str], block_page_ip: str | None = None) -> str:
    """One AdGuard regex rule, scoped to client_ips via the `$client`
    modifier (confirmed live against a real AdGuard Home instance --
    see common/adguard_client.py's docstring). The regex body mirrors
    common/matching.py's own `_domain_regex()` anchoring EXACTLY
    (`(?:^|\\.)(?:pattern)\\Z`, case-insensitive) so a domain is
    hard-denied here under precisely the same suffix-match rules Squid
    itself uses to decide bump-mode -- translated to AdGuard's regex
    rule syntax (Go's RE2 engine via the `/regex/` rule form): RE2 has
    no `\\Z`, but a plain `$` is equivalent here since a DNS query name
    never contains an embedded newline; `(?i)` is RE2's inline
    case-insensitivity flag, replacing Python's separate
    `re.IGNORECASE` argument.

    If block_page_ip is given, the rule ALSO carries a `$dnsrewrite`
    modifier pointing the DNS answer at that IP instead of the plain
    default deny (confirmed live combinable with `$client` on one rule).
    That IP is expected to be running dashboard/block_page_server.py,
    which only ever answers on port 80 -- deliberately no HTTPS
    equivalent, see that module's own docstring for why showing a page
    over HTTPS to a device that was never asked to trust this project's
    CA would be worse than today's plain failure, not better.
    """
    body = f"(?i)(?:^|\\.)(?:{pattern})$"
    rule = f"/{body}/$client={','.join(client_ips)}"
    if block_page_ip:
        rule += f",dnsrewrite=NOERROR;A;{block_page_ip}"
    return rule


def _domain_rule_unscoped(pattern: str, block_page_ip: str | None = None) -> str:
    """Same regex body as `_domain_rule()` above, with NO `$client=`
    scope -- for `build_category_deny_rules()`'s case where a category
    currently applies to literally every non-BYPASS device: one plain
    rule per domain instead of one `$client=`-scoped rule per domain
    listing every device's IP is both cheaper and simpler, and is the
    common case for a category an admin marks "Block for Everyone"."""
    body = f"(?i)(?:^|\\.)(?:{pattern})$"
    rule = f"/{body}/"
    if block_page_ip:
        rule += f"$dnsrewrite=NOERROR;A;{block_page_ip}"
    return rule


# Domains a browser's own built-in "Secure DNS"/DNS-over-HTTPS toggle
# would otherwise use to silently route around every bit of DNS-tier
# enforcement in this project -- see `build_anti_doh_rules()`'s own
# docstring below for why this needed closing, and
# docs/security/overview.md section 10 for the full writeup. Not
# admin-configurable and not stored in `domains`/`categories` on
# purpose: this isn't a household content decision, it's closing a
# hole in the mechanism those tables depend on to mean anything.
_DOH_CANARY_DOMAINS = (
    # Firefox (and some Chromium-based browsers) query this exact
    # domain before auto-enabling DNS-over-HTTPS; a resolver that
    # returns NXDOMAIN for it is Mozilla's own documented signal that
    # the network doesn't want DoH auto-enabled, and they leave the
    # system resolver in place instead -- not a guess, see
    # https://support.mozilla.org/kb/canary-domain-use-application-dns-net.
    "use-application-dns.net",
)

# The handful of public DoH resolvers real browsers/OSes ship as their
# default or one-click "Secure DNS" options. Blocking these specific
# hostnames makes the easy, one-toggle bypass (Settings > Secure DNS,
# no dev tools or technical skill needed) fail closed instead of
# silently working. Not an attempt at an exhaustive list of every DoH
# provider that has ever existed -- Chrome specifically probes its own
# small hardcoded provider list and falls back to the system resolver
# if the probe fails, so blocking Chrome's own candidates is enough to
# make its automatic upgrade fail closed the same way the canary domain
# does for Firefox; a household member deliberately configuring an
# obscure, unlisted DoH provider by hand is a meaningfully different
# (and smaller) threat than "flip the setting Chrome/Firefox already
# show by default."
_DOH_PROVIDER_DOMAINS = (
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
)


def build_anti_doh_rules() -> list[str]:
    """Unconditional, network-wide deny rules for the DoH canary/provider
    domains above -- closes the most realistic real-world bypass of
    DNS-tier enforcement found during the 2026-09-02 brute-force/
    injection audit (prompted directly: "can an end user bypass checks,
    e.g. via browser dev tools"). The literal dev-tools scenario doesn't
    apply anywhere in this codebase (verified: no client-supplied
    header/cookie/param feeds into any allow/deny decision -- see
    docs/security/overview.md section 9's SQL-injection audit for the
    same kind of sweep applied to this question), but investigating it
    surfaced a much more practically real one: a kid doesn't need dev
    tools OR any special skill to defeat this project's DNS-tier
    enforcement as it existed before this function -- Firefox and
    Chrome both ship a one-click "Secure DNS"/DNS-over-HTTPS toggle in
    their own visible Settings UI, and neither AdGuard nor
    `phase3/nftables-manager`'s baseline rules intercepted plain
    port-443 traffic for a normal (`authenticated_v4`, non-bump)
    device -- only port 53 is redirected for that class (see
    `knftables_adapter.go`'s `baselineRules`) -- so a DoH query sailed
    through completely unfiltered, and the browser then used whatever
    real (unfiltered) IP it got back, also over port 443, also
    untouched. This function does not fully close that class of gap
    (a bump-eligible device's port 443 traffic already gets redirected
    to Squid regardless of what IP a DoH query returns, and terminates
    there against an unconfigured domain; a NON-bump device still has
    no equivalent SNI-layer backstop) -- see docs/security/overview.md
    section 10 for the accepted residual gap and why closing it fully
    would mean giving DNS-tier-only devices some of Squid's own
    SNI-inspection machinery, a bigger design change than this pass.

    No `conn` parameter needed -- unlike every other rule builder in
    this module, this one reads no per-household state at all; it is
    the same fixed list for every deployment, every cycle, forever
    (until the lists above are edited by hand)."""
    return [_domain_rule_unscoped(d) for d in _DOH_CANARY_DOMAINS + _DOH_PROVIDER_DOMAINS]


def _fetch_eligible_devices(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every currently-bound, non-BYPASS device -- the shared "who does
    AdGuard-side enforcement apply to right now" query duplicated,
    before 2026-09-02, between `_build_domain_deny_rules()` and
    `build_category_deny_rules()` (identical query, identical
    `classify_device() != PolicyClass.BYPASS` filter, copy-pasted).
    `sync_once()` now calls this exactly once per cycle and threads the
    result into all three callers via their own `eligible_devices`
    parameter, instead of each independently re-querying and
    re-classifying the full device list -- on a household of 15 devices
    and 40 bump/splice domains, the nested per-domain/per-device
    authorization check inside `_build_domain_deny_rules()` alone made
    this query (and the classification pass over it) run 2-3x more than
    necessary every single cycle."""
    devices = conn.execute(
        """
        SELECT DISTINCT d.id, d.user_id, d.group_id, d.ignored, d.quarantined_at,
               d.is_authenticated, d.bump_enabled, d.bypass_login,
               COALESCE(g.ignored, 0) AS group_ignored, b.ipv4_address
        FROM devices d
        JOIN device_bindings b ON b.device_id = d.id AND b.active = 1
        LEFT JOIN groups g ON g.id = d.group_id
        ORDER BY b.ipv4_address
        """
    ).fetchall()
    return [row for row in devices if classify_device(row, bool(row["group_ignored"])) != PolicyClass.BYPASS]


def _build_domain_deny_rules(
    conn: sqlite3.Connection,
    mode: str,
    *,
    require_bump_eligible: bool,
    block_page_ip: str | None = None,
    eligible_devices: list[sqlite3.Row] | None = None,
) -> list[str]:
    """Shared engine behind `build_rules()` (`mode='bump'`) and
    `build_splice_deny_rules()` (`mode='splice'`) -- see each's own
    docstring for the specific invariant it enforces. For every `domains`
    row of the given `mode`, computes which currently-bound devices are
    NOT authorized for it and emits one `$client=`-scoped deny rule per
    domain (skipped entirely if nobody needs denying for it).

    **Reworked 2026-08-31, per the project owner's explicit direction on
    tighter Squid/AdGuard integration (RoadMap.md's dated entry, GH #9)**:
    a device is authorized for a domain when
    `matching.device_domain_reason()` (common/matching.py) returns
    non-None -- `is_global`, or an explicit user/group/device grant --
    AND, when `require_bump_eligible` is set, `policy_class.bump_eligible()`
    is ALSO true. That `AND` is the actual behavior change: previously
    (`build_rules()` before this rework) a `bump`-mode domain was only
    ever denied to devices that weren't bump-eligible at all -- a
    bump-eligible device got a free DNS pass to ANY bump-mode domain
    regardless of whether that SPECIFIC domain was assigned to it,
    relying entirely on Squid's own `authz_helper.decide()` to catch an
    unassigned one after decryption. Now AdGuard checks the same
    assignment `authz_helper.py` would check, before the DNS query even
    resolves -- a bump-eligible device only gets a clean resolution for a
    bump-mode domain that's actually `is_global` or assigned to it (via
    its user, group, or the device itself); an unassigned one is denied
    here, and the connection never reaches Squid at all. `is_global` on a
    bump-mode domain still only ever means "assigned to everyone", never
    "skip the bump-eligibility gate too" -- a non-bump-eligible device is
    still denied a global bump domain exactly as before.

    **A device classified `BYPASS` (`ignored=1`,
    `policy_class.classify_device()`) is excluded entirely** -- never
    added to any deny rule, on any domain, regardless of mode. Per the
    project owner's explicit direction the same day: "AdGuard DNS should
    apply a baseline of protection against all devices/users/groups
    unless the device/user/group is set to bypass/ignore." (`bypass_login`
    is deliberately NOT the same thing here -- see `classify_device()`'s
    own docstring; a `bypass_login` device still belongs to whatever
    user/group it's assigned to and is filtered normally. The dashboard's
    `update_device()`/`bypass_login_device()` routes default a newly
    `bypass_login`'d device to `ignored=1` too, but that's a UI default,
    not a rule this function enforces -- an admin can still un-ignore one
    while leaving `bypass_login` on.) An ignored device's packets never
    actually reach AdGuard's redirected port in the first place under
    normal ARP-spoofed interception (nftables' `bypass_v4` `return` --
    see `knftables_adapter.go`), so this exclusion is defense-in-depth
    for anything that ever points a device's DNS at this box directly
    (e.g. a manually-configured upstream), not a behavior change for the
    interception path itself.

    Deliberately still not filtered by `quarantined_at` on its own: a
    quarantined device's packets are dropped outright at the network
    layer (`quarantine_v4 counter drop`) regardless of what AdGuard says,
    so it's moot either way -- left to fall through the normal
    `device_domain_reason()` check rather than special-cased, since the
    project owner didn't ask for quarantine-specific handling here.

    Scope for `mode='splice'` (locked with the project owner, see
    RoadMap.md): only domains that HAVE a `domains` row. A domain with no
    row at all is unchanged -- deliberately still default-allow at the
    DNS tier in this pass; default-deny-for-unconfigured is a separate
    future decision.

    A device with no currently-active `device_bindings` row contributes
    no IP -- there's nothing to add a rule for yet; the same
    DHCP-staleness bound as `controller/discovery.py`'s snapshot loop
    applies here (a device's new IP is only picked up once discovery
    records it, and only enforced once the next adguard_sync cycle runs
    after that).

    Returns an empty list when there are no domains of this mode
    configured at all, or no non-BYPASS device currently has a known IP
    -- both legitimate "nothing to deny yet" states, not errors.

    `eligible_devices` (added 2026-09-02): pass the result of a single
    `_fetch_eligible_devices(conn)` call to reuse it across multiple
    builders in one `sync_once()` cycle instead of each re-querying and
    re-classifying the full device list -- see that function's own
    docstring. Defaults to `None`, which fetches it fresh (unchanged
    behavior for any direct caller, e.g. existing tests, that doesn't
    pass one in).
    """
    domains = conn.execute(
        "SELECT pattern, id, is_global FROM domains WHERE mode = ? ORDER BY id", (mode,)
    ).fetchall()
    if not domains:
        return []

    if eligible_devices is None:
        eligible_devices = _fetch_eligible_devices(conn)
    if not eligible_devices:
        return []

    rules = []
    for domain in domains:
        denied_ips = []
        for device in eligible_devices:
            authorized = matching.device_domain_reason(conn, device, domain) is not None
            if require_bump_eligible:
                authorized = authorized and bump_eligible(device)
            if not authorized:
                denied_ips.append(device["ipv4_address"])
        if denied_ips:
            rules.append(_domain_rule(domain["pattern"], denied_ips, block_page_ip))
    return rules


def build_rules(
    conn: sqlite3.Connection,
    block_page_ip: str | None = None,
    eligible_devices: list[sqlite3.Row] | None = None,
) -> list[str]:
    """The complete list of managed hard-deny rules for right now: one
    rule per `mode = 'bump'` domain, denying every device that isn't BOTH
    currently `bump_eligible()` (`common/policy_class.py`) AND actually
    authorized for that specific domain (`is_global`, or an explicit
    user/group/device grant -- see `_build_domain_deny_rules()`'s own
    docstring for the 2026-08-31 rework that added the per-domain
    assignment check on top of the original bump-eligibility-only gate).

    **Original fix, 2026-08-31 -- a real gap, same class of bug as
    classify_device() and bypass_login (see RoadMap.md's dated entry
    for that one)**: this used to select on the raw `d.bump_enabled = 0`
    column instead of the actual derived `bump_eligible()` state. A
    device with `bump_enabled = 1` set (an admin can do this at any
    time, including on a device that hasn't logged in yet) but not yet
    actually `AUTHENTICATED` -- e.g. a genuinely new, still-PREAUTH
    device Phase 4 auto-creates, or one deliberately pre-configured for
    bump ahead of its first login -- was excluded from this hard-deny
    list entirely (since `bump_enabled = 1`), while ALSO not being a
    member of nftables' `bump_v4` set (`bump_eligible()` requires
    `AUTHENTICATED` too, which it isn't yet). The result: AdGuard
    resolved the real IP for a `mode='bump'` domain, and nftables never
    redirected the resulting HTTPS connection to Squid either -- a full,
    unfiltered bypass of the exact invariant this module exists to
    enforce, worse than either a hard deny or a Squid-refined
    connection. Fixed to select the same way `controller/policy_state.py`
    already does: fetch the columns `bump_eligible()` needs and exclude
    only devices it actually returns True for.

    Returns an empty list when there are no bump-mode domains configured
    at all, or no device needs denying -- both legitimate "nothing to
    deny yet" states, not errors.
    """
    return _build_domain_deny_rules(
        conn, "bump", require_bump_eligible=True, block_page_ip=block_page_ip, eligible_devices=eligible_devices
    )


def build_splice_deny_rules(
    conn: sqlite3.Connection,
    block_page_ip: str | None = None,
    eligible_devices: list[sqlite3.Row] | None = None,
) -> list[str]:
    """One hard-deny rule per `mode = 'splice'` domain, scoped to every
    currently-bound device NOT authorized for it per
    `matching.device_domain_reason()` (common/matching.py) -- the DNS-tier
    enforcement of the same per-user/group/device/everyone domain
    assignment system the dashboard's Domains page already manages. No
    `bump_eligible()` gate here (unlike `build_rules()` above) -- splice
    mode is exactly the tier a non-bump device uses, and a bump-eligible
    device can browse a splice-mode domain too, so eligibility is purely
    about domain assignment, not bump status.

    **Added 2026-08-31, closing a real gap found while scoping tighter
    Squid/AdGuard integration (RoadMap.md's dated entry, GH #9)**: until
    this, `build_rules()` above was the ONLY thing this module did --
    hard-deny bump-mode domains for non-bump-eligible devices. It never
    touched splice-mode domains at all, so the entire per-user/group/
    device/everyone content allowlist built on the Domains page was
    completely unenforced at the DNS tier (the tier most devices actually
    use, since bump is a deliberately small curated set) -- a domain
    assigned to one kid was reachable by every device on the LAN as long
    as it went through AdGuard instead of Squid.

    See `_build_domain_deny_rules()`'s own docstring for the full
    algorithm, the `is_global`/unconfigured-domain scope, and the
    `ignored`/BYPASS exclusion (added the same day).

    Composes with `build_rules()`'s bump-mode hard-deny rules in the same
    managed block (`sync_once()` concatenates both lists) -- same
    `_domain_rule()` call, same `$client=`-scoping, same optional
    `$dnsrewrite` block-page redirect.
    """
    return _build_domain_deny_rules(
        conn, "splice", require_bump_eligible=False, block_page_ip=block_page_ip, eligible_devices=eligible_devices
    )


def _category_domain_patterns(conn: sqlite3.Connection, category_id: int) -> list[str]:
    """A category's blocked-domain patterns minus anything matching a
    `category_overrides` row -- allow-exceptions the admin added for a
    domain the category's own list/manual additions would otherwise
    catch. Matched by exact pattern-string equality (not suffix/regex
    overlap) -- an MVP-scope limitation: an override has to name the same
    pattern that's actually stored in `category_domains`, not a broader
    or narrower one that happens to overlap it."""
    overrides = {
        row["pattern"] for row in conn.execute(
            "SELECT pattern FROM category_overrides WHERE category_id = ?", (category_id,)
        )
    }
    return [
        row["pattern"] for row in conn.execute(
            "SELECT pattern FROM category_domains WHERE category_id = ?", (category_id,)
        )
        if row["pattern"] not in overrides
    ]


def build_category_deny_rules(
    conn: sqlite3.Connection,
    now: datetime | None = None,
    block_page_ip: str | None = None,
    eligible_devices: list[sqlite3.Row] | None = None,
) -> list[str]:
    """DNS-tier enforcement for every category AT OR UNDER
    `matching.MAX_SCOPED_CATEGORY_DOMAINS` -- a category over that many
    domains is handled entirely by `sync_category_subscriptions()`
    instead (see this module's docstring's Phase 8 addendum for why a
    huge list can't go through `$client=`-scoped custom rules the way
    domain-level rules do).

    For each in-scope category, resolves which currently-bound, non-BYPASS
    devices it applies to RIGHT NOW -- either unconditionally
    (`matching.category_applies_to_device()`) or via any currently-active,
    non-lockout schedule that references it
    (`schedule_eval.schedule_is_active()` +
    `matching.schedule_applies_to_device()`). If that set is literally
    every eligible device, emits one cheap unscoped rule per domain
    (`_domain_rule_unscoped()`) instead of a `$client=`-scoped one --
    see that helper's own docstring. A category with zero currently-
    applicable devices, or zero domains once `category_overrides` are
    subtracted, contributes nothing.

    `now` defaults to the current UTC instant; tests inject a fixed
    value, same convention as `controller/policy_state.py`'s
    `compute_desired_policy()`.

    `eligible_devices` (added 2026-09-02): same shared-fetch parameter
    as `_build_domain_deny_rules()`'s own -- see `_fetch_eligible_devices()`'s
    docstring for why this exists. Defaults to `None`, which fetches it
    fresh (unchanged behavior for any direct caller that doesn't pass
    one in).
    """
    if now is None:
        now = datetime.now(timezone.utc)

    categories = conn.execute("SELECT * FROM categories").fetchall()
    if not categories:
        return []

    if eligible_devices is None:
        eligible_devices = _fetch_eligible_devices(conn)
    if not eligible_devices:
        return []

    rules = []
    for category in categories:
        domain_count = conn.execute(
            "SELECT COUNT(*) AS c FROM category_domains WHERE category_id = ?", (category["id"],)
        ).fetchone()["c"]
        if domain_count == 0 or domain_count > MAX_SCOPED_CATEGORY_DOMAINS:
            continue

        patterns = _category_domain_patterns(conn, category["id"])
        if not patterns:
            continue

        gating_schedules = conn.execute(
            "SELECT s.* FROM schedule_categories sc JOIN schedules s ON s.id = sc.schedule_id "
            "WHERE sc.category_id = ? AND s.lockout_all = 0",
            (category["id"],),
        ).fetchall()

        applicable_ips = []
        for device in eligible_devices:
            applies = matching.category_applies_to_device(conn, device, category)
            if not applies:
                for schedule in gating_schedules:
                    # schedule_is_active_for_device() (not the bare
                    # schedule_is_active()) so a Phase 12 schedule_overrides
                    # row -- e.g. a kid manually shifted into Free Time --
                    # can suppress an is_mode gating schedule here exactly
                    # like it suppresses one in policy_state.py's nftables
                    # lockout overlay. A non-mode schedule is unaffected.
                    if schedule_eval.schedule_is_active_for_device(
                        conn, schedule, device, now
                    ) and matching.schedule_applies_to_device(conn, device, schedule):
                        applies = True
                        break
            if applies:
                applicable_ips.append(device["ipv4_address"])

        if not applicable_ips:
            continue

        if len(applicable_ips) == len(eligible_devices):
            rules.extend(_domain_rule_unscoped(pattern, block_page_ip) for pattern in patterns)
        else:
            rules.extend(_domain_rule(pattern, applicable_ips, block_page_ip) for pattern in patterns)

    return rules


def sync_category_subscriptions(
    conn: sqlite3.Connection, base_url: str, username: str, password: str,
    now: datetime | None = None, timeout: float = adguard_client.DEFAULT_TIMEOUT,
) -> None:
    """Keeps AdGuard Home's own native filter subscriptions in sync for
    every category OVER `matching.MAX_SCOPED_CATEGORY_DOMAINS` (a category
    at or under it is handled by `build_category_deny_rules()` instead,
    and skipped here) -- see this module's docstring's Phase 8 addendum
    for why a huge list needs AdGuard's own filtering engine rather than
    this project's `$client=`-scoped custom rules.

    Only two things can make an over-threshold category's subscription
    ENABLED: `categories.is_global` set directly (always enabled), or an
    `is_global`, non-`lockout_all` schedule referencing it via
    `schedule_categories` whose window is currently active
    (`schedule_eval.schedule_is_active()`) -- enabled only while that
    window is open. **This function does not, and cannot, enforce a
    per-user/device/group scoping for an over-threshold category** -- the
    dashboard's category routes (`dashboard/dashboard.py`) are
    responsible for never letting one be configured that way in the first
    place; a category assigned any other way would be silently
    under-enforced by the two-driver check above, so that configuration
    must never reach this function.

    Adds a subscription that doesn't exist in AdGuard yet
    (`adguard_client.add_filter_url()`), or flips `enabled` on one that
    already exists and disagrees with the computed state
    (`adguard_client.set_filter_url_enabled()`) -- never removes a
    subscription once added (disabling is sufficient, and removing would
    lose AdGuard's own last-fetched/rule-count state for no benefit).

    **NOT yet verified live** -- see `common/adguard_client.py`'s own note
    on the three functions this calls.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    categories = conn.execute(
        "SELECT * FROM categories WHERE subscription_url IS NOT NULL AND subscription_url != ''"
    ).fetchall()
    over_threshold = []
    for category in categories:
        domain_count = conn.execute(
            "SELECT COUNT(*) AS c FROM category_domains WHERE category_id = ?", (category["id"],)
        ).fetchone()["c"]
        if domain_count > MAX_SCOPED_CATEGORY_DOMAINS:
            over_threshold.append(category)
    if not over_threshold:
        return

    current_filters = {
        f["url"]: f for f in adguard_client.get_filters_status(base_url, username, password, timeout=timeout)
    }

    for category in over_threshold:
        should_enable = bool(category["is_global"])
        if not should_enable:
            # Deliberately still the bare schedule_is_active() clock check,
            # not schedule_is_active_for_device() -- a Phase 12 override
            # targets one specific user/group/device, but this function
            # can only ever enable/disable an AdGuard native filter
            # household-wide (see this function's own docstring on why an
            # over-threshold category can't be per-client scoped at all).
            # There's no single device to evaluate an override against
            # here, so a per-target override structurally cannot apply to
            # this path -- an is_mode schedule that's also is_global with
            # an over-threshold category is expected to stay clock-driven.
            gating_schedules = conn.execute(
                "SELECT s.* FROM schedule_categories sc JOIN schedules s ON s.id = sc.schedule_id "
                "WHERE sc.category_id = ? AND s.lockout_all = 0 AND s.is_global = 1",
                (category["id"],),
            ).fetchall()
            should_enable = any(schedule_eval.schedule_is_active(s, now) for s in gating_schedules)

        url = category["subscription_url"]
        existing = current_filters.get(url)
        if existing is None:
            adguard_client.add_filter_url(base_url, username, password, category["name"], url, timeout=timeout)
            if not should_enable:
                adguard_client.set_filter_url_enabled(
                    base_url, username, password, url, category["name"], False, timeout=timeout
                )
        elif bool(existing.get("enabled")) != should_enable:
            adguard_client.set_filter_url_enabled(
                base_url, username, password, url, category["name"], should_enable, timeout=timeout
            )


def _strip_managed_block(rules: list[str]) -> list[str]:
    """Remove a previously-synced managed block from AdGuard's rules
    list, keeping everything else (an admin's own manually-added rules,
    in whatever order they were in) exactly as-is."""
    if _MARKER_BEGIN not in rules:
        return list(rules)
    start = rules.index(_MARKER_BEGIN)
    try:
        end = rules.index(_MARKER_END, start)
        return rules[:start] + rules[end + 1 :]
    except ValueError:
        # A begin marker with no matching end (hand-edited AdGuard
        # rules, or an interrupted previous sync) -- drop from the
        # begin marker to the end of the list rather than leave a
        # dangling, unterminated block sitting there forever.
        return rules[:start]


def sync_safesearch(
    conn: sqlite3.Connection, base_url: str, username: str, password: str, timeout: float = adguard_client.DEFAULT_TIMEOUT
) -> None:
    """G3 (Bark Home parity): reconciles AdGuard Home's own native
    SafeSearch/Restricted-Mode master toggle against this project's
    `settings.safesearch_enabled` key (dashboard's Settings page),
    same "recompute and reconcile every cycle" discipline as everything
    else in this module. Confirmed live 2026-09-01 -- see
    common/adguard_client.py's own module note.

    Network-wide only, matching Bark Home's own behavior exactly --
    there is no per-user/group/device equivalent here, unlike
    categories/schedules elsewhere in this module.

    Deliberately touches ONLY the `enabled` field, never the per-service
    booleans (`google`/`youtube`/`bing`/etc.) -- those are left exactly
    as AdGuard's own status reports them, so an admin who has gone into
    AdGuard's own UI and turned off, say, `pixabay` specifically keeps
    that choice untouched by this project's own reconciliation. This
    project only ever offers the one master on/off from its own
    Settings page.
    """
    desired = db.get_setting(conn, "safesearch_enabled", "0") == "1"
    current = adguard_client.get_safesearch_status(base_url, username, password, timeout=timeout)
    if bool(current.get("enabled")) == desired:
        return
    payload = dict(current)
    payload["enabled"] = desired
    adguard_client.set_safesearch_settings(base_url, username, password, payload, timeout=timeout)


def sync_optigate_rewrite(
    conn: sqlite3.Connection,
    base_url: str,
    username: str,
    password: str,
    block_page_ip: str | None,
    timeout: float = adguard_client.DEFAULT_TIMEOUT,
) -> None:
    """Reconciles AdGuard Home's own DNS-rewrite entries against this
    project's single `optigate.home` entry (the memorable-URL feature,
    RoadMap.md's dated 2026-09-07 entry) -- same "recompute and reconcile
    every cycle" discipline as sync_safesearch() above, so renaming the
    hostname prefix (Settings page) or the box's own LAN IP changing
    (DASHBOARD_URL) self-heals on the next cycle, no manual step needed.

    Skipped entirely if block_page_ip is None -- same "not configured,
    not an error" treatment every other block_page_ip consumer already
    gives it (see controller/main.py's `_parse_block_page_ip()` own
    docstring): there's nowhere to point the rewrite at without it.

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


def sync_once(
    conn: sqlite3.Connection, base_url: str, username: str, password: str, block_page_ip: str | None = None
) -> int:
    """One full sync cycle. Returns the number of managed CUSTOM rules
    pushed -- does not count native filter-subscription toggles from
    `sync_category_subscriptions()` or the SafeSearch master toggle from
    `sync_safesearch()`, separate mechanisms (Phase 8/G3) each with
    their own success/failure shape. Never 0 as of 2026-09-02:
    `build_anti_doh_rules()`'s fixed baseline is always included, so the
    minimum healthy count is `len(build_anti_doh_rules())`, not 0 --
    see that function's own docstring before assuming an empty managed
    block still means "nothing to deny.\"

    Fetches the eligible-device list ONCE (2026-09-02, a real
    efficiency gap found by code review) and shares it across all three
    device-aware builders below, instead of each independently
    re-querying and re-classifying the full device list -- see
    `_fetch_eligible_devices()`'s own docstring for the before/after."""
    eligible_devices = _fetch_eligible_devices(conn)
    managed = (
        build_rules(conn, block_page_ip, eligible_devices=eligible_devices)
        + build_splice_deny_rules(conn, block_page_ip, eligible_devices=eligible_devices)
        + build_category_deny_rules(conn, block_page_ip=block_page_ip, eligible_devices=eligible_devices)
        + build_anti_doh_rules()
    )
    current = adguard_client.get_custom_rules(base_url, username, password)
    preserved = _strip_managed_block(current)

    new_rules = preserved if not managed else preserved + [_MARKER_BEGIN, *managed, _MARKER_END]
    adguard_client.set_custom_rules(base_url, username, password, new_rules)
    sync_category_subscriptions(conn, base_url, username, password)
    sync_safesearch(conn, base_url, username, password)
    sync_optigate_rewrite(conn, base_url, username, password, block_page_ip)
    return len(managed)


def run_loop(
    interval: float,
    base_url: str,
    username: str,
    password: str,
    block_page_ip: str | None = None,
    on_error=None,
    on_success=None,
) -> PeriodicTask:
    """Starts `sync_once()` running on a fixed interval, on its own
    background thread, until the returned `PeriodicTask.stop()` is
    called -- same shape as `controller/discovery.py`'s `run_loop()`,
    including the same reason for opening its own DB connection lazily
    on the background thread rather than accepting one from the caller
    (see that module's docstring: `sqlite3.Connection` objects are only
    usable from the thread that created them).

    A failed sync (AdGuard unreachable, a transient HTTP error) is
    reported via `on_error` rather than killing the loop, same as every
    other periodic task in this codebase -- a temporarily-unreachable
    AdGuard means the PREVIOUSLY-pushed rules stay in effect (fails
    closed: whatever was denied stays denied), not a reason to stop
    trying.
    """
    state: dict[str, sqlite3.Connection] = {}

    def task() -> None:
        conn = state.get("conn")
        if conn is None:
            import db  # local import: mirrors discovery.run_loop's own lazy `import db`

            conn = db.get_conn()
            db.init_db(conn)
            state["conn"] = conn
        sync_once(conn, base_url, username, password, block_page_ip)

    pt = PeriodicTask(interval, task, on_error=on_error, on_success=on_success, thread_name="adguard-sync")
    pt.start()
    return pt
