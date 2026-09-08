# Security Overview

This document describes the security model of parental_proxy as it actually
exists in code today: how each credential is checked, what trust boundary
each component sits behind, and where there are no protections at all. It is
written for an AI agent (or human) about to extend this codebase — read it
before touching auth, the Squid helper protocol, or the SSL-bump chain.

No secret values (passwords, hashes, salts, keys) appear in this file, only
mechanisms and file/function references.

---

## 1. Dashboard admin authentication

**Where:** `common/auth.py` (hashing), `dashboard/dashboard.py` (HTTP Basic
challenge, credential storage, bootstrap).

### Password hashing

`common/auth.py` implements PBKDF2-HMAC-SHA256, stdlib-only (no third-party
crypto dependency, since the proxy container needs to verify passwords too
and intentionally has no pip packages installed):

- `hash_password(password: str) -> str` — generates a 16-byte random salt via
  `os.urandom(16)`, runs `hashlib.pbkdf2_hmac("sha256", ..., iterations=260_000)`,
  and returns an encoded string of the form
  `pbkdf2_sha256$<iterations>$<salt_hex>$<digest_hex>` (the `$`-delimited
  format is self-describing, similar to Django's/passlib's convention, so the
  iteration count travels with the hash and can be bumped later without
  invalidating stored hashes).
- `verify_password(password: str, encoded: str) -> bool` — splits the encoded
  string, re-runs PBKDF2 with the embedded algorithm/iteration/salt, and
  compares digests with `hmac.compare_digest` (constant-time, avoids a
  timing side-channel on hash comparison).
- Constants: `ITERATIONS = 260_000`, `ALGORITHM = "pbkdf2_sha256"`.

This same module is used for both the dashboard admin password
(`settings.admin_password_hash`) and `users.password_hash` — but as of
2026-08-30 (see §3), nothing actually reads/verifies `users.password_hash`
today. It's set by `add_user()`/`reset_password()` but has no active
consumer: Squid no longer authenticates per-request at all (intercept
mode, §3), and the Phase 4 captive portal that would eventually verify a
kid's own login against this same field (see RoadMap.md's Phase 4 section)
isn't built yet. Treat it as reserved/dormant, not as a currently-enforced
credential, until that portal exists.

### Where admin credentials live and how they're checked

All in `dashboard/dashboard.py`:

- `bootstrap_admin()` — runs once at import time (called unconditionally near
  the bottom of the file, before `waitress.serve`). If `settings.admin_username`
  isn't already set in the DB, seeds it from `DASHBOARD_USER` env var (default
  `"admin"`). If `settings.admin_password_hash` isn't already set, seeds it
  from `DASHBOARD_PASSWORD` env var if provided, otherwise generates a random
  password via `secrets.token_urlsafe(12)`, hashes it, and prints it once to
  stderr (`docker compose logs dashboard`) since there is no other way to
  recover it. After first run, env vars are never consulted again — the
  admin login is fully DB-resident and editable from the Settings page
  (`update_admin()` at `/settings/admin`).
- `_check_admin_auth(basic_auth) -> bool` — reads `admin_username` and
  `admin_password_hash` from the `settings` table, and returns
  `basic_auth.username == expected_user and auth.verify_password(basic_auth.password, expected_hash)`.
  Note this is a plain `==` on username (not constant-time) but a
  constant-time compare on the password digest via `verify_password`.
- `require_admin(view)` — a decorator (`functools.wraps`) that calls
  `_check_admin_auth(request.authorization)` and returns a 401 with a
  `WWW-Authenticate: Basic realm="OptiGate Admin"` header on failure.
  Applied to essentially every route in the dashboard except `/ca-cert`
  (deliberately public — the CA certificate is not a secret, every client
  device needs to fetch it) and the `/blocked` friendly block page.

### Session mechanism

There is **no server-side session** and no session cookie for the admin
login. Every request is independently authenticated via the `Authorization:
Basic ...` header, which the browser caches and resends automatically for
the lifetime of the browser session (standard HTTP Basic behavior — this is
what "logged in" means here, not a cookie or token issued by the app).
`app.secret_key` is set (`db.get_setting(conn, "secret_key")`, seeded once by
`bootstrap_admin()` via `secrets.token_hex(32)`) but at the time of writing
nothing in `dashboard.py` calls `flask.session` — the key exists but is
unused for auth; if Flask sessions are added later, this key is already
provisioned correctly (random, DB-persisted, not re-generated per process).

### `users.password_hash` — now consumed by the Phase 4 captive portal (2026-08-31)

`add_user()` (`/users/add`) and `reset_password()` (`/users/reset-password`)
in `dashboard/dashboard.py` both call `auth.hash_password(password)` and
store the result in `users.password_hash`. Before 2026-08-30 this was the
credential each family member configured in their device's proxy settings,
checked by Squid on every request; that mechanism is gone (§3), and
`users.password_hash` went unverified by anything for about a day.

**As of 2026-08-31, this is a real, live-verified auth surface**:
`dashboard/captive_portal_server.py` (Phase 4 milestone 3 -- see
`docs/architecture/overview.md`) checks a submitted username/password
against it with the exact same `auth.verify_password()` call the
dashboard admin login uses against `settings.admin_password_hash` --
one shared, already-reviewed PBKDF2-SHA256 implementation
(`common/auth.py`), not a second credential-checking code path. A
successful check flips `devices.is_authenticated` for whichever device
the request's own source IP resolves to (`common/device_identity.py`'s
new `resolve_device()`) -- DNS-tier access only, never `bump_enabled`.

This is a genuinely new externally-reachable-eventually surface (per
this doc's own §7 LAN-only caveats, and the standing security-by-design
practice that flagged this exact risk before any Phase 4 code existed):
unlike the admin login (behind HTTP Basic auth, `/`-scoped, requires
already knowing the admin credential), the captive-portal login form is
reachable by ANY device nftables has classified `unauthenticated_v4` --
by design, since it exists specifically to be reachable by a device that
has never logged in before. Two things this needed, both built
alongside the login form itself rather than retrofitted (see §6 below
for the general policy this matches): a per-source-IP rate limiter (5
failed attempts / 60s, in-memory, blocking a request outright --
including one with the CORRECT password -- once tripped, so an attacker
can't use up the limiter's budget on wrong guesses and slip the right
one in unrestricted at the end), and `Cache-Control: no-store` on every
response (this is per-device, per-moment login state, never something a
browser or an OS's own captive-portal prober should cache).

### The portal-side admin action — a higher-stakes surface on the same page (2026-08-31)

`dashboard/captive_portal_server.py`'s login page also carries a
collapsed admin action (a `<details>` disclosure -- see
`docs/architecture/overview.md`) that grants strictly more than the kid
login above: **Bypass** or **assign to a group**, either of which
moves the requesting device out of `PREAUTH` entirely. It checks the
SAME credentials as the dashboard's own HTTP-Basic admin login
(`common/auth.py`'s `verify_admin_credentials()`, one shared check, not
a second implementation), and **shares the kid-login form's own rate
limiter rather than a separate one** -- a deliberate choice, not an
oversight: a lower, easier-to-exhaust budget on the higher-value target
would be the wrong direction; sharing means an attacker's wrong
guesses against either credential draw from the same pool.

This does widen the practical blast radius of a leaked/guessed admin
password beyond what existed before 2026-08-31: previously, admin
credentials were only useful via the dashboard's own HTTP-Basic prompt
(reachable at the dashboard's own bind address/port); now they are also
directly actionable from `:3131` on ANY device nftables has classified
`unauthenticated_v4` -- which, by this feature's own design, includes
every not-yet-logged-in device on the LAN. This is an accepted
tradeoff for a LAN-scoped household tool (the same §7 LAN-trust
reasoning the rest of this doc already applies elsewhere), not a gap
introduced without noticing it: if this system is ever exposed beyond
the LAN, this specific surface is one of the first things worth
revisiting.

A real, unrelated bug was found and fixed while building this (see
`docs/architecture/overview.md`'s own dated entry for the full trace):
`common/policy_class.py`'s `classify_device()` never actually consulted
`bypass_login` before now, so both this new action's own Bypass button
and Milestone 2's pre-existing dashboard one were, in practice, no-ops
at the network-policy level -- fail-closed (the device stayed gated,
not exposed), so not a security hole, but worth recording here since it
means any earlier session's use of "Bypass" before this fix genuinely
did not exempt the device from anything.

---

## 2. Dashboard CSRF protection

**Where:** `dashboard/dashboard.py`, `_reject_cross_origin_writes()`
(registered via `@app.before_request`).

Because the dashboard authenticates with HTTP Basic rather than a session
cookie plus a CSRF token, a classic CSRF-token-in-form defense isn't a
natural fit — but the ambient-credential problem is the same as cookies:
once a browser has entered Basic credentials for this origin, it will
attach them automatically to *any* request to that origin, including one
triggered by a malicious cross-site page (e.g. an auto-submitting hidden
form POSTing to `/users/delete`).

The mitigation implemented is an **Origin/Referer allowlist check**:

```python
@app.before_request
def _reject_cross_origin_writes():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    for header in ("Origin", "Referer"):
        value = request.headers.get(header)
        if value:
            if urlparse(value).netloc != request.host:
                return Response("Cross-origin request blocked.", 403)
            return None
    return None
```

Logic: only state-changing methods are checked (GET/HEAD are exempt, matching
the assumption that no GET route mutates state). For each candidate header
in order, if present and its host (`urlparse(value).netloc`) doesn't match
`request.host`, the request is rejected with 403. If *neither* header is
present, the request is allowed through — the reasoning documented inline is
that a real browser CSRF attack always carries at least one of these headers
on a cross-site POST, so the only traffic with neither header is a
non-browser client (curl, a script, an API caller) that has no ambient
credentials to steal in the first place — it must have supplied Basic auth
itself.

**Limitations to know before relying on or extending this:**

- It is a same-origin check, not a cryptographic anti-CSRF token — it trusts
  that browsers reliably send `Origin` (they do, for cross-site
  state-changing requests, per the Fetch spec) and that no legitimate
  same-site flow needs to omit both headers.
- It only checks `netloc` (host:port), not scheme — an attacker on
  `http://dashboardhost` vs. the real `https://dashboardhost` would pass,
  but this deployment has no TLS on the dashboard at all (see §7), so that
  distinction doesn't currently apply.
- It is global (`before_request` on the whole app), not scoped per-route —
  if a future route needs a legitimate cross-origin POST (e.g. a webhook),
  it will need an explicit carve-out here.
- It does not protect GET routes that have side effects. If a future route
  is added that mutates state on GET (it shouldn't be, but nothing enforces
  that), this check does not cover it.

---

## 3. Squid-side identity: device-based, not credential-based (intercept mode)

**Where:** `common/device_identity.py` (the resolver), consumed by
`proxy/sni_helper.py` and `proxy/authz_helper.py`; intercept-mode ports
configured in `proxy/squid.conf.template` (`http_port 3129 intercept`,
`https_port 3130 intercept ssl-bump ...`).

**This replaced a real, previously-documented mechanism.** Before
2026-08-30, each family member had one login, checked per-request by
`proxy/basic_auth_helper.py` via Squid's `auth_param basic` (HTTP Basic,
challenged with a 407 during the `CONNECT` handshake). That mechanism was
removed along with `basic_auth_helper.py` itself when Squid moved to
**intercept mode** — nftables NAT-redirects a bump-enabled device's own
port 80/443 traffic to Squid (see
`phase3/nftables-manager/internal/nft/knftables_adapter.go`'s `bump_v4`
rules and RoadMap.md's "two independent axes"/"Squid intercept mode"
sections), so the client never sends a `CONNECT` at all for an intercepted
HTTPS connection — there is no handshake step left for a 407 challenge to
answer, and therefore no way to challenge for a per-request login anymore.

### The replacement: resolve identity from the client's IP, not a credential

`common/device_identity.py`'s `resolve_device(conn, client_ip)`:

```sql
SELECT d.* FROM device_bindings b
JOIN devices d ON d.id = b.device_id
WHERE b.ipv4_address = ? AND b.active = 1
ORDER BY b.last_seen_at DESC LIMIT 1
```

Both `sni_helper.py` (`handle_splice`, `handle_block_page`) and
`authz_helper.py` (`decide`) call this with `%>a` (the client's source IP,
still available on an intercepted connection) in place of the old `%LOGIN`
field. A `None` result here — no active binding for that IP at all, a
genuinely never-seen device — is treated exactly like the old "empty/absent
`%LOGIN`" case: denied, logged as unidentified where the old code logged
`"(unauthenticated)"`.

**Fixed 2026-08-31 — a real, previously-shipped bug**: this used to be a
single `resolve_user(conn, client_ip)` function that INNER JOINed straight
through to `users` via `devices.user_id` in one query — so a device
assigned to a GROUP (not a person) had no `users` row to join to and
resolved to `None`, indistinguishable from "never seen at all," and was
denied everything unconditionally. Split into `resolve_device()` above
(the binding lookup, unchanged in behavior) plus a separate
`resolve_user_for_device(conn, device)` (`devices.user_id -> users`, or
`None` for an unassigned *or* group-assigned device) specifically so those
two very different cases — "no identity resolved at all" vs. "a real,
resolvable device identity that just isn't a *person*" — can never be
conflated again. `common/matching.py`'s `device_domain_reason(conn, device,
domain)` is the actual authorization check now: `is_global`, or an explicit
`user_domains`/`group_domains`/`device_domains` grant via the device's
user, its group, or the device itself directly. A resolved device with no
user at all can still be fully authorized this way — see
`proxy/authz_helper.py`'s new `reason="show_requires_user"` for the one
remaining case that can't be evaluated without a real user (Crunchyroll's
`user_shows` has no group/device equivalent).

**This is not itself a new authentication mechanism — it deliberately has
none.** There is no credential check anywhere in this path. "Identity" here
means *whichever device currently holds this IP, and whichever user, group,
or direct grant that device is administratively assigned to* (via the
dashboard's `/devices` and `/domains` pages, or the Phase 4 captive portal)
— a standing assignment, not a per-request proof of identity. See §6 below
for the trust-boundary consequence of that.

### Why this is safe to rely on despite IPs changing (DHCP)

`device_bindings` is keyed by MAC address, not IP — `common/identity.py`'s
`record_binding()` handles a device's IP changing (DHCP renewal) by
deactivating the stale `(mac, old_ip)` row and activating a fresh
`(mac, new_ip)` one, so `resolve_device()`'s `WHERE ... AND active = 1`
always targets whichever IP is *currently* live for that MAC, not a stale
one.

**The gap this depends on -- narrowed further, 2026-08-31**: something has
to actually call `record_binding()` regularly when a device's IP changes
for this to stay current. `controller/discovery.py`'s `snapshot_once()`
(a periodic `ip neigh show` snapshot) is wired into an actual running
loop (`discovery.run_loop()`, started from `controller/main.py`'s `run()`
on its own background thread and its own DB connection, interval
configurable via `--discovery-interval`). **Correction to this
paragraph's own 2026-08-30 claim**: it said the higher-precedence live
rtnetlink-event listener "still doesn't exist" -- that was true when
written, but `controller/rtnetlink_listener.py` was built and wired in
the same day (enabled by default alongside `--db-path`, see
`--no-rtnetlink`), so most DHCP-renewal staleness is now closed near-
immediately rather than bounded by the snapshot's own interval. The
snapshot loop remains the catch-all for anything the live listener
missed (e.g. a device already idle before this process started). As of
2026-08-31, `controller/active_scan.py` narrows the remaining gap
further still for a device that's gone quiet rather than renewed: it
periodically nudges the kernel to re-resolve a stale binding's IP (a
plain UDP `sendto()` to a closed port, since the controller holds no
`CAP_NET_RAW` -- see `docs/architecture/overview.md`), letting the same
snapshot/rtnetlink sources pick up a real device that's still on the LAN
but hasn't generated fresh traffic on its own. During whatever window
remains before any of these sources catches a new IP, `resolve_device()`
for that IP returns `None` -- the device fails toward *less* access
(denied, not misattributed to a different user), which is the safe
direction, but it's still a real, bounded-but-nonzero gap, not a
hypothetical one. See RoadMap.md Milestone 4 and `controller/discovery.py`'s
docstring.

### The hard-deny invariant: what stops a non-bump device from ever seeing a `mode='bump'` domain

Squid's own identity resolution above only ever runs for traffic that
already reached Squid's intercept ports — which nftables only routes
there for a device `common/policy_class.py`'s `bump_eligible()` returns
True for (`bump_v4` set membership: `bump_enabled = 1` AND currently
`AUTHENTICATED`, not `bump_enabled` alone) in the first place. For every
OTHER device, the actual enforcement point is one layer earlier, at
DNS: **`controller/adguard_sync.py`** (added 2026-08-30, closing the
last gap this section used to flag) computes, for every
`domains.mode = 'bump'` row, a per-client AdGuard Home filtering rule
(`$client=ip1,ip2,...`) scoped to exactly the devices that are
currently NOT `bump_eligible()`, and pushes the full set as a
`/control/filtering/set_rules` replace every sync cycle. A non-bump
device's DNS query for a bump-mode domain (Crunchyroll, or any other
domain an admin sets to `bump`) never even resolves — confirmed live
against a real AdGuard Home instance to return `0.0.0.0`, not merely
designed to. This is what makes the "two independent axes" architecture
(RoadMap.md, locked 2026-08-30) actually hold in practice: a device
that's authenticated but not bump-enabled gets normal DNS-tier
protection for everything else, but is structurally incapable of
resolving a domain the household has marked as needing Squid's
refinement, regardless of what app or client makes the request.

**Real bug found and fixed 2026-08-31, while auditing this exact
invariant for a second time** (prompted by the `classify_device()`/
`bypass_login` fix found the same day): `build_rules()` used to select
on the raw `bump_enabled` column rather than the actual derived
`bump_eligible()` state above. A device with `bump_enabled = 1` set but
not yet `AUTHENTICATED` (a genuinely new PREAUTH device, or one
pre-configured for bump ahead of its first login) was excluded from
this hard-deny list — while simultaneously NOT being a member of
nftables' `bump_v4` set either, since `bump_eligible()` requires
`AUTHENTICATED` too. The result was a full, silent bypass: AdGuard
resolved the real IP for the `mode='bump'` domain, and nftables never
redirected the resulting HTTPS connection to Squid — worse than either
a hard deny or Squid's own refinement, a completely unfiltered
connection to exactly the domain this whole mechanism exists to
control. Now fixed to select the same way `controller/policy_state.py`
already does.

Same freshness caveat as the DHCP note above applies here too — a
device's current IP has to already be in `device_bindings` (via the
discovery loop) before `adguard_sync` can scope a deny rule to it, and
the AdGuard sync itself runs on its own interval (`--adguard-interval`,
default 30s). A brand-new or just-renewed device is briefly unresolved
by identity, not un-denied by policy — see `controller/adguard_sync.py`'s
own `build_rules()` docstring.

**A subtle failure mode this invariant depends on staying fail-closed**
(found and fixed 2026-08-30): `adguard_sync.sync_once()` reads AdGuard's
*current* custom rules first (`common/adguard_client.get_custom_rules()`)
so it can preserve anything it doesn't manage — an admin's own
hand-added AdGuard rule — before overwriting with the full replacement
list. A first version of a fix for a real AdGuard API quirk (a
freshly-configured instance reports its `user_rules` key as `null`, not
`[]`) went too far and treated *any* anomalous read (a non-dict
response, a missing key entirely — not just the one confirmed-live
`null` shape) the same way: silently as "no rules yet." That would have
let a merely malformed read proceed straight to a destructive
full-replace write, silently discarding real rules (including the
per-client bump-deny rules this section is about) instead of raising
and leaving AdGuard's actual, working rules untouched. Caught by code
review before it shipped; `get_custom_rules()` now only special-cases
the one confirmed shape (key present, value `null`) and still raises
`AdGuardError` — which `run_loop()` reports via `on_error` without
touching AdGuard, i.e. fails closed — for a missing key or non-object
response.

### The shared authorization resolver, and closing two real gaps at once (2026-08-31, GH #9)

Everything in this section so far is about the `bump`-mode hard-deny
invariant. A separate, previously-unenforced concern: whether a device is
even allowed a given `splice`-mode domain at all, based on the Domains
page's per-user/group/device/everyone assignment
(`user_domains`/`group_domains`/`device_domains`/`domains.is_global`).

**Two real gaps, found together while scoping "tighter Squid/AdGuard
integration" per the project owner's request**, both traced back to the
same root cause and fixed with the same shared function:

1. **A live bug on Squid itself, not an AdGuard-only issue.** The old
   `resolve_user(conn, client_ip)` (§3 above, since replaced) resolved
   straight through to a `users` row via `devices.user_id` in one query —
   a device assigned to a **group** had no such row and resolved to
   `None`, indistinguishable from "never seen at all," and was denied
   unconditionally by both `authz_helper.decide()` and
   `sni_helper.handle_splice()` before ever reaching a domain check. Even
   a user-resolved device could never benefit from a `group_domains` or
   `device_domains` grant — `common/matching.py`'s `group_has_domain()`
   and `device_has_domain()` existed (built for the dashboard's Domains
   page) but were never called from any enforcement path at all; their own
   docstrings said so explicitly.
2. **AdGuard enforced none of this at all.** `controller/adguard_sync.py`
   (the module §3.4 above describes) did exactly one thing before this
   fix: the `bump`-mode hard-deny. `splice`-mode domain assignment — the
   content control most devices actually rely on, since bump is a
   deliberately small curated set — was completely unenforced at the DNS
   tier. A domain assigned to one kid was reachable by every device on the
   LAN as long as it went through AdGuard instead of Squid.

**The fix**: `common/matching.py`'s `device_domain_reason(conn, device,
domain)` is now the single authorization check, used everywhere instead of
each call site inlining its own version — `is_global`, then the device's
own `user_domains` grant (if it has a `user_id`), then its `group_domains`
grant (if it has a `group_id`), then a direct `device_domains` grant,
first match wins. `common/device_identity.py`'s `resolve_user()` was split
into `resolve_device()` (the binding lookup) and
`resolve_user_for_device()` (derives the user, if any, from an
already-resolved device) specifically so "no identity at all" and "a real
device identity with no *person* attached" are never conflated again.
`proxy/authz_helper.py` and `proxy/sni_helper.py` both now resolve the
device first and call `device_domain_reason()`; `controller/adguard_sync.py`
gained `build_splice_deny_rules()`, using the exact same `$client=`-scoped
rule mechanism §3.4 already describes, now covering `mode='splice',
is_global=0` domains too, pushed in the same managed block alongside the
existing bump hard-deny.

**Scope deliberately still excludes a domain with no `domains` row at
all** — that stays default-allow at the DNS tier, unchanged from before
this fix. Making AdGuard default-deny for a totally unconfigured domain
(mirroring Squid's own `block_page_mode` posture) was considered and
explicitly deferred to a separate future decision, since it's a much
bigger behavior change (every new site anyone visits needs an explicit
approve) that wasn't part of this pass's confirmed scope.

**A second, smaller logging gap closed alongside this**:
`dashboard/block_page_server.py` (AdGuard's kid-facing block page) wrote
nothing to `access_log` at all before this fix — not even the block
itself, per its own module docstring at the time ("AdGuard never touches
this project's database at all"). It now resolves identity the same way
the Squid helpers do and logs a row with `reason="dns_tier_denied"`,
wrapped in a try/except so a DB hiccup there can never break the actual
page a kid is looking at. `access_log` gained a `device_id` column (see
`docs/database/schema.md`) so a device- or group-only row (no `user_id` at
all) can still be filtered and reactively approved from the Report page —
`dashboard.py`'s `approve_from_report()` now accepts `scope=device` and
`scope=group` alongside the existing `user`/`global`, granting
`device_domains`/`group_domains` instead of `user_domains`.

### Rework, same day: AdGuard now checks domain assignment for bump-eligible devices too

The section above describes the state right after GH #9 first landed:
`build_rules()` (bump hard-deny) and `build_splice_deny_rules()` (splice
assignment) as two separate concerns, the first keyed purely on
bump-eligibility. **Before committing any of it, the project owner
reviewed and corrected that model** — a bump-eligible device was still
getting a free DNS pass to *any* `bump`-mode domain, with the actual
per-domain assignment check left entirely to Squid's own
`authz_helper.decide()`, after decryption. Five explicit points, the
one that actually changed behavior: *"If a user has a device subject to
SSL Bump, AdGuard should check the domain first and verify it is
allowed... If the domain is not allowed it should still be blocked by
AdGuard, never going to SSL Bump."*

`build_rules()` and `build_splice_deny_rules()` are now both thin
wrappers around one shared engine, `_build_domain_deny_rules(conn, mode,
require_bump_eligible, ...)`. A device is authorized for a domain when
`device_domain_reason()` returns non-`None` **and**, only when
`require_bump_eligible=True` (i.e. `mode='bump'`), `bump_eligible()` is
*also* true. `is_global` on a bump-mode domain still only ever means
"assigned to everyone" — it does not skip the bump-eligibility gate; a
non-bump-eligible device is denied a global bump domain exactly as
before this rework. The net effect: a bump-eligible device now only gets
a clean DNS resolution for a bump-mode domain that's actually assigned
to it (globally, or via its user/group/device) — an unassigned one is
blocked by AdGuard outright, and the connection never reaches Squid to
be decrypted and denied there.

**A fourth point surfaced a distinction this project already had, just
never enforced anywhere**: *"AdGuard DNS should apply a baseline of
protection against all devices/users/groups unless the device/user/group
is set to bypass/ignore."* `common/policy_class.py`'s `classify_device()`
already distinguishes `ignored` (BYPASS — "outside the whole system,
for good") from `bypass_login` (only skips the captive-portal login
step; the device "can still belong to a user or group" and its domain
rules still apply — see that function's own docstring). Confirmed with
the project owner that "bypass/ignore" here means `ignored` specifically,
not `bypass_login`. `_build_domain_deny_rules()` now excludes any
`classify_device() == BYPASS` device from every rule it builds, on
either mode — defense-in-depth, since an `ignored` device's packets
already never reach AdGuard's redirected port at all under normal
ARP-spoofed interception (nftables' `bypass_v4` `return`).

**A related UI default, the project owner's own explicit follow-up**:
"anything that gets bypass_login should be added to ignore by default
but give me the ability to change that later." `dashboard.py`'s
`update_device()` and `bypass_login_device()` now default a device to
`ignored=1` the moment `bypass_login` is newly turned on — but only as a
default: skipped if the same submission (or the device's existing state)
already carries a real `user_id`/`group_id`, and only fires on the actual
0→1 transition, so it never fights a later, deliberate "actually, assign
it somewhere" edit. This is a dashboard-side convenience, not something
`_build_domain_deny_rules()` itself enforces — the two flags remain
independently readable and settable at all times.

---

## 4. The `external_acl_type` helper protocol — internal trust boundary

**Where:** `common/squid_helper.py` (shared loop), `proxy/sni_helper.py`,
`proxy/authz_helper.py`; wired up in `proxy/squid.conf.template` via
`external_acl_type ... /usr/bin/python3 /opt/parental-proxy/<helper>.py`.

### Protocol mechanics

Squid speaks a simple line protocol to each helper, implemented once in
`common/squid_helper.py`'s `run(name, field_count, handler, *, unquote=True,
keep_trailing_spaces=False)`:

- Squid launches the helper as a **long-lived local subprocess** (per
  `children-max=N` in the `external_acl_type` line) and writes one
  space-separated, percent-encoded line per request to its stdin.
- The helper reads `sys.stdin` in a loop, splits each line into exactly
  `field_count` fields, percent-decodes them (`urllib.parse.unquote`, unless
  `unquote=False`), and calls `handler(conn, *fields)`.
- The handler's boolean return is written back as `"OK\n"` or `"ERR\n"` to
  stdout, flushed immediately (`sys.stdout.flush()`), so Squid can read the
  reply before sending the next line.
- Any exception raised by the handler is caught at the loop level, logged to
  stderr, and treated as `False`/`"ERR\n"` — **one malformed or
  exception-raising request must never kill the helper process** (a crashed
  helper would leave Squid unable to evaluate that ACL at all for every
  subsequent request until Squid restarts it).
- A line with the wrong number of fields (e.g. the field-count-off-by-one
  bug documented in `squid.conf.template` around the trailing `%DATA`
  macro) is answered `"ERR\n"` without ever calling the handler.

`sni_helper.py` uses `field_count=3` (`%>a %ssl::>sni %DATA`) and is
invoked four times under four different `sys.argv[1]` modes (`bump`,
`trusted`, `splice`, `block_page`) dispatched via a `HANDLERS` dict — each
mode backs a separate `acl ... external ...` line and a separate long-lived
helper process (no shared in-memory state between the four modes).
`authz_helper.py` uses `field_count=4` (`%>a %DST %PATH %DATA`) and is
invoked once, only for domains already decided to be in `bump` mode. Both
field counts dropped by one from their pre-2026-08-30 values when `%LOGIN`
was removed (§3).

### Threat model: local trust, not network-exposed

This is the key property to reason about when extending these helpers:
**Squid invokes them as local subprocesses communicating over stdin/stdout
pipes, never over a network socket.** There is no listening port, no
network-reachable attack surface, and no way for an external client to talk
to `sni_helper.py` or `authz_helper.py` directly — only Squid's own C code,
running as the same container's process tree, can write to their stdin.

Consequences for what threat model applies:

- **Does apply:** input to these helpers must be treated as coming from a
  trusted-but-fallible local component (Squid itself) that can send
  malformed, unexpected, or unexpectedly-encoded data due to version quirks
  or config mistakes — hence the defensive per-line try/except and
  field-count validation in `squid_helper.run()`. The values inside the
  fields (`%>a`, `%DST`, SNI, path) originate from the end-user's traffic
  and **are** attacker-influenceable in content (a malicious
  hostname/path/SNI string, or — per §3 — a spoofed source IP), so the handlers must not trust those
  values as safe — e.g. all DB access goes through parameterized queries
  (`conn.execute("... WHERE username = ?", (username,))`), and hostname/path
  parsing (`_split_host_port`, `matching.find_domain`) treats them as
  arbitrary untrusted strings, not code.
- **Does not apply:** there is no need for these helpers to authenticate
  their caller, rate-limit requests, defend against a network-based
  attacker connecting directly to them, or worry about transport
  confidentiality between "client" and "server" — there is no network hop
  between Squid and the helper to secure. Do not add TCP listeners, HTTP
  endpoints, or auth tokens to these helpers on the assumption they need
  network-facing hardening; that would be solving a problem this design
  doesn't have, at the cost of introducing a new one (an actually
  network-reachable surface).

If a future change ever makes any of these helpers reachable other than via
Squid's own subprocess stdin (e.g. exposing one as a standalone service for
reuse), the threat model changes completely and this section's guidance no
longer applies — that helper would need the same scrutiny as the dashboard
itself (auth, input validation against a hostile network peer, etc.).

---

## 5. SSL-Bump / CA certificate trust model

**Where:** CA generation in `proxy/entrypoint.sh`; bump-chain configuration
and mode semantics in `proxy/squid.conf.template`; per-domain mode decisions
in `proxy/sni_helper.py`; public cert download at the dashboard's `/ca-cert`
route (`dashboard/dashboard.py`, deliberately unauthenticated since a
certificate is not a secret).

### What the CA can do

`entrypoint.sh` generates a self-signed root CA on first run if
`$SSL_DIR/ca_cert.pem` / `ca_key.pem` don't already exist:

```sh
openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
  -keyout "$SSL_DIR/ca_key.pem" -out "$SSL_DIR/ca_cert.pem" \
  -subj "/O=${CA_ORG:-OptiGate}/CN=${CA_COMMON_NAME:-OptiGate CA}" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

`basicConstraints=CA:TRUE` and `keyUsage=keyCertSign` are explicitly forced
(not just relying on the base image's `openssl.cnf` defaults) so Squid's
`sslcrtd_program` (`security_file_certgen`, configured in
`squid.conf.template`'s `sslcrtd_program`/`sslcrtd_children`) can mint
per-site leaf certificates signed by this key on the fly, as directed by
`https_port 3130 intercept ssl-bump generate-host-certificates=on
cert=... key=...`.

**Once a device is told to trust this CA certificate as a root, that CA can
mint a certificate for *any* hostname and have the device accept it as
genuine** — this is not a limitation specific to this project, it is the
fundamental mechanism of how TLS-terminating ("MITM") proxies work: the
proxy presents a certificate for the real destination hostname, signed by a
key the client trusts, and the client has no way to distinguish that from
the real site's actual certificate. Trusting this CA is equivalent to
trusting the proxy operator to decrypt and observe any TLS connection to any
site, not merely the sites this project chooses to bump. That trust is
concentrated entirely in the private key at `$SSL_DIR/ca_key.pem`, which
"never leaves this container" (per `entrypoint.sh`'s comment) but is
included in the backup archive described in the README (so restoring a
backup restores the same trusted identity — devices don't need to re-trust a
new cert after a restore, which is convenient operationally but also means
that backup archive is exactly as sensitive as the key itself).

### Why a device that doesn't trust the cert sees a warning for bump-mode sites

For any domain in `bump` mode (Crunchyroll, or any admin-configured domain —
see `sni_helper.py`'s `handle_bump`), `ssl_bump bump step2 sni_bump` in
`squid.conf.template` means Squid fully terminates the TLS connection and
re-encrypts it with a leaf cert signed by the local CA. If the connecting
device has not installed/trusted that CA as a root, its TLS stack correctly
identifies the presented certificate as untrusted (signed by an unknown CA)
and shows the browser's standard "connection not private" warning.

**This is a designed-in signal, not a bug.** Both the README and
`SETTINGS_BODY` in `dashboard.py` describe it as a diagnostic: "if a
`bump`-mode site like Crunchyroll already loads cleanly on a device, that
device's certificate trust is set up correctly." The `block_page_mode`
setting (`terminate` vs. `redirect`, see `sni_helper.py`'s
`handle_block_page` and `db.get_setting(conn, "block_page_mode", "terminate")`)
explicitly trades on this: switching to `redirect` bumps *every* blocked
connection (including previously-untouched `splice`-mode ones) so a friendly
deny page can be served — but only produces a clean page if the device
already trusts the CA; otherwise it produces the same "not private" warning,
which the docs call out as strictly worse than the plain connection failure
`terminate` mode produces. This is why `terminate` is the default and the
Settings page warns not to switch to `redirect` until certificate trust is
confirmed fleet-wide.

### Why `splice` mode never has this issue

`splice`-mode domains (the default mode) are handled by
`ssl_bump splice step2 sni_splice_allowed` — Squid inspects only the
ClientHello's SNI field during the TLS handshake (`ssl_bump peek step1`,
then the SNI-based ACLs in `sni_helper.py`'s `handle_splice`/`handle_trusted`)
and, if allowed, **passes the encrypted bytes through unmodified** — it never
terminates the TLS session, never presents a substitute certificate, and
never sees anything beyond the hostname in plaintext. Because the client's
TLS handshake completes directly with the real origin server using the real
origin's real certificate, there is nothing for the client to distrust:
splice mode is transport-layer forwarding, not interception, so no
certificate warning can ever occur for it. This is the whole reason
`trusted` and `splice` domains exist as separate modes from `bump` — they
get per-host filtering with none of the CA-trust prerequisite or MITM
exposure that `bump` mode inherently carries.

---

## 6. Rate-limiting, lockout, brute-force protection

**Correction, 2026-08-31**: this section used to say "there is none,
anywhere in this codebase" — that's no longer true as of Phase 4
milestone 3. `dashboard/captive_portal_server.py`'s login form (§1's
`users.password_hash` entry above has the full writeup) has a real,
in-memory, per-source-IP limiter: 5 failed attempts / 60s, and a
tripped limiter blocks the NEXT attempt outright regardless of whether
its password is actually correct, closing the obvious "use up the
budget on wrong guesses, slip the right one in last" gap a naive
per-failure-only counter would leave open. This was built alongside the
login form itself, not retrofitted, per this project's own standing
security-by-design practice. It resets on a dashboard process restart
(in-memory, no new DB table for a first pass) and would need revisiting
if this surface is ever exposed beyond the LAN (Phase 7) — but for a
LAN-scoped captive-portal login, an attacker who already needs local
network access to even reach it is a meaningfully smaller threat model
than an internet-facing one.

**Correction, 2026-09-02**: this section used to list the dashboard
admin login as the one significant real gap left ("no rate limiting at
all"). A dedicated audit (prompted by the project owner, ahead of a
planned full code-review pass) closed it: `require_admin` now shares
the exact same mechanism the captive portal already used, factored out
into `common/rate_limit.py`'s `RateLimiter` (5 failed attempts / 60s,
per source IP, in-memory) rather than a second implementation --
`dashboard.py` and `captive_portal_server.py` each hold their own
separate instance (different network surfaces, deliberately not sharing
a budget). Same "use up the budget on wrong guesses" closure as the
portal: a rate-limited request is rejected (`429`, `Retry-After: 60`)
*before* even checking the supplied credentials, which also means an
attacker can no longer force repeated 260,000-iteration PBKDF2
computations by flooding once already limited. Only a request that
actually supplied an `Authorization` header counts against the budget
or gets checked against it at all — the routine credential-less first
request every browser's very first hit on this origin triggers isn't a
guessing attempt (it can never succeed either way) and would otherwise
risk rate-limiting normal multi-device household use rather than an
attacker, who must supply *some* credential guess to have any hope of
succeeding and so can never dodge the counter this way.

**Failed attempts are now dashboard-visible, not just in container
logs** (same 2026-09-02 pass): a wrong-password attempt against either
the dashboard admin login or either of the captive portal's two forms
now also writes a `system_events` row (`source` one of
`dashboard_admin_login`, `captive_portal_login`,
`captive_portal_admin_action`; `severity='error'`), visible on the
`/events` page (Phase 11) alongside every other operational failure —
see `docs/dashboard/routes.md`'s Events section, now updated to reflect
that the dashboard itself writes here too, not only
`controller/main.py`'s background loops. The attempted *password* is
never logged anywhere, in `system_events` or in `logging` calls — only
the source IP and the attempted username, truncated to 100 characters
before being stored (that field is fully attacker-controlled on every
attempt, and `system_events` has no row-count pruning yet, see Phase
11's own note). A successful login logs nothing at all, matching
`system_events`'s own deliberately-not-a-firehose design (see
`common/system_events.py`'s docstring) -- only the failure is a
"real event" worth a row.

**A related, independently-found bug fixed in the same pass**: the
dashboard container never called `logging.basicConfig()` anywhere
(unlike `controller/main.py`, which does) -- every `log.info()`/
`log.warning()` call in `dashboard.py`, `captive_portal_server.py`, and
`block_page_server.py`, including the *pre-existing* failed-login
`log.info()` calls in `captive_portal_server.py` from Phase 4, silently
never reached `docker compose logs dashboard` for INFO-level calls (only
WARNING+ ones surfaced, via Python's own bare last-resort handler).
Fixed by adding the same call to `dashboard.py`'s `main()` -- in `main()`
specifically, not at module import time, so importing this module for
tests never installs a handler on the root logger.

Still true, and still worth an extending agent knowing explicitly
before pointing any part of this system at the internet:

- **No IP-based throttling** anywhere in `common/squid_helper.py` or
  `matching.py`.
- **Squid's side has no login left to brute-force at all** (§3) — a
  meaningfully *different* risk now, not a smaller version of the old one:
  identity is granted to whoever's traffic arrives from a bump-enabled
  device's current IP, with no credential check whatsoever. There is
  nothing to guess, but also nothing standing between "controls that IP"
  and "is treated as that device's assigned user" — see §7's LAN-trust
  discussion for why this is accepted rather than mitigated.
- **Both the dashboard's and the portal's limiters are in-memory and
  per-process**, resetting on a restart and never shared across a
  multi-worker deployment (this app runs as a single waitress process,
  so that's moot today, but would need revisiting if that ever changes)
  -- an attacker who can force/wait out a container restart gets a fresh
  budget. Acceptable for a LAN-scoped household tool, not for an
  internet-facing one.

For the admin login and Squid's IP-based identity, the other mitigating
factors present are architectural, not brute-force-specific: (a)
`_check_admin_auth`'s password comparison is constant-time
(`hmac.compare_digest` inside `verify_password`), removing a timing
side-channel, and (b) the LAN-scoping described in §7, which — while it
is *not itself authentication* and is explicitly not one — currently
limits who can even reach the dashboard's login prompt, or spoof a
bump-enabled device's IP, to begin with in the intended LAN-only
deployment. If this system is ever deployed such that the dashboard is
reachable from the internet, IP-based throttling for Squid's identity
model and a persisted (not in-memory) lockout store would need to be
added — nothing in the current code provides either.

---

## 7. Scoping / trust boundaries — LAN-only design

**Where:** `common/matching.py`'s `ip_in_configured_lan()`; `local_network`
setting seeded in `proxy/entrypoint.sh` and `dashboard/dashboard.py`'s
`bootstrap_admin()`; documented caveats in `.env.example` and
`README.md`.

### The LAN-IP check as a defense layer

`matching.ip_in_configured_lan(conn, ip_str)` checks the connecting client's
IP against the `local_network` setting — one or more space-separated CIDRs
(e.g. `192.168.1.0/24`). It is consulted in two places: `authz_helper.py`'s
`decide()` (HTTP-layer, bump-mode domains) and `sni_helper.py`'s
`handle_splice()` (SNI-layer, splice-mode domains) — both deny with
`reason="outside_lan"` if the client IP doesn't match.

**Its role changed with §3's identity model.** Before 2026-08-30 this was
explicitly a second, independent layer on top of per-person proxy
authentication — a correct username/password from outside the configured
range was still denied. With that per-request credential gone, this check
is now, alongside `device_identity.resolve_device()`'s device-assignment
lookup, one of the only two things standing between arbitrary traffic
reaching Squid's intercept ports and being treated as a specific user's
(the third, upstream layer is nftables only ever redirecting a
bump-enabled device's own current IP to those ports in the first place —
see §3's device-identity section and RoadMap.md's nftables skeleton, not
covered further in this file).

An empty `local_network` setting **disables this check entirely** —
`ip_in_configured_lan()`'s docstring and code both treat a blank value as
"check disabled" (`return True`).

### The Docker networking caveat

**As of 2026-08-30, `docker-compose.yml`'s `proxy` service runs with
`network_mode: host`** — not the plain bridge networking this section
originally warned about — specifically because bridge networking was
found (via a live verification pass, see RoadMap.md) to break more than
just this LAN-IP check: it also breaks Squid's own `SO_ORIGINAL_DST`
destination recovery entirely, since `phase3/nftables-manager`'s
redirect fires in the host's own network namespace and a bridge-
networked container is a different namespace. Host networking fixes
both at once — the proxy now sees real client IPs, so this check works
correctly on the intended deployment target (a native Linux Docker
host; **not** Docker Desktop on Windows/Mac, which doesn't support
`network_mode: host` the same way).

`.env.example` still documents the fallback for testing under Docker
Desktop or another environment where real client IPs genuinely aren't
visible: leave `LOCAL_NETWORK` blank (here or in the dashboard's
Settings page) to disable the check. **An agent reintroducing bridge
networking for this service should recognize that doing so silently
makes this defense layer unable to distinguish LAN clients from
anything else, AND breaks Squid's own interception mechanism** — see
RoadMap.md's live-verification section for exactly how that failure
looks in practice. The documented mitigation (disabling the check
outright) leaves nftables' `bump_v4` IP-set membership (RoadMap.md) as
the only thing gating which traffic reaches Squid's intercept ports at
all, with no LAN-range check or credential behind it.

The new `adguard` service (2026-08-30, see §3's hard-deny note below)
runs with `network_mode: host` for the same underlying reason —
`phase3/nftables-manager`'s DNS-tier redirect (`udp/tcp dport 53
redirect to :5353`) also fires in the host's own namespace, and
AdGuard's own per-client `$client=` rules need to see devices' real LAN
IPs to mean anything at all. Its own admin UI (separate from this
project's dashboard) defaults to `127.0.0.1`-only via `ADGUARD_WEB_BIND`,
mirroring `DASHBOARD_BIND`'s reasoning exactly — with host networking,
container-level port publishing no longer applies, so the app's own
listen address is what actually gates LAN exposure.

### Current LAN-only assumptions worth revisiting before any internet-facing deployment

The codebase and docs consistently assume a home-LAN deployment; concretely,
what's evidenced in code:

- `DASHBOARD_BIND` defaults to `127.0.0.1` in `.env.example` and
  `docker-compose.yml` ("dashboard only reachable from this machine — use
  SSH port-forwarding for remote access"); `0.0.0.0` is offered as the
  alternative for "reachable from any device on your LAN," not from the
  internet.
- The dashboard is served over **plain HTTP** via `waitress.serve(app,
  host=host, port=port, threads=8)` in `dashboard.py`'s `main()` — there is
  no TLS termination anywhere in the dashboard container. Admin credentials
  (HTTP Basic, §1) and every form submission travel unencrypted between
  browser and dashboard. This is a reasonable trade for a LAN-only tool but
  would need a reverse proxy with TLS (or equivalent) in front before any
  exposure beyond a trusted LAN/VPN.
- The LAN-IP check is treated throughout the codebase as a meaningful trust
  signal — but per `.env.example`, it is routinely disabled outright under
  Docker Desktop/bridge networking, at which point nftables' bump_v4 set
  membership (§3) is the only thing left gating Squid access, with no
  LAN-range check and no credential of any kind behind it.
- **Correction**: both the dashboard admin login and the captive portal's
  login now DO have rate limiting (§6, `common/rate_limit.py`, added
  2026-09-02) — this bullet used to say "none anywhere," which stopped
  being true that day. What's still a real gap for internet-facing use:
  the limiter is in-memory/per-process (resets on a container restart,
  and Squid's own IP-based identity model has no login to rate-limit at
  all) — acceptable when the only reachable parties are already on the
  trusted LAN, not acceptable once the dashboard is reachable from an
  untrusted network without a persisted, restart-surviving lockout store.
- Squid's `ssl_bump` CA trust model (§5) assumes the operator controls and
  can push CA trust to every device on the network (README's per-device
  certificate-trust install steps) — a workable assumption for a household
  under one administrative control, not for an arbitrary internet-facing
  user base.

None of this is a defect in what the project claims to be — README and
`.env.example` are explicit that this is a home/LAN parental-control tool —
but any future work aimed at internet-facing or multi-household/multi-tenant
use would need to add: TLS on the dashboard, a persisted (not in-memory)
lockout store to replace the existing per-process rate limiter (§6),
and a reconsideration of what "LAN membership" is even supposed to mean
as a trust signal once clients aren't all on one administratively-controlled
network.

## 8. Content-category and schedule enforcement (Phase 8, added 2026-08-31/09-01)

Two new, independent enforcement mechanisms, both built as pure computed
overlays rather than mutating any existing state:

**DNS-tier category blocking** (`controller/adguard_sync.py`) splits by
size, confirmed via live research that this split is necessary, not
optional (see RoadMap.md's Phase 8 entry and `docs/database/schema.md`'s
scale note): a category at or under `matching.MAX_SCOPED_CATEGORY_DOMAINS`
(5,000) domains is enforced the same way per-domain assignment already is
— `$client=`-scoped AdGuard custom rules
(`build_category_deny_rules()`), emitting a cheap unscoped rule instead
when the category currently applies to every eligible device. A category
over that threshold is enforced via AdGuard's own native filter-list
subscription mechanism instead (`sync_category_subscriptions()`,
`common/adguard_client.py`'s `add_filter_url`/`set_filter_url_enabled`)
— **live-verified 2026-09-01** against a real running AdGuard Home
v0.107.79: every request/response shape in `common/adguard_client.py`'s
docstrings matched on the first try, and `sync_category_subscriptions()`
itself was run end-to-end against a real scratch 5,001-domain category
(correctly added+enabled on `is_global=1`, correctly disabled once
flipped off with no gating schedule) — see RoadMap.md's Phase 8 entry
for the full writeup. Both paths exclude
`BYPASS` (`ignored=1`) devices, same baseline-protection rule §3's
`device_domain_reason()` already applies to domain assignment.

**nftables-tier scheduled lockout** (`controller/policy_state.py`): a
device under an active `schedules.lockout_all=1` window is reclassified
to `QUARANTINE` for that one `compute_desired_policy()` cycle —
**never writing `devices.quarantined_at`**. This is deliberate, not an
oversight: `quarantined_at` is an admin's own manual, persistent
isolation flag (see `docs/database/schema.md`'s `devices` comment); a
scheduled lockout is an ephemeral, time-driven state that must turn
itself off the moment the window closes, with nothing left over to
clean up, and must never interact with an admin's independent manual
quarantine in either direction. Same "two independent axes" pattern this
project already used for `bump_eligible()` layered on top of
`classify_device()`. Confirmed via code review of
`phase3/nftables-manager` (Go) that this needed zero changes there — the
`quarantine_v4` nftables set is a pure opaque IP bucket with no model of
*why* an IP is in it, so the Python controller freely deciding
membership (now including this overlay) was already the sole authority.

**Time-zone handling**: `common/schedule_eval.py` evaluates a schedule's
window in its own stored IANA `time_zone`, converting the current UTC
instant via stdlib `zoneinfo` — never the server's local time, never bare
UTC (a household's "bedtime 21:00" is a wall-clock concept). `zoneinfo`
has no bundled tz database of its own; `tzdata` (PyPI) was added to
`controller/requirements.txt`/`dashboard/requirements.txt` as a second
deliberate, documented exception to this project's stdlib-only
discipline (pure data, no compiler, same footing as the existing
`pyroute2` exception) rather than assuming `python:3.12-slim` or a given
host has system tzdata.

**Block-list vs. allow-list, explicitly**: everything in §3 above
(`domains`/`user_domains`/etc.) is an allow-list — denied unless
assigned. `categories`/`schedules` are the opposite polarity — assigning
one means block. Reusing the identical junction-table shape (and the
dashboard's combobox widget, relabeled `BLOCK_ACCESS_SELECTS`) for an
inverted meaning is a deliberate consistency choice, not a naming
coincidence; the dashboard's copy says "Block for Everyone" specifically
so this isn't mistaken for the Domains page's grant.

## 9. SQL injection audit (2026-09-02)

Full sweep, prompted by the project owner ahead of a planned full
code-review pass: every `.execute()`/`.executemany()`/`.executescript()`
call across the Python codebase (`common/`, `controller/`, `dashboard/`,
`proxy/`, `defaults/`) and every `db.QueryRow`/`db.Exec` call in the Go
side (`phase3/nftables-manager/internal/dbsource/sqlite.go`) — clean.
No dynamic SQL text is ever built from request-derived or otherwise
untrusted data anywhere in this codebase; every value that varies by
request goes through a `?` bind parameter, never string interpolation,
concatenation, or `%`/`.format()` substitution into the query text
itself.

The one pattern worth calling out explicitly, since a naive grep for
`execute(f"` flags it: `dashboard/dashboard.py`'s `_set_quarantine(conn,
where_sql, params, *, paused)` (G6) and `report()`'s (Report page)
`where_sql` filter-building both f-string-interpolate a `WHERE` clause
into the query text. This is safe in both cases because `where_sql` is
never built from request data — every call site passes one of a small,
fixed set of hardcoded literal clause strings (e.g. `"id = ?"`,
`"user_id = ? AND ignored = 0"`, `"ignored = 0"`), chosen by which
Python code path executes, never a string built from `request.form`/
`request.args`. Every actual value that varies per request (a device
id, a user id, a status filter) still flows through `params` as a bind
parameter in every one of these queries. This is a query-shape
selector, not a template filled with untrusted input — a genuinely
different (and safe) pattern from the injection-vulnerable version a
surface-level grep might mistake it for. Anyone extending either
function should keep it that way: never make `where_sql` itself
derived from request data, even partially.

`common/db.py`'s `init_db()`/`SCHEMA` uses `executescript()` against a
module-level constant string (the DDL) — no interpolation, not
attacker-reachable at all.

## 10. Client-side tamper resistance (2026-09-02)

The project owner asked directly: can an end user (realistically, a
kid) bypass a block by using their browser's developer tools — e.g.
tracing a request to a blocked site and flipping some variable that
grants access?

**Verified: no, that specific mechanism doesn't exist anywhere in this
codebase.** Every block page was read end to end
(`dashboard/block_page_server.py`'s `_BlockPageHandler`,
`dashboard/dashboard.py`'s `BLOCKED_BODY`/`blocked()`,
`dashboard/captive_portal_server.py`'s login page) — each is static
HTML with no client-side JavaScript that decides whether to grant
access; the closest thing to interactive logic is a plain HTML
`<form method="post">` for "Request approval"/login, both fully
re-verified server-side on submit. `proxy/sni_helper.py` and
`proxy/authz_helper.py` (§4 above) were also checked specifically for
this: neither reads any client-supplied HTTP header, cookie, or query
parameter into an allow/deny decision — every input is either Squid's
own protocol-line fields (`%>a` source IP, `%ssl::>sni`, `%DST`,
`%PATH`, all facts about the actual TCP/TLS connection itself, not
something a page's JS can rewrite after the fact) or a DB-resident
value the dashboard alone can change. There is no gate to defeat with
a dev-tools variable because the browser is never given a page whose
own client-side logic decides "allowed" or "blocked" in the first
place — the connection either reaches the real destination or it
doesn't, decided entirely by infrastructure the browser has zero
visibility into (DNS answer, TLS termination, packet routing), before
any content exists for dev tools to inspect or alter.

**A materially more realistic bypass was found while investigating
this, and has been closed**: **DNS-over-HTTPS (DoH)**. Firefox and
Chrome both ship a one-click "Secure DNS"/"DNS over HTTPS" toggle in
their own visible Settings UI — no dev tools, no technical skill,
just a documented setting. Before this pass, turning it on completely
defeated every bit of this project's DNS-tier enforcement (domain
blocking, categories, schedules, SafeSearch, ad-blocking) for any
normal, non-bump device: `phase3/nftables-manager`'s baseline rules
(`knftables_adapter.go`) only redirect port 53 for an
`authenticated_v4` device — port 443 (which DoH itself runs over, and
which the browser then also uses to reach whatever real IP the DoH
query returned) was completely untouched for that device class, so a
DoH-resolved query and its followup connection both sailed through
the interception layer entirely unfiltered.

**Fixed**: `controller/adguard_sync.py`'s new `build_anti_doh_rules()`
adds an unconditional, network-wide (not per-device, not admin-
configurable, not stored in `domains`/`categories`) deny for:
- `use-application-dns.net` — the exact domain Firefox (and some
  Chromium builds) query before auto-enabling DoH; a network that
  returns NXDOMAIN for it is Mozilla's own documented signal to leave
  the system resolver in place instead
  ([Mozilla's own KB article](https://support.mozilla.org/kb/canary-domain-use-application-dns-net)).
- The handful of public DoH resolvers real browsers/OSes ship as
  their default or one-click options (`cloudflare-dns.com`,
  `mozilla.cloudflare-dns.com`, `dns.google`, `dns.quad9.net`,
  `doh.opendns.com`, `dns.nextdns.io`, `doh.cleanbrowsing.org`) —
  closes Chrome's own auto-upgrade path too, since Chrome probes its
  own small hardcoded provider list and falls back to the system
  resolver if the probe fails.

Deliberately not admin-configurable and not part of the
`domains`/`categories` tables: this isn't a household content
decision an admin should be able to accidentally turn off, it's
closing a hole in the mechanism those very tables depend on to mean
anything. A household member who genuinely wants their own device
fully outside this system already has the existing escape hatch —
mark it `ignored` (BYPASS) — so no second one was needed here.

**Accepted residual gap, not fully closed by this pass**: this list
cannot be exhaustive (a household member could manually configure an
obscure, unlisted DoH provider — a meaningfully smaller threat than
"flip the setting the browser already shows by default," but not
zero), and it only protects `authenticated_v4` (non-bump) devices at
the DNS tier. A **bump-eligible** device's port 443 traffic already
gets redirected to Squid regardless of what IP a DoH query returns
(`bump_v4`'s baseline rules redirect port 443 unconditionally), and
terminates there against an unconfigured domain (§3's hard-deny
invariant) — so bump devices were never exposed to this gap the same
way. Fully closing it for non-bump devices would mean giving
DNS-tier-only devices some form of Squid's own SNI-inspection
machinery, a materially bigger design change than this pass; revisit
if DoH bypass attempts are ever observed in practice (the Events page,
Phase 11, would be a reasonable place to eventually surface a signal
for this, though nothing does yet).

**Live-verified against the real smoke-test VM's AdGuard Home
instance**, not just unit-tested: rebuilt and recreated the real
`controller` container there; its next real `adguard_sync` cycle
pushed all 8 rules, unscoped, into the real instance's own custom-rules
list (`/control/filtering/status`). `dig`ging each one against the
real resolver: `use-application-dns.net` returned real **NXDOMAIN**
(AdGuard Home has its own built-in special-case handling for this
exact domain whenever any filtering is active at all -- this project's
explicit rule is a documented, defense-in-depth backstop, not the sole
reason it works); the 7 provider domains returned real **NOERROR
answers of `0.0.0.0`**, matching this instance's configured
`blocking_mode: default` -- still an effective block, since `0.0.0.0`
isn't a connectable address for a DoH bootstrap request either way. An
unrelated control domain resolved normally throughout, confirming no
collateral blocking.
