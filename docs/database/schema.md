# Database schema

Single shared SQLite database file used by every component: the Squid-side
Python helpers (`proxy/sni_helper.py`, `proxy/authz_helper.py`), the
caching layer (`common/series_resolve.py`), and the Flask dashboard
(`dashboard/dashboard.py`). All of them open the same file via
`common/db.py`; there is no ORM and no ID-generation scheme beyond
SQLite's own `INTEGER PRIMARY KEY` rowid aliasing.

## Where the schema lives

**File:** `common/db.py`
**Constant:** `SCHEMA` (a single multi-statement SQL string, lines 18-97)
**Applied by:** `init_db(conn)` (line 110), which just runs
`conn.executescript(SCHEMA)`.

- **Migration style:** none. Every statement is `CREATE TABLE IF NOT EXISTS`
  / `CREATE INDEX IF NOT EXISTS`. There is no schema-version table, no
  ordered migration list, and no `ALTER TABLE` anywhere in the codebase.
  Changing a column's type/constraints today means editing the `CREATE
  TABLE` statement in place, which only takes effect for brand-new database
  files -- an existing deployed `.db` file keeps its old column definitions
  until someone manually migrates it (or the table is dropped and
  recreated). Keep this in mind before assuming an edit to `SCHEMA` retrofits
  existing installs.
- **Called from:** `init_db()` runs on every dashboard request that opens a
  connection (`dashboard.get_db()`, dashboard.py:59-62) and on every proxy
  container start (`proxy/entrypoint.sh` line 35, inline Python heredoc).
  It's cheap and idempotent, so it's safe to call unconditionally rather
  than gating it behind a "first run" check.
- **Connection setup:** `get_conn()` (db.py:100-107) opens the file at
  `DB_PATH`, sets `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`,
  `PRAGMA foreign_keys=ON`, and `row_factory = sqlite3.Row` (so query
  results are dict-like, accessed by column name -- `row["field"]` -- for
  every query in the codebase). WAL + a busy timeout are what let the proxy
  container and the dashboard container hit the same file concurrently
  without a real database server.

## Tables

### `settings`
Generic admin-editable key/value store. Everything configurable that isn't
better modeled as its own table lives here.

| Column | Type | Constraints |
|---|---|---|
| `key`   | TEXT | PRIMARY KEY |
| `value` | TEXT | NOT NULL |

Accessed only through `get_setting(conn, key, default=None)`,
`set_setting(conn, key, value)` (upsert via `ON CONFLICT(key) DO UPDATE`),
and `set_setting_if_absent(conn, key, value)` (`ON CONFLICT(key) DO
NOTHING`) in `common/db.py`. Known keys actually written/read elsewhere:

- `admin_username`, `admin_password_hash` -- dashboard HTTP Basic admin
  login, bootstrapped from `DASHBOARD_USER`/`DASHBOARD_PASSWORD` env vars on
  first run by `dashboard.bootstrap_admin()`, editable afterward from the
  Settings page (`update_admin`).
- `local_network` -- space-separated CIDR list (e.g.
  `192.168.1.0/24 10.0.0.0/24`) checked by `matching.ip_in_configured_lan()`.
  Empty string disables the LAN check entirely (access then rests solely on
  per-person proxy login), which matters under Docker bridge/Desktop
  networking where the proxy only ever sees an internal gateway IP.
- `block_page_mode` -- `"terminate"` (default) or `"redirect"`. Read by
  `sni_helper.handle_block_page()` to decide whether an unrecognized/denied
  splice-mode connection is bumped so a real HTTP deny page can be served,
  or just fails the TLS connection outright. See the enum section below.
- `secret_key` -- random hex token generated once (`secrets.token_hex(32)`)
  and used as the Flask app's `app.secret_key`.
- `cr_resolver_last_error` -- last Crunchyroll-CMS resolver failure message,
  set by `series_resolve._record_resolver_error()` and cleared by
  `_clear_resolver_error()` on the next success. Surfaced as a banner on the
  dashboard's Report page (`dashboard.report()`).

### `users`
One row per proxy login (one per kid/person), independent of the dashboard
admin login (which lives in `settings`, not here).

| Column | Type | Constraints |
|---|---|---|
| `id`            | INTEGER | PRIMARY KEY |
| `username`      | TEXT | UNIQUE NOT NULL |
| `display_name`  | TEXT | NOT NULL |
| `password_hash` | TEXT | NOT NULL |
| `created_at`    | TEXT | NOT NULL (ISO-8601 UTC, see `db.now_iso()`) |

`username` identifies a person for domain/show assignment and (via
`devices.user_id`) device ownership. `password_hash` is set by `add_user()`/
`reset_password()` but, as of 2026-08-30, has no active consumer: Squid
resolves identity from the client's device instead of a per-request login
(see `common/device_identity.py` and `docs/security/overview.md` §3) --
`password_hash` is reserved for the future Phase 4 captive-portal login
(RoadMap.md), not checked by anything today. Usernames are restricted by
the dashboard's `add_user()` to `[A-Za-z0-9_.-]+`. Deleting a user
(`dashboard.delete_user()`) cascades to `user_domains` and `user_shows` via
`ON DELETE CASCADE` (enforced because `PRAGMA foreign_keys=ON` is set on
every connection).

### `domains`
Every domain the proxy knows about and how to treat it. This is the core
policy table -- `matching.find_domain()` scans it in `id` order (first
regex match wins) for essentially every proxy decision.

| Column | Type | Constraints |
|---|---|---|
| `id`         | INTEGER | PRIMARY KEY |
| `pattern`    | TEXT | UNIQUE NOT NULL -- a regex, not a literal hostname |
| `mode`       | TEXT | NOT NULL, `CHECK (mode IN ('splice','bump','trusted'))` |
| `kind`       | TEXT | NOT NULL DEFAULT `'generic'`, `CHECK (kind IN ('generic','crunchyroll'))` |
| `is_global`  | INTEGER | NOT NULL DEFAULT 0 (boolean: 1/0) |
| `note`       | TEXT | nullable, admin-facing free text |
| `created_at` | TEXT | NOT NULL (ISO-8601 UTC) |

**`pattern`** is compiled by `matching._domain_regex()` as
`(?:^|\.)(?:<pattern>)\Z` (case-insensitive), i.e. an anchored domain-suffix
match -- `crunchyroll\.com` matches `crunchyroll.com` and any subdomain, but
not `evilcrunchyroll.com` or `crunchyroll.com.attacker.example`. An invalid
regex is skipped rather than raising (results in `find_domain` returning
`None` for that row, effectively disabling it). Patterns are admin-supplied
free-form regex, validated at write time only by `re.compile()` succeeding
and a 200-character cap (`dashboard.add_domain()` / `add_path()`).

**`mode`** (enum, exhaustive per the CHECK constraint):
- `splice` -- host-only check via SNI, connection is never decrypted.
  Evaluated by `sni_helper.handle_splice()`. This is the *only* stage that
  ever observes splice-mode traffic, so it's the only place that logs it.
- `bump` -- fully decrypted (`sni_helper.handle_bump()` tells Squid to
  bump); path/show-level rules then apply at the HTTP layer via
  `authz_helper.decide()`.
- `trusted` -- always spliced, never checked or logged at all (deliberately
  invisible -- see `sni_helper.py` module docstring). Used for large binary
  CDN traffic (Crunchyroll's raw video CDN hosts) where the meaningful
  authorization decision already happened upstream, at the bump-mode
  manifest/playback-token request.

**`kind`** (enum): `generic` (default) or `crunchyroll`. A `crunchyroll`
domain gets an extra show-level resolution layer on top of the normal
domain/path checks (`authz_helper._decide_crunchyroll()`); only one such
row is ever seeded (see Seed data below), and the dashboard explicitly
refuses to let it be deleted (`delete_domain()`).

**`is_global`**: `1` means every user gets this domain automatically (no
`user_domains` row needed) -- used for shared infrastructure the whole
household depends on (Google, CDNs, cookie-consent scripts, etc.) as well
as the trusted CDN hosts and the Crunchyroll domain itself. `0` means each
user needs an explicit `user_domains` row.

### `user_domains`
Per-user domain assignment (many-to-many `users` <-> `domains`), used only
for domains where `is_global = 0`.

| Column | Type | Constraints |
|---|---|---|
| `id`        | INTEGER | PRIMARY KEY |
| `user_id`   | INTEGER | NOT NULL, `REFERENCES users(id) ON DELETE CASCADE` |
| `domain_id` | INTEGER | NOT NULL, `REFERENCES domains(id) ON DELETE CASCADE` |
| | | `UNIQUE(user_id, domain_id)` |

Checked by `matching.user_has_domain(conn, user_id, domain_id)` (plain
existence check). Rows are added/removed via
`dashboard.toggle_user_domain()` (`INSERT OR IGNORE` / `DELETE`) and by the
paste-a-URL shortcut `add_domain_from_url()`. Deleting either the user or
the domain removes the assignment automatically (cascade).

### `domain_paths`
Allowed URL-path patterns for a `bump`-mode domain. **Global per domain,
not per-user** -- this is defense-in-depth against unrecognized request
shapes, the spiritual successor to v1's flat `allowed_paths.txt`, and
intentionally does not vary per kid.

| Column | Type | Constraints |
|---|---|---|
| `id`        | INTEGER | PRIMARY KEY |
| `domain_id` | INTEGER | NOT NULL, `REFERENCES domains(id) ON DELETE CASCADE` |
| `pattern`   | TEXT | NOT NULL |
| | | `UNIQUE(domain_id, pattern)` |

`pattern` is a regex checked with `.search()` (not anchored automatically --
admins are expected to write `^/...` themselves; see
`dashboard.path_to_pattern()`, which prefixes `^` and `re.escape()`s a
literal path when deriving a suggested pattern from a real blocked
request). Semantics, from `matching.path_allowed()` and its caller
`authz_helper._has_any_path_rules()`: **a domain with zero `domain_paths`
rows allows every path** once the domain check itself passes -- admins only
need to curate paths for domains where restricting *which* pages are
reachable actually matters (this is why the Crunchyroll domain is
pre-seeded with an extensive path list but most domains have none).

### `user_shows`
Per-user approved Crunchyroll series (independent of `domain_paths` --
show-level authorization for the `crunchyroll` `kind` domain).

| Column | Type | Constraints |
|---|---|---|
| `id`          | INTEGER | PRIMARY KEY |
| `user_id`     | INTEGER | NOT NULL, `REFERENCES users(id) ON DELETE CASCADE` |
| `series_id`   | TEXT | NOT NULL (Crunchyroll series id, stored upper-cased) |
| `series_name` | TEXT | NOT NULL (display name, editable, refreshed on re-approve) |
| | | `UNIQUE(user_id, series_id)` |

Checked by `matching.user_has_show(conn, user_id, series_id)`, which
upper-cases `series_id` before comparing (series IDs are treated
case-insensitively everywhere, normalized to upper-case at every write:
`dashboard.add_show()`, `dashboard.approve_from_report()`,
`series_resolve._cache_put()`). Rows are inserted with `INSERT ... ON
CONFLICT(user_id, series_id) DO UPDATE SET series_name = excluded.series_name`
so re-approving an already-approved show just refreshes its display name.

### `series_cache`
Crunchyroll CMS object-id -> parent series-id resolution cache (an object
id from a watch/playback URL isn't itself a series id; resolving it costs a
CMS API call, so the mapping is cached since it never changes once known).

| Column | Type | Constraints |
|---|---|---|
| `object_id`  | TEXT | PRIMARY KEY (upper-cased) |
| `series_id`  | TEXT | nullable -- see sentinel note below |
| `expires_at` | REAL | NOT NULL (Unix timestamp, `time.time()`-based) |

Managed entirely by `common/series_resolve.py`:
- **Positive entries** (`series_id` = real series id) live for
  `POSITIVE_TTL_SECONDS` = 30 days, and are deliberately still served
  *past* expiry (`allow_stale=True`) if the live Crunchyroll API is
  unreachable at the time -- a parent series never changes, so a stale
  positive hit is still correct, and this keeps already-approved playback
  working through a resolver/network outage instead of breaking it.
- **Negative entries** use the string sentinel `_MISSING =
  "__missing__"` as the stored `series_id` value (so a negative hit is
  `series_id IS NULL` in code, i.e. resolvable-to-nothing, without needing
  a separate boolean "found" column) and expire after
  `NEGATIVE_TTL_SECONDS` = 1 hour; an expired negative entry is always
  re-checked rather than served stale, since blocking a show forever on a
  transient lookup failure would be a worse failure mode than a delayed
  block.
- Writes go through `_cache_put()`'s
  `INSERT ... ON CONFLICT(object_id) DO UPDATE SET series_id = excluded.series_id,
  expires_at = excluded.expires_at` (upsert), so re-resolving the same
  object id just overwrites the row.

### `access_log`
Append-only audit trail of every access decision the proxy makes (subject
to the dedupe window described below). Backs the dashboard's Report page
and its one-click "approve" action.

| Column        | Type    | Constraints |
|---|---|---|
| `id`          | INTEGER | PRIMARY KEY |
| `ts`          | TEXT    | NOT NULL (ISO-8601 UTC, `db.now_iso()`) |
| `user_id`     | INTEGER | nullable -- NULL when the identified device has no resolvable user at all: a group- or device-only identity (see `device_domain_reason()` below), or a genuinely never-seen IP (`reason="not_authenticated"`/`"(unauthenticated)"`) |
| `device_id`   | INTEGER | nullable, added 2026-08-31 (`ALTER TABLE`, see `common/db.py`'s `_migrate()`) -- which `devices` row made this request, when known. Lets the Report page filter/act on a row by device or group even with `user_id` NULL. No `REFERENCES` clause, matching `user_id`'s own convention on this table. Pre-migration rows have this NULL. |
| `username`    | TEXT    | NOT NULL -- the resolved user's username; the device's own label/MAC when there's a device but no user (`device_identity.log_identity_fields()`); or `"(unauthenticated)"` when neither resolves at all |
| `domain`      | TEXT    | NOT NULL -- the hostname actually observed (SNI or `%DST`), not the `domains.pattern` regex that matched it |
| `path`        | TEXT    | nullable -- always NULL for SNI-layer (splice) entries, since nothing is decrypted at that layer to reveal a path |
| `series_id`   | TEXT    | nullable -- set only for Crunchyroll show-level decisions |
| `series_name` | TEXT    | nullable -- set only alongside `series_id` when a name is already known (report-driven approvals resolve/attach a name; live proxy-time denials generally don't have one yet) |
| `allowed`     | INTEGER | NOT NULL (boolean: 1/0) |
| `reason`      | TEXT    | free-text enum, see below -- not constrained by a CHECK, just convention |

**Indexes:**
- `idx_access_log_ts` on `access_log(ts DESC)` -- supports the Report
  page's `ORDER BY id DESC LIMIT 200` browsing pattern (recency).
- `idx_access_log_dedupe` on
  `access_log(username, domain, allowed, series_id, ts DESC)` -- supports
  the dedupe lookup in `common/logging_util.py` (see below).

All writes to this table go through the single entry point
`logging_util.log_access()` (`common/logging_util.py`) -- there is no other
`INSERT INTO access_log` in the codebase. Reads happen from
`dashboard.report()` (filtered listing) and `dashboard.approve_from_report()`
(single-row lookup by `id` to drive the one-click approve action).

#### Dedupe logic (`common/logging_util.py: log_access()`)
The same `(username, domain, allowed, series_id, path)` combination is only
written once per `DEDUPE_WINDOW_SECONDS` (5 minutes), so one browsing
session doesn't produce dozens of near-identical rows from repeated TLS
connections, page assets, or polling requests. Two notable SQL techniques
worth knowing when touching this table:

- **Null-safe comparison via `IS`:** the dedupe `SELECT` uses
  `series_id IS ?` and a path comparison also written with `IS ?` (not
  `= ?`), because SQLite's `=` never matches when either side is `NULL`
  while `IS` treats two `NULL`s as equal. This matters because `series_id`
  and `path` are frequently `NULL` (SNI-layer entries, non-Crunchyroll
  domains) and two such rows still need to collapse into one dedupe bucket.
- **In-SQL path normalization:** `path` is compared with its query string
  stripped on both sides -- computed in Python for the incoming value
  (`path.split("?", 1)[0]`) and in SQL for the already-stored value via
  `CASE WHEN instr(path, '?') > 0 THEN substr(path, 1, instr(path, '?') - 1)
  ELSE path END`, so `?cachebust=123` variants of the same page collapse
  into one dedupe entry while genuinely different pages on the same domain
  each still get their own row.

## Phase 2/3 tables (groups, devices, identity model)

These tables support device-level assignment and Phase 3's interception
layer (`phase3/nftables-manager`, `phase3/arp-worker`, `controller/` --
none of that code lives in this repo's proxy/dashboard tree; see
RoadMap.md). They predate this doc's last full pass and were missing from
it entirely; added 2026-08-30 alongside the Squid intercept-mode update.

### `groups`
A named category of shared devices (e.g. "TVs", "IoT") that gets its own
domain allow-list, for devices that don't belong to any one person.

| Column | Type | Constraints |
|---|---|---|
| `id`         | INTEGER | PRIMARY KEY |
| `name`       | TEXT | UNIQUE NOT NULL |
| `created_at` | TEXT | NOT NULL |

### `group_domains`
The group-level equivalent of `user_domains` -- a row grants every device
in `group_id` access to `domain_id`, independent of that domain's own
`is_global` flag. `UNIQUE(group_id, domain_id)`, both FKs `ON DELETE
CASCADE`. Not consulted by any proxy enforcement path yet (`common/matching.py`'s
`group_has_domain()` exists but has no caller in `sni_helper.py`/
`authz_helper.py` -- groups aren't identifiable at Squid request time until
Phase 3's interception layer exists to establish device identity at the
network level).

### `devices`
One physical device, identified by MAC address, managed from the
dashboard's `/devices` page (`dashboard.py`'s `add_device()`/
`update_device()`).

| Column             | Type    | Constraints |
|---|---|---|
| `id`                | INTEGER | PRIMARY KEY |
| `mac_address`       | TEXT    | UNIQUE NOT NULL |
| `label`             | TEXT    | nullable |
| `user_id`           | INTEGER | REFERENCES `users(id)` ON DELETE SET NULL |
| `group_id`          | INTEGER | REFERENCES `groups(id)` ON DELETE SET NULL |
| `ignored`           | INTEGER | NOT NULL DEFAULT 0 |
| `last_known_ip`     | TEXT    | nullable |
| `last_seen_at`      | TEXT    | nullable -- NULL means never observed; nothing populates this yet |
| `bump_enabled`      | INTEGER | NOT NULL DEFAULT 0 |
| `bypass_login`      | INTEGER | NOT NULL DEFAULT 0 |
| `is_authenticated`  | INTEGER | NOT NULL DEFAULT 1 |
| `quarantined_at`    | TEXT    | nullable -- NULL means not quarantined |
| `created_at`        | TEXT    | NOT NULL |
|                     |         | `CHECK (user_id IS NULL OR group_id IS NULL)` -- at most one assignment |

Semantics (see `common/db.py`'s own schema comment for the full reasoning):
`ignored` = permanently outside the whole system (stronger than
unassigned); `bump_enabled` = this device is one of the curated set that
gets Squid/SSL-Bump refinement on top of DNS-tier protection, independent
of (and layered on top of) `is_authenticated` -- see
`common/policy_class.py`'s `bump_eligible()` and RoadMap.md's "two
independent axes" section, locked 2026-08-30; `is_authenticated` = the
captive-portal gate's own flag, live as of Phase 4 (`dashboard/captive_portal_server.py`,
2026-08-31) -- the schema default of 1 is still correct for a device an
admin creates directly through the dashboard (implies trust), but
`common/identity.py`'s `record_binding()` now overrides it to 0 for a
genuinely new, auto-discovered MAC (Phase 4 milestone 1), landing it in
`PolicyClass.PREAUTH` until it logs in. **Confirmed live, not just by
design, 2026-09-02**: `dashboard.py`'s `add_device()`/`import_devices()`
were checked and neither one ever sets `is_authenticated`, so a bulk-
imported or hand-added device really does land fully authenticated with
zero captive-portal gate -- initially mistaken for a regression of the
same bug `bypass_login` had (see below), until the project owner
clarified the real motivating case: a browser-less IoT device (a smart
plug, a thermostat -- anything that can never render the portal's login
page) would be permanently, unrecoverably locked out if gated the same
way an auto-discovered MAC is. Admin-entered = known/trusted = the
vouching act itself, the same way "never seen this MAC before" is
treated as not-vouched-for and gated. Do not "fix" this asymmetry.

`bypass_login` = exempts a
device from the LOGIN requirement specifically (not from interception
or policy generally, unlike `ignored`) -- **real bug found and fixed
2026-08-31**: `classify_device()` never actually consulted this column
before that date, so setting it had no effect on real nftables policy
at all despite the dashboard's own hint text claiming otherwise; now
fixed, `is_authenticated OR bypass_login` is sufficient for
`AUTHENTICATED`, see `docs/architecture/overview.md`'s dated entry for
the full trace; `quarantined_at` = Milestone 8's operator-triggered
isolation state, nothing sets it yet (no dashboard control exists).
Indexed on `user_id` and `group_id`.

### `device_domains`
A single device's own domain allow-list, independent of (and additive to)
its `user_id`/`group_id` assignment. `UNIQUE(device_id, domain_id)`, both
FKs `ON DELETE CASCADE`. Same not-yet-consulted-by-enforcement status as
`group_domains` above (`matching.device_has_domain()` has no caller yet).

### `device_bindings`
Every observed MAC↔IPv4 pairing, feeding `controller/desired_state.py`'s
and `controller/policy_state.py`'s desired-state computation, and (as of
2026-08-30) `common/device_identity.py`'s Squid-side identity resolution.

| Column          | Type    | Constraints |
|---|---|---|
| `id`             | INTEGER | PRIMARY KEY |
| `device_id`      | INTEGER | REFERENCES `devices(id)` ON DELETE SET NULL, nullable |
| `mac_address`    | TEXT    | NOT NULL |
| `ipv4_address`   | TEXT    | NOT NULL |
| `first_seen_at`  | TEXT    | NOT NULL |
| `last_seen_at`   | TEXT    | NOT NULL |
| `source`         | TEXT    | NOT NULL `CHECK IN ('rtnetlink','snapshot','adguard','bettercap','active_scan')` |
| `confidence`     | REAL    | NOT NULL DEFAULT 1.0 |
| `active`         | INTEGER | NOT NULL DEFAULT 1 |
|                  |         | `UNIQUE(mac_address, ipv4_address)` |

A device's IP can change (DHCP renewal) and an IP can be reassigned to a
different MAC over time -- this table keeps every observed pairing rather
than overwriting in place, with `active` marking which one to trust right
now. Written exclusively through `common/identity.py`'s
`record_binding()`, which handles both conflict shapes (IP reassigned to a
new MAC; a device's own IP changing) by deactivating the stale row and
logging a `network_events` row. `device_id` is never auto-associated with
an *existing* `devices` row from network data alone (no hostname/vendor
guessing) -- but as of 2026-08-31 (Phase 4), a MAC genuinely never seen
before (no prior `device_bindings` row of any kind for it) gets a brand
new, unassociated `devices` row auto-created (`is_authenticated = 0`,
PREAUTH) rather than a dangling `device_id = NULL` binding: this closes a
real gap where such a device was invisible to `desired_state.py`'s own
join and got no interception at all. An already-known-but-unassociated
MAC from before this shipped is deliberately left alone (no retroactive
backfill) even across a later DHCP renewal -- see `record_binding()`'s own
docstring for the exact one-time-only condition. **Freshness caveat**:
`record_binding()` is called from `controller/discovery.py`'s
`snapshot_once()` (a periodic `ip neigh show` poll, wired into a running
loop since 2026-08-30 via `discovery.run_loop()`) and the higher-
precedence live `controller/rtnetlink_listener.py` (wired in by default
alongside `--db-path`, see `--no-rtnetlink`) -- see
`docs/security/overview.md` §3 for how these two sources bound the
remaining DHCP-renewal staleness window.
Indexed on `device_id` and on `(ipv4_address, active)`.

### `interception_runtime`
Singleton row (`CHECK (singleton_id = 1)`) tracking Phase 3's own runtime
state -- what generation the controller wants applied vs. what the ARP
worker has confirmed, plus separate health columns for the
controller↔ARP-worker pipeline and for `phase3/nftables-manager`, so the
two subsystems never clobber each other's status. Written by
`controller/health.py`; not read by anything in this repo yet (an
"interception health" dashboard view doesn't exist).

| Column                 | Type    | Constraints |
|---|---|---|
| `singleton_id`          | INTEGER | PRIMARY KEY `CHECK (singleton_id = 1)` |
| `desired_generation`    | INTEGER | NOT NULL DEFAULT 0 |
| `applied_generation`    | INTEGER | NOT NULL DEFAULT 0 |
| `mode`                  | TEXT    | NOT NULL DEFAULT `'stopped'` `CHECK IN ('stopped','running','repair_only','fail_open')` |
| `last_healthy_at`       | TEXT    | nullable |
| `fail_open_reason`      | TEXT    | nullable |
| `desired_policy_json`   | TEXT    | nullable -- `controller/policy_state.py`'s `DesiredPolicy` blob, read directly by `phase3/nftables-manager` (Go) via the shared DB rather than a new IPC protocol |
| `nft_mode`              | TEXT    | NOT NULL DEFAULT `'stopped'` `CHECK IN ('stopped','running','fail_open')` |
| `nft_last_healthy_at`   | TEXT    | nullable |
| `nft_fail_reason`       | TEXT    | nullable |

### `network_events`
Append-only, normalized network/identity-layer event log (device
seen/lost, a binding created or superseded by a MAC/IP conflict) --
distinct from `access_log`, which is proxy-layer allow/deny decisions.
This is the "outbox events" RoadMap.md's Milestone 4 refers to. Written by
`common/identity.py`'s `record_binding()`/`record_network_event()`.

| Column         | Type    | Constraints |
|---|---|---|
| `id`            | INTEGER | PRIMARY KEY |
| `event_type`    | TEXT    | NOT NULL, free-text (e.g. `ip_reassigned`, `ip_changed`, `device_auto_created`, `binding_pending_association`) |
| `device_id`     | INTEGER | REFERENCES `devices(id)` ON DELETE SET NULL, nullable |
| `mac_address`   | TEXT    | nullable |
| `ipv4_address`  | TEXT    | nullable |
| `source`        | TEXT    | NOT NULL |
| `observed_at`   | TEXT    | NOT NULL |
| `payload_json`  | TEXT    | nullable |

Indexed on `observed_at DESC` and on `device_id`.

### `system_events`
Added 2026-09-01 (Phase 11), ahead of G1 real-network testing. A
DIFFERENT kind of event log from `network_events` above -- this one is
operational (did a background sync/discovery loop fail or recover), not
identity-layer (did a device's MAC/IP binding change). Deliberately not
a firehose: only real failures (one row per occurrence) and the specific
failure→success "recovery" transition are recorded, never a routine
successful cycle -- see `common/system_events.py`'s own docstring.
Written by `controller/main.py`'s `on_error`/`on_success` wiring around
its periodic loops (AdGuard sync, category subscription fetch, active
ARP scan, device discovery, the controller↔worker heartbeat); read by
`dashboard/dashboard.py`'s `/events` page (`docs/dashboard/routes.md`).
**Stale-doc correction 2026-09-07**: "the dashboard never writes to this
table itself" (this section's own earlier claim) stopped being true on
2026-09-02, when `dashboard/captive_portal_server.py`'s
`_log_failed_login()` started writing `error` rows here for failed
captive-portal login/admin-action attempts (source
`captive_portal_login` / `captive_portal_admin_action`) as part of that
day's brute-force audit -- see `common/system_events.py`'s own
`_MAX_STORED_EVENTS` comment for the security reasoning (this table
gained its first attacker-controlled writer that day).

| Column     | Type    | Constraints |
|---|---|---|
| `id`       | INTEGER | PRIMARY KEY |
| `ts`       | TEXT    | NOT NULL |
| `source`   | TEXT    | NOT NULL -- which loop/component, e.g. `adguard_sync`, `category_fetch`, `controller_heartbeat`, `captive_portal_login` |
| `severity` | TEXT    | NOT NULL, CHECK IN (`error`, `recovery`) |
| `message`  | TEXT    | NOT NULL |
| `detail`   | TEXT    | nullable -- optional longer context. **Used since 2026-09-07**: for `source = 'captive_portal_login'` rows specifically, `_log_failed_login()` stores the attempting device's `mac_address` here (not a new column -- reusing this existing free-text field), so `dashboard.py`'s `_failed_login_attempts()` can answer "has this specific pending device already tried and been denied" via a plain `detail = ?` lookup. Every other source still leaves this NULL. |

Indexed on `ts DESC`. Nothing prunes this table automatically -- the
dashboard's `EVENT_DISPLAY_LIMIT` only bounds what's shown, not what's
stored; add real pruning (mirroring the existing "Remove outdated
devices" Settings pattern) if its growth ever actually proves to be a
problem in practice, not before.

## Phase 8 tables (categories, schedules)

**Opposite polarity from every table above**: `domains`/`user_domains`/
`group_domains`/`device_domains` are an ALLOW-list (denied unless
assigned). `categories`/`schedules` are a BLOCK-list — assigning one to a
user/group/device (or `is_global`) means block, not allow. Same
junction-table shape as the domain tables (reused deliberately, including
the dashboard's `ACCESS_SELECTS` widget, relabeled `BLOCK_ACCESS_SELECTS`
for the copy), opposite meaning.

### `categories`
| Column             | Type    | Constraints |
|---|---|---|
| `id`                | INTEGER | PRIMARY KEY |
| `name`              | TEXT    | UNIQUE NOT NULL |
| `subscription_url`  | TEXT    | nullable -- NULL means manual-curation-only (e.g. "AI", "Weapons" -- no public blocklist exists for either) |
| `last_synced_at`    | TEXT    | nullable -- when `common/category_fetch.py` last successfully fetched `subscription_url` |
| `is_global`         | INTEGER | NOT NULL DEFAULT 0 -- blocked for everyone |
| `created_at`        | TEXT    | NOT NULL |

### `category_domains`
The resolved domain list for a category. `source` lets a re-sync
(`common/category_fetch.py`) replace only `'subscription'` rows for a
category, leaving every `'manual'` row untouched.

| Column         | Type    | Constraints |
|---|---|---|
| `id`            | INTEGER | PRIMARY KEY |
| `category_id`   | INTEGER | NOT NULL REFERENCES `categories(id)` ON DELETE CASCADE |
| `pattern`       | TEXT    | NOT NULL -- `re.escape()`d before storage, same convention as `domains.pattern` |
| `source`        | TEXT    | NOT NULL `CHECK IN ('subscription','manual')` |
| `created_at`    | TEXT    | NOT NULL |

UNIQUE(`category_id`, `pattern`).

### `category_overrides`
Admin-added allow-exceptions within a category — a domain matching a
pattern here is never blocked by that category, even if it's also a
member. Matched by exact pattern-string equality (see
`controller/adguard_sync.py`'s `_category_domain_patterns()`), not
suffix/regex overlap — an MVP-scope limitation.

| Column         | Type    | Constraints |
|---|---|---|
| `id`            | INTEGER | PRIMARY KEY |
| `category_id`   | INTEGER | NOT NULL REFERENCES `categories(id)` ON DELETE CASCADE |
| `pattern`       | TEXT    | NOT NULL |
| `note`          | TEXT    | nullable |
| `created_at`    | TEXT    | NOT NULL |

UNIQUE(`category_id`, `pattern`).

### `category_users` / `category_groups` / `category_devices`
Same shape as `user_domains`/`group_domains`/`device_domains` (`id`,
`category_id`, one of `user_id`/`group_id`/`device_id`, all
`ON DELETE CASCADE`, `UNIQUE(category_id, *_id)`) — which
user/group/device this category is BLOCKED for.

### `schedules`
A time window during which its assigned categories (or a full lockout)
apply to its assigned users/groups/devices.

| Column         | Type    | Constraints |
|---|---|---|
| `id`            | INTEGER | PRIMARY KEY |
| `name`          | TEXT    | UNIQUE NOT NULL |
| `days_of_week`  | TEXT    | NOT NULL -- comma list of lowercase 3-letter codes, e.g. `"mon,tue,wed,thu,fri"` |
| `start_time`    | TEXT    | NOT NULL -- `"HH:MM"`, evaluated in `time_zone` |
| `end_time`      | TEXT    | NOT NULL -- `"HH:MM"`; `end_time < start_time` means an overnight window (e.g. bedtime `"21:00"`→`"06:00"`), handled explicitly by `common/schedule_eval.py` |
| `time_zone`     | TEXT    | NOT NULL -- IANA name, e.g. `"America/Chicago"`; stored per-schedule so a later change to the household default never moves an existing schedule's meaning |
| `lockout_all`   | INTEGER | NOT NULL DEFAULT 0 -- 1 = full nftables-tier lockout (see `controller/policy_state.py`'s QUARANTINE overlay), `schedule_categories` ignored; 0 = a normal DNS-tier category block |
| `is_global`     | INTEGER | NOT NULL DEFAULT 0 |
| `is_mode`       | INTEGER | NOT NULL DEFAULT 0 -- added 2026-09-05 (Phase 12). See `schedule_overrides` below. |
| `created_at`    | TEXT    | NOT NULL |

**`is_mode`**: marks a schedule as one of a target's mutually-exclusive
daily "modes" (e.g. School / Free Time / Bedtime) — eligible to be
manually forced active, or forced inactive, by a `schedule_overrides` row.
Deliberately opt-in per schedule rather than "an override suspends
*every* schedule for this target": a standing safety-net category block
(Adult, Gambling, etc.) should never be silently lifted just because
someone shifted a kid into Free Time. `0` (the default) means a schedule
is evaluated purely by the clock, exactly as before this feature existed
— see `common/schedule_eval.py`'s `schedule_is_active_for_device()`.

### `schedule_categories`
Which categories are blocked while a (non-`lockout_all`) schedule is
active. `id`, `schedule_id` REFERENCES `schedules(id)` ON DELETE CASCADE,
`category_id` REFERENCES `categories(id)` ON DELETE CASCADE,
UNIQUE(`schedule_id`, `category_id`).

### `schedule_users` / `schedule_groups` / `schedule_devices`
Same shape as `category_users`/`category_groups`/`category_devices`
above — who a schedule applies to.

### `schedule_overrides`
Added 2026-09-05 (Phase 12): a manual, time-boxed "shift mode now" action
— e.g. school lets out early, so a parent forces the Free Time schedule
active for a kid right now instead of waiting for School's own window to
end, or starts School early one day. Deliberately a one-off action, not a
saved/reusable preset — see RoadMap.md's design discussion for the
alternatives considered.

| Column        | Type    | Constraints |
|---|---|---|
| `id`           | INTEGER | PRIMARY KEY |
| `schedule_id`  | INTEGER | NOT NULL REFERENCES `schedules(id)` ON DELETE CASCADE -- the schedule being forced active. Must itself have `is_mode = 1` and must already target the row's own user/group/device (via `is_global` or the junction tables above); `dashboard.add_schedule_override()` enforces both before ever inserting a row here. |
| `user_id`      | INTEGER | REFERENCES `users(id)` ON DELETE CASCADE, nullable |
| `group_id`     | INTEGER | REFERENCES `groups(id)` ON DELETE CASCADE, nullable |
| `device_id`    | INTEGER | REFERENCES `devices(id)` ON DELETE CASCADE, nullable |
| `created_at`   | TEXT    | NOT NULL |
| `expires_at`   | TEXT    | NOT NULL |

Exactly one of `user_id`/`group_id`/`device_id` is set — same target
shape as `schedule_users`/`schedule_groups`/`schedule_devices`, but a
single ad hoc row instead of a saved many-to-many assignment. Enforced by
the dashboard route, not a CHECK constraint (SQLite has no clean way to
express "exactly one of these three columns is non-NULL", unlike
`devices`' own two-column `CHECK (user_id IS NULL OR group_id IS NULL)`).

Read live (`expires_at > now`) by `common/schedule_eval.py`'s
`active_override_for_device()` — no background job needed, the same
"compute on read, nothing to reconcile" pattern the schedules' own
day/time windows already use. Once past `expires_at` a row here is simply
inert; nothing prunes it automatically (same "nothing prunes this yet"
convention as `system_events`), but `dashboard.add_schedule_override()`
deletes any existing override for the exact same target before writing a
new one, so stale rows don't pile up in the common case — only one
override is ever in effect per target at a time.

**How an override changes enforcement**: `schedule_is_active_for_device()`
is a device-aware wrapper around `schedule_is_active()` that both
`controller/policy_state.py` (the nftables `lockout_all` overlay) and
`controller/adguard_sync.py`'s `build_category_deny_rules()` (DNS-tier
category blocks) call instead of the bare clock check — one choke point,
so an override affects both enforcement paths without either module
needing its own special case. For an `is_mode` schedule: an active
override for a device means that schedule is active only if the override
names it specifically; every *other* `is_mode` schedule targeting the
same device is forced inactive for the override's duration, regardless of
the clock ("instead of", not "in addition to"). A non-`is_mode` schedule
is never affected. `controller/adguard_sync.py`'s
`sync_category_subscriptions()` (native AdGuard filter subscriptions for
over-threshold categories) is the one exception — it can only ever
enable/disable a filter household-wide, so a per-target override
structurally cannot apply there; it stays on the bare clock check.

**Scale note** (`common/matching.py`'s `MAX_SCOPED_CATEGORY_DOMAINS = 5000`):
real category blocklists range from tens to ~953K domains
(confirmed live against [The Block List Project](https://github.com/blocklistproject/Lists)).
A category at or under this many domains can be scoped to a specific
user/group/device (`controller/adguard_sync.py`'s
`build_category_deny_rules()`, `$client=`-scoped AdGuard custom rules —
the same mechanism `domains` assignment already uses). A category over
it can only ever be `is_global` (enforced by `dashboard/dashboard.py`'s
`update_category_access()`), pushed to AdGuard as one of its own native
filter subscriptions instead (`sync_category_subscriptions()`) — AdGuard
Home has no way to scope a subscribed list that size to a subset of
clients ([AdguardTeam/AdGuardHome#8103](https://github.com/AdguardTeam/AdGuardHome/discussions/8103)).

## Relationships (ER summary)

```
users (1) ──< user_domains >── (1) domains ──< domain_paths
  │                                  │
  └──< user_shows                    └── (self-contained: mode/kind/is_global)

access_log: loosely references users.id via user_id (nullable, no FK
constraint -- a log row must survive its user being deleted, so history
isn't lost) and free-text domain/series_id (no FK to domains/user_shows at
all -- a denied request may reference a domain or series that has no
`domains`/`user_shows` row yet, since a large part of this table's purpose
is recording activity for things that AREN'T configured/approved yet).

series_cache: standalone, keyed by Crunchyroll object_id, not related to
any other table by a real key (series_id values it stores are compared as
plain strings against user_shows.series_id, no FK).

settings: standalone key/value, unrelated to any other table.
```

Only `user_domains`, `domain_paths`, and `user_shows` have real foreign-key
constraints (all `ON DELETE CASCADE`, all enforced live because
`PRAGMA foreign_keys=ON` is set on every connection in `get_conn()`).
`access_log.user_id` is intentionally just a plain nullable INTEGER with no
`REFERENCES` clause -- deleting a user must not delete their history, and a
row logged for an unrecognized login string never had a real `user_id` to
reference in the first place.

## Enum-like columns, exhaustively

### `domains.mode`
Enforced by a `CHECK` constraint -- exactly these three values:
`splice`, `bump`, `trusted` (see the `domains` table section above for
semantics).

### `domains.kind`
Enforced by a `CHECK` constraint -- exactly these two values:
`generic`, `crunchyroll`.

### `access_log.reason`
**Not** constrained by the schema (plain `TEXT`) -- values are just a
convention followed by every write site. Enumerated by grepping every
`reason=` assignment in `proxy/sni_helper.py` and `proxy/authz_helper.py`:

From `proxy/sni_helper.py` (SNI/splice layer, `path` always NULL):
- `not_authenticated` -- `handle_splice()`: `device_identity.resolve_device()`
  found no active `device_bindings` row for the client IP at all (a
  genuinely never-seen device -- unchanged by the 2026-08-31 fix below).
- `outside_lan` -- `handle_splice()`: client IP failed `ip_in_configured_lan()`.
- `global_domain` -- `handle_splice()`: allowed because `domains.is_global = 1`.
- `user_domain` / `group_domain` / `device_domain` -- `handle_splice()`:
  allowed via `matching.device_domain_reason()` (added 2026-08-31, closing
  a real bug -- `group_domain`/`device_domain` previously could never fire
  at all since nothing called `group_has_domain()`/`device_has_domain()`
  from any enforcement path) because of an explicit `user_domains` /
  `group_domains` / `device_domains` row, respectively.
- `domain_not_assigned` -- `handle_splice()`: a real device identity
  resolved, but `device_domain_reason()` found no authorization by any
  axis (added 2026-08-31; replaces what used to be an implicit
  `allowed=False` with no distinct reason of its own).
- `unknown_domain` -- `handle_block_page()`: connection reached the catch-all rule and genuinely has no matching `domains` row at all (only logged when `block_page_mode != 'redirect'`, since redirect mode instead falls through to `authz_helper.decide()` which logs a richer, path-bearing version of the same case).

From `proxy/authz_helper.py` (HTTP layer, bump-mode domains, `path` always populated):
- `outside_lan` -- `decide()`: client IP failed the LAN check (mirrors the SNI-layer reason of the same name).
- `unknown_domain` -- `decide()`: no `domains` row matches this hostname at all.
- `not_bump_mode` -- `decide()`: a `domains` row exists but its `mode` isn't `bump` (reached via the ssl_bump `block_page` redirect path for a denied splice-mode domain).
- `domain_not_assigned` -- `decide()`: domain exists and is `bump` mode, but `matching.device_domain_reason()` found no authorization by any axis (global, user, group, or device).
- `path_not_allowed` -- `decide()` (generic bump domain) and `_decide_crunchyroll()` (Crunchyroll `OTHER`-shape fallback): domain permitted, but the request path matched none of its `domain_paths` patterns (only checked when the domain has at least one path rule at all).
- `global_domain` / `user_domain` / `group_domain` / `device_domain` -- `decide()`: generic bump-mode domain allowed, via whichever axis `device_domain_reason()` matched first (see the SNI-layer entries above for `group_domain`/`device_domain`'s 2026-08-31 history).
- `show_requires_user` -- `decide()`: a crunchyroll-kind domain IS authorized (via group/device), but no user resolved for this device at all -- `user_shows` is keyed by `user_id` only, so there's no group/device-level show list to check (added 2026-08-31, alongside the `group_domain`/`device_domain` fix).
- `blocked_shape` -- `_decide_crunchyroll()`: `cr_urls.classify()` recognized the URL as a shape that's always denied.
- `show_approved` / `show_not_approved` -- `_decide_crunchyroll()` (both the direct `SERIES_PAGE` case and the resolved `WATCH_PAGE`/`PLAYBACK` case): whether `matching.user_has_show()` found this `series_id` in the user's `user_shows`. Logged once per series id when a request references more than one (e.g. a playback request naming multiple objects).
- `resolution_failed` -- `_decide_crunchyroll()`: `series_resolve.resolve_series_ids()` returned `None` (CMS API unreachable and no usable stale-positive cache entry existed for every requested object id) -- fails closed.

From `dashboard/block_page_server.py` (AdGuard-side block page, added
2026-08-31 -- this module wrote nothing to `access_log` at all before
then):
- `dns_tier_denied` -- `_log_block()`: every hit gets this one
  undifferentiated reason (the server only ever sees the `Host` header, not
  which `domains`/`devices` rule caused the DNS-tier redirect that landed
  the browser here).

`CMS_OBJECTS`-kind Crunchyroll requests (pure metadata) are never logged at
all -- they're allowed unconditionally and return before reaching any
`log_access()` call (matches v1 behavior, see `_decide_crunchyroll()`).

## Seed data (`defaults/seed_defaults.py`)

Run once per container start by `proxy/entrypoint.sh` (also safe to run
manually/repeatedly -- see "Reset / run locally" below). Purely additive
and non-destructive: every insert is `INSERT OR IGNORE`, so re-running
against an already-configured database changes nothing, and anything an
admin has since edited or removed via the dashboard stays exactly as they
left it.

1. **`GLOBAL_SPLICE_DOMAINS`** (23 entries) -- infrastructure Crunchyroll's
   site depends on, inserted as `mode='splice'`, `kind='generic'`,
   `is_global=1`. Carried over from v1's flat `allowed_sites.txt`. Includes
   Google/gstatic/googleapis/googleusercontent, `ctfassets.net` (Crunchyroll
   CMS assets), `vimeo.com`, analytics/telemetry (`segment.com`,
   `datadoghq.com`, `googletagmanager.com`), notification/SSO providers
   (`braze.com`, `auth0.com`, `firebaseapp.com`), geolocation services
   (`ipify.org`, `ipapi.co`, `iplocate.io`, `ipinfo.io`), the video player
   stack (`bitmovin.com`, `litix.io`), cookie-consent vendors
   (`cookielaw.org`, `ketchcdn.com`, `ketchjs.com`, `onetrust.com`), a CDN
   (`akamaized.net`), and a script CDN (`jsdelivr.net`).
2. **`TRUSTED_DOMAINS`** (2 entries) -- `gccrunchyroll.com` and
   `crunchyrollcdn.com`, inserted as `mode='trusted'`, `is_global=1`.
   Crunchyroll's raw video CDN hosts: large binary traffic with nothing
   meaningful to authorize per-request, since the real per-show decision
   already happened at the bump-mode manifest/playback-token request.
3. **The Crunchyroll domain itself** -- a single row,
   `pattern='crunchyroll\.com'`, `mode='bump'`, `kind='crunchyroll'`,
   `is_global=1`, note `"Crunchyroll -- shows approved per-user"`. This is
   the one domain the dashboard refuses to let an admin delete
   (`dashboard.delete_domain()`). Note the seed script's comment recording
   that a separate `crunchyrollsvc.com` playback-service domain was
   deliberately *not* added (confirmed against Crunchyroll's live webpack
   bundle 2026-08-28 that production playback is served from
   `www.crunchyroll.com/playback`, not the dev-only `cr-play-service.*
   .crunchyrollsvc.com` host).
4. **`CRUNCHYROLL_PATHS`** (~25 regex patterns) -- inserted into
   `domain_paths` for the Crunchyroll domain row above (looked up by
   `pattern = 'crunchyroll\.com'` immediately after inserting it). Defense
   in depth for request shapes `cr_urls.classify()` doesn't specifically
   recognize -- login/auth/API endpoints, static assets (`css/js/images`),
   discover/browse pages, versioned API paths (`/subs/v\d+/`,
   `/playback/v\d+/`, `/accounts/v\d+/`, `/content/v\d+/`, etc.), i18n,
   skip-events, playhead tracking, and personalization/recommendation rows
   (`/personalization/v\d+/`, added for GH #4's "Top 10" home-page rows).
   Carried over from v1's flat `allowed_paths.txt`.
5. **`DEFAULT_CATEGORIES`** (Phase 8, 10 entries) -- Adult, Gambling,
   Drugs, Fraud & Scams, Facebook, TikTok, Twitter/X, WhatsApp (each with
   a real, live-verified `subscription_url` from
   [The Block List Project](https://github.com/blocklistproject/Lists)),
   plus AI and Weapons (`subscription_url=None` -- no public blocklist
   exists for either, manual-curation-only). **None are seeded
   `is_global`** -- the row existing blocks nothing on its own; an admin
   still has to turn one on and choose who it applies to from the
   Categories page. **No `category_domains` rows are seeded for the
   subscription-backed categories** -- those only appear once something
   actually calls `common/category_fetch.py`'s `fetch_and_sync_category()`
   (the controller's own daily background loop, or the dashboard's "Sync
   now" button) -- confirmed live: a real, non-mocked sync of the seeded
   WhatsApp URL fetched 226 real domains end-to-end.
   **AI is the one exception**: it has no `subscription_url` for
   `category_fetch.py` to sync from, so instead `seed()` inserts a
   **one-time manual snapshot** of 1,195 domains straight into
   `category_domains` (`source='manual'`), from
   [`defaults/ai_sites_seed.py`](../../defaults/ai_sites_seed.py) --
   sourced from Microsoft Purview's own published
   [AI-sites list](https://learn.microsoft.com/en-us/purview/ai-microsoft-purview-supported-sites)
   (fetched live 2026-09-01). 15 entries from Microsoft's original list
   were deliberately dropped because they scope one AI feature to a *path*
   on an otherwise general-purpose domain (`github.com/features/copilot`,
   `aws.amazon.com/bedrock/titan`, `bing.com/chat`, `sindresorhus.com`'s 3
   tools, and 9 others -- see the module's own docstring for the full
   list) -- this project's `category_domains` model has no path scoping,
   so blocking the bare domain would have collaterally blocked large
   unrelated sites. Being `source='manual'` (the same tag an admin's own
   hand-added domain gets), a re-seed never touches or duplicates these
   rows; an admin can freely add to or delete from this starter set from
   the AI category's own Manage page. At 1,195 domains it's well under
   `matching.MAX_SCOPED_CATEGORY_DOMAINS` (5,000), so -- unlike the four
   over-threshold subscription categories -- AI can still be scoped to a
   specific kid/device, not just turned on globally.

Run directly: `python3 defaults/seed_defaults.py` (imports `db` from the
same directory via a `sys.path.insert` at the top of the file -- run it
from a context where `common/` is importable as `db`, e.g. from inside the
proxy container's `/opt/parental-proxy/`, or with that directory added to
`PYTHONPATH`/`sys.path` manually). Also imports its sibling
`defaults/ai_sites_seed.py` by bare module name (`from ai_sites_seed import
AI_SITE_DOMAINS`) -- both files must be copied into the same directory in
any deployment image; `proxy/Dockerfile` does this with a single `COPY
defaults/seed_defaults.py defaults/ai_sites_seed.py ...` line.

## Running / resetting the database locally

- **Path:** controlled entirely by the `PP_DB_PATH` environment variable,
  read once at import time into the module-level `db.DB_PATH` (default
  `/config/parental_proxy.db`, i.e. the shared Docker volume `pp_config`
  mounted into both the `proxy` and `dashboard` containers per
  `docker-compose.yml`). There is no CLI flag -- only the env var.
- **Sidecar files:** because `journal_mode=WAL` is on, expect
  `parental_proxy.db-wal` and `parental_proxy.db-shm` alongside the main
  file; a full reset means removing all three (or the whole volume).
- **No dedicated reset script.** To start clean:
  - **Docker:** `docker compose down -v` removes the `pp_config` volume
    entirely (deletes the DB, the WAL/SHM sidecars, and the generated CA
    certificate together), then `docker compose up` recreates everything
    and re-runs `proxy/entrypoint.sh`'s seeding on next start.
  - **Locally / outside Docker:** delete the file at whatever `PP_DB_PATH`
    points to (plus its `-wal`/`-shm` siblings if present), then run
    `python3 defaults/seed_defaults.py` (which itself calls
    `db.init_db()` before seeding) to get a freshly-schema'd, freshly-seeded
    database again.
  - **Tests:** `tests/conftest.py`'s `conn` fixture gives every test a
    throwaway SQLite file under `tmp_path` with the schema applied and
    *no* seed data (`db.init_db()` only, `seed()` is not called) --
    monkeypatches `db.DB_PATH` directly rather than touching the env var,
    since `db.py` reads `PP_DB_PATH` once at import time. A safe fallback
    path (`%TEMP%/parental_proxy_pytest_default.db` equivalent) is set via
    `os.environ.setdefault("PP_DB_PATH", ...)` at collection time so a
    stray early import of `db` never touches a real `/config` path.
- **Inspecting the live file directly:** it's a normal SQLite database --
  `sqlite3 /path/to/parental_proxy.db` (or any SQLite browser) works, but
  do so read-only or briefly while both containers are stopped/idle if
  writing, since the WAL mode assumes cooperating connections rather than
  an external tool holding a long write transaction.
