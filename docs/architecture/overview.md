# Architecture Overview

Reference for navigating and modifying this codebase. Written against the
tree as of 2026-08-28, **updated 2026-08-30 for Squid's move to intercept
mode** (see `docs/review-2026-08-28.md` for the earlier live-testing
bugfix history referenced throughout this doc, and RoadMap.md's "Squid:
explicit-proxy-with-login -> transparent intercept" section for the
architecture change itself). **Re-audited 2026-09-02** against the
merged `fix/cross-tier-domain-enforcement` branch (Phase 8 categories/
schedules, G3/G6, the Events page) -- §1's file tree, §7's route groups,
and the dashboard's line count were the parts that had actually gone
stale; everything else held up. **Re-audited again 2026-09-07** after a
long session of dashboard-only feature work (bulk-actions toolbars on
every list page, group-level Ignore mode, the Health page's toggle-
command display) -- the dashboard's line count and this section's
`policy_class.py`/`groups` entries needed touching up; the request-flow/
component-boundary material below (nothing in that work touched Squid,
AdGuard rule generation, or the interception layer itself) held up
unchanged.

This is a parental-control **transparent, intercepting proxy**: a single
Squid instance with SSL-Bump enabled, sitting between LAN clients and the
internet, making per-device allow/deny decisions by calling out to small
Python scripts that read/write one shared SQLite database. Traffic reaches
Squid via NAT redirection (Phase 3's `phase3/nftables-manager`, not part of
this Phase 1/2 codebase) rather than any per-device proxy configuration --
no device points its proxy settings at Squid at all; the only per-device
step is trusting the CA certificate. A Flask dashboard is the only way an
admin edits the shared database's contents, including which devices are
assigned to which user and which are SSL-Bump-enabled.

---

## 1. Components and exact file locations

```
common/                      shared Python modules, imported by both containers
  db.py                        SQLite schema (SCHEMA string) + get_conn()/init_db()
  auth.py                      PBKDF2-SHA256 password hashing (hash_password/verify_password),
                                verify_admin_credentials() (shared by dashboard.py's Basic-Auth
                                check and captive_portal_server.py's portal-side admin action)
  matching.py                  domain/path regex matching, LAN CIDR check;
                                device_domain_reason(conn, device, domain) -- the shared
                                is_global/user/group/device authorization check (added
                                2026-08-31), used by both proxy helpers and
                                controller/adguard_sync.py's build_splice_deny_rules();
                                also category_applies_to_device()/schedule_applies_to_device()
                                (Phase 8) and MAX_SCOPED_CATEGORY_DOMAINS (the 5,000-domain
                                per-client-scoping threshold)
  device_identity.py           resolve_device(conn, client_ip) -- source IP -> device_bindings ->
                                the devices row itself (Squid's identity source since 2026-08-30);
                                resolve_user_for_device(conn, device) -- devices.user_id -> users row,
                                or None for an unassigned/group-assigned device (split from a single
                                resolve_user() 2026-08-31 -- see matching.device_domain_reason())
  identity.py                   record_binding() -- the discovery-side write path into
                                device_bindings, MAC/IP conflict handling, and Phase 4's
                                auto-gate-new-devices behavior (see §9)
  policy_class.py               PolicyClass enum + classify_device() (bypass > quarantine >
                                authenticated/preauth precedence) and bump_eligible() --
                                consumed by controller/policy_state.py, not the proxy directly.
                                Both take an explicit group_ignored parameter (added
                                2026-09-07, defaults False so every pre-existing caller stays
                                correct unchanged) -- a device's effective BYPASS state is its
                                own `ignored` column OR its group's (see `groups` below);
                                every raw-SQL BYPASS filter that doesn't go through this
                                function (controller/desired_state.py,
                                controller/adguard_sync.py's _fetch_eligible_devices()) has its
                                own matching LEFT JOIN fix instead
  logging_util.py              log_access() -- deduped access-log writer
  squid_helper.py              shared stdin/stdout protocol loop (run())
  series_resolve.py            Crunchyroll object-id -> series-id cache (resolve_series_ids())
  cr_api.py                    Crunchyroll CMS API client (TokenManager, SeriesResolver)
  cr_urls.py                   Crunchyroll URL classifier (classify(), RequestKind enum)
  adguard_client.py             stdlib REST client for AdGuard Home's control API -- custom
                                filtering rules, SafeSearch, native filter-list subscriptions
                                (add_url/remove_url/set_url), query-log reads
  system_events.py              log_event()/failure_recovery_callbacks() -- the admin-visible
                                Events page's write side (Phase 11, see §9)
  schedule_eval.py               Phase 8: schedule_is_active()/is_full_lockout_active(), stdlib
                                zoneinfo, handles an overnight window (e.g. bedtime) explicitly
  blocklist_parser.py           Phase 8: parse_hostlist() -- the three real subscription-list
                                formats (bare domain-per-line, hosts-file, AdGuard/adblock)
  category_fetch.py             Phase 8: fetch_and_sync_category() -- HTTP GETs a category's
                                subscription_url, replaces only its source='subscription' rows
  sdnotify.py                    stdlib-only systemd sd_notify client (READY=1/WATCHDOG=1),
                                used by the controller's heartbeat pacer
  rate_limit.py                  RateLimiter -- shared per-IP sliding-window brute-force
                                limiter (2026-09-02), used by dashboard.py's admin login AND
                                captive_portal_server.py's two forms, each its own instance
  optigate_rewrite.py            parse_block_page_ip()/sync_optigate_rewrite() -- the
                                optigate.home DNS rewrite, moved here from
                                controller/adguard_sync.py 2026-09-08 so dashboard.py can push
                                it directly instead of only via controller's periodic cycle
                                (the interception profile, off by default for most installs --
                                see this module's own docstring for the real gap this closed)

controller/                   Python control-plane container (added 2026-08-30, see
                                docker-compose.yml's "interception" profile below)
  main.py                       run()/run_cycle() -- the real control loop: worker IPC,
                                heartbeat pacer, and every periodic sync/discovery task below,
                                each wired through system_events.failure_recovery_callbacks()
  policy_state.py               compute_desired_policy() -- classify_device() per device plus
                                Phase 8's lockout_all schedule overlay, written to
                                interception_runtime.desired_policy_json for the Go side to read
  desired_state.py              db_backed_desired_state() -- which devices are real ARP-worker
                                targets at all (active device_bindings, non-ignored)
  reconcile.py                  order-insensitive idempotent reconciliation against the worker
  ipc_client.py / lease.py      WorkerClient (Unix-socket IPC to phase3/arp-worker) / HeartbeatPacer
  discovery.py                  periodic `ip neigh` snapshot -> identity.record_binding()
  rtnetlink_listener.py         live kernel neighbor-table event listener (pyroute2) -- the
                                highest-precedence discovery source, no discrete per-cycle
                                success concept (see §9)
  active_scan.py                rate-limited active ARP nudge for stale/onboarding bindings
  network_sweep.py              active whole-subnet discovery sweep (nudges every host in
                                local_network, not just already-known-stale ones -- reuses
                                active_scan.nudge(); admin-configurable interval/on-off from
                                the dashboard, re-read live, no restart needed)
  mdns_lookup.py                 best-effort mDNS reverse-PTR hostname lookup for devices on
                                the "Devices awaiting login" card (hand-rolled DNS wire format,
                                no CAP_NET_RAW/library needed -- see its own module docstring);
                                writes device_bindings.hostname, display only
  adguard_sync.py                build_rules()/build_splice_deny_rules()/
                                build_category_deny_rules()/build_ech_strip_rules()/
                                sync_category_subscriptions()/sync_safesearch() -- everything
                                pushed to AdGuard's custom rules + native filter/SafeSearch
                                settings (see §2's AdGuard bullet). build_ech_strip_rules()
                                (2026-09-09, RoadMap.md item 17) adds a $dnstype=HTTPS rule per
                                bump-mode domain, scoped to its authorized client IPs, so an
                                ECH-carrying HTTPS/SVCB DNS record can't defeat SSL-Bump on a
                                Cloudflare-fronted site (forces an A/AAAA + visible-SNI fallback)
  adguard_discovery.py           reads AdGuard's own query log to refresh device_bindings.last_seen_at
  health.py / readiness.py      interception_runtime health-column writer / worker+AdGuard
                                startup readiness waits
  periodic.py                    PeriodicTask -- the shared interval-task primitive every loop
                                above builds on (on_error/on_success callbacks)

proxy/                        Squid container
  Dockerfile                    debian:bookworm-slim + squid-openssl
  entrypoint.sh                 first-run seeding, CA cert generation, squid.conf render
  squid.conf.template           the actual Squid config (intercept-mode http_port/https_port,
                                 acls, http_access, ssl_bump -- see RoadMap.md's intercept-mode section)
  sni_helper.py                 external_acl_type for ssl_bump step2 (handle_bump/handle_trusted/
                                 handle_splice/handle_block_page)
  authz_helper.py               external_acl_type for the HTTP-layer decision (decide())

dashboard/                    Flask container
  dashboard.py                  all routes: users, domains, categories, schedules, devices,
                                groups, paths, shows, report, events, health, settings, /ca-cert.
                                main() also starts the three background components below (each
                                gated -- block_page_server + adguard_report_sync on DASHBOARD_URL,
                                captive_portal_server unless CAPTIVE_PORTAL_DISABLED)
  captive_portal_server.py      Phase 4: the forced-enrollment login server (see §9). Its
                                portal-side admin action offers Bypass, Ignore (2026-09-09,
                                RoadMap.md item 22), or assign-to-group for an admin at the
                                gated device itself
  block_page_server.py          the kid-facing block page, run as its own process (see §9's
                                network_mode: host note)
  adguard_config_sync.py        keeps AdGuard's own admin password in sync with the dashboard's
                                (one credential to remember); _with_permission_retry() (2026-09-09,
                                RoadMap.md item 19a) retries a transient PermissionError around the
                                AdGuardHome.yaml read/write
  adguard_report_sync.py        (2026-09-09, RoadMap.md item 25) background poller: reads AdGuard's
                                own query log and back-fills access_log with DNS-tier hard-denies
                                that resolve to the block-page IP -- the ones a device hits over
                                HTTPS, which never reach block_page_server.py (port 443 refuses)
                                so were invisible on the Report page
  dev_server.py                  local-only launcher for manual/visual testing against a real
                                browser without a full Docker stack -- not part of any image
  Dockerfile                    python:3.12-slim + waitress. COPYs its dashboard/*.py modules by
                                explicit name (not a glob) -- a new module must be added to that
                                line or the image can't import it
  requirements.txt              flask>=3.0, waitress>=3.0, tzdata>=2024.1 (Phase 8 -- see
                                controller/requirements.txt's own comment on the same package)

defaults/
  seed_defaults.py              idempotent first-run seed data (seed())

adguard/                      AdGuard Home container (Phase 3, added 2026-08-30)
  Dockerfile                     thin wrapper: FROM adguard/adguardhome:v0.107.79
  entrypoint.sh                  automated first-run bootstrap via AdGuard's own
                                  /control/install/configure API -- no manual setup wizard

docker-compose.yml             six services total. proxy/adguard/dashboard run by default;
                                arp-worker/nftables-manager/controller (added 2026-08-30) are
                                gated behind the "interception" compose profile -- `docker compose
                                up` alone never starts them, `docker compose --profile
                                interception up -d` does. ALL SIX run with network_mode: host (see
                                docker-compose.yml's own comments on each) -- proxy/adguard/
                                nftables-manager/arp-worker need it to see real host interfaces
                                and share nftables' own redirect namespace; dashboard/controller
                                need it to reach AdGuard's loopback-bound admin API. Each service's
                                own app-level bind address (DASHBOARD_BIND/ADGUARD_WEB_BIND) is
                                what gates LAN exposure now, not a Docker port-publish mapping.
                                proxy/dashboard/nftables-manager/controller share the optigate_config
                                volume; adguard has its own optigate_adguard_conf/optigate_adguard_work;
                                arp-worker and controller share optigate_run (just their Unix socket).
```

`phase3/arp-worker/Dockerfile` and `phase3/nftables-manager/Dockerfile`
are plain multi-stage Go builds (compile static, run in a minimal
runtime image -- nftables-manager's also installs the real `nft` CLI,
since `knftables` shells out to it rather than using netlink directly,
plus `conntrack` (2026-09-09, RoadMap.md item 21): `internal/nft/conntrack.go`
shells out to it to flush already-open connections when a device is
reclassified to something more restrictive, since `ct mark` persists for
a connection's whole lifetime and `nft` itself has no "delete a tracked
connection" primitive). `nftables-manager`'s baseline redirect ruleset
also carries a self-IP exception (2026-09-09, RoadMap.md item 7): a
`bump_v4` device's traffic addressed to the box's own LAN IP returns
before the Squid redirect, so `optigate.home` and AdGuard-rewritten
hard-deny pages reach `block_page_server.py` directly instead of Squid's
Host-header-forgery check -- the IP comes from `-dashboard-url`, reusing
the existing `DASHBOARD_URL` value (`nft.SelfIPFromDashboardURL`).
`controller/Dockerfile` flat-copies `common/*.py` alongside
`controller/*.py`, same pattern as proxy/dashboard use for `common/`.
Starting the interception profile for real requires
`ARP_WORKER_IFACE`/`GATEWAY_IP`/`GATEWAY_MAC` in `.env` with no sensible
default -- deliberately: this project's own testing discipline treats
"deploy real ARP-spoofing to a real LAN" as a decision that needs a
human, not something a default `docker compose up` should ever do
silently. See RoadMap.md's live-verification section for how this was
proven end-to-end (Docker-bridge test network, never the real
production box).

Both container images `COPY common/*.py` into their own image root (proxy's
`/opt/optigate/`, dashboard's `/app/`) and add that directory to
`sys.path`. There is no shared package install step -- it's a flat file copy,
so a change to any `common/*.py` file requires rebuilding **both** images to
take effect everywhere.

---

## 2. Tech stack

- **Python 3** -- proxy container uses whatever `python3` Debian bookworm-slim
  ships (stdlib-only: `auth.py` is deliberately stdlib so the proxy container
  never needs `pip`); dashboard container is pinned to `python:3.12-slim`.
- **Squid, specifically `squid-openssl`** -- see `proxy/Dockerfile` comment:
  Debian's plain `squid` package is built `--with-gnutls` and does not support
  SSL-Bump at all (`squid -k parse` fails on the `ssl-bump` http_port option).
  `squid-openssl` is the same version built `--with-openssl`, which
  `ssl_bump`/`sslcrtd_program` require. This is a hard requirement, not an
  optimization -- installing plain `squid` breaks the entire project.
- **Flask** (dashboard web framework) served by **waitress** (`dashboard.py`
  `main()`), not Flask's dev server.
- **SQLite** (stdlib `sqlite3`), WAL mode, as the only datastore -- no
  Postgres/Redis/etc.
- **Docker / docker-compose** -- six services total (three by default:
  proxy, adguard, dashboard; three more behind the "interception" profile:
  arp-worker, nftables-manager, controller, added 2026-08-30).
- **Go 1.25** -- `phase3/arp-worker/` and `phase3/nftables-manager/`, each
  its own module, built via multi-stage Dockerfiles into static binaries.
- **pyroute2** (`controller/requirements.txt`, added 2026-08-30) -- the
  one third-party dependency in this otherwise stdlib-only package,
  needed for `controller/rtnetlink_listener.py`'s live netlink socket
  handling (pure Python itself, no C extension).
- **AdGuard Home** (`adguard/adguardhome:v0.107.79`, pinned rather than
  `latest`) -- the DNS tier's filtering engine, enforcing two rule sets via
  its `$client=`-scoped custom filtering rules, both built by
  `controller/adguard_sync.py`'s shared `_build_domain_deny_rules(conn,
  mode, require_bump_eligible, ...)` engine and pushed together in one
  managed block:
  - `build_rules()` (since 2026-08-30, reworked 2026-08-31): for every
    `mode='bump'` domain, denies any device that isn't BOTH currently
    `bump_eligible()` AND actually authorized for that specific domain
    (`matching.device_domain_reason()` -- `is_global`, or a user/group/
    device grant). The bump-eligibility-only version had a real gap
    **fixed 2026-08-31**: it used to select on the raw `bump_enabled`
    column, which let a `bump_enabled=1`-but-not-yet-`AUTHENTICATED`
    device bypass both this hard-deny AND nftables' `bump_v4` redirect at
    once -- see RoadMap.md's dated audit entry. The bump-eligibility-only
    check was itself **superseded the same day** (project owner's
    explicit direction, GH #9): a bump-eligible device used to get a free
    DNS pass to *any* bump-mode domain, relying entirely on Squid to
    catch an unassigned one after decryption -- now AdGuard checks the
    same per-domain assignment first. `is_global` still only ever means
    "assigned to everyone," never "skip the bump-eligibility gate."
  - `build_splice_deny_rules()` (added 2026-08-31, GH #9): the same
    per-user/group/device/everyone assignment, enforced at the DNS tier
    too, for `mode='splice'` domains -- no bump-eligibility gate here,
    since splice is exactly the tier a non-bump device uses. Closes a gap
    where the entire Domains-page content allowlist was completely
    unenforced for any device not going through Squid.
  Both exclude any device `common/policy_class.py`'s `classify_device()`
  returns `BYPASS` for (`ignored=1`, not `bypass_login` -- see that
  function's own docstring for the distinction) from every rule, on
  either mode -- the project owner's explicit direction the same day:
  AdGuard's baseline protection applies to everyone unless a device is
  set to `ignored`. Scope deliberately still excludes domains with no
  `domains` row at all (default-allow, unchanged) -- see
  `_build_domain_deny_rules()`'s own docstring and RoadMap.md's dated
  entry.
  - `build_anti_doh_rules()` (added 2026-09-02, no `conn` parameter --
    it reads no per-household state at all): an unconditional,
    non-admin-configurable deny for Firefox's DoH-auto-enable canary
    domain plus known public DoH resolvers, always included in
    `sync_once()`'s managed block regardless of what's configured --
    see `docs/security/overview.md` section 10 for why this needed to
    exist (a browser's own "Secure DNS" Settings toggle otherwise fully
    defeated DNS-tier enforcement for any non-bump device).
  Also provides network-wide ad/
  tracker blocking for every device: its own default filter is enabled
  automatically on first configure, plus (2026-08-30) a curated set of
  uBlockOrigin/uAssets domain-blocking lists added by
  `adguard/entrypoint.sh` -- see RoadMap.md's live-verification section
  for which lists and why (not the whole uAssets repo -- most of it is
  browser-extension-only cosmetic/scriptlet rules a DNS server can't
  apply). Since 2026-08-31, also a discovery source in the other
  direction: `controller/adguard_discovery.py` periodically reads
  AdGuard's own `/control/querylog` (via `common/adguard_client.py`'s
  `get_query_log`) to refresh `device_bindings.last_seen_at` for
  already-known IPs -- it can only ever confirm an existing binding is
  still active (DNS carries no MAC/link-layer information), never
  discover a new one.
- **Controller startup readiness** (`controller/readiness.py`, added
  2026-08-31) -- `wait_for_worker`/`wait_for_adguard` retry connecting to
  the ARP worker's Unix socket and AdGuard's API for a bounded timeout
  before `controller/main.py`'s `run()` proceeds, rather than failing (or
  silently degrading) on the very first attempt. The worker socket wait
  still raises past its timeout (Docker's `restart: unless-stopped`
  remains the fallback); the AdGuard wait never raises -- AdGuard isn't
  required for the rest of `run()` to function.
- **ARP send-failure visibility** (added 2026-08-31, closing a gap a
  live NIC-down test found): `phase3/arp-worker`'s `worker.Worker`
  tracks a global consecutive-send-failure count, reported to the
  controller on every `heartbeat_ack`. `controller/main.py`'s
  `run_cycle` reports the pipeline as `fail_open` (not `running`) once
  3 or more failures are seen in a row -- previously, a sustained ARP
  send failure (e.g. the bound network interface going down) was
  completely invisible to `interception_runtime`/`/health`, since
  health reporting only ever tracked the controller<->worker Unix-socket
  heartbeat, which such a failure doesn't touch at all.
- **Active ARP scanning** (`controller/active_scan.py`, added
  2026-08-31) -- the discovery precedence list's last source, "only
  when stale or onboarding a new device." Holds no `CAP_NET_RAW` itself
  (only `phase3/arp-worker` does); instead it opens a plain UDP socket
  and `sendto()`s a closed port on a stale `device_bindings` IP, which
  forces the kernel's own routing layer to (re)resolve that address's
  link-layer identity as a side effect -- confirmed live against a real
  kernel before this was built, no new `arp-worker` IPC op needed. Only
  ever nudges; `controller/discovery.py`'s already-running snapshot
  loop is what actually observes and records any resulting resolution.
  Rate-limited (`--active-scan-limit` bindings per `--active-scan-interval`,
  only bindings older than `--active-scan-stale-after`) to avoid a scan
  storm on a large LAN.
- **Active whole-subnet discovery sweep** (`controller/network_sweep.py`,
  added 2026-09-09, project owner's direct request: "The entire
  solution is designed to make sure no one can avoid it") -- closes a
  real gap active_scan.py's own docstring flags but doesn't solve:
  every discovery source above is reactive, so a device that never
  generates traffic this box's kernel happens to observe (one that
  joined the LAN and simply sat quietly) is invisible indefinitely, no
  matter how long the system runs. Reuses `active_scan.nudge()` and the
  SAME `local_network` setting `matching.ip_in_configured_lan()`
  already reads, just applied to every host address in that range
  instead of one already-known stale IP -- no new privileged code, no
  new `arp-worker` IPC op, and any resulting resolution is picked up by
  `discovery.py`'s own snapshot loop exactly like any other source.
  Runs once at controller startup, then on an admin-configurable
  interval (dashboard Settings page: `network_sweep_enabled` default
  on, `network_sweep_interval_minutes` default 60) -- both re-read
  fresh every ~30s check tick, so a settings change takes effect live,
  without a controller restart. Capped at 4096 host addresses per
  sweep so a misconfigured huge range degrades gracefully instead of
  hanging or flooding the LAN.
- **mDNS hostname lookup** (`controller/mdns_lookup.py`, added
  2026-09-11, project owner's direct request after being asked to scope
  "pre-authentication" down: "I need to see the device type that is
  trying to connect... to distinguish between an Amazon Echo and an
  actual laptop/phone") -- sends a reverse-PTR query (`<reversed-ip>.
  in-addr.arpa`) to the mDNS multicast group (`224.0.0.251:5353`) with
  the "QU" bit set (RFC 6762 SS5.4), so a responding device unicasts its
  answer straight back without this process needing `CAP_NET_RAW` or to
  join the multicast group at all -- same "no special privilege needed"
  shape as `active_scan.py`'s own UDP-nudge trick, different protocol.
  The DNS wire format (query build + response parse, including
  compression-pointer decompression) is hand-rolled rather than pulling
  in a third-party mDNS library -- small enough to unit-test directly
  against crafted byte strings (`tests/test_controller_mdns_lookup.py`)
  and keeps the dependency footprint where it already was. Every
  response byte is treated as untrusted network input: bounds-checked,
  a hard cap on compression-pointer jumps (`_MAX_NAME_JUMPS`) to refuse
  a hostile/corrupt pointer loop, and any parse failure is swallowed the
  same as a genuine non-response. Not every device answers -- most
  smart speakers, including Echoes, don't -- so this is a hint, paired
  with `common/oui_lookup.py`'s MAC-vendor lookup (a pure offline static
  lookup against a bundled IEEE OUI snapshot, no networking at all) for
  the "Manufacturer" column. Both are DISPLAY ONLY on the "Devices
  awaiting login" card (`device_bindings.hostname`, written by this
  module) -- never consumed for auto-association; see that column's own
  schema comment in `common/db.py` for why (the v2 roadmap explicitly
  rules out hostname/vendor-guessing auto-merge). Rate-limited
  (`--mdns-lookup-limit` pending devices per `--mdns-lookup-interval`,
  default 5 per 120s), only probing bindings with no hostname yet.
- **Auto-gating new devices** (`common/identity.py`'s `record_binding()`,
  added 2026-08-31, Phase 4's first milestone) -- a MAC genuinely never
  seen before now gets a brand-new, unassociated `devices` row
  auto-created for it (`is_authenticated = 0`, landing it in
  `common/policy_class.py`'s `PREAUTH`), rather than a dangling
  `device_id = NULL` binding. Closes a real gap: previously such a
  device was invisible to `controller/desired_state.py`'s own `JOIN`
  and got no interception of any kind (full, unfiltered access) until
  a human manually created its `devices` row via the dashboard. Only
  fires the first time a MAC is ever recorded -- an already-known-but-
  unassociated MAC from before this shipped is deliberately left alone
  (no retroactive backfill, a 2026-08-31 product decision), even across
  a later DHCP renewal. This is the foundation the captive-portal login
  flow (below) sits on top of.
- **Captive-portal login server** (`dashboard/captive_portal_server.py`,
  added 2026-08-31, Phase 4 milestone 3) -- the actual forcing
  mechanism for the PREAUTH devices milestone 1 creates.
  `phase3/nftables-manager`'s baseline rules have redirected
  `unauthenticated_v4`'s plain-HTTP traffic to `:3131` since Phase 3 was
  first designed (`# -> future portal` in the original design doc); this
  is that future portal, needing zero nftables/interception changes.
  Started from `dashboard/dashboard.py`'s `main()` (same
  `network_mode: host` process as `block_page_server.py`, so `:3131` is
  reachable at the host's real LAN address), disable-able via
  `CAPTIVE_PORTAL_DISABLED` as an operator kill switch. Deliberately
  returns the SAME login-page HTML for every request regardless of path
  or Host header -- since nftables redirects by source IP and
  destination port, not hostname, this alone is what makes every major
  OS's own captive-portal probe (Apple/Google/Microsoft/Firefox, each
  expecting a different exact response on a different URL) detect "there
  is a captive portal" and open that exact probe URL in a real browser/
  webview, which lands right back here and renders the login form. A
  successful login (checked against the same `users.password_hash`
  PBKDF2 hashes the admin dashboard already uses) flips
  `devices.is_authenticated` -- DNS-tier access only, never
  `bump_enabled` -- via `common/device_identity.py`'s new
  `resolve_device()` (source IP -> `device_bindings` -> the `devices`
  row itself, the write-side counterpart to that module's
  `resolve_user_for_device()`, the read-side function derived from a
  resolved device -- see §1's device_identity.py entry). No interception for HTTPS (tcp/443) -- see the
  module's own docstring for why that's a deliberate, industry-standard
  limitation (matching real commercial captive portals) rather than an
  oversight, and RoadMap.md for the follow-up hardening option this
  leaves open. The success page also closes the design sketch's
  "reminder screen" bullet from both sides (added 2026-08-31): a kid
  logging in here sees a note if their own `user_id` already has a
  DIFFERENT `bump_enabled` device, since this login only ever grants
  DNS-tier access and they might otherwise wonder why something that
  works on their usual device doesn't work here; separately,
  `dashboard/dashboard.py`'s device-detail page now prompts (a plain
  `confirm()`, matching this app's existing no-framework convention)
  for CA-cert-installed confirmation before actually checking
  `bump_enabled`, so an admin doesn't accidentally flip it before the
  cert is in place.
- **Portal-side admin action** (added 2026-08-31) -- the design
  sketch's other quick-add path, for an admin physically at the gated
  device itself rather than on a separate device with dashboard access.
  A collapsed `<details>` section on the same login page asks for the
  SAME admin credentials `dashboard.py`'s HTTP-Basic login checks
  (`common/auth.py`'s new `verify_admin_credentials()`, factored out of
  `dashboard.py`'s own `_check_admin_auth` so there's exactly one
  admin-credential check shared by both surfaces), then offers
  **Bypass** (identical effect to `/devices/bypass_login`) or
  **assign to a group** (clears any prior `user_id`, since
  `group_id`/`user_id` are mutually exclusive per the `devices` table's
  own `CHECK` constraint, and sets `is_authenticated = 1` directly --
  group assignment shouldn't depend on the `bypass_login` fallback
  below to actually take effect). Shares the kid-login form's own
  per-IP rate limiter rather than a separate budget, the more
  conservative choice given this surface grants strictly more.

  **Real bug found and fixed building this, 2026-08-31**:
  `common/policy_class.py`'s `classify_device()` never consulted
  `bypass_login` at all, despite the dashboard's own hint text and this
  design sketch both describing it as exempting a device from the
  captive-portal gate -- a device an admin marked `bypass_login` (via
  Milestone 2's dashboard button, or this new portal action) was, in
  reality, staying stuck in `PREAUTH` forever, still redirected to the
  portal on every request. Fixed: `classify_device()` now treats
  `is_authenticated OR bypass_login` as sufficient for `AUTHENTICATED`
  (still distinct from `ignored`/`BYPASS` -- `bypass_login` only skips
  the login requirement, not the whole policy system, so quarantine
  still takes precedence over it). `controller/policy_state.py`'s own
  query also needed a fix -- it never even `SELECT`ed `bypass_login` in
  the first place, so `classify_device()` could not have honored it
  regardless of its own logic.

---

## 3. Component diagram (text form)

```
                         LAN client (bump-enabled device)
                                   |
                    Port 80/443 traffic, NAT-redirected here
                    by Phase 3's nftables (phase3/nftables-manager,
                    not part of this repo's proxy/dashboard tree) --
                    no per-device proxy config, only a trusted CA cert
                                   v
                 +--------------------------------------+
                 |         proxy container (Squid)       |
                 |  squid.conf (rendered from            |
                 |  squid.conf.template by entrypoint.sh)|
                 |  http_port 3129 intercept /            |
                 |  https_port 3130 intercept ssl-bump    |
                 |                                        |
                 |  identity: %>a -> device_identity.py -> |
                 |    device_bindings -> devices.user_id  |
                 |  ssl_bump step1/step2 -> sni_helper.py |
                 |  http_access (post-bump) -> authz_helper.py
                 +--------------------+-------------------+
                                      |
                     reads/writes    (import db, matching,
                                      device_identity, logging_util,
                                      series_resolve, cr_urls -- all
                                      from common/)
                                      |
                                      v
                 +--------------------------------------+
                 |   /config/optigate.db (SQLite,  |
                 |   WAL mode) on the `pp_config` Docker  |
                 |   named volume -- single source of     |
                 |   truth, shared by both containers     |
                 +--------------------+-------------------+
                                      ^
                     reads/writes    (import db, auth, cr_api,
                                      matching -- from common/)
                                      |
                 +--------------------+-------------------+
                 |     dashboard container (Flask)        |
                 |     dashboard.py -- users/domains/      |
                 |     paths/shows/report/settings routes  |
                 |     served by waitress on :8787         |
                 +--------------------+-------------------+
                                      |
                          admin's browser (HTTP Basic auth,
                          DASHBOARD_BIND / DASHBOARD_URL)

  (separate, outbound-only path, no LAN client involved:)
  proxy container's authz_helper.py -> common/series_resolve.py ->
  common/cr_api.py -> https://www.crunchyroll.com/auth/v1/token and
  /content/v2/cms/objects/{ids}  (Crunchyroll's real CMS API, anonymous
  client token, cached in series_cache table)

  dashboard.py also calls common/cr_api.py's series_title() directly, for
  the show-approval UI (best-effort display name lookup).
```

`docker-compose.yml`'s `depends_on: [proxy]` on the dashboard service exists
specifically because the proxy container's `entrypoint.sh` is what `chown -R
proxy:proxy /config` and generates the CA cert on the shared volume before
the dashboard (running as the same `proxy` user) ever opens the database.

---

## 4. The shared SQLite database (`common/db.py`)

- Path: `OG_DB_PATH` env var, default `/config/optigate.db` (see
  `db.py`'s `DB_PATH = Path(os.environ.get("OG_DB_PATH", "/config/optigate.db"))`).
  Both `docker-compose.yml` service blocks set `OG_DB_PATH=/config/optigate.db`
  explicitly, backed by the same `pp_config:` named volume mounted at
  `/config` in both containers.
- `get_conn()` opens with `timeout=5.0`, `isolation_level=None` (autocommit),
  then sets `PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`, `PRAGMA
  foreign_keys=ON`, and `row_factory = sqlite3.Row`. WAL + busy_timeout is
  what makes concurrent access from many processes (each Squid helper
  invocation is a fresh process, plus the dashboard's Flask/waitress workers)
  safe without a real database server.
- `init_db()` runs the `SCHEMA` string (`CREATE TABLE IF NOT EXISTS ...`) --
  called by every entry point (`squid_helper.run()`, `dashboard.get_db()`,
  `seed_defaults.py main()`), so schema creation is idempotent and doesn't
  depend on ordering between containers.
- Core Phase 1/2 tables: `settings` (key/value, e.g. `local_network`,
  `block_page_mode`, `admin_username`, `admin_password_hash`, `secret_key`),
  `users`, `domains` (`mode` CHECK IN splice/bump/trusted, `kind` CHECK IN
  generic/crunchyroll, `is_global`), `user_domains` (per-user domain
  grants), `domain_paths` (per-domain allowed-path regexes, not per-user),
  `user_shows` (per-user approved Crunchyroll `series_id`s), `series_cache`
  (object_id -> series_id, with `expires_at`), `access_log` (the report
  page's data source, indexed on `ts DESC` and a dedupe composite index),
  `groups`/`group_domains`/`devices`/`device_domains` (shared-device
  categories and per-device identity/assignment).
  **Full current schema, including Phase 3's `device_bindings`/
  `interception_runtime`/`network_events`, Phase 8's `categories`/
  `category_domains`/`category_overrides`/`schedules`/`schedule_categories`
  (block-list polarity, see §9), and Phase 11's `system_events`, lives in
  [`docs/database/schema.md`](../database/schema.md) -- this list is not
  kept exhaustive here, don't treat it as the full table count.**
- There is **no caching layer** in front of the DB anywhere in the request
  path -- every `external_acl_type` line in `squid.conf.template` is declared
  with `ttl=0 negative_ttl=0`, so Squid calls the helper (and thus queries
  SQLite) on every single new connection/request rather than caching a
  verdict. This is why dashboard edits (e.g. approving a show) take effect
  immediately with no proxy restart or reconfigure.

---

## 5. The three domain modes

Set per-row in `domains.mode`, enforced in `common/matching.find_domain()`
lookups and consumed by both `sni_helper.py` and `authz_helper.py`:

- **`splice`** (default for new domains) -- host-only. Squid peeks at the TLS
  ClientHello's SNI (`ssl_bump peek step1`) and, based on
  `sni_helper.py handle_splice`, either splices (passes the encrypted bytes
  through untouched, `ssl_bump splice step2 sni_splice_allowed`) or the
  connection falls through toward `handle_block_page`/terminate. No
  decryption ever happens for an allowed splice-mode site. The report can
  only ever record the domain, never a path, for a `splice` decision --
  nothing downstream ever sees more than the SNI.
- **`bump`** -- fully decrypted (`ssl_bump bump step2 sni_bump`). Once
  bumped, every real HTTP request over that connection is re-evaluated by
  `authz_helper.py`'s `decide()` at the HTTP layer, where path-level and (for
  Crunchyroll) show-level rules apply. Any domain can be switched to `bump`
  from the dashboard to get a per-domain allowed-paths list (same idea as
  v1's `allowed_paths.txt`), independent of the Crunchyroll-specific logic.
- **`trusted`** -- always spliced, never checked, never logged
  (`sni_helper.py handle_trusted` just checks `mode == "trusted"`, no login/
  LAN/user checks at all, and it's the only sni_helper mode with no
  `logging_util.log_access()` call anywhere in its handler). Reserved for
  large-binary CDN traffic (seeded: `gccrunchyroll.com`, `crunchyrollcdn.com`)
  where the actual show-level decision already happened at the earlier
  manifest/token request, which *is* bumped -- there's nothing left to decide
  by the time the CDN request itself happens, so decrypting it would only add
  overhead and log noise for no security benefit.

Every domain is also either **global** (`is_global=1`, granted to every user
automatically -- shared infra like fonts/auth/analytics) or **per-user**
(`is_global=0`, requires a `user_domains` row via `matching.user_has_domain()`).

### Blocked-site experience (`settings.block_page_mode`)

A separate, deployment-wide setting (`terminate` default, or `redirect`),
read by `sni_helper.py handle_block_page()`:
- `terminate`: the SNI-layer catch-all always returns `False`, so
  `squid.conf.template`'s final `ssl_bump terminate step2 all` fires and the
  connection is torn down with no decryption at all -- safe on a device that
  hasn't installed the CA cert, but no explanation shown.
- `redirect`: `handle_block_page()` returns `True`, which (via
  `ssl_bump bump step2 sni_show_block_page`) decrypts *just that one blocked
  connection* so `authz_helper.py`'s normal deny path can serve
  `deny_info ${DASHBOARD_URL}/blocked authz_allowed` (appended to
  `squid.conf` by `entrypoint.sh` only if `DASHBOARD_URL` is set) instead of a
  bare connection failure. Tradeoff: the proxy briefly sees that one blocked
  attempt's real Host+Path, and the device must already trust the CA cert or
  the browser shows a TLS warning instead of a clean page.

---

## 6. End-to-end request flow

### 6a. TLS/SNI layer (every HTTPS connection)

1. The client sends nothing special at all -- no `CONNECT`, no proxy
   configuration, no login. Phase 3's nftables (outside this repo's
   proxy/dashboard tree; see RoadMap.md) NAT-redirects a bump-enabled
   device's own port 443 traffic straight to `https_port 3130 intercept
   ssl-bump ...`, and Squid recovers the real destination via
   `SO_ORIGINAL_DST`. This replaced the pre-2026-08-30 explicit-proxy model
   (`http_port 3128 ssl-bump` + `auth_param basic` + a per-request `CONNECT`
   and 407 Basic-Auth challenge, driven by the now-deleted
   `proxy/basic_auth_helper.py`) -- an intercepted connection never sends a
   `CONNECT` for HTTPS, so there is no handshake step left to challenge with
   a 407 in the first place. Identity is resolved later, per-decision, from
   the client's source IP (`%>a`) via `common/device_identity.py`'s
   `resolve_device(conn, client_ip)` (source IP -> `device_bindings` -> the
   `devices` row itself) and, from that, `resolve_user_for_device(conn,
   device)` (`devices.user_id` -> `users` row, or `None` for an unassigned
   or group-assigned device -- split from a single `resolve_user()`
   2026-08-31, see `docs/security/overview.md` §3's dated entry for the bug
   this fixed) -- see that section for the full model and its
   DHCP/staleness caveat.
2. `http_access deny CONNECT !SSL_ports` / `allow CONNECT` /
   `allow CONNECT step1`/`step2` still gate the (now purely internal, since
   there's no client-sent `CONNECT`) tunnel/negotiation phase Squid itself
   uses to peek and bump.
3. `ssl_bump peek step1` -- Squid peeks at the ClientHello without
   decrypting, extracting the SNI hostname.
4. At step2, four `external_acl_type` ACLs (all backed by
   `proxy/sni_helper.py`, invoked with different CLI args -- `bump`,
   `trusted`, `splice`, `block_page` -- see `HANDLERS` dict and `main()`) are
   checked in the fixed order written into `squid.conf.template`'s "SSL BUMP
   DECISION CHAIN" section (first match wins):
   - `sni_trusted` -> `handle_trusted()` -> splice if `mode == 'trusted'`
   - `sni_bump` -> `handle_bump()` -> bump if `mode == 'bump'`
   - `sni_splice_allowed` -> `handle_splice()` -> splice if `mode == 'splice'`
     AND `device_identity.resolve_device()` resolves a device for the
     client IP, that IP is inside the configured LAN
     (`matching.ip_in_configured_lan()`), and
     `matching.device_domain_reason()` (added 2026-08-31) authorizes it --
     `is_global`, or an explicit `user_domains`/`group_domains`/
     `device_domains` grant via the device's user, its group, or the
     device itself directly, whichever matches first
   - `sni_show_block_page` -> `handle_block_page()` -> bump-for-denial only if
     `block_page_mode == 'redirect'`
   - final catch-all: `ssl_bump terminate step2 all`
   Each handler calls `matching.find_domain(conn, sni)`, which iterates
   `domains` rows in `id` order and regex-matches via
   `matching._domain_regex()` -- an anchored domain-suffix match
   (`r"(?:^|\.)(?:" + pattern + r")\Z"`), specifically chosen so a stored
   pattern like `jsdelivr\.net` cannot be satisfied by `evil-jsdelivr.net` or
   `jsdelivr.net.attacker.example` (this was a real bypass before the anchor
   was added).

### 6b. HTTP layer (only reached for `bump`-mode connections, once decrypted)

5. Once `ssl_bump bump` fires, `http_access allow CONNECT step2` only covers
   the TLS negotiation itself -- **not** the real decrypted request that
   follows (this distinction is load-bearing: a bare `http_access allow
   step2`, without `CONNECT`, previously bypassed all per-domain/path/show
   enforcement, see squid.conf.template's inline comment and
   `docs/review-2026-08-28.md`). The actual decrypted HTTP request instead
   falls through to `http_access allow authz_allowed`, backed by
   `external_acl_type authz_check` -> `proxy/authz_helper.py decide()`.
6. `decide(conn, client_ip, dst, path, _data)`:
   - resolves via `device_identity.resolve_device(conn, client_ip)`, then
     `resolve_user_for_device()` for whichever user (if any) owns it; fails
     closed (silently, no log) if no device resolves at all -- a genuinely
     never-seen IP -- or logged `reason="outside_lan"` if outside the
     configured LAN (`matching.ip_in_configured_lan()`)
   - `matching.find_domain()` on the decrypted `Host` (`%DST`, host:port
     split via `_split_host_port()`); denies as `unknown_domain` or
     `not_bump_mode` if the domain isn't a `bump`-mode row (this is also how
     a `redirect`-mode block-page connection, which got bumped only to be
     denied, is actually denied here)
   - checks `matching.device_domain_reason(conn, device, domain)` (added
     2026-08-31) -- `is_global`, or an explicit `user_domains`/
     `group_domains`/`device_domains` grant, whichever matches first; denies
     `reason="domain_not_assigned"` if none do
   - **if `domain.kind == 'crunchyroll'`**: requires a resolved user at all
     (`user_shows` has no group/device equivalent) -- denies
     `reason="show_requires_user"` if the domain is authorized via
     group/device but no user resolved, else delegates to
     `_decide_crunchyroll()` (see 6c below)
   - **otherwise**: `matching.path_allowed(conn, domain_id, path)` against
     `domain_paths` rows, but only enforced if the domain has *any*
     configured paths at all (`_has_any_path_rules()`) -- a domain with zero
     path rows allows any path once the domain-level check passes.
   - every branch calls `logging_util.log_access()` with a `reason` string
     (`global_domain`, `user_domain`, `group_domain`, `device_domain`,
     `path_not_allowed`, `domain_not_assigned`, `unknown_domain`,
     `not_bump_mode`, `outside_lan`, `show_requires_user`, etc.) and a
     `device_id` (added 2026-08-31) -- these reason strings are what the
     dashboard's Report page displays and what makes an entry
     "Approve"-able, now for a device/group identity too, not just a user.

### 6c. Crunchyroll-specific show resolution

`authz_helper._decide_crunchyroll(conn, user, hostname, path, domain)`:
1. Builds the full URL and calls `common/cr_urls.py classify(url)`, which
   pattern-matches (no network I/O, no state) against
   `SERIES_URL_RE`/`WATCH_URL_RE`/`PLAYBACK_URL_RE`/`CMS_OBJECTS_URL_RE` and
   returns a `ClassifiedRequest(kind, ids)`.
   - `CMS_OBJECTS` -> always allowed (metadata-only, matches v1 behavior).
   - `BLOCKED_SHAPE` -> always denied (fail-closed: looks like a guarded
     route -- `/watch/`, `/playback/`, `/cms/objects/` -- but didn't match a
     known-safe shape).
   - `OTHER` -> falls back to the domain's `domain_paths` allowlist exactly
     like a non-Crunchyroll bump-mode domain would.
   - `SERIES_PAGE` -> checks `matching.user_has_show()` directly against the
     URL's own series id.
   - `WATCH_PAGE` / `PLAYBACK` -> the URL only carries an *object* id (an
     episode or playback-token id), not a series id, so it must be resolved
     first via `common/series_resolve.py resolve_series_ids(conn, request.ids)`.
2. `series_resolve.resolve_series_ids()` is cache-first against the
   `series_cache` table (`_cache_get`/`_cache_put`): a hit returns
   immediately; a miss calls `cr_api.SeriesResolver().resolve()` (which does
   the actual network call to `https://www.crunchyroll.com/content/v2/cms/objects/{ids}`,
   authenticated with an anonymous client-credentials Bearer token from
   `TokenManager` against `https://www.crunchyroll.com/auth/v1/token`). A
   successful resolution is cached for `POSITIVE_TTL_SECONDS` (30 days, since
   an object's parent series never changes); an explicit miss is cached
   negatively for `NEGATIVE_TTL_SECONDS` (1 hour). If the resolver raises
   `cr_api.ResolutionError` (network down, or the hardcoded anonymous client
   id has been rotated -- see `cr_api.py`'s `ANON_BASIC_CREDENTIAL` comment),
   `resolve_series_ids()` falls back to serving a still-present *positive*
   cache entry even past its TTL (`allow_stale=True`) rather than break
   playback of an already-approved show; an id with no positive history at
   all returns `None` from the whole function, which `decide()` treats as
   `resolution_failed` and denies (fail-closed contract, same as v1).
3. Each resolved `series_id` is checked against `matching.user_has_show()`
   (`user_shows` table, `series_id` normalized upper-case), and every
   individual object id gets its own `logging_util.log_access()` call with
   `series_id`/`series_name` attached, so a report entry for a blocked show
   is individually approvable.

`common/cr_api.py` is called from two places: `series_resolve.py` (the
proxy-side resolution path above) and `dashboard.py` directly, for
`series_title(series_id)` -- a best-effort display-name lookup used by the
show-approval UI, tolerant of any failure (returns `None`, dashboard falls
back to the raw id).

---

## 7. Dashboard (`dashboard/dashboard.py`)

Single-file Flask app (~6500 lines), imports `adguard_client`, `auth`,
`category_fetch`, `cr_api`, `db`, `matching`, `schedule_eval` from `common/` (via
`sys.path.insert(0, str(Path(__file__).parent))`, since the Dockerfile
copies `common/*.py` flat into `/app/` alongside `dashboard.py`). Served
by `waitress.serve()` in `main()`, not Flask's dev server, bound to
`DASHBOARD_HOST`/`DASHBOARD_PORT` (default `127.0.0.1:8787`). Since
2026-08-30 `dashboard` runs `network_mode: host` (needed so it can reach
AdGuard's loopback-bound admin API for the filter-refresh button below),
so `DASHBOARD_HOST` is set directly from `DASHBOARD_BIND` in
`docker-compose.yml` and IS the actual host-exposure control now --
before that, `DASHBOARD_HOST` was hardcoded to `0.0.0.0` and a separate
Docker port-publish mapping controlled host exposure instead.

Route groups (see the numbered `# ====` section banners in the file):
- **Admin auth**: `bootstrap_admin()` seeds `admin_username`/
  `admin_password_hash` into `settings` from `DASHBOARD_USER`/
  `DASHBOARD_PASSWORD` env vars on first run only (prints a generated
  password to stderr if unset); `require_admin` decorator + `_check_admin_auth()`
  gate every route except `/ca-cert` and `/blocked` (both deliberately public
  -- a CA cert isn't a secret, and a blocked kid needs to see the block page
  without logging in as admin).
- A `before_request` hook (`_reject_cross_origin_writes`) is a lightweight
  CSRF guard: rejects any POST/PUT/PATCH/DELETE whose Origin/Referer host
  doesn't match `request.host` (relevant because Basic-Auth credentials are
  attached by the browser automatically, unlike a cookie session that a
  SameSite policy could protect).
- **Users** (`/users`, `/users/add`, `/users/delete`, `/users/reset-password`,
  `/users/<id>`): CRUD on the `users` table, `add_user()` calls
  `auth.hash_password()`.
- **Shows** (`/shows/add`, `/shows/remove`, `parse_series_url()`): per-user
  `user_shows` management, including the "paste a Crunchyroll URL" flow that
  parses out a series id.
- **Domains** (`/domains`, `/domains/add`, `/domains/add-url`,
  `/domains/delete`, `/domains/<id>`, `/domains/update`,
  `/domains/access`, `/domains/paths/add`, `/domains/paths/delete`):
  CRUD on `domains`, `user_domains`, and `domain_paths`; `path_to_pattern()`
  converts a pasted URL path into a stored regex pattern.
  `update_domain_access()` replaces a domain's entire grant set (Everyone
  + users + groups + devices) in one call, rather than a per-assignment
  toggle -- see `docs/dashboard/routes.md` for the full route reference.
- **Categories** (`/categories`, `/schedules`, Phase 8, opposite polarity
  from Domains -- assignment means BLOCK, not allow, see §9): CRUD on
  `categories`/`category_domains`/`category_overrides` and
  `schedules`/`schedule_categories`, plus the size-threshold-aware
  `update_category_access()` (rejects a non-global assignment once
  `domain_count` exceeds `matching.MAX_SCOPED_CATEGORY_DOMAINS`) and
  "Sync now" buttons calling `category_fetch.py`.
- **Devices and groups** (`/devices`, `/groups`): a device's
  `user_id`/`group_id`/`bump_enabled`/`bypass_login`/`quarantined_at`
  assignment -- consumed by `common/device_identity.py`,
  `common/policy_class.py`, and (once Phase 3 is deployed) nftables.
  Includes CSV bulk import (`/devices/import`, G7) and the ad-hoc
  pause/resume routes (`/devices/pause`, `/devices/pause-all`,
  `/users/pause`, G6) that write `devices.quarantined_at`. Both pages
  got a full bulk-actions-toolbar pass (Entra-style buttons: Download
  CSV / Enable / Disable / Delete / Manage, 2026-09-07) -- see
  `docs/dashboard/routes.md` for the per-route detail, not repeated
  here. `groups.ignored` (added the same day) is a real, enforced
  policy input, not just a UI label -- see the `policy_class.py` bullet
  above and `docs/database/schema.md`'s `groups` entry for the full
  "additive with the device's own `ignored`" semantics.
- **Events** (`/events`, Phase 11): read-only historical trail of every
  background loop's real failures and recoveries, from `system_events`
  (written by `controller/main.py`, never by the dashboard itself) --
  see §9.
- **Report** (`/report`, `/report/approve`): reads `access_log`, and
  `approve_from_report()` implements the one-click-approve flow -- for a
  domain-level denial it creates a `user_domains` row (creating the `domains`
  row itself first if it never existed, scoped to that one user); for a
  show-level denial it creates a `user_shows` row.
- **Health** (`/health`, added 2026-08-30): read-only view of
  `interception_runtime` (the controller<->arp-worker pipeline's
  `mode`/`last_healthy_at`/`fail_open_reason` and nftables-manager's own
  `nft_mode`/`nft_last_healthy_at`/`nft_fail_reason`) -- only meaningful
  once the optional `interception` compose profile is running. Flags a
  subsystem "stale" (not just its literal `mode` value) when its
  `last_healthy_at` hasn't advanced in `HEALTH_STALE_AFTER_SECONDS`
  (30s), since a crashed/crash-looping process can't write its own
  `fail_open` row -- the process that would do that is the one that's
  dead. `render()` (the shared page-chrome wrapper every route uses)
  separately lights a sidebar "!" alarm badge from the same
  `_subsystem_unhealthy()` predicate on every page, not just `/health`
  itself. **Since 2026-09-07**: each subsystem card also shows the
  exact `docker compose` command to flip its current state -- a
  deliberate choice (project owner's, after being asked) over granting
  the dashboard container Docker socket access to actually start/stop
  those containers itself; see §9's own bullet on this. See
  `docs/dashboard/routes.md`'s own "Health" section for the full route
  reference.
- **Settings** (`/settings`, `/settings/network`, `/settings/filtering`,
  `/settings/household`, `/settings/admin`, `/settings/adguard/refresh`,
  `/settings/device-stale-days`): editable `local_network` and the
  network discovery sweep, `block_page_mode`/AdGuard connection
  settings/SafeSearch intent, the default schedule time zone and the
  `optigate.home` hostname, admin credentials, and the stale-device
  cleanup threshold -- all live edits to the `settings` table, no
  container restart needed. **Merged into these three grouped routes
  2026-09-09 (RoadMap.md item 3, "one Save button per settings-shaped
  page, not several")** -- each used to be 2-3 separate routes/forms
  saved independently (`/settings/local-network` +
  `/settings/network-sweep`; `/settings/adguard` +
  `/settings/safesearch` + `/settings/block-page-mode`;
  `/settings/household-time-zone` + `/settings/optigate-hostname`); now
  each group is one atomic save, so a bad value in one field no longer
  silently leaves an unrelated field in that same group unsaved. One-off
  actions with different consequences than a persisted setting (AdGuard
  filter refresh, the network sweep's "Run now", CA cert regeneration/
  upload, backup restore, stale-device cleanup) deliberately stayed as
  their own separate buttons/routes -- see `docs/dashboard/routes.md`'s
  "Settings" section for the full reasoning and route reference. Several
  of these (AdGuard filter refresh, SafeSearch) write *intent* only; a
  `controller/` background loop is what actually reconciles it against
  AdGuard on its own next cycle -- see `adguard_sync.py` in §1's
  controller/ listing.
- `/ca-cert`: unauthenticated `send_file()` of `OG_CA_CERT_PATH`
  (`/config/ssl_cert/ca_cert.pem`) for device onboarding.
- `/blocked`: unauthenticated, the target of `deny_info` for `redirect`-mode
  block pages.

---

## 8. Container startup (`proxy/entrypoint.sh`, `proxy/Dockerfile`)

1. `mkdir -p /config /config/ssl_cert`, then `chown -R proxy:proxy /config`
   -- both containers run helper/dashboard code as the `proxy` user (Debian
   uid 13) so the shared SQLite file (+ `-wal`/`-shm` sidecars) stays
   writable by both; this also repairs a volume left root-owned by an older
   build.
2. Runs `defaults/seed_defaults.py` and an inline Python heredoc
   (`db.set_setting_if_absent` for `local_network`/`block_page_mode`) as the
   `proxy` user via `runuser` if available, so the DB file it may create is
   correctly owned.
3. Generates the SSL-Bump CA cert (`openssl req -x509 ... -addext
   basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign`)
   into `$SSL_DIR` only if missing -- this is the cert devices must trust,
   and its private key never leaves the container/volume.
4. Initializes Squid's `security_file_certgen` cert-signing DB
   (`/var/lib/squid/ssl_db`) if missing -- `squid-openssl` doesn't pre-create
   `/var/lib/squid` itself, so this directory must be created before
   `security_file_certgen -c` runs or it fails.
5. Copies `squid.conf.template` to `/etc/squid/squid.conf`, then
   conditionally appends `deny_info ${DASHBOARD_URL}/blocked authz_allowed`
   if `DASHBOARD_URL` is set (this line can't be templated with `envsubst`
   directly because an empty `DASHBOARD_URL` would still need the whole line
   dropped, not substituted empty).
6. `exec squid -N -f /etc/squid/squid.conf`.

`defaults/seed_defaults.py`'s `seed()` is fully idempotent (`INSERT OR
IGNORE` everywhere), safe to run on every container start against an
already-configured database -- it seeds `GLOBAL_SPLICE_DOMAINS` (infra like
`google.com`, `gstatic.com`, `jsdelivr.net`, etc., all `splice`/global),
`TRUSTED_DOMAINS` (`gccrunchyroll.com`, `crunchyrollcdn.com`, both
`trusted`/global), the `crunchyroll.com` domain itself (`bump`,
`kind='crunchyroll'`, global), and `CRUNCHYROLL_PATHS` attached to that
domain's `domain_paths`. Notably it does *not* seed a `crunchyrollsvc.com`
domain -- confirmed against Crunchyroll's live webpack bundle that the
`cr-play-service.*.crunchyrollsvc.com` host is dev-only and real production
playback goes through `www.crunchyroll.com/playback`, already covered.

---

## 9. Non-obvious design decisions worth knowing before changing this code

- **`%DATA` must be declared in every `external_acl_type` FORMAT line even
  though every handler ignores it.** Squid always appends a `%DATA` field to
  the line it sends a helper unless the FORMAT already includes one. None of
  the `acl ... external ...` lines in `squid.conf.template` pass a static
  argument, so `%DATA` is always literally `"-"` -- but it is still sent,
  making the line one field longer than its `%macro` count suggests.
  Omitting it previously meant every helper's `field_count` (in
  `squid_helper.run()`) was off by one, so every request was rejected as a
  malformed line and silently fell through to the terminate-all catch-all.
  This is why every handler signature in `sni_helper.py` and
  `authz_helper.py` ends with an unused `_data: str = "-"` parameter.
- **`http_access allow CONNECT step2` must be qualified with `CONNECT`, not
  left bare.** Squid's `at_step` state does not reset after `ssl_bump`
  reaches step2 -- the first decrypted HTTP request that follows a bump
  decision is *also* evaluated with step2 still true. A bare `http_access
  allow step2` therefore grants that real request unconditional access
  before `authz_allowed` is ever reached, bypassing all per-domain/path/show
  enforcement for every bump-mode request including Crunchyroll. Confirmed
  against a real Squid instance (see `docs/review-2026-08-28.md`).
- **CDN domains are `trusted` (spliced, unchecked, unlogged) rather than
  `bump`**, because the actual show-level authorization decision already
  happened at the earlier manifest/playback-token request (which *is*
  bumped) -- by the time raw video bytes are being requested from
  `crunchyrollcdn.com`/`gccrunchyroll.com`, there's nothing left to decide
  per-user, so decrypting it would only add overhead and log noise.
- **Domain patterns are anchored regexes, not substrings**
  (`matching._domain_regex()`): `r"(?:^|\.)(?:" + pattern + r")\Z"`. Without
  this anchor, `re.search` treated every stored pattern as an unanchored
  substring match, so an FQDN merely *containing* an allowed string (e.g.
  `evil-jsdelivr.net` against the seeded `jsdelivr\.net`) would slip through.
- **`domain_paths` is per-domain, not per-user.** It's defense-in-depth
  against unrecognized endpoint shapes on a `bump`-mode domain (same idea as
  v1's flat `allowed_paths.txt`), not a per-kid permission -- per-kid
  permission for Crunchyroll is expressed at the show level
  (`user_shows`), and for any other domain at the domain level
  (`user_domains`).
- **A `bump`-mode domain with zero configured `domain_paths` rows allows any
  path** once the domain-level check passes (`_has_any_path_rules()`) --
  path restriction is opt-in per domain, so admins only curate paths for
  domains where it actually matters.
- **`access_log` dedupe includes `path` with its query string stripped**
  (`logging_util.log_access()`), and treats `series_id` as part of the
  dedupe key using SQLite's null-safe `IS`. This means a path-less SNI-layer
  entry and a later path-bearing HTTP-layer entry for the same event are
  different dedupe keys, so a richer, later entry is never hidden behind an
  earlier, less informative one within the same 5-minute window.
- **`series_resolve.py` never deletes an expired positive cache row before
  attempting a live re-resolve.** `_cache_get()` reports an expired positive
  entry as a miss (so a fresh resolve is attempted) but leaves the row in
  place, specifically so `resolve_series_ids()`'s `allow_stale=True` fallback
  can still serve it if the live resolver call then fails. An earlier version
  of this logic deleted the stale entry first, which broke the fallback it
  was supposed to support (see README's "Testing notes" section, S2.6).
- **Everything is fail-closed by convention**: an unrecognized/malformed
  Squid protocol line returns `ERR` (`squid_helper.run()`'s `except Exception`
  wraps any handler crash the same way), `cr_urls.classify()` returns
  `BLOCKED_SHAPE` rather than `OTHER` for anything that looks like a guarded
  route but doesn't match a known-safe shape, and
  `series_resolve.resolve_series_ids()` returns `None` (which
  `authz_helper.decide()` treats as a hard deny) for any object id with no
  usable cache history at all.
- **Phase 8's `categories`/`schedules` are a BLOCK-list, the opposite
  polarity from every domain-assignment table above them** (`domains`/
  `user_domains`/`group_domains`/`device_domains` are an allow-list,
  denied unless assigned). Same junction-table shape, reused deliberately
  (down to the dashboard's combobox widget, relabeled
  `BLOCK_ACCESS_SELECTS`), opposite meaning -- see
  `docs/security/overview.md` §8 and `docs/database/schema.md`'s Phase 8
  section before assuming "assigned" means "allowed" anywhere in that
  code.
- **A module needed by both the dashboard and controller images must live
  in `common/`, never duplicated under both `common/` and `controller/`
  with the same filename.** Both Dockerfiles flat-copy `common/*.py` then
  their own directory's `*.py` into the SAME `/app/` directory (see
  `controller/Dockerfile`'s own comment) -- a same-named file in both
  would silently collide (whichever `COPY` ran last wins in that image).
  `common/category_fetch.py` (Phase 8) is the concrete example: it needs
  `controller/periodic.py`'s `PeriodicTask` for its own `run_loop()`, but
  that import is done lazily INSIDE `run_loop()`, not at module level,
  specifically so `dashboard.py` can `import category_fetch` and call its
  other functions (the "Sync now" button) even though
  `controller/periodic.py` was never copied into the dashboard image at
  all -- the same reason `common/adguard_client.py` (the REST client) and
  `controller/adguard_sync.py` (the scheduling/business logic on top of
  it) are already split the way they are.
- **G3's `sync_safesearch()` only ever writes the `enabled` field of
  AdGuard's SafeSearch config, never the per-service booleans**
  (`google`/`youtube`/`bing`/etc.), even though `PUT
  /control/safesearch/settings` has no partial-patch form -- every field
  must be resupplied on every call. It does this by reading the current
  config first and only flipping the one field this project owns, the
  same "don't clobber an admin's own customization" discipline
  `adguard_sync.py`'s custom-rules merge and `sync_category_subscriptions()`
  already apply to AdGuard's other settings. Unlike categories/schedules
  elsewhere in this file, SafeSearch is deliberately network-wide only --
  matching Bark Home's own behavior -- with no per-user/group/device
  scoping built at all.
- **G6's ad-hoc "pause the internet" needed zero enforcement-layer
  changes.** `devices.quarantined_at` and the QUARANTINE nftables set
  were already fully general (Phase 3) -- `classify_device()` already
  treats a non-NULL value as QUARANTINE regardless of who or what set
  it, and `controller/policy_state.py` already computes it into the real
  kernel ruleset every cycle. G6 is purely three dashboard routes writing
  to a column that was already real and already live-verified. There is
  deliberately no "why was this paused" tracking -- a manual pause and a
  schedule's `lockout_all` overlay both express through this exact same
  mechanism, so resuming a device always just means "un-pause it,"
  regardless of how many different things might have paused it.
- **`system_events`'s failure/recovery-transition tracking lives in an
  in-process closure, deliberately not persisted state.**
  `common/system_events.py`'s `failure_recovery_callbacks()` tracks
  whether a given loop is "currently failing" in a plain dict captured
  by its returned closures, not a DB column -- so a container restart
  implicitly and correctly resets that tracking. A process that starts
  up and immediately succeeds is NOT a "recovery" worth a row (there was
  no observed failure THIS process ever knew about), even if the
  previous process instance had been failing right up until it was
  restarted. This trades slightly-incomplete recovery visibility across
  a restart boundary for real simplicity -- no new persisted state
  needing its own migration/cleanup story, and every existing periodic
  loop in this codebase already opens its own connection freshly per
  cycle (see `discovery.run_loop()`'s own docstring on why), so
  "just track it in memory, in the same process" is the same shape this
  codebase already uses everywhere else.
- **Two loops deliberately don't get `system_events` recovery
  tracking, and it's not an oversight.** `rtnetlink_listener.py` is a
  continuous event listener, not a fixed-interval sync -- there's no
  discrete per-cycle "did this succeed" moment to hook a transition onto
  the way `PeriodicTask`'s new `on_success` callback assumes; its
  failures still get an `error` row each occurrence, there's just no
  matching `recovery` row. The controller↔worker heartbeat's OWN
  recovery already surfaces through the Health page's `fail_open` state
  transition, and its actual reconnect logic lives in `run_cycle()`'s
  `_reconnect()` path, not a `PeriodicTask` hook at all -- adding a
  second, redundant recovery-tracking mechanism there would just be two
  sources of truth for the same fact.
- **`dashboard.py` and `captive_portal_server.py` are also
  `system_events` writers now (2026-09-02), not just `controller/`'s
  background loops.** A failed login/admin-action attempt logs an
  `error` row with no matching `recovery` -- same "pure failure
  counter" shape as `rtnetlink_listener.py` above, since "someone typed
  the right password eventually" isn't a notable recovery worth its own
  row (a successful login logs nothing at all). See
  `docs/security/overview.md` section 6 for the full brute-force-audit
  writeup this came out of, and `common/rate_limit.py` for the shared
  limiter mechanism both files now use.
- **`groups.ignored` is additive with a device's own `ignored` bit, never
  a replacement for it** (added 2026-09-07) -- a device's effective
  BYPASS state is `devices.ignored OR (its group's ignored, if it
  belongs to one)`. Turning a group's flag back off never clears any
  member device's own column; it only stops contributing to the OR.
  This is real, live-enforced policy (not just a dashboard label), so
  every place that reads `devices.ignored` for actual classification --
  not just `common/policy_class.py`'s `classify_device()`, which takes
  it as an explicit parameter, but also the raw-SQL BYPASS filters in
  `controller/desired_state.py` and
  `controller/adguard_sync.py`'s `_fetch_eligible_devices()` -- had to be
  individually audited and given a matching `LEFT JOIN groups` fix. A
  new bug of this exact shape (a raw-SQL device query that checks
  `ignored = 0` without also joining `groups`) is the thing to watch for
  if this column ever grows a second consumer.
- **The Health page's per-subsystem toggle command is deliberately not a
  working button.** Asked (2026-09-07) to add a Settings-page on/off
  switch for the interception containers (`controller`/`arp-worker`/
  `nftables-manager`), the project owner was first asked how it should
  be built, since a real one requires giving the dashboard container
  Docker socket access to start/stop sibling containers -- a privilege
  it has none of today, already declined once at smaller scope (an
  AdGuard-restart convenience, earlier the same session). The decision:
  no new privilege at all -- the Health page already shows each
  subsystem's live status, so it now also shows the *opposite* action's
  exact `docker compose` command right there, for the admin to run over
  SSH. If this is ever revisited toward a real working switch, treat the
  privilege tradeoff as a fresh decision, not something this precedent
  already settled in favor of convenience.
