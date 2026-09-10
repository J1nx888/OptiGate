# OptiGate

> A self-hosted, SSL-Bumping Squid proxy with a Flask admin dashboard that enforces per-person website/show permissions on a home network, with a full audit log and one-click "approve" workflow.

## Overview

OptiGate (formerly "Parental Proxy v2") is a from-scratch rewrite of an earlier Crunchyroll-only whitelist proxy, now grown into a self-hosted replacement for a commercial whole-home filter (Bark Home). It's built around three ideas: everything is configured live from a web dashboard (no config files to hand-edit, no restarts for rule changes); every person in the household has their own site/show permissions, applied per-request based on which assigned device their traffic comes from (not a per-request login, since 2026-08-30 -- see below); and every allow/block decision is logged with who/what/when, with a one-click "Approve" action on any blocked report entry.

The system has two enforcement tiers, not one: a **DNS tier** (AdGuard Home, `adguard/`) that gives every device on the LAN baseline content filtering — domain assignment, block-list categories, SafeSearch/Restricted Mode, time-based schedules — with zero per-device setup at all; and a smaller, deliberately curated **SSL-Bump tier** (Squid, `proxy/`) for the handful of devices/domains that need path- or show-level rules (e.g. which Crunchyroll series a kid may watch), via `external_acl_type` helper scripts rather than Squid's native ACL language. Both tiers, plus the Flask admin dashboard (`dashboard/`), read and write one shared SQLite database. A third piece, the network-level **interception layer** (`phase3/arp-worker`, `phase3/nftables-manager`, `controller/`), is what gets a device's traffic to either tier at all without any per-device proxy configuration — built, tested in isolation, and as of 2026-09-02 also validated live against the real household Orbi mesh (G1 is a GO, see [G1 runbook](deployment/g1-runbook.md)); a full back-to-back matrix pass and the soak test still remain before decommissioning Bark Home.

The remaining work — YouTube channel/creator-level filtering, and the real-network validation above — is tracked in [`../RoadMap.md`](../RoadMap.md), which is the authoritative status on what's built vs. planned; **this documentation describes the system as it exists in code today**, including everything shipped so far, not just the original Phase 1/2 scope its earlier revisions covered.

## How it works

**DNS tier (every device, no setup):** the interception layer redirects port 53 to AdGuard Home, which enforces domain assignment, block-list categories, and time-based schedules by computing per-client (or global, for large lists) filtering rules and pushing them via its own API (`controller/adguard_sync.py`) -- see [Architecture](architecture/overview.md) for the size-threshold split between the two enforcement mechanisms. This is the baseline every device gets, matching Bark Home's own coverage, and it's what most of Phase 8-11's newer features (categories, schedules, SafeSearch, ad-hoc pause) actually enforce through.

**SSL-Bump tier (a curated subset of devices/domains):** a bump-enabled device's port 80/443 traffic reaches Squid's intercept ports (`http_port 3129 intercept` / `https_port 3130 intercept ssl-bump`) via NAT redirection -- no per-device proxy configuration, just a trusted CA certificate (see `docs/architecture/overview.md` for what does that redirecting; it's Phase 3's interception layer, outside this repo's proxy/dashboard tree). At the TLS layer, Squid peeks at the SNI hostname and asks `proxy/sni_helper.py` (one of four modes: `bump`/`trusted`/`splice`/`block_page`) whether to decrypt, splice through untouched, or terminate — consulting `common/matching.py` and the shared SQLite database for the domain's configured mode and the requesting device's assigned user's permissions (identity resolved from the client's source IP via `common/device_identity.py` → `device_bindings` → `devices.user_id`, replacing a per-request Basic-Auth login as of 2026-08-30). If a domain is in `bump` mode, the now-decrypted HTTP-layer request is additionally checked by `proxy/authz_helper.py`, which for Crunchyroll resolves the actual show being requested (`common/cr_urls.py` → `common/series_resolve.py` → `common/cr_api.py`) and checks it against that user's approved-shows list. Every decision is logged via `common/logging_util.py`. The Flask dashboard (`dashboard/dashboard.py`) reads and writes the same database to manage users, domains, devices, per-user assignments, and the report/approve workflow.

## Repository layout

```
common/        Shared Python modules, flat-copied into whichever image(s) need them
  db.py              SQLite schema (SCHEMA string) + init_db() -- 28 tables total, see
                      docs/database/schema.md for the full current list
  auth.py            password hashing/verification (PBKDF2), verify_admin_credentials()
  matching.py        domain/user/LAN-permission lookup logic, category/schedule targeting
  device_identity.py resolve_device(conn, client_ip) + resolve_user_for_device(conn, device)
                      -- Squid's identity source since 2026-08-30 (split into two
                      functions 2026-08-31, see docs/security/overview.md §3)
  identity.py        record_binding() -- the discovery-side device_bindings writer
  policy_class.py    classify_device()/bump_eligible() -- the interception layer's policy model
  squid_helper.py    shared external_acl_type request/response protocol plumbing
  logging_util.py    deduped access-log writer
  cr_urls.py         Crunchyroll URL classification (playback/series/season/episode)
  series_resolve.py  resolves a Crunchyroll URL's ids to a series_id (with caching)
  cr_api.py          Crunchyroll CMS API client (anonymous token flow)
  adguard_client.py  AdGuard Home REST client (custom rules, SafeSearch, filter subscriptions)
  rate_limit.py      in-memory sliding-window RateLimiter -- dashboard admin login +
                      captive portal login brute-force protection
  system_events.py   admin-visible failure/recovery log, written by controller/'s loops
  schedule_eval.py, blocklist_parser.py, category_fetch.py -- Phase 8 (categories/schedules)
  sdnotify.py        stdlib systemd sd_notify client, used by controller/'s heartbeat pacer

proxy/         The Squid container (SSL-Bump tier)
  squid.conf.template   Squid config: intercept-mode ports, ssl_bump rules, http_access,
                         external_acl_type wiring (see RoadMap.md's intercept-mode section)
  sni_helper.py          external_acl_type handler for ssl_bump step2 (bump/trusted/splice/block_page)
  authz_helper.py        external_acl_type handler for the decrypted HTTP layer
  entrypoint.sh          generates the CA cert, fixes volume ownership, starts Squid
  Dockerfile             squid-openssl (NOT plain squid -- required for SSL-Bump)

adguard/       The AdGuard Home container (DNS tier), thin wrapper + first-run bootstrap

dashboard/     The Flask admin container
  dashboard.py             every route + inline Jinja2 templates (single file, ~8000 lines);
                            main() also starts the three background components below
  captive_portal_server.py forced-enrollment login server (Phase 4); portal-side admin
                            action offers Bypass / Ignore / assign-to-group
  block_page_server.py     kid-facing DNS-tier block page (plain HTTP only, by design)
  adguard_config_sync.py   keeps AdGuard's own admin password in sync with the dashboard's
  adguard_report_sync.py   polls AdGuard's query log to back-fill the Report page with
                            HTTPS DNS-tier hard-denies (RoadMap.md item 25)
  Dockerfile               flattens common/*.py + the dashboard/*.py modules (COPYd by
                            explicit name) into one /app directory

controller/    Python control-plane container (the interception layer's brains,
               "interception" compose profile only) -- policy computation, AdGuard sync,
               device discovery (rtnetlink/snapshot/active-scan), health reporting.
               See docs/architecture/overview.md §1 for the full module list.

phase3/        Go components of the interception layer (own "interception" profile)
  arp-worker/         ARP-spoofing daemon, real CAP_NET_RAW, speaks Unix-socket IPC to controller/
  nftables-manager/   reads desired policy from the shared SQLite DB, reconciles real nftables

defaults/
  seed_defaults.py   idempotent first-run seed data (global domains, Crunchyroll config,
                      Phase 8's starter categories)
  ai_sites_seed.py   the "AI" category's manually-curated starter domain list

tests/         Tier-1 pytest suite (1151 passed / 34 skipped on Windows as of
               2026-09-09 -- no Docker/network required, the skips are AF_UNIX-only
               tests that run (and pass) on Linux). The Go components under phase3/
               have their own `go test ./...` suites, not counted here.
docs/          This documentation
```

## Documentation

| Section | Contents |
|---------|----------|
| [Architecture](architecture/overview.md) | Components, tech stack, component diagram, the three domain modes, end-to-end request flow, non-obvious design decisions |
| [Dashboard routes](dashboard/routes.md) | Every Flask route, the template constants, CSRF/`flash_redirect` patterns, how to add a new page |
| [Database schema](database/schema.md) | Every table (including the Phase 2/3 devices/groups/identity tables), columns/constraints/relationships, every `access_log.reason` value enumerated, seed data |
| [Deployment](deployment/setup.md) | Local setup (`setup.sh` and manual), every env var, the CA cert, port mappings, CI |
| [G1 runbook](deployment/g1-runbook.md) | Real-network ARP interception validation — **GO as of 2026-09-02**; back-to-back pass + soak test still remain before replacing Bark Home |
| [Security](security/overview.md) | Auth/CSRF/password hashing, Squid's device-identity model (intercept mode, since 2026-08-30), the CA/bump trust model, rate-limiting (in-memory/per-process, both login surfaces), LAN-only scoping |
| [Testing](testing/overview.md) | How to run the suite, key fixtures, mutation-testing verification process, how to add a test |

## Quick start

```bash
# Interactive setup (prompts for LAN CIDR, admin credentials, builds + starts both containers)
./setup.sh

# Or manually:
cp .env.example .env    # edit LOCAL_NETWORK, DASHBOARD_USER, DASHBOARD_PASSWORD, etc.
docker compose up -d --build

# If DASHBOARD_PASSWORD was left blank, retrieve the auto-generated one:
docker compose logs dashboard

# Run the test suite:
pip install -r requirements-dev.txt -r dashboard/requirements.txt
pytest
```

Dashboard defaults to `http://127.0.0.1:8787` (not LAN-reachable until `DASHBOARD_BIND` is changed). The command above starts only `proxy`/`adguard`/`dashboard` -- no device configures a proxy setting at all; the only per-device manual step is trusting the CA cert. The interception layer (`arp-worker`/`nftables-manager`/`controller`, what actually gets real household traffic to these containers with zero per-device config) is a separate, explicit `docker compose --profile interception up -d` -- see [G1 runbook](deployment/g1-runbook.md) before ever pointing that at a real LAN.

## Key technical decisions

- **`external_acl_type` helper scripts instead of Squid's native ACL language** for all authorization logic — lets every decision be backed by live SQLite lookups (per-user, per-domain, per-path) rather than static config, which is what makes "everything editable from the dashboard, no reconfigure" possible.
- **Three domain modes (`splice`/`bump`/`trusted`) as an explicit privacy/cost tradeoff**, not a single always-decrypt design — most traffic never needs to be decrypted to enforce a domain-level allow/deny, and only domains needing path/show-level rules pay the cost (and trust-warning risk) of SSL-Bump.
- **One shared SQLite database, no caching layer, `ttl=0`** on the `external_acl_type` helpers — every Squid decision is a live read of current dashboard state, so permission changes take effect immediately with no reconfigure/restart.
- **`squid-openssl`, not plain `squid`** — Debian's default `squid` package is built against GnuTLS, which doesn't support SSL-Bump at all; this is an easy, silent trap when rebuilding the Dockerfile from scratch.
- **Crunchyroll show-resolution is deliberately special-cased**, not built as a generic "any site" feature — nothing else in scope has a documented API to resolve "this URL belongs to this show," so generalizing the pattern prematurely would have added complexity with no second user.
- **Rate-limiting on both login surfaces, in-memory/per-process by design** — the dashboard admin login and the captive portal's login (`common/rate_limit.py`, added 2026-09-02) each get their own 5-attempts/60s limiter; resetting on a container restart is an accepted tradeoff for a LAN-only deployment, not an oversight — see [Security overview](security/overview.md) section 6 for what a persisted, restart-surviving version would need before any internet-facing exposure.
- **Squid identity is device-based, not credential-based** (since 2026-08-30) — a client's source IP is resolved through `device_bindings` to a `devices.user_id`, replacing the old per-request Basic-Auth login. This is what makes "no per-device proxy configuration, just a CA cert" possible, at the cost of a different trust boundary (whoever controls a bump-enabled device's IP is treated as its assigned user, with no credential check) — see [Security overview](security/overview.md) section 3 for the full tradeoff.
- **"Two independent axes" as a recurring pattern, not a one-off** — bump-eligibility layered on top of base classification, a scheduled `lockout_all` overlay layered on top of (never mutating) an admin's own manual quarantine, category assignment separate from schedule gating. Each pair composes rather than one silently overriding the other's own state.
- **Categories/schedules are a block-list, the opposite polarity from every other domain-assignment table** — `domains`/`user_domains`/etc. are allow-lists (denied unless assigned); assigning a category or schedule means *block*. Same junction-table shape, reused deliberately, inverted meaning — see [Architecture](architecture/overview.md) §9 before assuming "assigned" means "allowed" anywhere in that code.

## Where the v2 redesign discussion lives

The full plan (DNS-tier filtering via a Layer-2 ARP-interception daemon, captive-portal forced enrollment, per-device SSL-Bump curation, YouTube channel filtering, dashboard UI rework, eventual remote access) is tracked in [`RoadMap.md`](../RoadMap.md) at the repo root — kept up to date as phases complete, not just a one-time snapshot. The concrete technical design for Phase 3 specifically (language/library choices, IPC schema, nftables skeleton, DB migration draft) lives in [`docs/design/phase3-technical-design.md`](design/phase3-technical-design.md). As of 2026-08-30 the docs above DO reflect the parts of that redesign that have actually shipped into this repo's proxy/dashboard/database code — Squid's intercept mode and device-based identity, and the devices/groups/identity-model database tables — but Phase 3's actual interception layer (`phase3/arp-worker`, `phase3/nftables-manager`, `controller/`) lives in its own part of the repo tree, is fully built and tested in isolation, and was validated live against the real household Orbi mesh on 2026-09-02 (**G1 is a GO**); RoadMap.md, not this doc, is the authoritative status on the remaining pre-deployment steps (a back-to-back matrix pass and the soak test) — see [`docs/deployment/g1-runbook.md`](deployment/g1-runbook.md) and RoadMap.md's "Path to deployment" section.
