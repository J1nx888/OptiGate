# AGENTS.md

Orientation for an AI agent (or a new human) working in this repository.
This is the "read this first" file: what the project is, how to build and
test it, the big-picture architecture, and the non-obvious traps. It is
deliberately short — the authoritative technical reference is under
[`docs/`](docs/project.md), and the forward plan is [`RoadMap.md`](RoadMap.md).

## What this is

**OptiGate** (formerly "Parental Proxy v2") — a self-hosted, SSL-Bumping Squid proxy plus a Flask
admin dashboard that enforces per-person website/show permissions on a home
network, with a full audit log and a one-click "approve" workflow. It began
as a Crunchyroll-only whitelist proxy and is mid-way through a larger
rewrite aimed at replacing a commercial whole-home filter (Bark Home).

Read these in order the first time:

1. [`README.md`](README.md) — what exists and works **today**, in user terms.
2. [`docs/project.md`](docs/project.md) → [`docs/architecture/overview.md`](docs/architecture/overview.md)
   — the technical reference for the current system. `architecture/overview.md`
   §9 ("Non-obvious design decisions") is required reading before changing
   any proxy/Squid code.
3. [`RoadMap.md`](RoadMap.md) — the only source of truth for what is planned
   vs. built vs. deployed. It is a living document; **append to it, keep it
   current** as phases complete.

Other docs: [`docs/dashboard/routes.md`](docs/dashboard/routes.md),
[`docs/database/schema.md`](docs/database/schema.md),
[`docs/deployment/setup.md`](docs/deployment/setup.md),
[`docs/security/overview.md`](docs/security/overview.md),
[`docs/testing/overview.md`](docs/testing/overview.md),
[`docs/design/phase3-technical-design.md`](docs/design/phase3-technical-design.md),
and [`docs/review-2026-08-28.md`](docs/review-2026-08-28.md) (the live
smoke-test bugfix history that the architecture doc keeps referring back to).

## Environment notes

- Development happens on **Windows**; deployment target is **Linux**.
- **No Docker daemon** in the usual dev/CI sandbox — `docker compose up`
  cannot be run here. Phase 2/3 verification is done manually against a
  disposable Debian/Ubuntu VM and, sparingly, a real production box.
- **No C compiler** in the dev/CI environment — this constrains dependency
  choices (see `controller/requirements.txt`'s comment: `pyroute2` is the
  single third-party Python dep, chosen because it is pure-Python).

## Commands

### Python test suite (Tier-1, no Docker — this is what CI runs)

Run from the **repo root**:

```bash
pip install -r requirements-dev.txt -r dashboard/requirements.txt
pytest
```

- `pytest.ini` sets `testpaths = tests`, so a bare `pytest` is enough — no
  path argument, no `PYTHONPATH`/`PYTHONPATH` setup (`tests/conftest.py`
  builds `sys.path` itself, on purpose, to sidestep the `;` vs `:`
  separator gotcha between PowerShell and Git Bash).
- Single file / single test:
  ```bash
  pytest tests/test_logging_dedupe.py::test_window_expiry_allows_a_new_row
  ```
- CI-style verbose run (exactly what `.github/workflows/tests.yml` does):
  ```bash
  pytest -v
  ```
- Parallel: `pytest -n auto` works if `pytest-xdist` is installed (it is
  not in `requirements-dev.txt`). Every DB-touching test gets its own
  throwaway SQLite file via `tmp_path`, so order does not matter.
- `dashboard/requirements.txt` is required even though it looks like a
  runtime-only dep, because `tests/test_dashboard.py` imports `dashboard.py`
  directly.
- Live authoritative test count: `pytest --collect-only -q`. Several files
  are `AF_UNIX`-only and skip on Windows (`socket.AF_UNIX` doesn't exist
  there), so a Windows run shows more skips than a Linux run.

### Go components (`phase3/arp-worker/`, `phase3/nftables-manager/`)

Two separate Go modules (`go 1.25`), each built via its own multi-stage
Dockerfile. From inside each module directory:

```bash
go build ./...
go vet ./...
go test ./...
```

`-race` is unavailable in the sandboxed test environments (no C compiler);
`go test ./... -count=10` is the substitute used for flake-checking.
`nftables-manager`'s `internal/nft` package needs `CAP_NET_ADMIN` to run
against a real kernel — its pure-logic `internal/policy` package does not.

### Running the stack (Linux + Docker only, not in this sandbox)

```bash
./setup.sh                              # interactive first-run wizard, writes .env, builds + starts
docker compose up -d --build            # manual equivalent (3 default services)
docker compose --profile interception up -d   # + the 3 Phase 3 services (needs .env vars, see below)
docker compose logs -f dashboard        # follow logs / read the auto-generated admin password
docker compose down                     # stop; the pp_config volume (DB + CA cert) is preserved
```

The `interception` profile refuses to start without `ARP_WORKER_IFACE` /
`GATEWAY_IP` / `GATEWAY_MAC` in `.env` — deliberately no defaults, because
"start ARP-spoofing a real LAN" must be a human decision.

## Architecture in one screen

Two Docker containers by default (`proxy`, `dashboard`) plus `adguard`;
three more (`arp-worker`, `nftables-manager`, `controller`) behind the
`interception` compose profile. **All six run `network_mode: host`**
(Linux-only; see `docker-compose.yml` comments and `docs/deployment/setup.md`).

```
common/     Shared Python, imported by BOTH containers. NOT a package —
            each Dockerfile flat-copies common/*.py into the image root and
            adds it to sys.path. A change to any common/*.py file requires
            rebuilding BOTH images. Bare imports (`import db`), never
            `from common import db`.
              db.py              SQLite schema (SCHEMA string) + get_conn()/init_db()
              matching.py        domain-suffix / path / LAN-CIDR matching
              device_identity.py resolve_device(conn, client_ip) + resolve_user_for_device(conn, device)
                                  — Squid's identity source (split 2026-08-31 so a
                                  group/device-only identity, with no `users` row at
                                  all, is never conflated with "no identity resolved")
              identity.py        record_binding() etc. — writes device_bindings rows
              squid_helper.py    the shared stdin/stdout external_acl_type protocol loop
              logging_util.py    deduped access-log writer
              auth.py            PBKDF2 password hashing (stdlib-only, so the proxy needs no pip)
              cr_api.py / cr_urls.py / series_resolve.py   Crunchyroll CMS resolution + cache
              adguard_client.py  HTTP client for AdGuard Home's admin API
              policy_class.py    classify_device()/bump_eligible() — the interception policy model
              system_events.py   admin-visible failure/recovery log (Events page, written by controller/)
              schedule_eval.py / blocklist_parser.py / category_fetch.py   Phase 8 (categories/schedules)

proxy/      The Squid container. squid-openssl (NOT plain squid — Debian's
            is GnuTLS-built and cannot SSL-Bump at all). Native intercept
            mode since 2026-08-30: http_port 3129 intercept / https_port
            3130 intercept ssl-bump. No device configures a proxy setting;
            traffic is NAT-redirected here.
              sni_helper.py     external_acl_type for the ssl_bump step2 decision
              authz_helper.py   external_acl_type for the decrypted HTTP-layer decision
              squid.conf.template / entrypoint.sh

dashboard/  Single-file Flask app (~6500 lines, inline Jinja2), served by
            waitress on :8787. The ONLY place an admin edits config.

defaults/seed_defaults.py   idempotent first-run seed data
adguard/                    thin wrapper on adguard/adguardhome, auto-bootstrapped
controller/                 Phase 3 control loop (interception profile only)
phase3/arp-worker/          Go — privileged ARP poisoning + corrective restore
phase3/nftables-manager/    Go — reconciles kernel nftables against a DB-computed policy
```

**The one datastore is one SQLite file** (`/config/parental_proxy.db`, WAL
mode) on the shared `pp_config` Docker volume. Both containers open it
directly; they coordinate purely through files on that volume, no other
IPC. There is **no caching layer** — every `external_acl_type` line is
declared `ttl=0 negative_ttl=0`, so Squid re-queries SQLite on every new
connection. That is what makes "every dashboard edit takes effect instantly,
no reconfigure/restart" true.

**Request flow (abridged):** intercepted TLS → Squid peeks SNI →
`sni_helper.py` decides bump / splice / trusted / block-page, resolving the
client's identity from its source IP via `device_identity.resolve_device`
(`device_bindings` → the `devices` row itself, regardless of whether it has
a `user_id`) — this replaced per-request Basic-Auth on 2026-08-30. Domain
access is then checked via `matching.device_domain_reason()` (added
2026-08-31), which authorizes via `is_global`, the device's user, its
group, or the device itself directly — whichever grants it first. If the
domain is `bump` mode, the decrypted HTTP request is re-checked by
`authz_helper.py`, which for Crunchyroll resolves the requested show
(`cr_urls` → `series_resolve` → `cr_api`, cached in `series_cache`) against
the user's approved list — a group/device-only identity with no resolvable
user gets `reason="show_requires_user"` here, since `user_shows` has no
group/device equivalent. Every decision is logged
with a `reason` string — those strings are what the Report page shows and
what makes an entry "Approve"-able. Full version: `docs/architecture/overview.md` §6.

**Three domain modes** (`domains.mode`): `splice` (default; SNI-only, never
decrypted, domain-level allow/deny only), `bump` (fully decrypted, path- and
show-level rules), `trusted` (always spliced, never checked, never logged —
for CDN bulk traffic where the real decision already happened upstream).

## Traps that have already bitten someone

These are the ones most likely to waste your time; the full list is
`docs/architecture/overview.md` §9.

- **`squid-openssl`, never plain `squid`.** Debian's default package is
  built `--with-gnutls` and `squid -k parse` fails on `ssl-bump`. Silent
  trap when editing `proxy/Dockerfile`.
- **Every `external_acl_type` FORMAT line must declare `%DATA`** even though
  every handler ignores it — Squid always appends it, so omitting it makes
  every helper's field count off by one and every request silently falls
  through to terminate-all. This is why every handler signature ends with an
  unused `_data: str = "-"`.
- **`http_access allow CONNECT step2` must keep the `CONNECT`.** Squid's
  `at_step` does not reset after a bump, so a bare `http_access allow step2`
  grants the first decrypted request unconditional access, bypassing all
  per-domain/path/show enforcement.
- **Domain patterns are anchored regexes, not substrings**
  (`matching._domain_regex()`: `(?:^|\.)(?:PATTERN)\Z`). Without the anchor
  `evil-jsdelivr.net` matches a `jsdelivr\.net` rule. This was a real bypass.
- **`series_resolve.py` must not delete an expired positive cache row before
  the live re-resolve** — the `allow_stale=True` fallback needs it to still
  be there if the resolver call fails.
- **Everything is fail-closed by convention** — malformed helper input →
  `ERR`, `cr_urls.classify()` → `BLOCKED_SHAPE` for anything guarded-looking
  it doesn't recognize, `resolve_series_ids()` → `None` (hard deny) for an
  id with no usable cache history. Keep it that way.
- **Config/protocol regressions go in `tests/test_squid_conf_regressions.py`**,
  which checks the *text* of `squid.conf.template` — not in a logic test.
- **When reverting a deliberate mutation-test breakage, use a targeted
  string-replace back, never `git checkout`/`git stash`** — those blow away
  unrelated uncommitted work. See `docs/testing/overview.md` "Mutation-testing
  verification approach".
- **`docker compose up -d --build dashboard` can restart `proxy` too**,
  not just dashboard, even though `proxy` wasn't named. `dashboard`
  declares `depends_on: [proxy]`, and any edit to `common/*.py` changes
  BOTH images' content (both Dockerfiles `COPY` it in) — Compose then
  recreates the now-stale `proxy` container to satisfy that dependency,
  a brief live Squid restart nobody asked for by name. Harmless when
  interception is off (confirmed live 2026-09-07), but call it out to
  whoever's watching before running a `common/`-touching dashboard
  rebuild against production.

## Working conventions

- **Security is built in from the start, not retrofitted.** Flag security
  tradeoffs proactively. `docs/security/overview.md` tracks the known,
  accepted gaps (e.g. both login surfaces DO have rate-limiting since
  2026-09-02, but it's in-memory/per-process — resets on a restart, an
  accepted tradeoff for the LAN-only model, not an oversight) — check it
  before doing anything internet-facing.
- **Keep docs current in the same change.** `README.md` describes today,
  `RoadMap.md` tracks the plan (append, don't snapshot), `docs/` is the
  reference. A behavior change that lands without a matching doc update is
  incomplete.
- Test names are long descriptive sentences, often naming the GH issue or
  `docs/review-2026-08-28.md` item they regress-test. No test classes.
- `.claude/` is gitignored and stays that way.
- **Mock up a UI-shape decision before building it.** For a genuine
  layout/navigation-shape choice (not a small tweak), build 1-2 quick
  HTML mockups (the `visualize` tool, or any throwaway static page) and
  get it approved before touching real template code — this is how the
  sidebar nav shell got picked over a top-bar alternative. Cheaper to
  redo a mockup than a real implementation.
- **Write a multi-line commit message to a scratchpad file first**, then
  commit with `git commit -F <file>`, rather than passing it inline —
  avoids shell backtick/quote interpolation silently corrupting the
  message.
