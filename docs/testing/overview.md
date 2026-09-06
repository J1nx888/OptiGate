# Test suite overview

This covers the **Tier-1 (no-Docker) test suite** in `tests/` — the pure-Python
unit/integration tests for everything in `common/`, `proxy/`, `defaults/`, and
`dashboard/` that doesn't require a running Squid instance or a real
container. "Tier-1" / "Phase 1" terminology comes from `docs/review-2026-08-28.md`.
Phase 2/3 (real Squid, real Docker networking, a real device) are **not**
covered by this suite and must still be exercised manually against a real
deployment — see the "What this does not cover" section of `tests/README.md`.

## Running the tests

From the **repo root** (`C:\Users\jonat\ClaudCode\parental_proxy`, or wherever
this repo is checked out):

```
pip install -r requirements-dev.txt
pip install -r dashboard/requirements.txt
pytest
```

- `requirements-dev.txt` installs `pytest>=8.0` — the only dev-only dependency.
  It is deliberately not part of either container image; see the comment at
  the top of the file.
- `dashboard/requirements.txt` is also required because `tests/test_dashboard.py`
  imports `dashboard.py` directly (Flask, etc.).
- `pytest.ini` (repo root) sets `testpaths = tests` and `python_files = test_*.py`,
  so plain `pytest` from the repo root is sufficient — no path argument needed.
- No environment variables need to be set by hand. `tests/conftest.py` sets a
  safe default for `PP_DB_PATH` itself (see below) before anything else can
  import `db`.
- Parallel runs work: every test that touches the DB gets its own throwaway
  SQLite file via pytest's `tmp_path`, so `pytest -n auto` works if
  `pytest-xdist` is installed (not in `requirements-dev.txt` by default).
- To run a single file or test: `pytest tests/test_logging_dedupe.py` or
  `pytest tests/test_logging_dedupe.py::test_window_expiry_allows_a_new_row`.
- Verbose CI-style run: `pytest -v` (this is exactly what
  `.github/workflows/tests.yml` runs).

### No PYTHONPATH setup needed — and why

The four source directories (`common/`, `proxy/`, `dashboard/`, `defaults/`)
are **not** installable packages — there is no `setup.py`/`pyproject.toml`
package layer, and modules do bare imports like `import db` or `import cr_api`,
never `from common import db`. This mirrors how the Dockerfiles actually
deploy the code: `common/*.py`, the proxy helpers, and
`defaults/seed_defaults.py` are all copied flat into `/opt/parental-proxy/` in
the proxy image, and `common/*.py` + `dashboard.py` are copied flat into
`/app/` in the dashboard image. To exercise the real, unmodified code, the
test suite has to reproduce that same flat layout on `sys.path`.

`tests/conftest.py` does this in code, at collection time, rather than
requiring the developer to export a `PYTHONPATH` env var:

```python
REPO_ROOT = Path(__file__).resolve().parent.parent
for sub in ("common", "proxy", "dashboard", "defaults"):
    p = str(REPO_ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)
```

This is a deliberate choice, called out in the conftest's own module
docstring, precisely to avoid a `PYTHONPATH`/src-layout trick. That matters on
this project because development happens on **Windows**: `PYTHONPATH` (and
`PATH`-like variables generally) uses `;` as the entry separator in
`cmd.exe`/PowerShell, but `:` in Git Bash and other POSIX shells. A
`PYTHONPATH=common;proxy;dashboard;defaults` that works from PowerShell breaks
silently (or errors) from Git Bash and vice versa. Since `conftest.py` builds
`sys.path` itself in Python, **no one ever needs to set `PYTHONPATH` by hand
to run this suite**, on any shell — this sidesteps the separator gotcha
entirely rather than documenting a workaround for it. If you ever do need to
run one of the flat modules standalone (outside pytest) and must fall back to
`PYTHONPATH`, remember: `;` on Windows cmd/PowerShell, `:` on Git Bash/WSL/Linux/macOS.

`conftest.py` also sets a default `PP_DB_PATH` env var (via `os.environ.setdefault`,
pointed at a throwaway file under the OS temp dir) before `pytest` is imported,
because `db.py` reads `PP_DB_PATH` once at its own import time into a
module-level `Path`. This is just a safe fallback for whichever import happens
first in the session — individual tests still isolate themselves via the
`conn` fixture (below), which monkeypatches `db.DB_PATH` directly.

## Key fixtures (`tests/conftest.py`)

### `block_network` (autouse)

```python
@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    import cr_api
    def _blocked(*args, **kwargs):
        raise RuntimeError(...)
    monkeypatch.setattr(cr_api._OPENER, "open", _blocked)
```

Applies to **every** test automatically (no need to request it). The only
network entry point anywhere in this codebase is `cr_api._OPENER.open` —
everything else goes through the shared SQLite file — so that's exactly what
gets patched to raise `RuntimeError` if hit.

Deliberately **not** implemented by patching `socket.socket` globally: doing
that breaks `ssl.py`'s `class SSLSocket(socket):` the first time anything in
the process imports `ssl`, raising a confusing `TypeError` far from the real
problem instead of a clean, on-purpose failure. Patching `cr_api._OPENER.open`
directly gives a precise, readable failure (`"Network access attempted during
a Tier-1 test. Mock the call instead..."`) pointing at exactly what to mock.

Any test that needs to exercise `cr_api` must mock at `cr_api._OPENER.open`
(or the higher-level `cr_api.SeriesResolver._get_json` / `cr_api.series_title`)
explicitly — see `tests/test_cr_api.py` for the patterns.

### `conn`

```python
@pytest.fixture
def conn(monkeypatch, tmp_path):
    import db
    db_file = tmp_path / "test.db"
    monkeypatch.setattr(db, "DB_PATH", db_file)
    connection = db.get_conn()
    db.init_db(connection)
    yield connection
    connection.close()
```

Gives each test a fresh, isolated SQLite connection with the schema already
applied and no data. Works by monkeypatching the `db.DB_PATH` module
attribute directly (not an env var) — `db.get_conn()` reads that attribute on
every call, so this is sufficient for full per-test isolation even though
`db.py` itself is only ever imported once per test session. Backed by
pytest's `tmp_path`, so every test gets its own throwaway file and tests can
run in any order or in parallel.

Used throughout `tests/test_logging_dedupe.py`, `tests/test_seed_idempotent.py`,
`tests/test_helpers_protocol.py`, and others that need real DB rows.
`tests/test_dashboard.py` does its own DB isolation on top of this pattern
(see below) because it also needs to reload the Flask app module.

## Test files and what they cover

| File | Test count | Covers |
|---|---|---|
| `tests/test_matching.py` | 22 | Domain-suffix anchoring (incl. the S2.1 bypass cases), path matching, LAN CIDR checks (IPv4/IPv6, bad input) |
| `tests/test_cr_urls.py` | 14 | Every `RequestKind`, including the fail-closed `BLOCKED_SHAPE` cases |
| `tests/test_auth.py` | 12 | PBKDF2 hash round-trip, and every way a stored hash can be malformed/tampered |
| `tests/test_logging_dedupe.py` | 9 | Access-log dedupe window, keyed by `(username, domain, allowed, series_id)` (and path — see GH #5 tests) |
| `tests/test_seed_idempotent.py` | 8 | `seed_defaults.seed()` run twice is a no-op; the S2.2 (`crunchyrollcdn.com` mode) fix; confirms `crunchyrollsvc.com` (dev-only, removed) is never seeded |
| `tests/test_helpers_protocol.py` | 33 | The shared Squid stdin/stdout protocol (`common/squid_helper.py`) plus the decision logic of both helpers (`sni_helper`, `authz_helper`), including the Crunchyroll show-approval flow. Identity is set up via real `device_bindings` rows (`common/identity.record_binding()`) since 2026-08-30, not a login string -- see `common/device_identity.py`. |
| `tests/test_dashboard.py` | 61 | Flask test client: admin auth, user/domain CRUD (incl. `add_show`/`remove_show`, `user_detail`, `domain_detail`, `update_domain`), all of Settings (incl. changing the admin login itself), report-approve (site and show), CSRF/cross-origin guard |
| `tests/test_cr_api.py` | 28 | `TokenManager` refresh/expiry, `SeriesResolver`'s retry-once-on-401, every `_read_json` error path (HTTP error, unreachable, timeout, malformed/non-dict JSON), every `series_id_of` fallback branch |
| `tests/test_series_resolve.py` | 11 | The object-id -> series-id cache: positive/negative TTL, cache-hit short-circuiting, the S2.6 stale-on-error fallback |
| `tests/test_squid_conf_regressions.py` | 7 | Config-text/structure regressions in `proxy/squid.conf.template` that a pure-logic unit test can't catch (see below), plus two 2026-08-30 regression guards keeping the deliberately-deferred `ssl_bump`/`http_access` catch-all flip (see `docs/security/overview.md` §3, RoadMap.md) from being silently re-flipped |

The counts above are per-file spot checks for the files this doc discusses in
detail, not a full table refresh -- this table predates several later
additions to `tests/` (Phase 3's `phase3/arp-worker`/`phase3/nftables-manager`
Go test suites aren't Python and aren't counted here at all; the Python
`tests/` directory itself has also grown past this table's original per-file
counts, most recently `tests/test_adguard_client.py` and
`tests/test_controller_adguard_sync.py`, added 2026-08-30 for
`common/adguard_client.py`'s HTTP client and `controller/adguard_sync.py`'s
rule-building/merge/run_loop logic (same mocked-network pattern as
`tests/test_cr_api.py` and `tests/test_controller_discovery.py`
respectively), plus more cases added to both `test_adguard_client.py` and
`tests/test_dashboard.py` the same day for the filter-update-checking
feature (`set_filters_update_interval()`/`refresh_filters()`, and the
dashboard's new `/settings/adguard`/`/settings/adguard/refresh` routes),
and later the same day again `tests/test_controller_rtnetlink_listener.py`
(new file, pure filtering logic plus threading/retry wiring against a
faked `pyroute2`), `tests/test_block_page_server.py` (new file, real
HTTP behavior of `dashboard/block_page_server.py`), and
`tests/test_controller_block_page_ip.py` (new file, `main.py`'s
`_parse_block_page_ip`). Still the same day, `tests/test_dashboard.py`
gained a "HEALTH" section (7 tests) for the new `/health` route and
its sidebar alarm badge, including a regression test for a real bug a
`/code-review max` pass caught in one of those tests itself -- an
earlier version hardcoded an absolute timestamp that silently aged past
the staleness threshold and started testing the wrong render branch,
fixed to use a relative one (see RoadMap.md) -- and gained
`_insert_runtime_row()`, matching the file's existing
`_insert_recent_denial`/`_insert_logged`/`_insert_device_with_last_seen`
small-factory-helper convention; `tests/test_adguard_client.py` gained
cases for `get_custom_rules()`'s handling of a `null` `user_rules` key
(the confirmed-live AdGuard quirk) versus a genuinely missing key or
non-dict response (which must still raise, not be silently swallowed --
also a same-day code-review catch). Separately,
`phase3/nftables-manager/internal/dbsource/sqlite_test.go` gained two
`WriteHealth` regression tests, written 2026-08-30 without a Go
toolchain in this dev sandbox and **verified for real 2026-08-31** on
the smoke-test VM (`go build`/`go vet`/`go test` clean, plus a
`-count=10` flake check) -- see RoadMap.md's dated VM-verification
writeup.

**2026-08-31, Milestone 6/4 gap-closing session**: `tests/test_controller_readiness.py`
(new file) covers `controller/readiness.py`'s two startup gates --
`wait_for_worker` against a real listening `AF_UNIX` socket (matching
`test_controller_run_integration.py`'s own reasoning for why a
socketpair won't do), `wait_for_adguard` against a faked
`adguard_client`. Worth its own callout: every test needing fake timing
passes `sleep=`/`now=` **explicitly** to the function under test rather
than monkeypatching `readiness.time.sleep`/`readiness.time.monotonic`
-- an earlier version of this file did the latter and it silently
didn't work, because `wait_for_worker`/`wait_for_adguard`'s own
`sleep=time.sleep, now=time.monotonic` default arguments bind the real
function objects at module-IMPORT time, before any monkeypatch can run.
Three tests were quietly sleeping on real wall-clock time instead
(masked because their assertions only checked eventual outcome, not
speed) and a fourth genuinely failed once real `AF_UNIX` sockets made
it collectable on Linux -- caught during the very VM verification pass
that also confirmed the `WriteHealth` fix above, a good example of why
a test written and only ever run on a platform that skips it isn't
proven correct. `tests/test_controller_adguard_discovery.py` (new file)
and additions to `tests/test_adguard_client.py`
(`normalize_query_log_time`, `get_query_log`) and
`tests/test_identity_bindings.py` (`touch_binding_by_ip`) cover the new
AdGuard query-log discovery source, all fully verified live against the
VM's real running AdGuard instance too (real DNS queries, real
`/control/querylog` response shapes), not just against mocks.

**Same night, follow-up**: closing the ARP send-failure visibility gap
(see docs/architecture/overview.md) added `phase3/arp-worker/internal/worker/worker_test.go`
cases for the new consecutive-send-failure counter (increments on
failure, resets on success), `tests/test_controller_ipc_client.py`
cases for parsing the new `heartbeat_ack` field (present, and absent
for backward compatibility with an older worker binary),
`tests/test_controller_run_cycle.py` cases for the new `fail_open`-at-
threshold decision, one new `tests/test_controller_run_integration.py`
case driving the same behavior through the real heartbeat-pacer thread
rather than injecting the value directly, and
`tests/test_controller_health.py` cases for `report_fail_open()`'s new
optional `applied_generation` parameter -- added after that
integration test, run for real on Linux, caught a genuine bug: a bare
`report_fail_open()` on a brand-new row let `applied_generation`
silently default to 0 instead of preserving the cycle's real, true
value. All of it verified live end-to-end too: a real veth-harness
NIC-down test showed `/health` flip to `fail_open` with a live-
incrementing reason within 2 seconds of the interface going down, and
correctly recover once it came back.

**Same night, second follow-up**: implementing active ARP scanning
(the discovery precedence list's last source -- see
docs/architecture/overview.md) added `tests/test_controller_active_scan.py`
-- 12 fully-mocked tests (a `_FakeSocket` stands in for `socket.socket`,
so nothing here touches a real network) covering staleness/rate-limit
selection (`select_stale_bindings`), the nudge itself (`nudge` sends
exactly one UDP datagram and always closes the socket, even on a
synchronous `OSError`), that `scan_once()` never writes
`device_bindings` itself (that's deliberately left to
`controller/discovery.py`'s own snapshot loop -- see `active_scan.py`'s
module docstring), and the usual `run_loop` wiring
(repeats/stops-promptly/reports-errors-without-dying) shared with every
other `*_discovery.py` module in this codebase. The UDP-nudge
*mechanism* itself (does `sendto()` to a closed port really trigger
kernel ARP resolution?) was verified live against a real kernel on the
smoke-test VM separately, before any of this code was written -- not
re-verified by these mocked tests, which only exercise this module's
own logic.

**Same night, third follow-up**: scoping Phase 4's first real milestone
(gating a genuinely new device by default -- see
docs/architecture/overview.md's "Auto-gating new devices" entry) found
that `common/identity.py`'s `record_binding()` needed to auto-create a
pending `devices` row for a MAC never seen before, rather than leaving
it a dangling `device_id = NULL` binding invisible to
`controller/desired_state.py`'s own `JOIN`. This is a real behavior
change to a function nearly every other test file in this suite already
calls, so most existing tests needed no changes at all (they already
pre-create a `devices` row via their own `_add_device` helper before
calling `record_binding`, so the new auto-create path never triggers for
them) -- only `tests/test_identity_bindings.py`'s own tests that
deliberately exercised the "brand-new, unassociated MAC" case needed
updating to expect a real `device_id` and a `device_auto_created` event
instead of `None`/`binding_pending_association`. Two new tests there
cover the one-time-only condition (a MAC's second-ever binding reuses
the same auto-created device, never creates a second one) and the
explicit "no retroactive backfill" product decision (an
already-known-but-unassociated MAC from before this shipped, simulated
by inserting a `device_id = NULL` row directly, stays unassociated even
across a later DHCP renewal). Two more new tests, in
`tests/test_controller_desired_state.py` and
`tests/test_controller_policy_state.py`, are the actual end-to-end proof
of the fix: calling `record_binding()` alone, with no `devices` row
pre-created at all, now produces a real poisoning target that lands in
nftables' `unauthenticated_v4` set -- which is exactly the "invisible to
interception entirely" gap this change closes.

**Same night, fourth follow-up**: Phase 4 milestone 2 (dashboard
visibility for the pending devices milestone 1 created -- see
docs/dashboard/routes.md's `/devices`/`/devices/bypass_login` entries)
added 7 new tests to `tests/test_dashboard.py`, following that file's
own established convention of exercising the real Flask routes against
a real (temp-file) SQLite DB rather than mocking anything: a pending
device (a raw `INSERT` with `is_authenticated = 0`, mirroring what
`record_binding()` would produce) appears in the highlighted card with
a working **Bypass** action; an `ignored`/`bypass_login` device is
correctly NOT treated as pending despite also having
`is_authenticated = 0`; pending devices sort ahead of already-
authenticated ones; and the new `bypass_login_device()` route only ever
touches the one column it's supposed to (verified by setting a label
first, then confirming it survives the bypass call intact) and requires
admin auth like every other `/devices/*` route. Visually verified too,
against this repo's own pre-existing `dashboard/dev_server.py` local
launcher (not a new tool) rendered in a real browser: the pending card,
the Status column's badges, and the Bypass action's full round trip
(disappears from the pending list, `bypass_login` flips to `yes`) all
confirmed exactly as designed.

**Same night, fifth follow-up**: Phase 4 milestone 3 (the captive-portal
login server, `dashboard/captive_portal_server.py` -- see
docs/architecture/overview.md) added two new test files.
`tests/test_captive_portal_server.py` follows
`tests/test_block_page_server.py`'s own established pattern exactly --
a real integration test binding an ephemeral port and making real HTTP
requests, since a stdlib `http.server` handler has no pure logic worth
mocking in isolation -- covering: every GET/HEAD gets the identical
login page regardless of path or Host header (the design's own core
claim: nftables redirects by source IP and destination port, not
hostname, so this alone must be what triggers every major OS's
captive-portal-detected UI); a successful POST login flips
`is_authenticated` for whichever device the request's real source IP
(`127.0.0.1`, since these are genuine loopback HTTP requests) resolves
to, never `bump_enabled`, and never overwrites an existing `user_id`
assignment; a wrong password, an unknown username, and a request from
an IP with no active binding all fail closed with an honest message
rather than a crash; and the per-source-IP rate limiter (5 failed
attempts/60s, built alongside the login form rather than retrofitted --
see docs/security/overview.md §6) blocks the next attempt outright,
including one with the actually-correct password, and resets on a
genuine success. `tests/test_device_identity.py` is a new file for a
previously-untested module (`resolve_user`, since replaced -- see below --
only ever had incidental coverage via `tests/test_helpers_protocol.py`) --
covers `resolve_device()` directly plus (as of 2026-08-31)
`resolve_user_for_device()`, including the group-assigned-device case that
motivated splitting it out of the original `resolve_user()`. Also visually
and interactively verified in a live
browser against `dashboard/dev_server.py`: the login page render,
completing a real login through the actual rendered form (not just
`fetch()`), and confirming `is_authenticated` flipped in the real
on-disk dev DB afterward.

**2026-08-31, "tighter Squid/AdGuard integration" pass (GH #9)**: 19 new
tests across five files, for the group/device authorization bug fix and
the AdGuard splice-tier enforcement gap it was found alongside (see
`docs/security/overview.md` §3.5 for the full writeup). `tests/test_helpers_protocol.py`
gained `_bind_ip_to_group()`/`_bind_ip_to_bare_device()` helpers and
regression tests proving a group-assigned device now gets real
`sni_helper`/`authz_helper` access via `group_domains`/`device_domains`
(the core bug), plus a `show_requires_user` case for a crunchyroll-kind
domain authorized via group/device with no resolvable user.
`tests/test_controller_adguard_sync.py` gained `build_splice_deny_rules()`
coverage (denies an unassigned device, excludes a user- or group-assigned
one, ignores global/bump domains) and a `sync_once()` test confirming both
rule sets get pushed together. `tests/test_block_page_server.py` gained
coverage for the new `access_log` write this module didn't do before
(a real row for a known device, a placeholder row for an unknown IP, and
a check that the page itself still renders even if the DB write fails --
that failure mode is deliberately swallowed, not surfaced, per this
module's own reasoning that a kid staring at a broken page is worse than
a silently-skipped log line). `tests/test_dashboard.py` gained Report-page
filter-by-device/group-target tests, a legacy-`?user=`-still-works
regression guard, and `approve_from_report()` `scope=device`/`scope=group`
tests (including the "device not in a group" error case). Verified live
in a browser against seeded dev data too, not just the test suite --
filtered the Report page to one device via the new combobox, approved a
device-only row, and confirmed the resulting `domains`/`device_domains`
rows directly in the dev DB.

**Same day, before committing any of the above**: the project owner
reviewed and corrected the design further -- AdGuard now also checks
per-domain assignment for bump-eligible devices, not just bump-eligibility
alone (see `docs/security/overview.md`'s "Rework, same day" subsection).
10 more tests: 5 in `tests/test_controller_adguard_sync.py`
(`_insert_device_with_binding()` gained an `ignored` param) -- a
bump-eligible device denied an unassigned non-global bump domain, then
allowed once assigned via `device_domains`; a non-bump-eligible device
still denied on a *global* bump domain (confirms the rework doesn't
weaken the original hard-deny); an `ignored` device excluded from both
`build_rules()` and `build_splice_deny_rules()` even when it would
otherwise clearly be denied. All 26 pre-existing tests in that file kept
passing completely unchanged through this rework, without modification --
worth noting explicitly, since every one of them uses an `is_global=True`
bump domain, under which the new assignment check trivially authorizes
everyone, leaving `bump_eligible()` as the only thing that ever
differentiated allow/deny in those fixtures, exactly as before. The other
5 new tests, in `tests/test_dashboard.py`, cover the bypass_login-defaults-
to-ignored UI behavior (project owner: "anything that gets the
bypass_login should be added to ignore by default but give me the ability
to change that later") for both `bypass_login_device()` (the quick-action
route) and `update_device()` (the full edit form) -- the plain default, a
device that already has an assignment keeping it, an explicit same-submit
assignment overriding the default, and a later resave not re-forcing
`ignored` back on. 552 tests total after this pass.

**2026-08-31/09-01, Phase 8 (content categories + time-based schedules)**:
87 new tests across nine files, none touching existing coverage. Three
new files for pure logic: `tests/test_schedule_eval.py` (15 tests --
same-day windows, the overnight-wraparound bedtime case in both legs,
naive-datetime-as-UTC, a real timezone-shifts-which-calendar-day-it-is
case for Australia/Sydney, a US DST spring-forward transition day, plus
`is_full_lockout_active()`'s DB-touching wrapper), `tests/test_blocklist_parser.py`
(12 tests -- one per real format confirmed live against
[The Block List Project](https://github.com/blocklistproject/Lists):
AdGuard/adblock, hosts-file including IPv6 null-routes and multiple
aliases per line, bare domain-per-line, plus comments/dedup/malformed-line
skipping), and `tests/test_category_fetch.py` (6 tests, `_OPENER.open`
faked same as `test_adguard_client.py`'s own pattern -- a re-sync
replacing only `source='subscription'` rows is the one worth calling
out, since a bug there would have silently discarded an admin's manual
additions on every scheduled refresh). `tests/test_matching.py` gained
7 tests for `category_applies_to_device()`/`schedule_applies_to_device()`
(is_global, and each of user/group/device targeting, plus a check that
an unrelated user's grant doesn't leak). `tests/test_adguard_client.py`
gained 5 tests for the three new native-filter-subscription functions
(**not yet live-verified** -- see `docs/security/overview.md` §8).
`tests/test_controller_adguard_sync.py` gained 11 tests: 7 for
`build_category_deny_rules()` (global category → unscoped rule, a
user-scoped category denies only that user's devices, an override
excludes its domain, an ignored device is excluded even from a global
category, a category over the scoping threshold contributes nothing,
a schedule-gated category is only active inside its window, zero
applicable devices contributes nothing) and 4 for
`sync_category_subscriptions()` against a small `_FakeAdGuardClient`
that records calls instead of touching the network (skips at-or-under-
threshold categories entirely, adds a new global category pre-enabled,
enables/disables strictly on whether a gating schedule is currently
active, and never removes an existing filter -- only ever toggles
`enabled`). `tests/test_controller_policy_state.py` gained 6 tests for
`compute_desired_policy()`'s new schedule-driven QUARANTINE overlay,
each with an injected fixed `now` (same convention `test_controller_readiness.py`
established for fake timing): a device under an active global lockout
schedule lands in `quarantine`; the same device outside the window is
unaffected; an `ignored` device stays in `bypass` even during an active
lockout schedule (baseline protection doesn't apply lockout to a device
that's supposed to be outside the whole system); a manually-
`quarantined_at` device is unaffected by schedule state in either
direction (the two-independent-axes proof); a non-`lockout_all` schedule
never triggers the overlay; and the real-current-time default path
doesn't raise. `tests/test_dashboard.py` gained 25 tests for the new
`/categories`/`/schedules`/`/settings/household-time-zone` routes,
including the one that actually matters most for this feature's whole
premise: `update_category_access()` rejects scoping an over-threshold
category to a specific user (error flash, no `category_users` row
written) while still allowing "Block for Everyone" on that same
oversized category. 639 tests total after this pass (552 + 87), still
30 skipped (the same pre-existing Windows-platform gaps --
`AF_UNIX`/`iproute2` -- unrelated to this feature, confirmed by diffing
skip reasons before/after).

**Same session, follow-up**: seeding 10 default categories
(`defaults/seed_defaults.py`'s `DEFAULT_CATEGORIES` -- see
`docs/database/schema.md`'s Seed data section) added 2 more tests to
`tests/test_seed_idempotent.py` (all 10 seeded with `is_global=0` and no
`category_domains` yet; a re-seed never overwrites an admin's own
`is_global` edit). 641 tests total. Also verified for real, outside the
test suite entirely: ran `category_fetch.fetch_and_sync_category()`
against the real, live, seeded WhatsApp URL with no mocks at all --
fetched 226 real domains, correctly `re.escape()`d and stored, `categories.last_synced_at` set -- the first genuine
non-mocked proof that the whole fetch → parse → store pipeline works
against real third-party data, not just the format samples the unit
tests use.

Also verified live against the seeded dashboard (scratch dev server,
real seeded SQLite DB), not just the test suite: added a category, added
a manual domain and an allow-override to it, set "Block for Everyone",
confirmed all three directly in the DB; added a `lockout_all` bedtime
schedule and confirmed its detail page correctly omits the categories
card entirely (not just disables it); zero server-side errors and zero
new browser-console errors throughout (the one console error present is
the same pre-existing, unrelated service-worker message already on the
long-shipped Domains page). **Not yet live-verified, needs the VM**:
AdGuard Home actually applying a category custom rule or a native filter
subscription against real DNS queries, and a real device losing
connectivity via `quarantine_v4` during a simulated bedtime window.

**2026-09-01, follow-up**: seeded the previously-empty "AI" category with a
1,195-domain manual snapshot from Microsoft Purview's own published
AI-sites list (see `docs/database/schema.md`'s Seed data section and
`defaults/ai_sites_seed.py`'s own docstring for full provenance). 6 new
tests added to `tests/test_seed_idempotent.py`: exact domain count seeded
with `source='manual'`; a handful of well-known AI domains
(`chatgpt.com`, `claude.ai`, `anthropic.com`, `character.ai`,
`midjourney.co`) present and correctly `re.escape()`d; the split between
"AI has domains immediately" vs. "every subscription-backed category has
zero `category_domains` rows until its first sync" made explicit as two
separate tests (replacing one test that asserted the old, now-incorrect
"no category has domains yet" blanket claim); and a reseed neither
duplicates nor clobbers a domain an admin adds to the category by hand.
644 tests total, all passing, no regressions. Also evaluated (not
integrated) a second candidate the project owner asked about, Stevo's AI
Blocklist -- fetched its real raw file live and confirmed it's built for
browser extensions (~82% CSS cosmetic/element-hiding rules, plus a few
path-scoped resource blocks), not DNS-tier whole-domain blocking; no test
coverage needed since nothing from it was wired in.

**2026-09-01, smoke-test VM catch-up**: no new tests this pass -- pure
live verification of the three items Phase 8 had shipped without,
against the real smoke-test VM (see RoadMap.md's dated entry for full
commands/output). Full suite re-confirmed clean on Linux both before and
after: 671 passed/0 skipped on the pre-fix commit, 674 passed/0 skipped
after landing the apt-HTTPS/CA-bundle Dockerfile fixes and the AI-seeding
commit (matches Windows' 644 passed + 30 skipped = 674 collected).
Verified for real, not unit-tested: `common/adguard_client.py`'s four
native-filter functions against a live AdGuard Home instance (all four
request/response shapes confirmed correct, no surprises);
`sync_category_subscriptions()` end-to-end against a scratch
5,001-domain category (add+enable, then disable); a scoped `$client=`
category rule differentiating two real Docker-container "devices" via
real `dig` queries; and the schedule-driven QUARANTINE overlay producing
genuine packet loss (`ping` 0/3 received, matching the real
`ip saddr @quarantine_v4 counter drop` rule's counter) and genuine
recovery once the schedule window closed. All test devices/bindings/
schedules/categories cleaned up afterward; a stray discovery-loop
binding conflict hit mid-test (see RoadMap.md) was resolved without
needing any code change.

**2026-09-01, G3 (SafeSearch/Restricted Mode)**: 11 new tests. 3 in
`tests/test_adguard_client.py` for `get_safesearch_status()`/
`set_safesearch_settings()` (shape confirmed live before writing these,
see RoadMap.md's Phase 9 entry). 5 in `tests/test_controller_adguard_sync.py`
for `sync_safesearch()` via `_FakeAdGuardClient` (extended with
`get_safesearch_status`/`set_safesearch_settings`): enables when the
setting is on and AdGuard is currently off, disables the reverse way, a
no-op when already matching, defaults off when the setting was never
configured at all, and -- the one that matters most for this feature's
whole "don't clobber an admin's own AdGuard customization" premise --
confirms per-service booleans (`duckduckgo`/`pixabay` off in the fake)
survive a reconcile untouched, only `enabled` changes. 3 in
`tests/test_dashboard.py` for the new Settings card and
`POST /settings/safesearch` (checked → `"1"`, unchecked → `"0"`).
Also had to patch 4 pre-existing `sync_once()`/`run_loop()`-level tests
in `tests/test_controller_adguard_sync.py` that don't care about
SafeSearch at all -- wiring `sync_safesearch()` into `sync_once()` meant
they started hitting the fake client's (previously untouched)
`get_safesearch_status`, which none of them had mocked; added a plain
`{"enabled": False}` stub to each (matching the setting's own untouched
default) rather than changing what they actually test. 655 passed, 30
skipped (Windows) -- zero regressions. Live-verified the full chain the
same day on the smoke-test VM (see RoadMap.md's Phase 9 entry): a real
`curl POST` against the running dashboard's `/settings/safesearch`,
through a real controller poll cycle, to a real AdGuard state change,
confirmed via a real `dig` rewrite -- including an unplanned but genuine
proof of the reconcile-every-cycle design: AdGuard was left `enabled:
true` from an earlier manual test while the DB setting was still `"0"`,
and the controller's first cycle after redeploying corrected that drift
on its own, with nothing telling it to. 685 passed/0 skipped on Linux.

**2026-09-01, G6 (ad-hoc pause)**: 12 new tests in `tests/test_dashboard.py`
covering all three scopes -- per-device pause/resume sets/clears
`quarantined_at` (and requires admin auth), the Paused badge renders on
the Devices list, whole-house pause skips `ignored` devices while resume
clears every currently-quarantined one regardless of cause, per-kid
pause/resume is correctly scoped to `WHERE user_id = ?` and never
touches another user's device, the per-kid card only renders when that
user actually has a device, and an `ignored` device is offered no pause
button at all (pausing one would be a silent no-op). No new
controller/nftables tests needed -- G6 added zero enforcement-layer code
(see RoadMap.md's Phase 10 entry), so the existing Phase 3/Phase 8
coverage of `classify_device()` and the QUARANTINE overlay already
covers what happens once `quarantined_at` is set, regardless of which UI
path set it. 666 passed, 30 skipped (Windows), 696 passed/0 skipped on
Linux, zero regressions.
Live-verified the per-device path end to end on the smoke-test VM the
same day, reusing the exact container from Phase 8's own live-verification
pass: a real `curl POST /devices/pause` wrote `quarantined_at` for real,
the already-running controller moved that device's real IP into the
real kernel `quarantine_v4` set on its next cycle, and a real `ping`
dropped 3/3 packets -- then `POST /devices/resume` reversed all of it.
Whole-house/per-kid were verified at the SQL layer only (same
`_set_quarantine()` write against more rows, already proven by the unit
tests and by per-device's own real nftables round-trip).

**2026-09-01, bulk CSV device import (G7 follow-on)**: 9 new tests in
`tests/test_dashboard.py` -- valid rows with a header (auto-skipped),
headerless CSV, a duplicate MAC skipped without clobbering the existing
device's own label, a row with no valid MAC skipped without aborting
the rest of the batch, empty-file and no-file-selected error paths,
admin auth required, and an imported row lands exactly as
`add_device()`'s own plain-Unassigned shape (no user/group/ignored).
First file-upload test in this suite -- Flask's test client accepts a
`(BytesIO, filename)` tuple for a multipart field with no new fixtures
needed. 675 passed, 30 skipped (Windows), 705 passed/0 skipped on
Linux, zero regressions. Live-verified
against the real smoke-test VM the same day: a real `curl -F
csv_file=@...` multipart upload against the actual running dashboard
(valid row, valid row, invalid-MAC row, duplicate row) came back with
exactly the expected counts in the flash message, and the database
ended up with exactly the two real, non-duplicate devices.

**2026-09-01, same-day follow-up**: fixed a real usability gap the
project owner asked about directly -- the flash message only reported
an aggregate duplicate count, not which MACs. 2 new tests: the capped
preview (15 duplicates in one batch -> shows 10 + "and 5 more", not all
15) and a test that pins down a related, previously-undocumented edge
case found while fixing this -- a genuinely malformed FIRST row is
indistinguishable from a real header by the auto-detection heuristic and
gets silently dropped without being counted as invalid at all (unlike
the same bad content anywhere else in the file). Also had to reorder an
existing test (`test_import_devices_skips_rows_with_no_valid_mac`) once
asserting on the actual message content revealed it had been
accidentally exercising that same ambiguous first-row case rather than
the ordinary mid-batch one it was meant to test. 677 passed, 30 skipped
(Windows), zero regressions.

**2026-09-01, Events page (Phase 11)**: project owner asked whether the
admin portal has any way to see a problem before diving into G1's
real-network testing -- investigated the actual current state (Health's
single non-historical `fail_open_reason`, `network_events` with zero UI,
everything else stdout-only) rather than assuming, then built
`system_events`/the `/events` page. 16 new tests. `tests/test_system_events.py`:
`log_event()`'s shape and severity validation; `failure_recovery_callbacks()`
logs every failure occurrence (not just the first, so consecutive
timestamps show duration), logs a `recovery` row only on the actual
failure->success transition (an ordinary success with no prior failure
logs nothing at all -- the core "not a firehose" behavior), and two
different sources' tracked state stays independent.
`tests/test_controller_periodic.py`: `on_success` fires on every
non-raising cycle, never fires for a raising one, and a dedicated
regression test alternates failure/success and asserts every event
before the transition is `error` and every one after is `success` --
catching the exact class of bug (on_success firing for a failed cycle,
or vice versa) that would silently corrupt the recovery-tracking logic
this feature depends on. `tests/test_dashboard.py`: empty state, a real
event listed, `recovery` severity rendered distinctly from `error`,
newest-first ordering, admin auth required (matches every other page),
and the display cap (`EVENT_DISPLAY_LIMIT`) hides older rows from the
page without deleting them from the table. 692 passed, 30 skipped
(Windows), 722 passed/0 skipped on Linux, zero regressions.
Live-verified with a genuine failure on the smoke-test VM the same day
(see RoadMap.md's Phase 11 entry): `docker stop`ping the real `adguard`
container produced real, correctly-timestamped `error` rows on the real
`/events` page for two independent loops (`adguard_sync`,
`adguard_discovery`) hitting the same outage, and restarting it produced
independent `recovery` rows for both, confirming the per-source
failure-tracking closures stay correctly isolated against a real
concurrent failure, not just the sequential ones the unit tests exercise.

**2026-09-02, brute-force & SQL-injection audit**: project owner asked
for a dedicated security pass on authentication specifically, ahead of
a planned full code-review. SQL injection: audited every `.execute()`
call in the codebase (plus the Go side's `db.QueryRow`/`db.Exec`
calls) -- clean, no dynamic SQL text built from untrusted input
anywhere; see `docs/security/overview.md` §9 for the one pattern
(`_set_quarantine()`/`report()`'s `where_sql` f-string interpolation)
that needed a closer look before being cleared as safe. Brute-force:
found the dashboard's HTTP-Basic admin login had no rate limiting at
all (a gap this doc's own security section had already flagged),
unlike the captive portal's login form. 12 new tests in the new
`tests/test_rate_limit.py` (pure sliding-window logic against the new
shared `common/rate_limit.RateLimiter` -- becomes limited at exactly
`max_attempts`, not one before or after; `clear()` resets one key
without affecting another; failures outside the window correctly
expire; two separate instances never share state, proving
`dashboard.py` and `captive_portal_server.py`'s separate budgets
actually stay separate). 7 new tests in `tests/test_dashboard.py`:
5 wrong passwords then rate-limited (even against a correct 6th
attempt); 4 wrong then correct still succeeds; a success clears the
count so 4-more-wrong afterward still doesn't trip it; credential-less
requests (the routine first hit any browser makes) never count against
the budget at all; a wrong password writes a `system_events` row
(username present, password absent from the message) while a correct
login or a credential-less request write none. `tests/test_captive_portal_server.py`'s
two old pure-logic tests against the module's former hand-rolled
limiter were removed (that logic lives in `test_rate_limit.py` now) and
replaced with 3 new ones confirming the module's real HTTP handlers
write the same kind of `system_events` row for a failed kid login and a
failed admin action. 712 passed, 30 skipped on Windows (up from 692/30
before this pass), zero regressions. **Confirmed same day on the
smoke-test VM's Linux checkout: 742 passed, 0 skipped.**

**Same day, follow-up -- client-side tamper resistance / DNS-over-HTTPS
bypass**: project owner asked whether an end user could bypass a block
via browser dev tools; investigating it surfaced a real, unrelated
bypass (a browser's own "Secure DNS" Settings toggle defeating all
DNS-tier enforcement for non-bump devices) rather than the literal
dev-tools scenario, which doesn't apply anywhere in this codebase --
full writeup in `docs/security/overview.md` section 10. Fixed with
`controller/adguard_sync.py`'s new `build_anti_doh_rules()`. 6 new
tests in `tests/test_controller_adguard_sync.py`: the function is
never empty and needs no `conn` parameter at all (it reads no
per-household state); covers the Firefox canary domain and known
public DoH providers; produces unscoped (not `$client=`-scoped) rules,
since this isn't a per-device decision; and `sync_once()` includes the
baseline even with literally nothing else configured. **2 pre-existing
`sync_once()` tests needed real fixes, not just number bumps**: both
had asserted an exact managed-rule count/content that assumed the
managed block could be entirely empty or contain only what
`build_rules()`/`build_splice_deny_rules()` compute -- neither is true
anymore now that the anti-DoH baseline is unconditional, so each was
rewritten to compute its expected count via
`adguard_sync.build_anti_doh_rules()` rather than a hardcoded number,
so a future change to that list doesn't silently re-break them the
same way. 718 passed, 30 skipped on Windows, zero regressions.
**Live-verified against the real smoke-test VM AdGuard instance**
(not just these unit tests): all 8 rules landed correctly, unscoped,
in the real running instance's custom-rules list after a real
`adguard_sync` cycle; `dig` against the real resolver confirmed
`use-application-dns.net` -> NXDOMAIN and each provider domain ->
`0.0.0.0`/NOERROR (this instance's configured `blocking_mode`), both
effective blocks, while a control domain resolved normally throughout.
Full suite re-run on the VM: **748 passed, 0 skipped** on Linux.

**Same night, sixth follow-up**: closed out the design sketch's
"reminder screen" bullet from both directions (see
docs/architecture/overview.md). 3 new tests in
`tests/test_captive_portal_server.py` cover the success page's bump
reminder: shown when the same `user_id` has a different
`bump_enabled` device, absent when they have none, and correctly
scoped to that SAME user (a different user's bump-enabled device must
never trigger it). One new test in `tests/test_dashboard.py` checks
the device-detail page's CA-cert `confirm()` is actually wired to the
`bump_enabled` checkbox specifically (asserting the checkbox's own
surrounding HTML contains `confirm(`, not just that the string appears
somewhere on the page) -- a plain client-side reminder, so this can
only verify the wiring exists, not that a real browser's dialog behaves
as expected; that part was checked separately by driving a real browser
and overriding `window.confirm` to simulate both Cancel (checkbox
reverts to unchecked) and OK (stays checked).

**Same night, seventh follow-up**: building the portal-side admin
action (docs/architecture/overview.md) surfaced a real bug --
`common/policy_class.py`'s `classify_device()` never consulted
`bypass_login` at all, so it had zero effect on real nftables policy
despite existing documentation claiming otherwise. Two new regression
tests in `tests/test_policy_class.py` (a `bypass_login` device
classifies `AUTHENTICATED` even while `is_authenticated = 0`; it does
NOT also short-circuit quarantine the way `ignored` does) and one true
end-to-end proof in `tests/test_controller_policy_state.py`
(`compute_desired_policy()` -- which needed its own fix, a missing
`bypass_login` column in the query -- puts such a device in the real
`"authenticated"` set). `tests/test_auth.py` gained 6 tests for the new
`verify_admin_credentials()` (accepts right creds, rejects wrong
username/password, fails closed with no expected username/hash/empty
hash) -- one function now shared by both the dashboard's HTTP-Basic
admin login and the new portal action, tested once rather than through
each caller separately. 11 new tests in
`tests/test_captive_portal_server.py` cover the admin section itself:
rendered only when relevant (no group dropdown with zero groups),
Bypass and assign-to-group both work end-to-end (including that
assign-to-group correctly clears a prior `user_id`, satisfying the
table's own mutual-exclusivity `CHECK`), wrong admin credentials (or a
kid's own credentials) are rejected, a nonexistent group is rejected,
and the admin action genuinely shares the kid-login rate limiter rather
than getting its own separate budget. Also visually and interactively
verified in a live browser: opened the collapsed admin section, filled
in real credentials, selected a real group from the live dropdown, and
confirmed the device's `group_id`/`is_authenticated` actually changed
in the dev DB afterward.

**Same night, eighth follow-up**: auditing every other `bump_enabled`/
`is_authenticated`/`bypass_login` check in the codebase (user request,
prompted by the `classify_device()` bug) found a second real gap of the
exact same kind -- `controller/adguard_sync.py`'s `build_rules()`
selected on the raw `bump_enabled` column instead of the derived
`bump_eligible()` state, letting a `bump_enabled=1`-but-not-yet-
authenticated device bypass both AdGuard's hard-deny AND nftables'
`bump_v4` redirect at once (see docs/security/overview.md's dated
entry for the full trace). One new regression test in
`tests/test_controller_adguard_sync.py` proves such a device is now
correctly included in the hard-deny list. The rest of the audit (Squid
helpers, `common/matching.py`, the Go side, every `INSERT INTO devices`
site) found the existing code already correct -- see RoadMap.md's own
dated audit entry for the full site-by-site trace, including one
currently-unreachable cosmetic inaccuracy noted but left alone
(dashboard.py's "awaiting login" display doesn't check
`quarantined_at`, but nothing can set that column yet).

**2026-09-05, Phase 12 (temporary schedule overrides)**: 13 new tests.
6 in `tests/test_schedule_eval.py` for `schedule_is_active_for_device()`/
`active_override_for_device()`/the updated `is_full_lockout_active()`:
an override forces its named mode schedule active outside its own clock
window, suppresses a *different* mode schedule during that schedule's
own active window ("instead of", not "in addition to"), never affects a
non-`is_mode` schedule, stops applying once `expires_at` is in the past
(normal schedule resumes), and can target a device indirectly via its
`user_id` when no override names the device directly. 1 in
`tests/test_controller_adguard_sync.py` proves the same suppression
reaches the DNS-tier category-block path (`build_category_deny_rules()`),
not just the nftables lockout overlay -- confirming both enforcement
paths really do share the one `schedule_is_active_for_device()` choke
point rather than needing independent coverage. 6 in `tests/test_dashboard.py`
cover the `/schedules/override` route end to end: a valid shift writes
the row, a non-`is_mode` schedule is rejected, a schedule that doesn't
already target the picked user/group/device is rejected (with no row
written), a second override for the same target replaces the first
rather than stacking, and `/schedules/override/cancel` deletes a row
immediately. All 749 tests pass locally (Windows, `AF_UNIX`-only files
skipped as usual). Also live-verified against the real Flask app via
`dashboard/dev_server.py`: added a real `is_mode` schedule and a real
device, confirmed the "Shift mode now" card and its combobox render,
posted a real override and confirmed it appeared correctly in "Active
overrides" with the right target/expiry, and confirmed Cancel removed it.

**2026-09-06, Phase 13 (SSL-Bump CA certificate management)**: 15 new
tests in `tests/test_dashboard.py`, all using real `openssl`-generated
certs/keys (`_generate_cert_pair()`, a small test helper) rather than
hand-rolled fake PEM data, since the whole point of
`_validate_ca_cert_pair()` is real X.509 parsing. Covers: a valid
matching pair is accepted and written; a mismatched pair, a non-CA cert
(`CA:FALSE` explicitly, since omitting the extension is unreliable
across openssl builds/configs), and garbage input are all rejected with
the target files left completely untouched; regenerate writes a fresh
pair and backs up whatever was there before (asserting the backup's
bytes equal the old file and the live file's bytes actually changed);
regenerate rejects a `/` in the Org/Common-Name fields (breaks openssl
`-subj` parsing); both routes require admin auth; the Settings page
shows real subject/expiry/fingerprint when a cert exists and "Not
generated yet" when it doesn't. One test is a **live-caught regression**:
`_ca_cert_info()`'s fingerprint parsing originally matched
`"SHA256 Fingerprint="`, but this project's openssl build (3.5.7) prints
`"sha256 Fingerprint="` (lowercase) -- the fingerprint silently came back
blank on the real Settings page with no error anywhere, found only by
actually loading the page against a real generated cert (a mocked-output
unit test would never have caught this; the fix and its regression test
both came from the live check, not the other way around). Full suite:
**762 passed, 34 skipped** (Windows).

**2026-09-06, Phase 14 (live user-testing fixes)**: ~35 new tests
across three files, plus a real refactor whose safety net is that every
*existing* test kept passing unchanged. 12 in `tests/test_matching.py`:
`schedule_applies_to_target()` (is_global, bare user id, bare group id,
neither-set-and-not-global) and `find_categories_for_hostname()`
(multiple categories matching the same domain, subdomain matching,
no-match returns `[]`, an override correctly flags `overridden=True`,
blank input short-circuits). 3 in `tests/test_schedule_eval.py`:
`active_schedules_for_target()` lists what's actually active for a user
right now and respects the clock window, reflects a live override
(forces a different mode schedule on even though the original one's own
window is what's normally active), and correctly excludes a schedule
scoped to a different user. `matching.schedule_applies_to_device()` and
`schedule_eval.schedule_is_active_for_device()`/
`active_override_for_device()` were refactored into thin wrappers over
new target-shaped versions -- confirmed non-breaking by running the
full pre-existing `test_matching.py`/`test_schedule_eval.py`/
`test_controller_adguard_sync.py`/`test_controller_policy_state.py`
suites unchanged afterward (all still passed). ~20 in
`tests/test_dashboard.py`: the user detail page's new "Active right
now" card (shows an active schedule, shows "Nothing active right now"
when none applies) and its fixed pause-card visibility (a real bug --
this card used to disappear entirely for a user with zero devices,
found by the project owner testing with an empty user, rather than
explaining there's nothing to pause yet); a full new
`group_detail()`/`pause_group()`/`resume_group()` suite (page renders,
unknown id redirects with an error, empty-group messaging, pause
affects every member device, resume clears it, an `ignored` device is
skipped, auth is required); category sync's new 0-domains-is-suspicious
flash (distinct from a normal non-zero result, and `sync-all` naming
which specific categories came back empty); and the new cross-category
lookup (`?domain=` on `/categories`) finding a domain in multiple real
categories, a clean no-match message, and confirming the results
section doesn't render at all with no `domain` param. Full suite:
**790 passed, 34 skipped** (Windows). Also live-verified against the
real Flask app with real data (not just mocks): actually ran
`category_fetch.sync_all_categories()` against the real
`blocklistproject.github.io` sources (Adult came back with 953,197 real
domains), then used the new lookup tool to find a genuinely overlapping
real domain (`a2e.ai`, present in both the AI and Adult lists) --
confirming the whole feature end to end against real fetched data, not
a synthetic fixture.

**2026-09-07, Phase 15 (search-box confusion + pending-device
visibility)**: 1 new test in `tests/test_captive_portal_server.py`
(`test_failed_login_records_the_attempting_devices_mac`) confirms a
failed kid-login POST writes the real device's MAC into
`system_events.detail`, not just `client_ip`/`username` as before.
~7 new in `tests/test_dashboard.py`: the pending-devices card now
sources current IP/last-seen/discovery-source from a real
`device_bindings` row (not `devices.last_seen_at`, which nothing
populates); shows "None yet" with zero failed logins and a real count
with one; a second pending device's row is unaffected by another
device's own recorded attempt (no cross-device leakage); and the
Categories page's two search boxes now carry distinguishing copy
("Filter by category name..." vs "Type a full domain, not a category
name"). Full suite: **796 passed, 34 skipped** (Windows). Live-verified
against the real Flask app: reproduced the exact reported search-box
failure (typing `a2e.ai` into the client-side name filter genuinely
hides every category row), confirmed the fix keeps both boxes working
independently afterward and the real domain-lookup result from Phase 14
still finds the same real overlap; seeded a realistic pending device
with a real `device_bindings` row and a real `system_events` failed-
login row and confirmed the enriched card renders the real IP,
timestamps, source, and attempt count exactly as designed.

**2026-09-07, Phase 16 (cross-category search performance)**: 6 new
tests in `tests/test_matching.py`, all against `find_categories_for_hostname()`'s
two-pass rewrite. `test_candidate_exact_patterns_are_escaped_suffixes_most_specific_first`
locks down the exact suffix list a hostname decomposes into.
`test_find_categories_for_hostname_fast_path_matches_a_subscription_style_literal`
and `..._slow_path_still_catches_a_custom_manual_regex` prove each pass
independently: a plain synced literal never needs the slow path at all,
and a genuine hand-typed regex (`.*\.badcasino\.(com|net)`) is still
found even though the fast exact-match pass can't recognize it.
`..._slow_path_never_scans_subscription_rows` guards the `source =
'manual'` scoping specifically -- a subscription-sourced literal must
still be found (via the fast path), confirming the slow path's
narrower scope never causes a real miss.
`..._combines_fast_and_slow_matches_across_categories` checks both
passes contributing results in the same search. `..._no_categories_at_all`
guards the early-exit added by the rewrite. Full suite: **802 passed,
34 skipped** (Windows). Live-verified, not just measured in a script:
timed the actual HTTP round-trip through the running Flask app against
the real seeded dev database before and after the fix (51s -> under 1s
for a miss, 21s -> ~0.6s for a hit) -- including catching a stale
still-running dev server showing the OLD timing mid-verification,
resolved by restarting it to actually load the edited modules.

Run `pytest --collect-only -q` against `tests/` for a live,
authoritative total (552 as of 2026-08-31 -- `AF_UNIX`-only files still
skip on Windows, where `socket.AF_UNIX` doesn't exist, so a Windows run
of the same suite at this commit collects 522 passed, 30 skipped, while
Linux collects all 552) rather than trusting the sum of this table.

### Representative pattern: `tests/test_logging_dedupe.py`

Straightforward `conn`-fixture-based tests: call `logging_util.log_access(conn, ...)`
one or more times with specific kwargs, then assert on the row count and
contents of `SELECT * FROM access_log`. Good template for any new test that
just needs isolated DB state and no mocking.

### Representative pattern: `tests/test_squid_conf_regressions.py`

A different style worth knowing about: these tests don't exercise Python
*logic* at all — they check the **text/structure of `proxy/squid.conf.template`**
directly (via `Path.read_text()` + regex), plus what `field_count` kwarg
each helper's `main()` passes to `squid_helper.run` (captured by
monkeypatching `squid_helper.run` itself). This file exists because real
bugs were found running against a live Squid instance (2026-08-28 smoke
test) that no unit test of helper logic could have caught: a missing `%DATA`
macro accounting in every `external_acl_type` FORMAT string, and a bare
`http_access allow step1`/`step2` that doesn't reset Squid's `at_step` state
and so bypasses `authz_allowed` for decrypted requests. (A third,
`basic_auth_helper.py`'s `unquote=True` percent-encoding fix, was removed
2026-08-30 along with that file itself -- see RoadMap.md's Squid
intercept-mode section.) Two more tests were added 2026-08-30, of a
slightly different kind: guards against silently completing a *listed but
deliberately deferred* checklist item (flipping the `ssl_bump`/`http_access`
catch-alls to allow-by-default before the AdGuard hard-deny integration
exists) -- see `docs/security/overview.md` §3 for why that flip is
currently wrong. When you fix something that's actually a Squid ACL/protocol
semantics issue (not a Python bug), this is the file to add a regression
test to — see its module docstring for the full incident writeups.

## Mutation-testing verification approach

This is a **process**, not a specific test file, but it's how fixes in this
repo have been verified to actually be caught by the suite (used during past
development sessions and worth repeating for any nontrivial fix):

1. Confirm the target test currently passes with the fix in place.
2. Deliberately reintroduce the bug with a **precise, minimal string-replace**
   in the source file (e.g. flip a comparison, remove the one line that was
   the actual fix, revert `unquote=True` back to `unquote=False`).
3. Re-run the specific test (or the whole file) and **assert it now fails**,
   ideally for the expected reason (read the failure message/traceback, don't
   just check the exit code).
4. Restore the fix by **manually re-applying the same precise string-replace
   in reverse** (Edit tool / undo the specific change) — **never use
   `git checkout` (or `git checkout -- <file>`, `git stash`, or similar) to
   revert during this process.** Those commands revert the *entire* file (or
   working tree) to its last-committed state, which can silently discard
   unrelated uncommitted work sitting in the same file or elsewhere in the
   tree. A targeted string-replace back to the original text is the only safe
   way to undo the deliberate breakage.
5. Re-run the test again and confirm it passes once more, confirming the
   restore was exact.

This is how you get real confidence that a test is actually exercising the
code path it claims to, rather than passing vacuously.

## CI: `.github/workflows/tests.yml`

Workflow name: `Tests`. Triggers: every push to `main`, and every pull
request (any branch). Single job, `pytest`, on `ubuntu-latest`:

1. `actions/checkout@v4`
2. `actions/setup-python@v5` pinned to Python `3.12`
3. `pip install -r requirements-dev.txt` then `pip install -r dashboard/requirements.txt`
4. `pytest -v`

What this actually verifies, concretely: the entire Tier-1 suite described
above — matching/CIDR logic, URL classification, auth hashing, log dedupe,
idempotent seeding, all three Squid helper protocols and their decision
logic, the Crunchyroll API client's retry/error handling, the series-id
resolve cache, the Flask dashboard's routes and CSRF guard, and the
`squid.conf.template` regression checks — on a clean Linux + Python 3.12
environment, with no Docker and no real network access (enforced by
`block_network`). It does **not** verify anything Phase 2/3 (real Squid
process, real container networking, a real device pulling real Crunchyroll
content) — that still requires manual testing against a real deployment (see
the parental_proxy smoke-test VM). For how this workflow interacts with
deploy triggers, see [`docs/deployment/setup.md`](../deployment/setup.md);
this document only covers what CI verifies, not when/how it gates deploys.

## Adding a new test

1. **Where**: a new source module gets a new `tests/test_<module>.py` file
   (matches the existing 1:1 file-per-module-ish pattern: `test_matching.py`
   for matching logic, `test_auth.py` for `common/auth.py`, etc.). A
   regression for a bug in an *existing* module's behavior belongs in that
   module's existing test file, alongside its siblings; a regression that's
   about Squid config/protocol semantics rather than Python logic belongs in
   `tests/test_squid_conf_regressions.py` (see its pattern above).
2. **Naming**: test functions are plain `def test_<description>()` — no test
   classes are used anywhere in this suite. Names are long and descriptive
   sentences (e.g. `test_path_bearing_call_is_not_suppressed_by_a_prior_path_less_entry`),
   often naming the GH issue or `docs/review-2026-08-28.md` item number they
   regression-test (e.g. "GH #5", "S2.6"). Follow that convention — a good
   test name should explain *why* the test exists without needing to open it.
3. **Fixtures to use**:
   - Need a DB? Take `conn` as a parameter — don't construct your own
     `sqlite3.connect()`.
   - Doing anything with `cr_api`? `block_network` already blocks real calls
     automatically; explicitly monkeypatch `cr_api._OPENER.open` or the
     higher-level methods it calls, per the pattern in `tests/test_cr_api.py`.
   - Testing dashboard routes? Use the `dashboard_app`/`client`/`db_conn`
     fixtures from `tests/test_dashboard.py` (currently file-local, not in
     `conftest.py` — copy the pattern, or move them to `conftest.py` if a
     second file starts needing them).
   - No fixture needed at all for pure config/text checks — see
     `tests/test_squid_conf_regressions.py`'s direct `Path.read_text()` usage.
4. **No new sys.path or PYTHONPATH setup is ever needed** for a new test file
   — anything under `tests/test_*.py` automatically gets `conftest.py`'s
   `sys.path` setup and `block_network` fixture for free just by being
   collected under `testpaths = tests`.
5. Run the new file on its own first (`pytest tests/test_<module>.py -v`) to
   confirm it passes in isolation, then run the full suite (`pytest`) to
   confirm it doesn't interact badly with other tests (shouldn't happen given
   the per-test `tmp_path` DB isolation, but worth checking once).
6. If the new test is a regression for a bug you just fixed, use the
   mutation-testing verification approach above to confirm it actually fails
   without the fix before considering it done.
