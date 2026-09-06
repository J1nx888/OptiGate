# Dashboard: routes and UI reference

Source of truth: `dashboard/dashboard.py` (~4000 lines). This is the **entire**
web app -- one Flask file with routes and Jinja2 templates defined as Python
string constants, rendered via `render_template_string`. There is no separate
JSON API, no frontend build, no static template files. To change the UI you
edit this one file.

Supporting modules it imports (all copied from `common/` into the same
container directory at build time -- see "Build/deploy layout" below):
`auth.py` (password hashing), `cr_api.py` (Crunchyroll metadata lookups),
`db.py` (SQLite schema/connection/settings), `matching.py` (domain/path
matching helpers shared with the proxy's own request-time checks),
`adguard_client.py` (AdGuard's REST API, used by the Settings page's
"check for filter updates now" and SafeSearch toggle), `category_fetch.py`
(Phase 8's "Sync now" button), `schedule_eval.py` (Phase 8, only for
`zoneinfo.available_timezones()` validation on the Schedules forms --
the actual schedule-is-active evaluation runs in `controller/`, not here).

## Build/deploy layout (why `import auth`/`import db` work)

`dashboard/dashboard.py` does `import auth`, `import cr_api`, `import db`,
`import matching` as top-level modules -- but those files physically live in
`common/`, not `dashboard/`. This resolves at runtime, not edit time:

- `dashboard/Dockerfile` does `COPY common/*.py /app/` then
  `COPY dashboard/dashboard.py /app/`, flattening everything into one
  directory (`/app`) inside the image.
- `dashboard.py` also does `sys.path.insert(0, str(Path(__file__).parent))`
  so the same trick works when run locally from the `dashboard/` folder,
  provided the `common/*.py` files have been copied or symlinked alongside
  it first.

If you add a new shared helper module under `common/`, remember it needs the
same `COPY common/*.py /app/` treatment -- already covered by the existing
wildcard copy, so nothing to change in the Dockerfile for a new file, but you
do need to `import <module>` (not `import common.<module>`) from
`dashboard.py`.

## Auth / session model (integration point only)

The dashboard has no login page, no session cookie, and no CSRF token. It
authenticates every request with **HTTP Basic Auth** against admin
credentials stored in the `settings` table (`admin_username`,
`admin_password_hash`):

- `require_admin` (decorator, ~line 113) wraps every protected view. It reads
  `request.authorization`, hands it to `_check_admin_auth()`, and returns a
  bare `401` with a `WWW-Authenticate: Basic` header on failure -- this is
  what makes the browser pop its native Basic Auth prompt.
- **Brute-force protection (2026-09-02)**: `require_admin` also checks a
  per-source-IP `common/rate_limit.RateLimiter` (5 failures/60s) before
  even calling `_check_admin_auth()` -- a request that's already
  over the limit gets a bare `429`/`Retry-After: 60` without the
  (expensive, 260,000-iteration PBKDF2) password check ever running.
  Only a request that actually supplied an `Authorization` header counts
  against the budget; the routine credential-less first hit every
  browser makes on a fresh origin doesn't. A wrong-password attempt also
  writes a `system_events` row (see this file's own Events section) --
  see `docs/security/overview.md` section 6 for the full writeup.
- `_check_admin_auth()` (~line 99) loads `admin_username` /
  `admin_password_hash` from `db.get_setting()` and calls
  `auth.verify_password(basic_auth.password, expected_hash)`. Hashing itself
  (`auth.hash_password` / `auth.verify_password`) is implemented in
  `common/auth.py` -- treat that as a black box here; it's documented
  separately in the security doc.
- `bootstrap_admin()` (~line 69) runs once at import time (see bottom of the
  file, `bootstrap_admin()` is called unconditionally at module load,
  before `main()`): seeds `admin_username`/`admin_password_hash` from the
  `DASHBOARD_USER`/`DASHBOARD_PASSWORD` env vars on first run, or generates a
  random password and prints it to stderr if `DASHBOARD_PASSWORD` isn't set.
  Also seeds `local_network` and a random `secret_key` setting if absent.
- `app.secret_key` is loaded from the `secret_key` setting right after
  bootstrap (bottom of file) -- present because Flask requires *a* secret key
  to exist, but nothing in this app currently uses `flask.session` or signed
  cookies; all state is server-side in SQLite and all auth is Basic Auth
  re-sent by the browser on every request.
- Per-user (kid) accounts in the `users` table are a **completely separate**
  credential set from the dashboard admin login -- but as of 2026-08-30
  (Squid's move to intercept mode), `users.password_hash` has no active
  consumer: identity for the Squid side is now resolved from the client's
  device (`common/device_identity.py`, source IP → `device_bindings` →
  `devices.user_id`), not a per-request login. `users.password_hash` is
  reserved for the future Phase 4 captive-portal login (see RoadMap.md).
  Don't confuse it with `settings.admin_password_hash` (checked by the
  dashboard) -- they remain two entirely separate credential stores even
  though only one is currently checked by anything.

## CSRF protection

Implemented as a single `@app.before_request` hook, `_reject_cross_origin_writes()`
at the top of `dashboard.py` (~line 39-56). Because auth is HTTP Basic, a
browser that already has credentials cached will silently attach them to a
cross-site POST -- the classic CSRF risk for Basic Auth apps. The mitigation:

1. Only applies to state-changing methods: `POST`, `PUT`, `PATCH`, `DELETE`.
   GET is exempt (also why `/report`'s filter form uses `method="get"`).
2. Checks the `Origin` header first; if absent, falls back to `Referer`.
3. If either is present and its host (`urlparse(value).netloc`) doesn't
   match `request.host`, the request is rejected with a bare
   `403 Response("Cross-origin request blocked.")`.
4. If **neither** header is present, the request is allowed through -- the
   reasoning documented in the docstring is that a non-browser client (curl,
   a script, an API caller) has no ambient cookies/credentials to abuse, so
   there's nothing for CSRF to exploit.

There is no per-form CSRF token anywhere in the templates. This
Origin/Referer check is the entire CSRF defense.

## The `flash_redirect()` helper

Defined once, near the top of the "SHARED PAGE CHROME" section (~line 191):

```python
def flash_redirect(endpoint: str, message: str, error: bool = False, **kwargs):
    return redirect(url_for(endpoint, message=message, error="1" if error else None, **kwargs))
```

Pattern used by essentially every POST handler in the file: after mutating
the DB, redirect (302) back to a GET-rendering view, passing the
user-facing outcome as query-string parameters instead of using Flask's
`flash()`/session-based flashing (consistent with "no session state"
above). `**kwargs` lets a handler also carry along any other query params
that view needs (most commonly `user_id=` to preserve the Domains page's
per-user filter, or `domain_id=` to land back on the right domain's detail
page).

On the receiving end, `render()` (~line 184) always pulls `message` and
`error` out of `request.args` and threads them into the `BASE` template,
which renders:

```jinja
{% if message %}<div class="flash {{ 'error' if error else 'ok' }}">{{ message }}</div>{% endif %}
```

So: call `flash_redirect(target_endpoint, "Some message.", error=True, **extra_query_params)`
from any POST handler; nothing else needs to be wired up for the message to
show on the next page load. Because the message lives in the URL query
string, it also means reloading the destination page re-shows the same flash
(it's not consumed/popped) -- acceptable for this app's scale.

Two report/domain flows redirect straight to `domain_detail` with a
`prefill_path=` kwarg instead of using `flash_redirect` for the "message"
part (see `add_domain_from_url` indirectly and `approve_from_report`'s
`path_not_allowed` branch) -- that's a plain `redirect(url_for(...))`, not
`flash_redirect`, because there's no flash message on that particular hop,
just a query param the destination template reads directly (see "Prefill"
below).

## Shared page chrome: `BASE` + `render()`

- `BASE` (~line 129): the entire HTML page shell as a Jinja2 template
  string -- `<!doctype html>`, inline `<style>` block (no external CSS
  file), a `<nav>` with four static links (Report / Users / Domains /
  Settings, each built with `url_for(...)` and highlighted via an `active`
  variable), the flash-message block, and `{{ body|safe }}` where the
  page-specific content is injected.
- `render(active: str, body: str)` (~line 184): the only place `BASE` is
  rendered. Every route handler ends by calling
  `render("<nav-key>", render_template_string(PAGE_BODY, ...))`, i.e. each
  view first renders its own body template into a string, then hands that
  string to `render()` to wrap in the shared chrome. `active` must be one of
  `"report"`, `"users"`, `"domains"`, `"settings"` to match the `nav` links'
  `active` check.
- CSS is a handful of utility classes reused across all pages: `.add-form`
  (flex row of inputs + submit button), `.btn`/`button.add`/`button.danger`/
  `button.small` (action styling), `.badge.mode-*` and `.badge.allowed`/
  `.badge.blocked` (colored pills for domain mode and report status), `.hint`
  (small muted helper text under a form), `.flash.ok`/`.flash.error`.
  Re-use these classes rather than inventing new styles when adding UI.

## Template constants (per-page bodies)

Each resource area defines one or more `..._BODY` string constants
containing just the inner page content (no `<html>`/`<nav>` -- that's
`BASE`'s job). They are rendered with `render_template_string(CONSTANT,
**context)` inside their route handler, and the result is passed to
`render()`. Full list, in file order:

| Constant | Rendered by | Notes |
|---|---|---|
| `USERS_BODY` | `users()` | Table of all users + "Add user" form. Also has the cert-download banner. |
| `USER_DETAIL_BODY` | `user_detail()` | One user's assigned domains (read-only list), approved shows table + add form, change-password form. |
| `DOMAINS_BODY` | `domains()` | All domains table (or filtered by `?user_id=`), "Add domain" form, and conditionally the "Approve a specific page for {user}" form. |
| `DOMAIN_DETAIL_BODY` | `domain_detail()` | One domain's mode/global/note edit form, assigned-users toggle table (only if not global), allowed-paths table + add form (only if mode is `bump`). |
| `REPORT_BODY` | `report()` | Access-log table with a user/group/device/status GET filter form (combobox, since 2026-08-31) and inline per-row "Approve" actions. |
| `SETTINGS_BODY` | `settings_page()` | Local network CIDR form, household time zone form (Phase 8), blocked-site experience mode form, admin username/password form. |
| `CATEGORIES_BODY` | `categories()` | Phase 8. All categories table, "Add category" form, "Sync all subscriptions now" button (shown only if any category has a `subscription_url`). |
| `CATEGORY_DETAIL_BODY` | `category_detail()` | Phase 8. Subscription info + "Sync now" (if `subscription_url` set), Blocked-for card (`BLOCK_ACCESS_SELECTS`, or a plain Everyone-only checkbox once over the scoping threshold), domains table + manual-add form, overrides table + add form. |
| `SCHEDULES_BODY` | `schedules()` | Phase 8. All schedules table, "Add schedule" form (days/time/time-zone/lockout). |
| `SCHEDULE_DETAIL_BODY` | `schedule_detail()` | Phase 8. When/window edit form, Blocked-for card, categories multi-select card (omitted entirely when `lockout_all` is set). |

All of these live in the same file as their route handlers, directly above
them (e.g. `USERS_BODY` is defined right before `users()`/`add_user()`).
When adding a new field to an existing page, edit the relevant `..._BODY`
constant's HTML/Jinja and the context dict passed to
`render_template_string(...)` in the corresponding view function together.

### Prefill / query-param-driven form pre-population

Two examples of the same pattern -- a GET view reads an extra query param
and threads it into the template as a value the form pre-fills, so the
admin's next action is one edit + submit rather than starting from scratch:

- **`prefill_path` on Domain Detail's "Add path" form.** `domain_detail()`
  passes `prefill_path=request.args.get("prefill_path")` into
  `DOMAIN_DETAIL_BODY`. The template shows an extra hint line
  ("A blocked request suggested the pattern below...") when it's set, and
  the path `<input>`'s `value="{{ prefill_path or '' }}"`. The value
  originates from `path_to_pattern(path)` (~line 475), which regex-escapes
  a real observed request path into a starting-point pattern anchored at
  `^`. Two producers redirect here with that param: `approve_from_report()`'s
  `path_not_allowed` branch, and (indirectly) anywhere else that wants to
  send the admin to "review and save a path rule" rather than silently
  guessing one.
- **`user_id` as a persistent filter on `/domains`.** `domains()` reads
  `?user_id=` from the query string, resolves it to a `filtered_user` row,
  and both filters the domain list (global domains + domains explicitly
  assigned to that user, via `matching.user_has_domain()`) and reveals the
  extra "Approve a specific page for {user}" form. Every mutating form on
  the filtered `DOMAINS_BODY` page (add domain, delete domain) carries a
  hidden `user_id` input so the POST handler can round-trip
  `redirect_kwargs = {"user_id": ...}` back into `flash_redirect(...,
  **redirect_kwargs)`, keeping the admin on the same filtered view after the
  action completes instead of bouncing them back to the unfiltered list.

## Routes by resource

### General / unauthenticated

- `GET /` -> `index()` -- redirects to `report`.
- `GET /logout` -> `logout()` -- **not a real server-side logout** (HTTP
  Basic Auth has no session to revoke). The nav's Logout link points here
  with a deliberately wrong credential embedded in the URL
  (`http://logout:logout@host/logout`), overwriting whatever the browser
  cached for this origin; `@require_admin` then 401s it like any other bad
  credential, and the browser's own response to a 401 on a top-level
  navigation is to show a fresh native sign-in prompt. The route body only
  ever runs in the practically-impossible case the real credentials happen
  to literally be `logout`/`logout`.
- `GET /sw.js` -> `service_worker()` -- serves the PWA service worker from
  the root path (not `/static/sw.js`), specifically so its default scope
  covers the whole app -- a service worker can only control paths at or
  below where it's served from. `Cache-Control: no-cache` so an updated
  worker is picked up promptly rather than being stuck behind a stale
  cached copy.
- `GET /ca-cert` -> `ca_cert()` -- **unauthenticated on purpose** (see file
  docstring: it's a public certificate, every client device needs it).
  Serves `CA_CERT_PATH` (env `PP_CA_CERT_PATH`, default
  `/config/ssl_cert/ca_cert.pem`) as a download named
  `parental-proxy-ca.crt`; 404s with an explanatory message if the proxy
  container hasn't generated it yet.
- `GET /blocked` -> `blocked()` -- static unauthenticated 403 HTML page shown
  to end users (not the admin) when Squid redirects a blocked bump-mode
  request here; inlined HTML, no shared `BASE`/template constant since it's
  a deliberately separate, minimal page. Looks up the most recent denied
  `access_log` row with a `user_id` from the last
  `BLOCKED_REQUEST_LOOKBACK_SECONDS` (30s) -- correlated by recency, not
  request identity, since passing the original URL through Squid's
  `deny_info` redirect isn't verified version-specific behavior. If that
  row hasn't already requested approval, shows a "Request approval" button.
- `POST /blocked/request-approval` -> `request_approval()` -- **also
  unauthenticated on purpose**, same reasoning as `/blocked` itself:
  whoever got blocked is the one clicking it, and the worst-case abuse is
  dashboard noise (an extra pending-request row), not a data leak or an
  access grant. Form field `log_id`; sets `approval_requested_at` on that
  `access_log` row only if it's still denied and hasn't already been
  requested. Surfaces as the "Pending approval requests" card on `/report`.

### Users (`/users`)

- `GET /users` -> `users()` -- lists all users with computed `domain_count`
  (global domains + explicit `user_domains` assignments, matching what the
  "N assigned" link's `?user_id=` filter actually shows on `/domains`) and
  `show_count`. Renders `USERS_BODY`, including the CA-certificate download
  banner unless previously dismissed (see next route).
- `POST /users/dismiss-cert-banner` -> `dismiss_cert_banner()` -- no form
  fields. Sets the `cert_banner_dismissed` setting to `"1"` so the banner
  stops showing on `/users`; the cert itself is still always reachable via
  `/ca-cert` or the Settings page. There's no way to un-dismiss it from the
  UI (would need a direct `settings` table edit).
- `POST /users/add` -> `add_user()` -- form fields `username`, `display_name`
  (optional, defaults to username), `password`. Validates username against
  `^[A-Za-z0-9_.-]+$`, requires both username and password, hashes the
  password via `auth.hash_password()`, inserts into `users`. Redirects to
  `users` via `flash_redirect`; duplicate username -> error flash.
- `POST /users/delete` -> `delete_user()` -- form field `user_id`. Hard
  deletes the row (cascades to `user_domains`/`user_shows` via FK
  `ON DELETE CASCADE`). Redirects to `users`.
- `POST /users/reset-password` -> `reset_password()` -- form fields
  `user_id`, `password`. Redirects to `user_detail` (not `users`) with
  `user_id=` preserved.
- `GET /users/<int:user_id>` -> `user_detail()` -- one user's assigned
  domains (read-only, via a JOIN on `user_domains`), approved
  `user_shows`, and the add-show/change-password forms. Also (added
  2026-09-06, a real feature gap found by live user testing -- there was
  previously no way to see this at all) an "Active right now" card
  listing every schedule currently in effect for this user, via
  `schedule_eval.active_schedules_for_target(conn, now, user_id=...)` --
  reflects any live "Shift mode now" override (RoadMap.md's Phase 12),
  not just the bare clock. Renders `USER_DETAIL_BODY`. Redirects to
  `users` with an error flash if the user id doesn't exist.
- `POST /shows/add` -> `add_show()` -- form fields `user_id`, `url` (a
  Crunchyroll series URL), `name` (optional override). Parses the URL with
  `parse_series_url()` (module-level regex `SERIES_URL_RE`, ~line 450) to
  extract a series id + slug-derived name; on parse failure, flashes the
  parse error back to `user_detail`. On success, looks up the real title via
  `cr_api.series_title(series_id)` (falls back to the slug-derived name, or
  the admin's override if given), then upserts into `user_shows` (`ON
  CONFLICT(user_id, series_id) DO UPDATE SET series_name = excluded.series_name`).
- `POST /shows/remove` -> `remove_show()` -- form fields `user_id`,
  `series_id`. Deletes from `user_shows`. Redirects to `user_detail`.

### Domains (`/domains`)

- `GET /domains` -> `domains()` -- optional `?user_id=` query param filters
  the list to global domains plus domains assigned to that user (via
  `matching.user_has_domain()`, the same function the proxy itself uses at
  request time -- deliberately not reimplemented here). Renders
  `DOMAINS_BODY`, including the "Approve a specific page for {user}" section
  only when `filtered_user` is set (see UI/UX notes below).
- `POST /domains/add` -> `add_domain()` -- form fields `pattern`, `mode`
  (`splice`/`bump`/`trusted`, default `splice`), `is_global` (checkbox),
  `note` (optional), plus optional `user_id` purely to preserve the filtered
  view across the redirect (this call does **not** assign the new domain to
  that user -- it's just for staying on the same filtered page). Validates:
  pattern non-empty, mode in the allowed set, pattern <= 200 chars, and
  pattern must compile as a regex (`re.compile`). Inserts into `domains`
  with `kind='generic'`. Duplicate pattern (UNIQUE constraint) -> error
  flash naming the pattern.
- `POST /domains/add-url -> add_domain_from_url()` -- GH #6 shortcut. Form
  fields `url`, `user_id` (**required** -- this route only makes sense from
  a user-filtered Domains view; if `user_id` is missing it flashes an
  explanatory error back to the unfiltered `domains` page). Steps: prepend
  `https://` if the URL has no scheme; extract `hostname` via `urlparse()`
  and re-validate it against a strict hostname regex (urlparse alone doesn't
  validate hostname syntax); extract `path` (default `/`); look up the
  domain via `matching.find_domain()` -- if it doesn't exist yet, create it
  in `bump` mode (`kind='generic'`, `is_global=0`, note
  `'Added via the paste-a-URL shortcut'`); if it exists but isn't already in
  `bump` mode, refuse with an error flash telling the admin to switch modes
  from Manage first (a page-level path rule requires bump mode -- splice
  mode never inspects the path). Then `INSERT OR IGNORE` a `domain_paths`
  row derived from the path via `path_to_pattern()`, and `INSERT OR IGNORE`
  a `user_domains` row assigning that domain to `user_id`. Success flash
  names the exact hostname+path approved.
- `POST /domains/delete` -> `delete_domain()` -- form field `domain_id`,
  optional `user_id` (redirect-preservation only, as above). Refuses to
  delete a domain whose `kind == 'crunchyroll'` (the built-in Crunchyroll
  domain backing the show-approval feature) with an explanatory error flash;
  otherwise hard-deletes the row (cascades to `user_domains`/`domain_paths`).
- `GET /domains/<int:domain_id>` -> `domain_detail()` -- loads the domain,
  all users (for the assign/grant toggle table), the set of currently
  assigned user ids, and its `domain_paths` rows. Also reads
  `?prefill_path=` (see Prefill section above). Renders `DOMAIN_DETAIL_BODY`.
  Redirects to `domains` with an error flash if the domain id doesn't exist.
- `POST /domains/update` -> `update_domain()` -- form fields `domain_id`,
  `mode`, `is_global` (checkbox), `note`. No validation on `mode` here
  (unlike `add_domain`) -- it's a `<select>` so the browser constrains the
  value in practice. Updates the row, redirects to `domain_detail`.
- `POST /domains/access` -> `update_domain_access()` -- **stale-doc
  correction (2026-09-01): this replaced a per-assignment
  `/domains/toggle-user` route from the GH #8 combobox redesign; that
  route no longer exists in code.** Form fields `domain_id`, `is_global`
  (checkbox), `user_ids`/`group_ids`/`device_ids` (multi-value, from the
  `BLOCK_ACCESS_SELECTS`-style combobox). Replaces the domain's **entire**
  access grant in one call -- deletes every existing `user_domains`/
  `group_domains`/`device_domains` row for this domain and re-inserts
  exactly what was submitted, so granting and revoking are the same
  action (a changed selection), not separate add/remove endpoints per
  assignment. Same shape as `update_category_access()` and
  `update_schedule_access()` below. Redirects to `domain_detail`.
- `POST /domains/paths/add` -> `add_path()` -- form fields `domain_id`,
  `pattern`. Validates non-empty, <= 200 chars, and compiles as a regex.
  `INSERT OR IGNORE` into `domain_paths`. Redirects to `domain_detail`.
- `POST /domains/paths/delete` -> `delete_path()` -- form field `path_id`.
  Looks up the `domain_id` first (needed for the redirect target after the
  row is gone), deletes the `domain_paths` row, redirects to
  `domain_detail` with that `domain_id` (or `None` if the path was already
  gone).

### Categories (`/categories`) -- Phase 8, opposite polarity from Domains

A category BLOCKS domains for whoever it's assigned to (or everyone) --
see `docs/database/schema.md`'s Phase 8 section and
`docs/security/overview.md` §8 for why this is the inverse of the
Domains page's allow-list model, and for the 5,000-domain scoping
threshold (`matching.MAX_SCOPED_CATEGORY_DOMAINS`) enforced below.

- `GET /categories` -> `categories()` -- lists every category with a
  computed `domain_count`; a "Sync all subscriptions now" button appears
  only if at least one category has a `subscription_url`. Also accepts
  an optional `?domain=` query param (added 2026-09-06, real gap found
  by live user testing: no way to check whether a domain appears in more
  than one category, e.g. `facebook.com` listed in both Facebook and
  Gambling, without opening each category individually) -- when present,
  runs `matching.find_categories_for_hostname()` and renders the
  matching categories (each flagged if a `category_overrides` row
  exempts that domain from that specific category despite being a
  pattern match) inline on the same page, via a plain `GET` form so the
  result is bookmarkable/shareable as a URL. Renders `CATEGORIES_BODY`.
  **Real bug fixed 2026-09-07**, found by live user testing: this page
  already had an unrelated client-side "Search categories..." box
  (`data-filter-table`, filters the visible table by category NAME only
  -- see the shared engine's own comment in `BASE`'s `<script>`) sitting
  right above the categories table. A domain typed into THAT box instead
  of the real lookup form below matches no category's name, hides every
  row, and reads exactly like "the lookup tool doesn't work" -- the two
  controls look similar and sit on the same page about domains, which is
  what made the mix-up likely. Fixed by renaming that box's placeholder
  to "Filter by category name..." with an explicit hint pointing at the
  real tool, and moving the domain-lookup card up to sit immediately
  after the categories table (it used to be the last card on the page).
  **Second real bug fixed the same day**: the lookup itself was
  genuinely, severely slow against this project's real seeded data (up
  to 51 seconds for a miss against the ~953K-domain Adult category) --
  see `matching.find_categories_for_hostname()`'s own docstring for the
  fast-indexed-lookup rewrite that brought it under a second. The form
  also gained an `onsubmit` handler that disables the Search button and
  shows "Searching…" immediately, since even a sub-second wait benefits
  from visible feedback on a plain (non-AJAX) page navigation.
- `POST /categories/add` -> `add_category()` -- form fields `name`,
  `subscription_url` (optional -- blank means manual-only). Redirects to
  `categories`; duplicate name -> error flash. The add form (and
  `category_detail()`'s own subscription card) carry hint text (added
  2026-09-06) spelling out that `subscription_url` must be a raw
  domain-list file (bare domain per line, hosts-file, or AdGuard/uBlock
  rule syntax -- see `common/blocklist_parser.py`) with a working example
  URL, not a webpage -- found live when an admin pointed a category at a
  Microsoft documentation page that visibly lists domains in a table but
  isn't in any of the three parseable shapes.
- `POST /categories/delete` -> `delete_category()` -- form field
  `category_id`. Cascades to every `category_*` junction table.
- `GET /categories/<int:category_id>` -> `category_detail()` -- the
  category's domains (source-tagged), overrides, and Access
  (`BLOCK_ACCESS_SELECTS`) card; shows a "too large to scope" notice
  instead of the full picker once `domain_count` exceeds the threshold.
  Renders `CATEGORY_DETAIL_BODY`.
- `POST /categories/access` -> `update_category_access()` -- form fields
  `category_id`, `is_global`, `user_ids`/`group_ids`/`device_ids` (same
  shape as `update_domain_access()`). **Rejects** (error flash, no write)
  a non-global assignment on a category whose `domain_count` exceeds
  `matching.MAX_SCOPED_CATEGORY_DOMAINS` -- the one piece of server-side
  enforcement that makes the threshold real, not just a UI suggestion.
- `POST /categories/domains/add` -> `add_category_domain()` -- form
  fields `category_id`, `pattern` (validated non-empty, <=200 chars,
  compiles as regex, same as `add_domain()`). `INSERT OR IGNORE` with
  `source='manual'`.
- `POST /categories/domains/delete` -> `delete_category_domain()` --
  form field `category_domain_id`. Deletes only if `source='manual'` (a
  `WHERE ... AND source = 'manual'` clause -- a subscription-sourced row
  silently survives this call, by design, since it'll just come back on
  the next sync anyway; remove it from the subscription source itself,
  or add an override, instead).
- `POST /categories/overrides/add` / `.../overrides/delete` -> allow-
  exception CRUD against `category_overrides`, same shape as the domain
  add/delete pattern.
- `POST /categories/<int:category_id>/sync` -> `sync_category_now()` --
  calls `common/category_fetch.py`'s `fetch_and_sync_category()`
  synchronously (blocks the request on the actual HTTP fetch); a
  `CategoryFetchError` flashes back to `category_detail` rather than
  raising a 500. **Fixed 2026-09-06** (real UX gap found by live user
  testing): a URL that fetches successfully but isn't a supported
  blocklist format (a webpage, say) legitimately parses to 0 domains --
  `parse_hostlist()` doesn't raise for that, so this used to flash an
  unexplained "Synced 0 domains." with no hint anything was wrong. A
  `count == 0` result now gets its own distinct, actionable error flash
  instead, since almost every real subscription source has domains.
- `POST /categories/sync-all` -> `sync_all_categories_now()` -- calls
  `sync_all_categories()`; one failing source is skipped, never aborts
  the rest. Same 2026-09-06 fix as above: names any category that came
  back with exactly 0 domains in the aggregate flash (`error=True` in
  that case) rather than only reporting an undifferentiated grand total.

### Schedules (`/schedules`) -- Phase 8

- `GET /schedules` -> `schedules()` -- lists every schedule with a
  computed `category_count`; the add form's default time zone comes from
  the `household_time_zone` setting. Renders `SCHEDULES_BODY`.
- `POST /schedules/add` -> `add_schedule()` -- form fields `name`,
  `days` (multi-value checkbox list, filtered to the 7 valid 3-letter
  codes and joined with commas -- silently drops anything else rather
  than rejecting the whole submission), `start_time`/`end_time`
  (`"HH:MM"`, validated by regex), `time_zone` (validated against
  `zoneinfo.available_timezones()`), `lockout_all` (checkbox). Requires
  at least one day.
- `POST /schedules/delete` -> `delete_schedule()` -- form field
  `schedule_id`. Cascades to every `schedule_*` junction table.
- `GET /schedules/<int:schedule_id>` -> `schedule_detail()` -- the
  when/window edit form, the Access (`BLOCK_ACCESS_SELECTS`) card, and a
  category multi-select card that's **omitted entirely** (not just
  disabled) when `lockout_all` is set, since a full lockout blocks
  everything regardless of any category assignment. Renders
  `SCHEDULE_DETAIL_BODY`.
- `POST /schedules/update` -> `update_schedule()` -- same field set/
  validation as `add_schedule()`, applied to an existing row.
- `POST /schedules/access` -> `update_schedule_access()` -- same shape
  as `update_category_access()`, minus the size-threshold check (a
  schedule's own target set has no domain-count concept itself; that
  check lives on the category side).
- `POST /schedules/categories` -> `update_schedule_categories()` --
  form fields `schedule_id`, `category_ids` (multi-select combobox,
  posted as a list) -- full replace of `schedule_categories` for that
  schedule, same grant-and-revoke-are-the-same-action shape as every
  other access-replace route in this file.
- `POST /schedules/override` -> `add_schedule_override()` -- Phase 12's
  "Shift mode now". Form fields `schedule_id`, `target` (single-select
  combobox, `"user:<id>"`/`"group:<id>"`/`"device:<id>"`, decoded by
  `_parse_override_target()`), `duration_minutes` (1-1440). Rejects with
  a flash error if the schedule isn't `is_mode = 1`, or if it doesn't
  already target the picked user/group/device (checked by
  `_schedule_targets_selection()` -- forcing a schedule that was never
  assigned to that target would silently do nothing at enforcement time).
  Creating a new override for a target first deletes any existing one for
  that exact target (`_clear_overrides_for_target()`) -- only one
  override can be in effect per target at a time. Writes one row to
  `schedule_overrides` with `expires_at` computed from the duration.
- `POST /schedules/override/cancel` -> `cancel_schedule_override()` --
  form field `override_id`. Deletes the row immediately (not a soft
  expiry) so the normal, clock-driven schedule resumes right away.

See `common/schedule_eval.py`'s `schedule_is_active_for_device()` for how
an active override actually changes enforcement -- it's the one choke
point both `controller/policy_state.py` (nftables lockout) and
`controller/adguard_sync.py` (DNS-tier category blocks) read through, so
this dashboard route never talks to either enforcement path directly.

### Report (`/report`)

- `GET /report` -> `report()` -- filters, built as a raw SQL string with
  conditionally appended `AND` clauses (parameterized, not
  string-interpolated -- safe from injection) against `access_log`, capped
  at `LIMIT 200`, newest first (`ORDER BY id DESC`). Also surfaces
  `db.get_setting(conn, "cr_resolver_last_error")` so a failing Crunchyroll
  metadata resolver shows a banner at the top of the page. Renders
  `REPORT_BODY`.
  - `?status=` (`blocked`/`allowed`) -- unchanged.
  - **Who/what filter, reworked 2026-08-31 (GH #9)**: the plain
    `<select name="user">` was replaced with the same shared combobox
    widget the Domains page uses (`_report_filter_combo()`, mirrors
    `_domains_filter_combo()`), now covering users, groups, AND devices --
    not just users. `?target=` (e.g. `device:7`, `group:2`, decoded by the
    already-shared `_parse_filter_target()`) is the current encoding;
    `_get_report_filter()` resolves it to at most one of
    `(filtered_user, filtered_group, filtered_device)`. A user filter still
    matches `access_log.username`; a device filter matches the new
    `access_log.device_id` column directly; a group filter matches
    `device_id IN (SELECT id FROM devices WHERE group_id = ?)` (access_log
    has no `group_id` of its own). The older `?user=<username>` param still
    works as a fallback when `?target=` isn't present, for any existing
    bookmarks/links. Rows written before this migration have `device_id
    IS NULL` and won't appear under a device/group filter -- not
    back-filled.
- `POST /report/approve` -> `approve_from_report()` -- form fields `log_id`
  and `scope` (`user` default, or `global`/`device`/`group` since
  2026-08-31 -- see below). Looks up the `access_log` row, validates the
  requested `scope` actually has something to grant against (`scope=user`
  needs `row["user_id"]`; `scope=device`/`group` need `row["device_id"]`
  to resolve to a real `devices` row; `scope=group` additionally needs
  that device to have a `group_id`) -- an invalid combination errors via
  `flash_redirect(..., error=True)` rather than crashing. Then branches
  three ways:
  1. **Show-scoped** (`row["series_id"]` set): `scope=device`/`group` are
     rejected here (`user_shows` has no group/device equivalent -- see
     `authz_helper.decide()`'s `show_requires_user` reason). Otherwise
     resolves the title via `cr_api.series_title()` and upserts
     `user_shows` for that user -- one-click "approve this show".
  2. **Path-not-allowed** (`row["reason"] == "path_not_allowed"`): the
     domain is already assigned (that's why the path check ran at all), so
     a plain assignment insert would be a silent no-op and the same
     request would be denied again. Instead this redirects to
     `domain_detail` with `prefill_path=path_to_pattern(row["path"])` so the
     admin reviews/saves an actual path rule (see Prefill section).
  3. **New/blocked domain** (anything else): looks up the domain via
     `matching.find_domain()`; if it's never been configured at all,
     creates it as `splice` mode, `is_global=0` (still `0` even for
     `scope=device`/`group`, only ever `1` for `scope=global`), note
     `'Auto-added from report approval'`, then grants it via
     `user_domains`/`device_domains`/`group_domains` depending on `scope`
     (`global` instead flips the domain's own `is_global`).
  All three branches end with `flash_redirect("report", ...)` except branch
  2, which does a plain `redirect(url_for("domain_detail", ...))` instead
  (no flash message on that hop, just the `prefill_path` param).
  **No separate "Block"/revoke action exists or is planned** -- revoking a
  grant already works via the Domains page's per-assignment delete on
  `user_domains`/`group_domains`/`device_domains`; the 2026-08-31 fix
  described in `docs/security/overview.md` §3.5 is what makes that revoke
  *actually take effect* on AdGuard's DNS tier too, not just Squid.

### Devices and groups (`/devices`, `/groups`)

Undocumented until this pass (2026-08-30) -- these routes predate the
Squid intercept-mode change but were missing from this file entirely. This
is where a device's `user_id`/`group_id`/`bump_enabled`/`bypass_login`
assignment (consumed by `common/device_identity.py` and, once Phase 3 is
deployed, `common/policy_class.py`/nftables) is actually set.

**2026-08-31 update**: a device no longer has to be added here manually to
get *some* real state -- `common/identity.py`'s `record_binding()` (Phase
4's first milestone) now auto-creates a pending `devices` row
(`is_authenticated = 0`) for a genuinely new MAC, so this page is also
where an admin now handles the result of that: a device that showed up on
the network on its own, gated to DNS-only until someone logs in via the
real captive portal (`dashboard/captive_portal_server.py`, Phase 4 --
**stale-doc correction 2026-09-07**: this was long done, but the doc
text here still said "not built" until now).

- `GET /devices` -> `devices()` -- lists all `devices` rows (LEFT JOINed to
  `users`/`groups` for display), plus the add-device and add-group forms.
  Renders `DEVICES_BODY`. Since 2026-08-31, also computes a `pending`
  column per row (`ignored = 0 AND bypass_login = 0 AND is_authenticated = 0`)
  and sorts pending rows first; when any exist, a highlighted "Devices
  awaiting login" card (mirroring the Report page's own `pending-card`
  convention for "Pending approval requests") lists them above the Groups
  card with a one-click **Bypass** action alongside the existing **Manage**
  link. **Enriched 2026-09-07** (real gap found by live user testing --
  the card previously showed only MAC address and `created_at`, nowhere
  near enough to act on): the query also correlates each pending MAC
  against its most-recently-updated `device_bindings` row for
  `current_ip`/`network_last_seen`/`binding_source` (`devices.last_seen_at`
  itself is never populated by anything -- see that column's own schema
  comment -- so `device_bindings` is the only place a real "last seen on
  the network" signal actually lives), and a new `_failed_login_attempts()`
  helper counts real captive-portal login failures for that MAC (via
  `system_events.detail`, see below) so an admin can tell "this kid
  already tried and got denied because nobody's assigned this device
  yet" apart from a device nobody has touched at all.
- `POST /devices/add` -> `add_device()` -- form fields `mac_address`
  (validated/normalized via `normalize_mac()`), `label` (optional),
  `assignment` (parsed by `_parse_device_assignment()` into a `(user_id,
  group_id, ignored)` triple -- see `DEVICE_ASSIGNMENT_SELECT`'s combined
  dropdown). Inserts into `devices`; duplicate MAC (UNIQUE constraint) ->
  error flash.
- `POST /devices/import` -> `import_devices()` (2026-09-01, a G7
  setup-convenience feature, on Settings not this page -- see
  `docs/deployment/setup.md`) -- multipart file field `csv_file`, one
  `mac_address,label` row per device. Auto-detects and skips a header
  row (via `normalize_mac()` on the first cell -- if it's not a valid
  MAC, that row is treated as a header, not data -- **known edge case**:
  a genuinely malformed first DATA row is indistinguishable from a real
  header by this heuristic and is silently dropped uncounted, capped at
  exactly the first row, never a systemic gap). `INSERT OR IGNORE` on the
  UNIQUE `mac_address` constraint -- an already-known MAC is skipped, not
  overwritten. **The flash message names which MACs were duplicates and
  which raw cells failed to parse** (`_preview_list()`, capped at 10 with
  "and N more"), not just an aggregate count -- added 2026-09-01 after
  the project owner asked whether an admin gets any way to react to a
  duplicate; the original cut only reported a bare count. Every row
  lands exactly like `add_device()` with no assignment (plain
  Unassigned) -- there's no separate bulk-assignment step; assign each
  one afterward from this page's own per-row Manage link.
- `GET /devices/<int:device_id>` -> `device_detail()` -- one device's
  editable assignment, `bump_enabled`, and `bypass_login` checkboxes.
  Renders `DEVICE_DETAIL_BODY`. Redirects to `devices` with an error flash
  if the device id doesn't exist. Since 2026-08-31, checking
  `bump_enabled` triggers a client-side `confirm()` reminding the admin
  to have installed the CA certificate first (RoadMap.md's Phase 4
  design sketch) -- unchecks itself if declined; purely a reminder, not
  a server-side gate (`update_device()` below still accepts either
  value regardless).
- `POST /devices/update` -> `update_device()` -- form fields `device_id`,
  `label`, `assignment`, `bump_enabled` (checkbox), `bypass_login`
  (checkbox). Updates the row. Redirects to `device_detail`.
  **`bypass_login` defaults `ignored` to 1 (added 2026-08-31, project
  owner's explicit direction)**: on the actual 0->1 transition of
  `bypass_login` (checked against the row's current DB value, not just
  whether the checkbox is ticked this submit), if this same submission's
  `assignment` resolved to neither a user nor a group, `ignored` is set
  to 1 too. Skipped entirely if the submission explicitly picked a
  user/group assignment (an explicit choice always wins), and only ever
  fires once per transition, so a later save with `bypass_login` already
  on never re-forces `ignored` back over an admin's own subsequent
  "actually, assign it somewhere" edit.
- `POST /devices/bypass_login` -> `bypass_login_device()` (added
  2026-08-31) -- form field `device_id`. Sets `bypass_login = 1` and
  nothing else -- deliberately a single-column `UPDATE`, not a wholesale
  form resubmit like `update_device()`, so the "Bypass" quick-action
  button in the pending-devices card can fire from a bare one-field form
  without needing to also resubmit (and risk blanking) the device's
  label/assignment/bump_enabled. **Also defaults `ignored` to 1 (added
  2026-08-31, same reasoning as `update_device()` above)**, via a single
  `CASE` expression in the same `UPDATE` -- skipped if the device already
  has a real `user_id`/`group_id`. Redirects to `devices`.
- `POST /devices/delete` -> `delete_device()` -- form field `device_id`.
  Hard-deletes the row (`device_bindings`/`device_domains`/
  `network_events` referencing it fall back to `device_id = NULL` via `ON
  DELETE SET NULL`/`CASCADE`, not left dangling). Redirects to `devices`.
- `POST /devices/pause` / `POST /devices/resume` -> `pause_device()` /
  `resume_device()` (G6, 2026-09-01) -- form fields `device_id`, optional
  `redirect_to=device_detail` (defaults to redirecting to `devices`).
  Writes/clears `devices.quarantined_at` via the shared `_set_quarantine()`
  helper -- no new enforcement, `common/policy_class.py`'s
  `classify_device()` and `controller/policy_state.py` already treat a
  non-NULL value as QUARANTINE (Phase 3), live-verified against a real
  device in Phase 8's own entry. The UI never offers these for an
  `ignored` device (BYPASS outranks QUARANTINE, so it would be a no-op).
- `POST /devices/pause-all` / `POST /devices/resume-all` ->
  `pause_all_devices()` / `resume_all_devices()` (G6) -- whole-house
  variant, no form fields. Pause excludes `ignored` devices
  (`WHERE ignored = 0`); resume clears every currently-quarantined device
  regardless of how it got that way (`WHERE quarantined_at IS NOT NULL`).
  Both redirect to `devices` with a count of devices affected.
- `POST /users/pause` / `POST /users/resume` -> `pause_user()` /
  `resume_user()` (G6) -- form field `user_id`. Per-kid variant of the
  above, scoped to `WHERE user_id = ?` (pause also excludes `ignored`).
  Redirects to `user_detail`. **Fixed 2026-09-06** (real UX bug found by
  live user testing): this card used to be omitted entirely from
  `USER_DETAIL_BODY` when the user had zero non-`ignored` devices,
  making the feature look missing rather than just not yet applicable --
  it now always renders, showing an explanatory "no devices assigned
  yet" message (and no pause form) in that case instead of disappearing.
- `POST /devices/cleanup` -> `cleanup_stale_devices()` -- deletes every
  device whose `last_seen_at` is older than the `device_stale_days`
  setting (see below); a device never observed at all (`last_seen_at IS
  NULL`) is never matched, so this can't mass-delete devices just because
  nothing populates `last_seen_at` yet (see `common/db.py`'s schema
  comment). Redirects to `devices`.
- `POST /groups/add` -> `add_group()` -- form field `name` (required, <=
  100 chars). Inserts into `groups`; duplicate name -> error flash.
- `POST /groups/delete` -> `delete_group()` -- form field `group_id`.
  Hard-deletes the row (`devices.group_id`/`group_domains` fall back to
  `NULL`/cascade). Redirects to `devices`.
- `GET /groups/<int:group_id>` -> `group_detail()` (added 2026-09-06,
  closing a real gap -- a group previously had no dedicated page at all,
  only a "Manage domains" link straight into a filtered `/domains` view,
  so there was nowhere to put a group-level pause control). Shows: which
  schedules are active for this group right now
  (`schedule_eval.active_schedules_for_target(group_id=...)`, same
  helper `user_detail()` uses), a Pause card, the group's member devices
  with their paused/active status, and a read-only assigned-domains
  summary linking to the `/domains?group_id=` filtered view for actually
  managing them. Renders `GROUP_DETAIL_BODY` under the `devices` nav tab
  (there's no separate "Groups" nav item). Redirects to `devices` with an
  error flash if the group id doesn't exist.
- `POST /groups/pause` / `POST /groups/resume` -> `pause_group()` /
  `resume_group()` (added 2026-09-06 -- the one pause granularity that
  was entirely missing; per-device and per-user pause both already
  existed). Form field `group_id`, same `_set_quarantine()` helper and
  `WHERE group_id = ? AND ignored = 0` / `WHERE group_id = ? AND
  quarantined_at IS NOT NULL` shape as the per-user routes above.
  Redirects to `group_detail`.
- `POST /settings/device-stale-days` -> `update_device_stale_days()` --
  form field `device_stale_days` (a whole number of days, or blank to
  disable cleanup entirely). Feeds `cleanup_stale_devices()` above.

### Health (`/health`)

Added 2026-08-30. Read-only view of `interception_runtime` (see
`common/db.py`'s schema comment) -- the only place this table's data is
surfaced anywhere in the app. Requires the optional `interception` compose
profile to actually be running; shows a "not running" card instead when
the singleton row doesn't exist at all (a normal, unremarkable deployment
shape, not an error).

- `GET /health` -> `health_page()` -- reads `mode`/`last_healthy_at`/
  `fail_open_reason`/`applied_generation` (controller<->arp-worker
  pipeline) and `nft_mode`/`nft_last_healthy_at`/`nft_fail_reason`
  (nftables-manager) from `interception_runtime`'s singleton row. Renders
  `HEALTH_BODY` with a green/red/amber badge per subsystem via
  `HEALTH_MODE_BADGE_CLASS`. `_is_stale()` additionally flags either
  subsystem "stale" (badge class `pending`) when its `last_healthy_at`
  hasn't advanced in over `HEALTH_STALE_AFTER_SECONDS` (30s) and `mode`
  isn't already `fail_open` -- a crashed/crash-looping process can't
  write its own `fail_open` row, so a frozen timestamp is itself the
  signal something's wrong (found live via a sustained OOM-kill test,
  see RoadMap.md). This page doesn't auto-refresh; reload to see the
  latest status.
- `render()` (the shared page-chrome wrapper every route calls into, not
  a route itself) separately queries the same singleton row on every
  page load to decide whether to show a "!" alarm badge next to "Health"
  in the sidebar -- lit for either subsystem being `fail_open` or stale,
  by the same `_is_stale()` logic. A missing row (interception profile
  not running) never lights this badge.

### Events (`/events`)

Added 2026-09-01, ahead of G1 real-network testing (project owner asked
whether the admin portal has any way to see a problem without SSH/Docker
CLI access -- answer at the time was no; see RoadMap.md's Phase 11
entry). Distinct from Health above: Health shows the CURRENT state of
exactly two subsystems (controller/arp-worker, nftables-manager); this
page is a historical trail of real failures across every background
sync/discovery loop (AdGuard sync, category subscription fetch, active
ARP scan, device discovery, the controller↔worker heartbeat) plus the
specific moment each one recovers -- populated by
`common/system_events.py`, written to from `controller/main.py`'s own
`on_error`/`on_success` wiring, not from this route itself. **2026-09-02:
a second category of writer joined** -- failed login attempts against
the dashboard's own admin auth and the captive portal's two forms (see
this section's own route notes below and `docs/security/overview.md`
section 6), so this page now doubles as the brute-force-attempt signal
the project owner asked for, not only an operational-health trail.

- `GET /events` -> `events_page()` -- reads the most recent
  `EVENT_DISPLAY_LIMIT` (200) rows from `system_events`, newest first.
  Renders `EVENTS_BODY`: a table (When/Source/Severity/Message) with the
  same client-side `data-filter-table` search box other list pages use,
  a severity badge (`error` reuses the "blocked" red, `recovery` reuses
  "allowed" green), and an empty-state message when nothing has ever
  failed. This route itself never deletes anything -- `EVENT_DISPLAY_LIMIT`
  only bounds what's DISPLAYED here, not what's stored. **2026-09-02**:
  the table itself now has a real cap (`common/system_events.py`'s
  `_MAX_STORED_EVENTS`, 5000), enforced by `log_event()` pruning back
  down to it after every insert -- added once failed-login attempts
  (rate-limited but never fully blocked) made this table's growth
  attacker-influenceable, not just organic.
- No write routes on **this page** -- but as of 2026-09-02, this
  dashboard process itself IS one of the writers into `system_events`,
  not only `controller/main.py`'s background loops: `require_admin`
  (this file's admin-auth section) logs a `dashboard_admin_login` error
  row on a wrong-password attempt, and
  `captive_portal_server.py` logs `captive_portal_login`/
  `captive_portal_admin_action` error rows the same way -- see
  `docs/security/overview.md` section 6. None of these three sources
  have a matching "recovery" event (a successful login isn't logged at
  all, matching `system_events`'s own not-a-firehose design) -- they're
  pure failure counters, same shape as `rtnetlink_listener.py`'s own
  error-only entries (§9 of the architecture doc).

### Settings (`/settings`)

- `GET /settings` -> `settings_page()` -- reads `local_network`,
  `admin_username`, `block_page_mode` (default `"terminate"`),
  `adguard_url`, `adguard_username`, `household_time_zone` (Phase 8,
  default `"UTC"`) settings. Renders `SETTINGS_BODY`. (Never reads or
  displays `admin_password_hash` or `adguard_password` -- both password
  fields are always blank/write-only.)
- `POST /settings/household-time-zone` -> `update_household_time_zone()`
  (Phase 8) -- form field `household_time_zone`, validated against
  `zoneinfo.available_timezones()`. Only used as the default a new
  Schedule's own `time_zone` is created with (see
  `docs/database/schema.md`'s `schedules` table) -- changing it never
  moves an already-created schedule's meaning.
- `POST /settings/local-network` -> `update_local_network()` -- form field
  `local_network` (space-separated CIDRs). No format validation beyond
  `.strip()` -- an invalid CIDR just fails silently at match time in
  `matching.ip_in_configured_lan()`. Saving an empty value flashes a
  specific message explaining the LAN check is now disabled.
- `POST /settings/block-page-mode` -> `update_block_page_mode()` -- form
  field `block_page_mode`, must be `"redirect"` or `"terminate"` or it's
  rejected with an error flash.
- `POST /settings/admin` -> `update_admin()` -- form fields
  `admin_username` (required, non-empty), `admin_password` (optional --
  leaving it blank keeps the current password hash). Updates
  `admin_username` unconditionally; only rehashes and updates
  `admin_password_hash` if a new password was actually submitted.
- `POST /settings/adguard` -> `update_adguard_settings()` -- form fields
  `adguard_url`, `adguard_username` (required, non-empty),
  `adguard_password` (optional -- leaving it blank keeps the current
  value, same pattern as `/settings/admin` above, except this one stores
  the password in plaintext since it has to be replayed as HTTP Basic
  Auth against AdGuard's own API, not verified locally). Seeded on first
  run from `ADGUARD_URL`/`ADGUARD_USERNAME`/`ADGUARD_PASSWORD` (added
  2026-08-30).
- `POST /settings/adguard/refresh` -> `refresh_adguard_filters()` --
  calls `adguard_client.refresh_filters()` with the stored connection
  settings. Flashes an error (not a 500) if the settings are incomplete
  or AdGuard is unreachable; otherwise flashes how many filter lists had
  new content (0 is a normal, healthy result). Added 2026-08-30.
- `_adguard_ui_url(adguard_url)` (added 2026-09-07, not a route -- a
  helper `settings_page()` calls) -- builds an "Open AdGuard's own
  dashboard" link for a quick click-through to AdGuard's own admin UI
  (full query log, blocked-domain stats, charts; asked for explicitly as
  a link-out, with tighter in-dashboard stats integration deferred to a
  future phase). Deliberately does NOT reuse `adguard_url`'s own host --
  that's the dashboard-to-AdGuard API address, always `127.0.0.1` under
  this project's shared `network_mode: host` setup regardless of
  `ADGUARD_WEB_BIND` (see `.env.example`), so a link built from it would
  send the admin's own browser to their own machine, not the Beelink.
  Instead combines the PORT from `adguard_url` with the HOST the browser
  actually used to reach the current page (`request.host`) -- same
  address, different port. Returns `None` (no link rendered) if
  `adguard_url` isn't configured. Can't detect the other real
  precondition for the link to actually load: `ADGUARD_WEB_BIND` must be
  something other than its secure-by-default `127.0.0.1` -- the
  Settings page states this explicitly next to the link rather than
  silently producing a link that fails for most default setups.
- `POST /settings/safesearch` -> `update_safesearch()` (G3, 2026-09-01) --
  one checkbox field `safesearch_enabled`. Only writes
  `settings.safesearch_enabled` (`"1"`/`"0"`) -- doesn't call AdGuard
  directly; `controller/adguard_sync.py`'s `sync_safesearch()` picks up
  the change on its own next cycle, same "dashboard writes intent,
  controller reconciles reality" split as every other AdGuard-facing
  setting on this page. Defaults `"0"` (off) on first run.
- `POST /settings/ca-cert/regenerate` -> `regenerate_ca_cert()` (Phase
  13, 2026-09-06) -- form fields `ca_org`, `ca_common_name` (both
  optional, default to the same values `proxy/entrypoint.sh` uses on
  first run). One-click "rotate now": generates a fresh self-signed CA
  with the exact same `openssl` invocation as first-run generation
  (RSA 2048, SHA-256, 10-year validity, `CA:TRUE`/`keyCertSign`), then
  calls `_replace_ca_cert_pair()`. Rejects a `/` in either field (breaks
  `openssl -subj`'s field-separator syntax).
- `POST /settings/ca-cert/upload` -> `upload_ca_cert()` (Phase 13) --
  multipart form fields `ca_cert_file`, `ca_key_file`. Validates with
  `_validate_ca_cert_pair()` (real X.509/PEM parsing, `CA:TRUE` +
  `keyCertSign` present, cert and key are an actual matching pair --
  all via `openssl` subprocess calls, not a Python crypto dependency)
  before ever writing anything; rejects with a specific flash error on
  any failure, leaving the existing files untouched. On success, calls
  the same `_replace_ca_cert_pair()` the regenerate route uses.
- Both routes are the single most sensitive write in this app -- they
  replace the private key Squid uses to intercept and mint per-site TLS
  certificates for every device on the network. `_replace_ca_cert_pair()`
  always backs up the previous cert+key (timestamped, alongside the
  originals) before overwriting, and both routes flash
  `CA_CERT_RESTART_NOTICE`: **this is the one dashboard change that isn't
  live** -- Squid only reads `cert=`/`key=` at startup
  (`proxy/squid.conf.template`), so the proxy container needs a manual
  `docker compose restart proxy` afterward, and every device needs the
  new certificate re-trusted since the old one no longer matches. A
  deliberate scope decision (2026-09-05 discussion with the project
  owner): a no-manual-restart version would need a watcher process added
  to the proxy container to detect the change and run `squid -k
  reconfigure` (plus clear Squid's `ssl_db` leaf-cert cache, since cached
  certs were signed by the old CA) -- judged not worth the extra moving
  part for a rare, deliberate admin action.

## Notable UI/UX behaviors

- **The `/domains` "Approve a specific page for {user}" form only renders
  when a user filter is active** (`{% if filtered_user %}` in
  `DOMAINS_BODY`, driven by `?user_id=` on the GET route). This is
  deliberate: approving a single page only makes sense in the context of a
  specific person (there's no "everyone gets this one page" concept the way
  whole-domain assignment has an "Everyone gets this" checkbox), so the
  route (`add_domain_from_url`) itself also hard-refuses without a
  `user_id`.
- **Domain mode badges are color-coded and consistent everywhere**:
  `.badge.mode-splice` (green-tinted), `.badge.mode-bump` (red-tinted),
  `.badge.mode-trusted` (gray) -- same CSS classes used on `/domains`,
  `/domains/<id>`, and the assigned-domains table on `/users/<id>`.
- **The Domain Detail page conditionally shows entire sections**: the
  "Assigned users" grant/revoke table only appears `{% if not d.is_global
  %}` (a global domain has no per-user assignment to manage), and the
  "Allowed paths" section only appears `{% if d.mode == 'bump' %}` (splice
  and trusted modes never consult path rules, so editing them there would be
  misleading).
- **Delete confirmation is client-side only**: destructive buttons
  (`delete_user`, `delete_domain`, `remove_show`) use inline
  `onclick="return confirm('...')"` -- there's no server-side "are you
  sure" step, so a JS-disabled/scripted client can delete without
  confirmation (acceptable here since admin-only + CSRF-guarded).
- **The `/report` approve button only appears for blocked rows with a known
  user OR device** (reworked 2026-08-31 for the device/group case, GH #9):
  `{% if not row.allowed and row.user_id %}` (submits `scope=user`)
  `{% elif not row.allowed and row.device_id %}` (submits `scope=device`)
  -- a row with neither (a genuinely never-seen identity, or a
  pre-migration row from before `access_log.device_id` existed) has
  nothing sensible to approve into, so no button is shown.
- **The built-in Crunchyroll domain (`kind == 'crunchyroll'`) is
  undeletable** but still fully editable (mode/global/note/paths) from
  Domain Detail -- `DOMAIN_DETAIL_BODY` shows an extra explanatory hint for
  it, and `delete_domain()` refuses the delete server-side regardless of
  what the UI does.
- **Waitress, not Flask's dev server, runs in production**: `main()`
  (bottom of file) calls `waitress.serve(app, host=..., port=..., threads=8)`
  -- `app.run()` is never invoked. `DASHBOARD_HOST` (default `127.0.0.1`)
  and `DASHBOARD_PORT` (default `8787`) control the bind address.

## How to add a new route/page

Follow the existing pattern end to end; using an existing resource area
(e.g. Domains) as your template is the fastest way to get the shape right.

1. **Decide the URL and method(s)** following the existing conventions:
   a plain resource path for `GET` list/detail views (e.g. `/widgets`,
   `/widgets/<int:id>`), and a `/<resource>/<action>` path for `POST`
   mutations (e.g. `/widgets/add`, `/widgets/delete`, `/widgets/update`).
2. **Write the handler function** in `dashboard/dashboard.py`, grouped under
   the relevant `# ====...====` section banner (or add a new banner section
   if this is a genuinely new resource). Decorate it `@app.route(...)` then
   `@require_admin` (unless it must be public like `/ca-cert`/`/blocked` --
   justify that explicitly, as those two routes' comments do).
   - Get a connection with `conn = get_db()` (wraps `db.get_conn()` +
     `db.init_db(conn)`).
   - For a `GET` view: query what the template needs, call
     `render_template_string(YOUR_BODY, **context)`, pass that string into
     `render("<nav-key>", body)`, and return it.
   - For a `POST` view: read `request.form.get(...)` fields, validate
     (mirror the style in `add_domain`/`add_path` -- required-field checks,
     length caps, `re.compile()` for anything stored as a regex pattern),
     mutate via `conn.execute(...)` + `conn.commit()`, and return
     `flash_redirect("<endpoint>", "message", error=True/False, **kwargs)`.
     Never return a bare `render(...)` from a POST handler -- always
     redirect (GET-after-POST), consistent with every existing handler.
3. **Define or extend a `..._BODY` template constant** near the top of that
   handler group. Reuse the shared CSS classes (`.add-form`, `button.add`,
   `button.danger`, `.badge.*`, `.hint`, `table`/`td`/`th`) rather than
   adding new ones unless the existing vocabulary genuinely doesn't fit. If
   the new page is a first-class nav destination, add a link to it in
   `BASE`'s `<nav>` block and pick a matching `active` key.
4. **Wire up redirects with `flash_redirect`** for every mutating action, so
   the outcome message shows up automatically on the destination page via
   `render()`'s existing `message`/`error` query-param handling -- no
   additional plumbing needed.
5. **If the new view needs a shared matching/db helper**, check
   `common/matching.py` and `common/db.py` first rather than reimplementing
   logic already used by the proxy side (e.g. `matching.find_domain()`,
   `matching.user_has_domain()`, `db.get_setting()`/`db.set_setting()`) --
   this keeps the dashboard's idea of "is this allowed" consistent with what
   the proxy actually enforces at request time.
6. **If you added a new file under `common/`**, no Dockerfile change is
   needed (`COPY common/*.py /app/` is already a wildcard) -- just
   `import <module_name>` (flat, not `common.<module_name>`) from
   `dashboard.py`, matching the existing `import auth` / `import db` /
   `import matching` style.
7. **Manual smoke test**: run `dashboard/dashboard.py` directly (needs
   `common/*.py` importable alongside it, and env vars `PP_DB_PATH`/
   `PP_CA_CERT_PATH` pointed somewhere writable), or rebuild the
   `dashboard` Docker image and hit the new route through the container.
