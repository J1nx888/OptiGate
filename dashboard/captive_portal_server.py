#!/usr/bin/env python3
"""Phase 4 milestone 3: the captive-portal login server nftables has
been redirecting PREAUTH (unauthenticated_v4) devices' plain-HTTP
traffic to since Phase 3 was designed -- see
phase3/nftables-manager/internal/nft/knftables_adapter.go's
`baselineRules`, which already carries
`ip saddr @unauthenticated_v4 tcp dport 80 redirect to :3131` with a
`# -> future portal` comment in the original design doc. This module
is that future portal; the nftables/interception side needed NO
changes at all.

**Design decision, confirmed by how OS captive-portal detection
actually works (Apple/Google/Microsoft/Firefox all publicly documented
-- see RoadMap.md's dated entry for the exact expected values each OS
checks for) rather than assumed**: every one of these OSes probes a
plain-HTTP URL expecting an EXACT response (Apple:
`captive.apple.com/hotspot-detect.html` -> the literal string
"Success"; Android/Chrome: `.../generate_204` -> a bare 204; Windows:
`www.msftconnecttest.com/connecttest.txt` -> "Microsoft Connect Test";
Firefox: `detectportal.firefox.com/success.txt` -> "success"). Getting
ANYTHING else -- wrong status, wrong body -- is what every one of them
already treats as "there's a captive portal," and each then opens (or
offers to open) exactly the URL it just probed in a real browser/
webview, which -- since nftables redirects by source IP and
destination PORT, not by hostname -- lands right back on THIS server
and renders whatever HTML we send. That means a single handler that
always returns the same login page for every GET, regardless of path
or Host header, is enough to trigger every major OS's native "Sign in
to network" UI AND to show the login form for a device manually typing
a URL -- no per-OS special-casing needed.

**Self-resolving success path, not something this module has to
handle**: once a login succeeds and the device's `is_authenticated`
flag flips, it takes controller/main.py's own next reconcile cycle
(`--poll-interval`, default 5s) to actually move the device's IP from
`unauthenticated_v4` to `authenticated_v4` in the real kernel ruleset
(see controller/policy_state.py). From that point on, this device's
port-80 traffic is no longer redirected here at all -- the OS's own
routine re-probe of its detection URL reaches the REAL Apple/Google/
Microsoft server directly and gets the REAL expected response, which
is what makes the OS dismiss its own captive-portal UI on its own.
Nothing here needs to detect or announce that transition itself.

**No interception for HTTPS (tcp/443) -- a known, deliberate,
documented limitation, not an oversight**: matches virtually every
commercial captive portal (hotel/airport WiFi) in existence, and
`phase3/nftables-manager`'s baseline rules were never designed to
redirect 443 for unauthenticated_v4 either (there is no cert this
project's own CA can present that an ungated device already trusts,
same reasoning as `block_page_server.py`'s own explicit choice never to
terminate TLS for a domain a device hasn't been told to trust). In
practice this is what actually triggers detection for the overwhelming
majority of real usage anyway: the OS's own automatic captive-portal
probe fires immediately upon a new interception generation taking
effect, using plain HTTP specifically because every captive portal
implementation relies on that being interceptable. A technically
determined user who notices the redirect and deliberately avoids ever
completing an HTTP request could evade the prompt indefinitely; RoadMap.md
tracks this explicitly as a possible future hardening item (e.g.
dropping tcp/udp 443 for unauthenticated_v4 too) rather than something
silently added here without verifying it doesn't also break the OS's
own captive-portal-assistant webview, which sometimes needs its own
auxiliary HTTPS requests to render correctly.

**Portal-side admin action, added 2026-08-31**: the design sketch's
admin-facing quick-add path (RoadMap.md) originally offered two ways to
handle a gated device -- "the same portal screen, or a separate device
with real dashboard access." Only the latter existed until now
(Milestone 2's dashboard Bypass/Manage actions). This adds the former,
for when an admin is physically at the gated device itself: a
collapsed `<details>` section on the same login page, asking for the
SAME admin credentials `dashboard/dashboard.py`'s HTTP-Basic login
checks (`common/auth.py`'s `verify_admin_credentials()`, factored out
of `dashboard.py`'s own `_check_admin_auth` so there's exactly one
admin-credential check, not two), offering **Bypass** (identical effect
to the dashboard's own `/devices/bypass_login`) or **assign to a
group**. Shares this module's own per-IP rate limiter with the kid
login form above -- a wrong admin-password guess counts against the
same budget, which is the more conservative choice given this surface
grants strictly more than the kid login ever does.
"""
from __future__ import annotations

import html
import logging
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import auth
import db
import rate_limit
import system_events
from device_identity import resolve_device

log = logging.getLogger("dashboard.captive_portal_server")

# Brute-force protection, added alongside this module's first version
# rather than retrofitted later (this project's standing security
# practice -- see RoadMap.md's cross-cutting security-by-design
# section): a login form an unauthenticated device can reach with no
# rate limiting at all is an obvious guessing-attack surface,
# especially since a kid's own password is realistically short/weak.
# 2026-09-02: factored the actual limiter mechanism out into
# common/rate_limit.py so dashboard.py's own HTTP-Basic admin login
# (audited the same day, found to have none at all) can reuse it
# rather than a second hand-rolled copy -- see that module's docstring.
# Still one shared instance for BOTH forms below (kid login and the
# portal admin action), a deliberate choice, not an oversight -- see
# _handle_admin_action's own comment.
_MAX_ATTEMPTS = 5
_WINDOW_SECONDS = 60.0
_LOGIN_LIMITER = rate_limit.RateLimiter(_MAX_ATTEMPTS, _WINDOW_SECONDS)

# Caps how much of an attacker-controlled username this module will ever
# write into system_events.message -- that column has no length limit of
# its own, and this is a field a hostile client fully controls on every
# single failed attempt.
_LOGGED_USERNAME_MAX_LEN = 100


def _log_failed_login(
    conn: sqlite3.Connection, source: str, client_ip: str, username: str, mac_address: str | None = None
) -> None:
    """Writes a dashboard-visible Events-page row for a failed login/
    admin-action attempt, alongside (not instead of) the log.info/
    log.warning calls at each call site below -- same "layer, don't
    replace" principle common/system_events.py's own docstring already
    established for controller/main.py's background loops. Never logs
    the attempted password, only the username and source IP -- a kid's
    (or an attacker's) mistyped password is still a real, sensitive
    credential-adjacent string not worth persisting anywhere.

    `mac_address` (added 2026-09-07, real gap found by live user
    testing): stored in `detail`, not a new column -- lets
    dashboard.py's pending-devices card answer "has this specific device
    already tried and been denied" via a plain `detail = ?` lookup,
    which matters because a never-assigned device that HAS tried to log
    in (and knows a real household username, just isn't allowed onto
    that account's device list yet) is a different situation from one
    that's simply never been used. Only `_handle_login()` below passes
    this -- `_handle_admin_action()`'s own failed-credential path checks
    admin credentials before it would resolve a device at all, so
    there's no device in hand yet at that point without adding a lookup
    purely for this, and that event type isn't "a device tried to log
    in" the way this one is anyway."""
    truncated = username[:_LOGGED_USERNAME_MAX_LEN]
    system_events.log_event(
        conn, source, "error",
        f"Failed login attempt from {client_ip} (username: {truncated!r})",
        detail=mac_address,
    )

_PAGE_TEMPLATE = """\
<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Sign in</title>
<style>
:root{{color-scheme:light dark;}}
body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:24rem;margin:4rem auto;
padding:0 1.25rem;text-align:center;color:#1e293b;}}
@media (prefers-color-scheme:dark){{body{{color:#e5eaf3;}}}}
.icon{{width:56px;height:56px;border-radius:16px;background:#2f6fed;display:inline-flex;
align-items:center;justify-content:center;margin:0 auto 1rem;}}
h1{{font-size:1.15rem;margin:0 0 .5rem;}}
p{{font-size:.92rem;opacity:.75;}}
.error{{color:#dc2626;font-size:.85rem;margin:0 0 .75rem;}}
form{{display:flex;flex-direction:column;gap:.6rem;margin-top:1.25rem;}}
input,select{{font-size:1rem;padding:.55rem .7rem;border-radius:8px;border:1px solid #94a3b8;
background:transparent;color:inherit;}}
button{{font-size:1rem;padding:.6rem;border-radius:8px;border:none;background:#2f6fed;
color:white;cursor:pointer;}}
details{{margin-top:1.75rem;text-align:left;}}
summary{{cursor:pointer;font-size:.85rem;opacity:.65;}}
details form{{margin-top:.75rem;}}
.group-row{{display:flex;gap:.4rem;}}
.group-row select{{flex:1;}}
.group-row button{{background:#475569;flex:none;}}
</style></head><body>
<div class='icon'>
<svg width='28' height='28' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2.2'
stroke-linecap='round' stroke-linejoin='round'><path d='M12 3l8 3.5v5.2c0 4.7-3.2 8.6-8 9.8
-4.8-1.2-8-5.1-8-9.8V6.5L12 3z'/></svg>
</div>
<h1>Sign in to use the internet</h1>
<p>This device hasn't logged in yet. Use your own username and password below.</p>
{error}
<form method="post" action="/">
  <input type="text" name="username" placeholder="Username" autocapitalize="none" autocorrect="off" required>
  <input type="password" name="password" placeholder="Password" required>
  <button type="submit">Sign in</button>
</form>
<p>Not your login? Ask a parent to bypass or assign this device from the dashboard instead.</p>
<details>
<summary>Parent or admin? Handle this device directly</summary>
<form method="post" action="/admin">
  {admin_error}
  <input type="text" name="admin_username" placeholder="Admin username" autocapitalize="none" autocorrect="off" required>
  <input type="password" name="admin_password" placeholder="Admin password" required>
  <button type="submit" name="action" value="bypass">Let this device online without logging in</button>
  <button type="submit" name="action" value="ignore">Ignore this device (exclude it from filtering entirely)</button>
{group_row}
</form>
</details>
</body></html>
"""

# Only rendered when at least one group already exists (dashboard
# /groups) -- a device an admin wants group-based rules for, without
# needing a personal login, matching the design sketch's own "assign
# to a device group" phrasing.
_GROUP_ROW_TEMPLATE = """\
  <div class="group-row">
    <select name="group_id">{options}</select>
    <button type="submit" name="action" value="assign_group">Assign to group</button>
  </div>\
"""

_SUCCESS_TEMPLATE = """\
<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Signed in</title>
<style>
:root{{color-scheme:light dark;}}
body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:24rem;margin:4rem auto;
padding:0 1.25rem;text-align:center;color:#1e293b;}}
@media (prefers-color-scheme:dark){{body{{color:#e5eaf3;}}}}
h1{{font-size:1.15rem;margin:0 0 .5rem;}}
p{{font-size:.92rem;opacity:.75;}}
.note{{background:#fef3c7;color:#92400e;border-radius:8px;padding:.6rem .8rem;
text-align:left;margin-top:1.25rem;}}
@media (prefers-color-scheme:dark){{.note{{background:#3f2d0a;color:#fcd34d;}}}}
</style></head><body>
<h1>You're signed in.</h1>
<p>It can take up to about 10 seconds for this device's internet access to
actually open up. Try reloading whatever page you were on.</p>
{bump_reminder}
</body></html>
"""

# Shown on the success page only when this same user already has a
# DIFFERENT device with SSL-Bump enabled -- see this module's own
# docstring's design-sketch reference (RoadMap.md): the login flow
# only ever grants DNS-tier access, so a kid whose usual device has
# full SSL-Bump refinement logging in from a NEW device here would
# otherwise have no idea why something that works on their other
# device doesn't work on this one.
_BUMP_REMINDER_HTML = (
    '<p class="note">Heads up: this is only basic (DNS-level) access. '
    "Your other device has extra access set up by a parent -- ask them "
    "to do the same for this one if you need it here too.</p>"
)

_ADMIN_ACTION_SUCCESS_TEMPLATE = """\
<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Done</title>
<style>
:root{{color-scheme:light dark;}}
body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:24rem;margin:4rem auto;
padding:0 1.25rem;text-align:center;color:#1e293b;}}
@media (prefers-color-scheme:dark){{body{{color:#e5eaf3;}}}}
h1{{font-size:1.15rem;margin:0 0 .5rem;}}
p{{font-size:.92rem;opacity:.75;}}
</style></head><body>
<h1>Done.</h1>
<p>{message} It can take up to about 10 seconds for this device's
internet access to actually open up.</p>
</body></html>
"""


def _render_admin_success(message: str) -> bytes:
    return _ADMIN_ACTION_SUCCESS_TEMPLATE.format(message=html.escape(message)).encode("utf-8")


def _fetch_groups(conn: sqlite3.Connection) -> list:
    return conn.execute("SELECT id, name FROM groups ORDER BY name").fetchall()


def _render(
    username_error: str | None = None, admin_error: str | None = None, groups: list | None = None
) -> bytes:
    error_html = f'<p class="error">{html.escape(username_error)}</p>' if username_error else ""
    admin_error_html = f'<p class="error">{html.escape(admin_error)}</p>' if admin_error else ""
    if groups:
        options = "".join(
            f'<option value="{g["id"]}">{html.escape(g["name"])}</option>' for g in groups
        )
        group_row = _GROUP_ROW_TEMPLATE.format(options=options)
    else:
        group_row = ""
    return _PAGE_TEMPLATE.format(
        error=error_html, admin_error=admin_error_html, group_row=group_row
    ).encode("utf-8")


def _render_success(show_bump_reminder: bool) -> bytes:
    reminder_html = _BUMP_REMINDER_HTML if show_bump_reminder else ""
    return _SUCCESS_TEMPLATE.format(bump_reminder=reminder_html).encode("utf-8")


class _CaptivePortalHandler(BaseHTTPRequestHandler):
    # BaseHTTPRequestHandler logs every request to stderr via
    # log_message() by default -- redirect through the logging module,
    # matching block_page_server.py's own precedent.
    def log_message(self, format: str, *args) -> None:  # noqa: A002 -- matches stdlib's own signature
        log.info("%s - %s", self.address_string(), format % args)

    def _send_html(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # Every response here is per-device, per-moment login state --
        # never something an OS's own captive-portal prober or a
        # browser should cache and reuse.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler's own naming convention
        # Deliberately the SAME response regardless of path/Host -- see
        # this module's own docstring for why that alone is enough to
        # trigger every major OS's captive-portal-detected UI. Groups
        # DO need a real DB read (unlike the rest of this response,
        # which is static) so the admin section's dropdown reflects
        # whatever groups actually exist right now.
        conn = db.get_conn()
        try:
            groups = _fetch_groups(conn)
        finally:
            conn.close()
        self._send_html(200, _render(groups=groups))

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(length) if length else b""
        fields = parse_qs(raw_body.decode("utf-8", errors="replace"))
        path = self.path.split("?", 1)[0]

        conn = db.get_conn()
        try:
            if path == "/admin":
                self._handle_admin_action(conn, fields)
            else:
                # Every other path is the kid-login form -- matching
                # do_GET's own "same response regardless of path"
                # design, POST only branches on the one path the admin
                # section's own form actually targets.
                username = (fields.get("username") or [""])[0].strip()
                password = (fields.get("password") or [""])[0]
                self._handle_login(conn, username, password)
        finally:
            conn.close()

    def _handle_login(self, conn: sqlite3.Connection, username: str, password: str) -> None:
        client_ip = self.client_address[0]
        if _LOGIN_LIMITER.is_limited(client_ip):
            log.warning("rate-limited login attempt from %s", client_ip)
            self._send_html(
                200, _render("Too many attempts -- wait a minute before trying again.", groups=_fetch_groups(conn))
            )
            return

        device = resolve_device(conn, client_ip)
        if device is None:
            # By construction this request could only have reached us
            # via nftables' unauthenticated_v4 redirect, which requires
            # an active device_bindings row to exist in the first
            # place -- reaching this branch means it was deactivated in
            # the narrow window since, not the common case. Fails
            # closed (no login granted) with an honest explanation
            # rather than silently retrying.
            log.warning("login attempt from %s but no active binding was found", client_ip)
            self._send_html(
                200,
                _render(
                    "We couldn't identify your device on the network yet -- try again shortly.",
                    groups=_fetch_groups(conn),
                ),
            )
            return

        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None or not auth.verify_password(password, user["password_hash"]):
            _LOGIN_LIMITER.record_failure(client_ip)
            log.info("failed login for username=%r from device %s", username, device["mac_address"])
            _log_failed_login(conn, "captive_portal_login", client_ip, username, mac_address=device["mac_address"])
            self._send_html(200, _render("Incorrect username or password.", groups=_fetch_groups(conn)))
            return

        # Deliberately NOT clearing _LOGIN_LIMITER here (fixed 2026-09-02,
        # a real bug found by code review): this limiter is shared with
        # _handle_admin_action() below on purpose, but that means a
        # success on ONE surface used to wipe out failures recorded
        # against the OTHER -- a household member's normal kid login
        # succeeding from a shared/NAT'd IP would silently hand an
        # in-progress admin-password guesser a fresh 5-attempt budget,
        # exactly defeating the "shared, more conservative budget"
        # reasoning this sharing exists for in the first place. Recorded
        # failures now simply age out of the window on their own
        # (_WINDOW_SECONDS) rather than being reset by an unrelated
        # credential domain's success.

        # Grants DNS-tier access ONLY -- never bump_enabled, matching
        # Phase 4's design sketch exactly (RoadMap.md). COALESCE so a
        # device an admin already assigned to a different user (or a
        # group) keeps that assignment; this login only fills in
        # user_id when nothing has claimed the device yet.
        conn.execute(
            "UPDATE devices SET is_authenticated = 1, user_id = COALESCE(user_id, ?) WHERE id = ?",
            (user["id"], device["id"]),
        )
        conn.commit()
        log.info("device %s authenticated as %s", device["mac_address"], username)

        # Does this same user already have a DIFFERENT device with
        # SSL-Bump enabled? If so, this login -- DNS-tier only, always
        # -- is a real step down from what they're used to elsewhere,
        # worth explaining rather than leaving them to wonder why
        # something that works on their other device doesn't work here.
        has_bump_elsewhere = conn.execute(
            "SELECT 1 FROM devices WHERE user_id = ? AND bump_enabled = 1 AND id != ? LIMIT 1",
            (user["id"], device["id"]),
        ).fetchone() is not None
        self._send_html(200, _render_success(has_bump_elsewhere))

    def _handle_admin_action(self, conn: sqlite3.Connection, fields: dict) -> None:
        client_ip = self.client_address[0]
        admin_username = (fields.get("admin_username") or [""])[0].strip()
        admin_password = (fields.get("admin_password") or [""])[0]
        action = (fields.get("action") or [""])[0]

        # Shares the kid-login form's own rate limiter above rather
        # than a separate budget -- see this module's own docstring for
        # why that's the more conservative choice (this surface grants
        # strictly more than the kid login ever does).
        if _LOGIN_LIMITER.is_limited(client_ip):
            log.warning("rate-limited admin action attempt from %s", client_ip)
            self._send_html(
                200,
                _render(
                    admin_error="Too many attempts -- wait a minute before trying again.",
                    groups=_fetch_groups(conn),
                ),
            )
            return

        expected_user = db.get_setting(conn, "admin_username")
        expected_hash = db.get_setting(conn, "admin_password_hash")
        if not auth.verify_admin_credentials(admin_username, admin_password, expected_user, expected_hash):
            _LOGIN_LIMITER.record_failure(client_ip)
            log.info("failed portal admin action attempt from %s", client_ip)
            _log_failed_login(conn, "captive_portal_admin_action", client_ip, admin_username)
            self._send_html(
                200,
                _render(admin_error="Incorrect admin username or password.", groups=_fetch_groups(conn)),
            )
            return

        # See the matching comment in _handle_login() above -- this
        # limiter is deliberately shared between both forms, so clearing
        # it here on an admin success would also wipe out failures
        # recorded against the kid-login form (and vice versa), reopening
        # the exact cross-surface reset this fix closes.

        device = resolve_device(conn, client_ip)
        if device is None:
            log.warning("admin action from %s but no active binding was found", client_ip)
            self._send_html(
                200,
                _render(
                    admin_error="We couldn't identify this device on the network yet -- try again shortly.",
                    groups=_fetch_groups(conn),
                ),
            )
            return

        if action == "bypass":
            # Identical effect to dashboard.py's own
            # /devices/bypass_login -- only ever touches this one
            # column, same reasoning as that route's own docstring.
            conn.execute("UPDATE devices SET bypass_login = 1 WHERE id = ?", (device["id"],))
            conn.commit()
            log.info("device %s bypassed via portal admin action", device["mac_address"])
            self._send_html(200, _render_admin_success("This device no longer needs to log in."))
            return

        if action == "ignore":
            # RoadMap.md's dated entry (item 22): bypass_login and
            # ignored are two different things -- bypass skips only the
            # captive-portal login while still applying full DNS-tier
            # filtering, but a device running its own DNS-hijack-
            # detecting security software (found live: a work laptop
            # running Cisco Umbrella/OpenDNS) needs to be excluded from
            # DNS interception ENTIRELY, which only `ignored` does. That
            # was only fixable from the dashboard's Devices page before
            # this -- an admin standing at the gated device itself had
            # no equivalent one-click option here, same gap `bypass`
            # already closed for the "skip login" case. Same semantics
            # as dashboard.py's own bulk_set_ignored_devices(): ignored
            # and a user/group assignment are mutually exclusive at the
            # UI level (devices' own CHECK constraint doesn't require
            # it, but every other ignore path in this project clears
            # both), so this clears any prior assignment too rather than
            # leaving a stale one behind a now-ignored device.
            conn.execute(
                "UPDATE devices SET ignored = 1, user_id = NULL, group_id = NULL WHERE id = ?",
                (device["id"],),
            )
            conn.commit()
            log.info("device %s ignored via portal admin action", device["mac_address"])
            self._send_html(200, _render_admin_success("This device is now excluded from filtering entirely."))
            return

        if action == "assign_group":
            group_id = (fields.get("group_id") or [""])[0]
            group = conn.execute("SELECT id, name FROM groups WHERE id = ?", (group_id,)).fetchone()
            if group is None:
                self._send_html(
                    200,
                    _render(admin_error="That group no longer exists -- refresh and try again.",
                            groups=_fetch_groups(conn)),
                )
                return
            # group_id/user_id are mutually exclusive (devices' own
            # CHECK constraint) -- clearing user_id here is required,
            # not just tidy, or this UPDATE would violate it whenever
            # the device already had a personal owner. is_authenticated
            # is set explicitly rather than relying on
            # common/policy_class.py's bypass_login fallback (2026-08-31
            # fix) -- both are true here, which is fine, but a group
            # assignment reads more clearly as "this device is now
            # authenticated, and governed by this group" than as a
            # bypass side effect.
            conn.execute(
                "UPDATE devices SET group_id = ?, user_id = NULL, is_authenticated = 1 WHERE id = ?",
                (group["id"], device["id"]),
            )
            conn.commit()
            log.info(
                "device %s assigned to group %r via portal admin action", device["mac_address"], group["name"]
            )
            self._send_html(200, _render_admin_success(f"Assigned to the {group['name']} group."))
            return

        self._send_html(200, _render(admin_error="Unknown action.", groups=_fetch_groups(conn)))


def start(host: str = "0.0.0.0", port: int = 3131) -> ThreadingHTTPServer:
    """Starts the captive-portal server on its own background thread
    and returns the live server object -- call `.shutdown()` on it to
    stop. `ThreadingHTTPServer` (not the single-threaded `HTTPServer`,
    same reasoning as block_page_server.py) so one slow/hanging client
    can't block every other gated device's login attempt, and so each
    request handler runs on its own thread -- required here (unlike
    block_page_server.py) since do_POST opens its own sqlite3
    connection per request; sqlite3.Connection objects are only usable
    from the thread that created them.
    """
    server = ThreadingHTTPServer((host, port), _CaptivePortalHandler)
    thread = threading.Thread(target=server.serve_forever, name="captive-portal-server", daemon=True)
    thread.start()
    return server
