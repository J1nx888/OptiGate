#!/usr/bin/env python3
"""Captive-portal login server. nftables redirects PREAUTH
(unauthenticated_v4) devices' plain-HTTP traffic here (see
phase3/nftables-manager's baseline rules) -- no changes are needed on
that side to add or modify what this module does.

Every GET returns the same login page regardless of path or Host
header. This is deliberate: every major OS's captive-portal detector
probes a specific plain-HTTP URL expecting an exact response (Apple:
`captive.apple.com/hotspot-detect.html` -> "Success"; Android/Chrome:
`.../generate_204` -> a bare 204; Windows:
`www.msftconnecttest.com/connecttest.txt` -> "Microsoft Connect Test";
Firefox: `detectportal.firefox.com/success.txt` -> "success"). Any
other response is what makes each OS show its "Sign in to network" UI,
which then opens exactly the URL it just probed -- since nftables
redirects by source IP and port, not hostname, that request lands back
here regardless of which URL it was, so one handler covers every OS
without per-OS branching.

Nothing here needs to detect or announce a successful login: once
`is_authenticated` flips, controller/main.py's own reconcile loop
moves the device from `unauthenticated_v4` to `authenticated_v4` (see
controller/policy_state.py) within one poll interval. From that point
the device's port-80 traffic isn't redirected here at all, so the OS's
own next re-probe reaches the real detection endpoint directly and
dismisses its UI on its own.

No interception for HTTPS (tcp/443) -- deliberate, not an oversight:
there is no cert this project's own CA can present that an ungated
device already trusts (same reasoning as block_page_server.py's own
choice never to terminate TLS for a domain a device hasn't been told
to trust). A user who notices the redirect and never completes a
plain-HTTP request could evade the prompt indefinitely; tracked as a
possible future hardening item in RoadMap.md rather than added here
without checking it doesn't also break the OS's own captive-portal
webview, which sometimes needs its own HTTPS requests to render.

The `<details>` admin section lets an admin standing at the gated
device itself Bypass, Ignore, or assign it to a group, using the same
credential check as the dashboard's own HTTP-Basic login
(`common/auth.py`'s `verify_admin_credentials()`). It shares the kid
login form's own rate limiter (`_LOGIN_LIMITER`) rather than a separate
budget -- deliberate, since this surface grants strictly more than the
kid login ever does.

Every device-claiming action (kid login, Bypass, Ignore, assign to
group) requires a device name before it succeeds, unless the device
already has one -- see `_render()`'s, `_handle_login()`'s, and
`_handle_admin_action()`'s own `needs_label` checks.
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

# Rate-limits both login forms below against brute-force guessing -- a
# kid's own password is realistically short/weak, and this form has no
# other protection. One shared instance for BOTH forms (kid login and
# the admin action), not a separate budget for each -- see
# _handle_admin_action's own comment on why.
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
    log.warning calls at each call site below. Never logs the attempted
    password, only the username and source IP.

    `mac_address` is stored in `detail`, not a new column: it lets
    dashboard.py's pending-devices card answer "has this specific
    device already tried and been denied" via a plain `detail = ?`
    lookup. Only `_handle_login()` below passes it -- `_handle_admin_
    action()`'s own failed-credential path checks admin credentials
    before it would resolve a device at all, so there's no device in
    hand yet at that point."""
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
{label_field}
  <button type="submit">Sign in</button>
</form>
<p>Not your login? Ask a parent to bypass or assign this device from the dashboard instead.</p>
<details>
<summary>Parent or admin? Handle this device directly</summary>
<form method="post" action="/admin">
  {admin_error}
  <input type="text" name="admin_username" placeholder="Admin username" autocapitalize="none" autocorrect="off" required>
  <input type="password" name="admin_password" placeholder="Admin password" required>
{label_field}
  <button type="submit" name="action" value="bypass">Let this device online without logging in</button>
  <button type="submit" name="action" value="ignore">Ignore this device (exclude it from filtering entirely)</button>
{group_row}
</form>
</details>
</body></html>
"""

# Rendered in both forms above via the same {label_field} placeholder,
# only when the device this request resolves to doesn't already have a
# label -- see _render()'s own `needs_label` param.
_LABEL_FIELD_TEMPLATE = """\
  <input type="text" name="label" placeholder="Name this device (e.g. Alex's phone)" value="{value}" required>\
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
# DIFFERENT device with SSL-Bump enabled -- this login only ever grants
# DNS-tier access, so a kid used to full access on another device would
# otherwise have no idea why this one is more limited.
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
    username_error: str | None = None, admin_error: str | None = None, groups: list | None = None,
    *, needs_label: bool = False, label_value: str = "",
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
    # label_value re-populates what was already typed across a
    # validation error (a wrong password, a missing/nonexistent group)
    # so a multi-field mistake doesn't cost retyping the device's name.
    label_field = _LABEL_FIELD_TEMPLATE.format(value=html.escape(label_value)) if needs_label else ""
    return _PAGE_TEMPLATE.format(
        error=error_html, admin_error=admin_error_html, group_row=group_row, label_field=label_field,
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
        # Same response regardless of path/Host -- see the module
        # docstring. Groups need a live DB read so the admin dropdown
        # reflects reality; resolving the device here too decides up
        # front whether either form needs to ask for a name (see
        # _render()'s own `needs_label`) -- a device that can't be
        # resolved yet simply isn't asked.
        conn = db.get_conn()
        try:
            groups = _fetch_groups(conn)
            device = resolve_device(conn, self.client_address[0])
            needs_label = device is not None and not (device["label"] or "").strip()
        finally:
            conn.close()
        self._send_html(200, _render(groups=groups, needs_label=needs_label))

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
                label = (fields.get("label") or [""])[0].strip()
                self._handle_login(conn, username, password, label)
        finally:
            conn.close()

    def _handle_login(self, conn: sqlite3.Connection, username: str, password: str, label: str) -> None:
        client_ip = self.client_address[0]
        if _LOGIN_LIMITER.is_limited(client_ip):
            log.warning("rate-limited login attempt from %s", client_ip)
            self._send_html(
                200, _render("Too many attempts -- wait a minute before trying again.", groups=_fetch_groups(conn))
            )
            return

        device = resolve_device(conn, client_ip)
        if device is None:
            # Reaching here requires an active device_bindings row (how
            # this request got redirected here at all), so None means it
            # was deactivated in the narrow window since. Fails closed
            # with an honest explanation rather than retrying silently.
            log.warning("login attempt from %s but no active binding was found", client_ip)
            self._send_html(
                200,
                _render(
                    "We couldn't identify your device on the network yet -- try again shortly.",
                    groups=_fetch_groups(conn),
                ),
            )
            return

        # Computed once, up front, so a device that already has a name
        # (from an earlier login, or set on the Devices page) is never
        # asked again.
        needs_label = not (device["label"] or "").strip()

        if not username or not password:
            # A real login never has an empty username or password (both
            # fields are `required`) -- this is an OS captive-portal
            # assistant auto-POSTing the bare form, or a resubmitted blank
            # one. Re-render and stop: this can never succeed, so it's
            # not worth logging or spending the rate-limit budget on.
            self._send_html(200, _render(groups=_fetch_groups(conn), needs_label=needs_label, label_value=label))
            return

        # Case-insensitive on purpose -- nothing else about this login
        # (the password, the admin dashboard login) is case-sensitive.
        # add_user() refuses a second username differing only by case,
        # so this can never become ambiguous.
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        if user is None or not auth.verify_password(password, user["password_hash"]):
            _LOGIN_LIMITER.record_failure(client_ip)
            log.info("failed login for username=%r from device %s", username, device["mac_address"])
            _log_failed_login(conn, "captive_portal_login", client_ip, username, mac_address=device["mac_address"])
            self._send_html(
                200,
                _render(
                    "Incorrect username or password.", groups=_fetch_groups(conn),
                    needs_label=needs_label, label_value=label,
                ),
            )
            return

        if needs_label and not label:
            # Credentials are correct -- only the missing name blocks
            # this login. Not a credential guess (don't touch the rate
            # limiter) and not a failure worth logging, same as the
            # blank-submission branch above.
            self._send_html(
                200,
                _render(
                    "Please also give this device a name (e.g. \"Alex's phone\") so it's easy to find later.",
                    groups=_fetch_groups(conn), needs_label=True, label_value=label,
                ),
            )
            return

        # Deliberately NOT clearing _LOGIN_LIMITER here: it's shared with
        # _handle_admin_action() below, and a success on one surface
        # clearing it would silently hand a fresh attempts budget to an
        # in-progress guess against the OTHER surface. Failures only age
        # out of the window on their own (_WINDOW_SECONDS).

        # Grants DNS-tier access ONLY -- never bump_enabled. Both
        # COALESCEs are no-ops when already set: user_id so a device an
        # admin already assigned to a user/group keeps that assignment,
        # label so an already-named device keeps its name (`label` is
        # only ever non-empty here when needs_label was True, and the
        # check above already rejected an empty one in that case).
        conn.execute(
            "UPDATE devices SET is_authenticated = 1, user_id = COALESCE(user_id, ?), "
            "label = COALESCE(label, ?) WHERE id = ?",
            (user["id"], label or None, device["id"]),
        )
        conn.commit()
        log.info("device %s authenticated as %s", device["mac_address"], username)
        # Auditable, dashboard-visible record that a device joined via
        # the portal -- the counterpart to the failed-attempt rows above.
        system_events.log_event(
            conn, "captive_portal_login", "info",
            f"{username!r} logged in from device {device['mac_address']} ({client_ip})",
        )

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
        label = (fields.get("label") or [""])[0].strip()

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

        # Same reasoning as _handle_login()'s own comment -- don't clear
        # the shared limiter here either.

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

        # Same requirement as _handle_login() -- checked once here,
        # before dispatching on `action`, since bypass/ignore/
        # assign_group all need it. "ignore" isn't exempt: the device it
        # excludes (e.g. a laptop running its own DNS-hijack detection)
        # is exactly the kind an admin wants to recognize by name later.
        needs_label = not (device["label"] or "").strip()
        if needs_label and not label:
            self._send_html(
                200,
                _render(
                    admin_error="Please also give this device a name (e.g. \"Kitchen Echo\") so it's easy to find later.",
                    groups=_fetch_groups(conn), needs_label=True, label_value=label,
                ),
            )
            return

        if action == "bypass":
            # Identical effect to dashboard.py's own
            # /devices/bypass_login. The label COALESCE is the same
            # no-op-if-already-named idea as _handle_login()'s own
            # UPDATE.
            conn.execute(
                "UPDATE devices SET bypass_login = 1, label = COALESCE(label, ?) WHERE id = ?",
                (label or None, device["id"]),
            )
            conn.commit()
            log.info("device %s bypassed via portal admin action", device["mac_address"])
            self._send_html(200, _render_admin_success("This device no longer needs to log in."))
            return

        if action == "ignore":
            # `ignored` differs from `bypass_login`: bypass only skips
            # the portal login while DNS-tier filtering still applies; a
            # device running its own DNS-hijack detection (e.g.
            # corporate security software) needs to be excluded from
            # interception entirely, which only `ignored` does. Clears
            # any prior user/group assignment too -- same mutual-
            # exclusion convention as dashboard.py's own
            # bulk_set_ignored_devices().
            conn.execute(
                "UPDATE devices SET ignored = 1, user_id = NULL, group_id = NULL, label = COALESCE(label, ?) "
                "WHERE id = ?",
                (label or None, device["id"]),
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
                            groups=_fetch_groups(conn), needs_label=needs_label, label_value=label),
                )
                return
            # group_id/user_id are mutually exclusive (devices' own CHECK
            # constraint) -- clearing user_id is required here, not just
            # tidy. is_authenticated is set explicitly rather than
            # relying on policy_class.py's bypass_login fallback, since a
            # group assignment reads more clearly as "authenticated,
            # governed by this group" than as a bypass side effect.
            conn.execute(
                "UPDATE devices SET group_id = ?, user_id = NULL, is_authenticated = 1, "
                "label = COALESCE(label, ?) WHERE id = ?",
                (group["id"], label or None, device["id"]),
            )
            conn.commit()
            log.info(
                "device %s assigned to group %r via portal admin action", device["mac_address"], group["name"]
            )
            self._send_html(200, _render_admin_success(f"Assigned to the {group['name']} group."))
            return

        self._send_html(
            200,
            _render(
                admin_error="Unknown action.", groups=_fetch_groups(conn),
                needs_label=needs_label, label_value=label,
            ),
        )


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
