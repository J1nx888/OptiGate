#!/usr/bin/env python3
"""Web dashboard for OptiGate (formerly "parental proxy v2").

Everything configurable lives here: users (proxy logins), domains (with
mode splice/bump/trusted, global-vs-per-user access, and per-domain path
restrictions for bump-mode domains), each user's approved Crunchyroll
shows, the access report (with one-click approve on blocked entries), and
settings (LAN CIDR, admin credentials).

Auth: HTTP Basic against admin credentials stored in `settings` (bootstrapped
once from DASHBOARD_USER/DASHBOARD_PASSWORD on first run, editable from the
Settings page afterward). /ca-cert is deliberately unauthenticated -- it's a
public certificate, not a secret, and every client device needs to fetch it.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, redirect, render_template_string, request, send_file, url_for

sys.path.insert(0, str(Path(__file__).parent))

import zoneinfo

import adguard_client
import adguard_config_sync
import auth
import backup
import category_fetch
import cr_api
import db
import matching
import optigate_rewrite
import rate_limit
import schedule_eval
import system_events

CA_CERT_PATH = Path(os.environ.get("OG_CA_CERT_PATH", "/config/ssl_cert/ca_cert.pem"))
# Not independently configurable via its own env var in docker-compose.yml
# today (only OG_CA_CERT_PATH is wired up there) -- derived from
# OG_CA_CERT_PATH's own directory so the two stay colocated the same way
# proxy/entrypoint.sh's SSL_DIR already colocates them, but still
# independently overridable (e.g. for a test that wants both paths under
# one throwaway tmp_path without depending on this derivation).
CA_KEY_PATH = Path(os.environ.get("OG_CA_KEY_PATH", str(CA_CERT_PATH.parent / "ca_key.pem")))

log = logging.getLogger("dashboard")

app = Flask(__name__)


@app.before_request
def _reject_cross_origin_writes():
    """Lightweight CSRF guard. The dashboard authenticates with HTTP Basic,
    so a browser that has logged in once will attach credentials to a
    cross-site form POST automatically. Browsers always send an Origin
    header on such POSTs; reject any whose Origin (or, failing that,
    Referer) host isn't this dashboard. A request carrying neither header
    is a non-browser client (curl, a script) with no ambient credentials to
    abuse, so it's allowed through."""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    for header in ("Origin", "Referer"):
        value = request.headers.get(header)
        if value:
            if urlparse(value).netloc != request.host:
                return Response("Cross-origin request blocked.", 403)
            return None
    return None


def get_db():
    # Fixed 2026-09-02, a real efficiency gap found by code review:
    # this used to also call db.init_db(conn) here -- re-executing the
    # entire 29-statement CREATE TABLE IF NOT EXISTS schema script plus
    # _migrate()'s 3 PRAGMA table_info introspection queries on EVERY
    # single request. The schema is a property of the database FILE,
    # not of any one connection, so it only ever needs establishing
    # once per process lifetime -- done explicitly at import time,
    # right before bootstrap_admin() (see the bottom of this file),
    # rather than as a side effect of every route handler's own call
    # here.
    return db.get_conn()


# ==========================================================
# ADMIN AUTH (DB-backed, bootstrapped from env on first run)
# ==========================================================

def bootstrap_admin() -> None:
    conn = get_db()
    try:
        env_user = os.environ.get("DASHBOARD_USER")
        env_pass = os.environ.get("DASHBOARD_PASSWORD")
        if db.get_setting(conn, "admin_username") is None:
            db.set_setting(conn, "admin_username", env_user or "admin")
        if db.get_setting(conn, "admin_password_hash") is None:
            if env_pass:
                db.set_setting(conn, "admin_password_hash", auth.hash_password(env_pass))
            else:
                generated = secrets.token_urlsafe(12)
                db.set_setting(conn, "admin_password_hash", auth.hash_password(generated))
                username = db.get_setting(conn, "admin_username")
                print(
                    "\n" + "=" * 64
                    + "\n  No DASHBOARD_PASSWORD was set. Generated an admin login:\n"
                    + f"    username: {username}\n"
                    + f"    password: {generated}\n"
                    + "  Change it from the Settings page after logging in.\n"
                    + "=" * 64 + "\n",
                    file=sys.stderr, flush=True,
                )
        db.set_setting_if_absent(conn, "local_network", os.environ.get("LOCAL_NETWORK", "192.168.1.0/24"))
        db.set_setting_if_absent(conn, "secret_key", secrets.token_hex(32))
        # AdGuard connection settings, for the Settings page's "Check for
        # filter updates now" button (common/adguard_client.py) -- seeded
        # from the same env vars docker-compose.yml passes to the adguard
        # service itself, so a matching ADGUARD_PASSWORD in .env "just
        # works" without a second manual entry. If ADGUARD_PASSWORD was
        # left blank there (adguard/entrypoint.sh auto-generates one in
        # that case, printed only to that container's own logs), this
        # stays blank too -- the Settings page below explains that and
        # lets an admin paste that generated password in by hand, same
        # as the dashboard's own admin login is editable after the fact.
        db.set_setting_if_absent(conn, "adguard_url", os.environ.get("ADGUARD_URL", ""))
        db.set_setting_if_absent(conn, "adguard_username", os.environ.get("ADGUARD_USERNAME", "admin"))
        db.set_setting_if_absent(conn, "adguard_password", os.environ.get("ADGUARD_PASSWORD", ""))
        # Phase 8: default IANA time zone new schedules are created with --
        # each schedule still stores its OWN time_zone once created (see
        # common/db.py's schedules table comment), so changing this later
        # never silently moves an existing schedule's meaning. Deliberately
        # NOT seeded with a hardcoded "UTC" fallback here (fixed
        # 2026-09-07, RoadMap.md's dated entry) -- this runs at container
        # boot, with no browser/request in scope to detect a real time
        # zone from, so hardcoding UTC here would always win over the
        # Settings page's own browser-side auto-detect (SETTINGS_BODY's
        # inline <script>, settings_page()) the FIRST time an admin loads
        # it, defeating the whole point of "default to wherever the
        # admin's own device is." Left genuinely absent unless
        # HOUSEHOLD_TIME_ZONE is explicitly set in .env (an existing,
        # still-supported override for anyone who already knows to use
        # it) -- settings_page()'s own get_setting(..., "UTC") fallback
        # still keeps new-schedule-creation safe in the narrow window
        # before any admin has visited Settings at all.
        if os.environ.get("HOUSEHOLD_TIME_ZONE"):
            db.set_setting_if_absent(conn, "household_time_zone", os.environ["HOUSEHOLD_TIME_ZONE"])
        # G3: SafeSearch/Restricted Mode defaults OFF -- an admin opts in
        # explicitly from Settings, since this changes real search-engine
        # behavior network-wide the moment it's turned on (see
        # controller/adguard_sync.py's sync_safesearch() docstring).
        db.set_setting_if_absent(conn, "safesearch_enabled", "0")
        conn.commit()
    finally:
        conn.close()


def _check_admin_auth(basic_auth) -> bool:
    if basic_auth is None:
        return False
    conn = get_db()
    try:
        expected_user = db.get_setting(conn, "admin_username")
        expected_hash = db.get_setting(conn, "admin_password_hash")
    finally:
        conn.close()
    # Shared with dashboard/captive_portal_server.py's own portal-side
    # admin action (added 2026-08-31) -- see auth.verify_admin_credentials's
    # own docstring for why this one check lives in common/auth.py rather
    # than being duplicated.
    return auth.verify_admin_credentials(basic_auth.username, basic_auth.password, expected_user, expected_hash)


# Brute-force protection, added 2026-09-02 after an audit (prompted by the
# project owner, ahead of a planned full code-review) found this login had
# NONE -- every one of this dashboard's ~80 routes sits behind
# require_admin below, and an attacker with network access to the
# dashboard port could attempt unlimited HTTP Basic credential guesses
# (see docs/security/overview.md section 6, now corrected). Reuses
# dashboard/captive_portal_server.py's own already-reasoned-about limiter
# mechanism via common/rate_limit.py rather than a second implementation.
# A SEPARATE instance from the portal's own limiter, deliberately -- these
# are different network surfaces (this dashboard's own bind address/port
# vs. the portal's :3131, reachable by different populations of devices),
# so a flood against one should never exhaust the other's budget.
_ADMIN_LOGIN_LIMITER = rate_limit.RateLimiter(max_attempts=5, window_seconds=60.0)

# Caps how much of an attacker-controlled username this module will ever
# write into system_events.message -- see captive_portal_server.py's own
# identical constant/reasoning for why.
_LOGGED_USERNAME_MAX_LEN = 100


def _log_failed_admin_login(client_ip: str, username: str) -> None:
    """Dashboard-visible Events-page row for a failed admin login,
    alongside (not instead of) the log.warning call at the one caller
    below -- same "layer, don't replace" principle
    common/system_events.py's own docstring already established.  Never
    logs the attempted password, only the username and source IP."""
    truncated = username[:_LOGGED_USERNAME_MAX_LEN]
    conn = get_db()
    try:
        system_events.log_event(
            conn, "dashboard_admin_login", "error",
            f"Failed admin login attempt from {client_ip} (username: {truncated!r})",
        )
    finally:
        conn.close()


def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        client_ip = request.remote_addr or "unknown"
        basic_auth = request.authorization
        # Only a request that actually supplied credentials counts
        # against the budget or gets checked against it -- the routine
        # "no Authorization header yet" 401 every browser's very first
        # request to this origin triggers isn't a guessing attempt (it
        # can never succeed either way), and counting it would risk
        # rate-limiting normal multi-device household use rather than
        # an actual attacker, who must supply *some* credential guess to
        # have any hope of succeeding and so can never dodge the counter
        # this way.
        if basic_auth is not None and _ADMIN_LOGIN_LIMITER.is_limited(client_ip):
            log.warning("rate-limited dashboard admin login attempt from %s", client_ip)
            return Response(
                "Too many failed login attempts. Wait a minute and try again.", 429,
                {"Retry-After": "60"},
            )
        if not _check_admin_auth(basic_auth):
            if basic_auth is not None:
                _ADMIN_LOGIN_LIMITER.record_failure(client_ip)
                log.warning("failed admin login attempt from %s (username: %r)", client_ip, basic_auth.username)
                _log_failed_admin_login(client_ip, basic_auth.username)
            return Response(
                "Authentication required", 401,
                {"WWW-Authenticate": 'Basic realm="OptiGate Admin"'},
            )
        if basic_auth is not None:
            _ADMIN_LOGIN_LIMITER.clear(client_ip)
        return view(*args, **kwargs)
    return wrapped


_LOGOUT_BODY = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log out -- OptiGate</title>
<link rel="stylesheet" href="{{ url_for('static', filename='css/app.css') }}">
</head>
<body>
<div class="page" style="max-width: 32rem; margin: 3rem auto; padding: 0 1rem;">
<div class="card">
<h1>Log out</h1>
<p>OptiGate's admin login uses your browser's own built-in sign-in
prompt, which has no "log out" button a website can press for you --
only your browser can actually forget a saved login. To sign out for
real, do ONE of these:</p>
<ul>
  <li><strong>Close this browser tab or window</strong> -- most browsers
  forget a saved login the moment the browser itself closes.</li>
  <li><strong>Clear this site's saved password</strong> from your
  browser's own settings (e.g. Chrome/Edge: Settings &rarr; Privacy and
  security &rarr; Clear browsing data &rarr; Cookies and site data,
  scoped to this site).</li>
</ul>
<p class="hint">Simply navigating back to the dashboard will sign you
right back in with whatever's still saved -- that's expected, not a
bug, until you do one of the two things above.</p>
<p><a class="btn add" href="{{ url_for('report') }}">&larr; Back to the dashboard</a></p>
</div>
</div>
</body>
</html>"""


@app.route("/logout")
def logout():
    """HTTP Basic Auth has no real server-side session to revoke -- the
    browser just caches the credential per-origin until it's closed, and
    there's no reliable, cross-browser way for a server to make it
    forget that.

    **Rewritten 2026-09-09 after a real live lockout**: this used to
    navigate here via a URL with a deliberately wrong credential embedded
    in it (http://logout:logout@host/logout) to try to force a fresh
    sign-in prompt -- a commonly-suggested Basic-Auth "logout" trick.
    Confirmed live that it actively backfires: several browsers cache
    "logout" as the *username* for this origin after that navigation,
    then keep resubmitting it on every later login attempt regardless of
    what password is typed, silently defeating every subsequent login
    until the browser's saved credentials are cleared by hand anyway --
    worse than doing nothing, since the admin has no way to tell their
    own (correct) password apart from a UI bug without checking server
    logs. Replaced with a plain page explaining the one real, manual step
    (close the browser, or clear its saved password for this site) --
    honest about the limitation instead of a trick that can lock someone
    out. Deliberately NOT behind @require_admin: this page must stay
    reachable even to someone who's currently unable to log in, and it
    reveals nothing sensitive."""
    return render_template_string(_LOGOUT_BODY)


# ==========================================================
# SHARED PAGE CHROME
# ==========================================================

BASE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OptiGate</title>
<meta name="theme-color" content="#2f6fed">
<link rel="manifest" href="{{ url_for('static', filename='manifest.webmanifest') }}">
<link rel="icon" href="{{ url_for('static', filename='icons/favicon.ico') }}">
<link rel="apple-touch-icon" href="{{ url_for('static', filename='icons/apple-touch-icon.png') }}">
<link rel="stylesheet" href="{{ url_for('static', filename='css/app.css') }}">
<script>
try { if (localStorage.getItem("og_sidebar_collapsed") === "1") document.documentElement.classList.add("sidebar-collapsed"); } catch (e) {}
</script>
</head>
<body>
{% set page_titles = {'report': 'Report', 'users': 'Users', 'domains': 'Domains', 'categories': 'Categories', 'schedules': 'Schedules', 'devices': 'Devices', 'health': 'Health', 'events': 'Events', 'settings': 'Settings'} %}
<div class="app-shell">
  <nav class="sidebar">
    <a class="sidebar-brand" href="{{ url_for('report') }}">
      <img src="{{ url_for('static', filename='icons/icon-192.png') }}" alt="">
      <span class="sidebar-label">OptiGate</span>
    </a>
    <div class="sidebar-nav">
      <a class="sidebar-item {{ 'active' if active=='report' else '' }}" href="{{ url_for('report') }}" title="Report">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="20" x2="6" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="18" y1="20" x2="18" y2="14"/></svg>
        <span class="sidebar-label">Report{% if pending_count %} <span class="badge pending">{{ pending_count }}</span>{% endif %}</span>
      </a>
      <a class="sidebar-item {{ 'active' if active=='users' else '' }}" href="{{ url_for('users') }}" title="Users">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        <span class="sidebar-label">Users</span>
      </a>
      <a class="sidebar-item {{ 'active' if active=='domains' else '' }}" href="{{ url_for('domains') }}" title="Domains">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a14.5 14.5 0 0 1 0 18a14.5 14.5 0 0 1 0-18z"/></svg>
        <span class="sidebar-label">Domains</span>
      </a>
      <a class="sidebar-item {{ 'active' if active=='categories' else '' }}" href="{{ url_for('categories') }}" title="Categories">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41L13.42 20.58a2 2 0 0 1-2.83 0L2.59 12.58a2 2 0 0 1 0-2.83L9.76 2.58A2 2 0 0 1 12.59 2.58"/><circle cx="7.5" cy="7.5" r="1.5"/></svg>
        <span class="sidebar-label">Categories</span>
      </a>
      <a class="sidebar-item {{ 'active' if active=='schedules' else '' }}" href="{{ url_for('schedules') }}" title="Schedules">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        <span class="sidebar-label">Schedules</span>
      </a>
      <a class="sidebar-item {{ 'active' if active=='devices' else '' }}" href="{{ url_for('devices') }}" title="Devices">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="13" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        <span class="sidebar-label">Devices</span>
      </a>
      <a class="sidebar-item {{ 'active' if active=='health' else '' }}" href="{{ url_for('health_page') }}" title="Health">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        <span class="sidebar-label">Health{% if interception_down %} <span class="badge blocked">!</span>{% endif %}</span>
      </a>
      <a class="sidebar-item {{ 'active' if active=='events' else '' }}" href="{{ url_for('events_page') }}" title="Events">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
        <span class="sidebar-label">Events</span>
      </a>
      <a class="sidebar-item {{ 'active' if active=='settings' else '' }}" href="{{ url_for('settings_page') }}" title="Settings">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
        <span class="sidebar-label">Settings</span>
      </a>
    </div>
    <div class="sidebar-bottom">
      <button type="button" class="sidebar-item sidebar-collapse-btn" id="sidebarToggle" title="Collapse sidebar" aria-label="Toggle sidebar width">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="11 17 6 12 11 7"/><polyline points="18 17 13 12 18 7"/></svg>
        <span class="sidebar-label">Collapse</span>
      </button>
      <a class="sidebar-item" href="{{ url_for('logout') }}" title="Log out">
        <svg class="sidebar-icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        <span class="sidebar-label">Log out</span>
      </a>
    </div>
  </nav>
  <div class="main">
    <header class="topbar-slim">
      <span class="page-title">{{ page_titles.get(active, active) }}</span>
    </header>
    <div class="page">
    {% if message %}<div class="flash {{ 'error' if error else 'ok' }}">{{ message }}</div>{% endif %}
    {{ body|safe }}
    </div>
  </div>
</div>
<script>
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));
}

// Instant client-side search, no page reload -- hides non-matching <tr>s
// (header rows, identified by containing a <th> since these tables don't
// use <thead>, are never hidden). Used by the Users/Groups/Categories/
// Schedules/Events list pages -- Domains and Devices moved to
// server-side ?q= search instead (2026-09-08) once those two paginated,
// since a client-side filter over one page of results would silently
// miss matches sitting on a page not currently shown. Separate from and layered on top
// of the server-side ?user_id= / ?group_id= / ?device_id= filters
// elsewhere, which narrow what's sent down in the first place. The
// combobox picker widgets below have their own, unrelated search box.
document.addEventListener("input", function (event) {
  var tableInput = event.target.closest("[data-filter-table]");
  if (!tableInput) return;
  var table = document.getElementById(tableInput.getAttribute("data-filter-table"));
  if (!table) return;
  var tableTerm = tableInput.value.trim().toLowerCase();
  var rows = table.rows;
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.querySelector("th")) continue;
    row.style.display = (!tableTerm || row.textContent.toLowerCase().indexOf(tableTerm) !== -1) ? "" : "none";
  }
});

// Combobox picker -- type-to-reveal search that replaces a full checkbox/
// radio list with a dropdown of only the entities that match what's
// typed. Below a small item count it shows everything as soon as you
// focus the box (no need to type for a handful of kids); above that
// threshold nothing renders until you type, so this scales to any number
// of users/groups/devices without ever putting more than a handful of
// rows in the DOM at once (see GH #8). Three modes, one engine:
//   multi   ACCESS_SELECTS -- click a result to add it as a removable
//       tag; each tag carries its own hidden input named data-field.
//   single  DEVICE_ASSIGNMENT_SELECT -- click a result to replace the
//       current selection, shown above the input; one hidden input.
//   nav     Domains page filter -- click a result to navigate to its
//       href; no form field involved at all.
(function () {
  var SHOW_ALL_THRESHOLD = 8;
  var MAX_RESULTS = 8;

  document.querySelectorAll("[data-combobox]").forEach(function (root) {
    var mode = root.dataset.mode;
    var field = root.dataset.field;
    var itemsEl = root.querySelector("[data-combobox-items]");
    var items = itemsEl ? JSON.parse(itemsEl.textContent || "[]") : [];
    var input = root.querySelector("[data-combobox-input]");
    var results = root.querySelector("[data-combobox-results]");
    var tagsBox = root.querySelector("[data-combobox-tags]");
    var currentBox = root.querySelector("[data-combobox-current]");
    var selectedIds = {};

    function itemLabel(id) {
      for (var i = 0; i < items.length; i++) if (items[i].id === id) return items[i].label;
      return id;
    }

    function renderCurrent() {
      if (!currentBox) return;
      var id = root.dataset.value || "";
      currentBox.textContent = id === "" ? "" : "Currently: " + itemLabel(id);
    }

    function renderTags() {
      if (!tagsBox) return;
      tagsBox.innerHTML = "";
      Object.keys(selectedIds).forEach(function (id) {
        var pill = document.createElement("span");
        pill.className = "combobox-tag";
        var label = document.createElement("span");
        label.textContent = itemLabel(id);
        pill.appendChild(label);
        var remove = document.createElement("button");
        remove.type = "button";
        remove.className = "combobox-tag-remove";
        remove.setAttribute("aria-label", "Remove " + itemLabel(id));
        remove.textContent = "×";
        remove.addEventListener("click", function () {
          delete selectedIds[id];
          renderTags();
          renderResults();
        });
        pill.appendChild(remove);
        var hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = field;
        hidden.value = id;
        pill.appendChild(hidden);
        tagsBox.appendChild(pill);
      });
    }

    function selectItem(item) {
      if (mode === "multi") {
        selectedIds[item.id] = true;
        renderTags();
        input.value = "";
        renderResults();
        input.focus();
        return;
      }
      if (mode === "single") {
        root.dataset.value = item.id;
        var hidden = root.querySelector("[data-combobox-hidden]");
        if (hidden) hidden.value = item.id;
        renderCurrent();
        input.value = "";
        results.style.display = "none";
        return;
      }
      if (mode === "nav" && item.href) {
        window.location.href = item.href;
      }
    }

    function renderResults() {
      var query = input.value.trim().toLowerCase();
      var pool = items.filter(function (item) { return !(mode === "multi" && selectedIds[item.id]); });
      var showAll = pool.length <= SHOW_ALL_THRESHOLD;
      results.innerHTML = "";
      if (!query && !showAll) {
        results.style.display = "block";
        var hint = document.createElement("div");
        hint.className = "combobox-empty";
        hint.textContent = "Type to search " + pool.length + " entries.";
        results.appendChild(hint);
        return;
      }
      var found = query
        ? pool.filter(function (item) { return item.label.toLowerCase().indexOf(query) !== -1; }).slice(0, MAX_RESULTS)
        : pool;
      if (!found.length) {
        results.style.display = "block";
        var empty = document.createElement("div");
        empty.className = "combobox-empty";
        empty.textContent = query ? "No matches." : (root.dataset.empty || "Nothing to pick from yet.");
        results.appendChild(empty);
        return;
      }
      results.style.display = "block";
      found.forEach(function (item) {
        var row = document.createElement("div");
        row.className = "combobox-result";
        row.textContent = item.label;
        // mousedown (not click) with preventDefault so the input never
        // blurs before the selection registers -- a plain click handler
        // here would lose the race: blur fires and hides this dropdown
        // before the click event reaches it.
        row.addEventListener("mousedown", function (event) {
          event.preventDefault();
          selectItem(item);
        });
        results.appendChild(row);
      });
    }

    input.addEventListener("input", renderResults);
    input.addEventListener("focus", renderResults);
    input.addEventListener("keydown", function (event) {
      if (event.key === "Escape") { results.style.display = "none"; input.blur(); }
    });
    document.addEventListener("click", function (event) {
      if (!root.contains(event.target)) results.style.display = "none";
    });

    if (mode === "multi") {
      var selectedEl = root.querySelector("[data-combobox-selected]");
      var preselected = selectedEl ? JSON.parse(selectedEl.textContent || "[]") : [];
      preselected.forEach(function (id) { selectedIds[String(id)] = true; });
      renderTags();
    } else if (mode === "single") {
      root.dataset.value = root.dataset.initial || "";
      renderCurrent();
    }
  });
})();

// Sidebar collapse toggle -- state persists per-browser via localStorage (a
// display preference, not app data) and is applied before first paint by
// the inline <script> in <head> reading it onto <html> early, so there's no
// flash of the wrong width on reload.
(function () {
  var toggle = document.getElementById("sidebarToggle");
  if (!toggle) return;
  toggle.addEventListener("click", function () {
    var collapsed = document.documentElement.classList.toggle("sidebar-collapsed");
    try { localStorage.setItem("og_sidebar_collapsed", collapsed ? "1" : "0"); } catch (e) {}
  });
})();
</script>
</body>
</html>
"""


def render(active: str, body: str) -> str:
    conn = get_db()
    pending_count = conn.execute(
        "SELECT COUNT(*) c FROM access_log WHERE approval_requested_at IS NOT NULL"
    ).fetchone()["c"]
    # Sidebar alarm badge: only for an interception layer that's actually
    # enabled (a row exists) and either explicitly fail-open or stale (see
    # _subsystem_unhealthy -- a crashed process can't self-report, so a
    # frozen last_healthy_at is its own signal) -- a missing row just
    # means the optional `interception` compose profile isn't running at
    # all, which is a normal, unremarkable deployment shape and shouldn't
    # nag every page with a "!" badge. Shares _get_runtime_row's one query
    # and _subsystem_unhealthy's one predicate with health_page() itself,
    # rather than each re-deriving "is this bad" independently.
    runtime_row = _get_runtime_row(conn)
    interception_down = bool(runtime_row) and (
        _subsystem_unhealthy(runtime_row["mode"], runtime_row["last_healthy_at"])
        or _subsystem_unhealthy(runtime_row["nft_mode"], runtime_row["nft_last_healthy_at"])
    )
    return render_template_string(
        BASE, active=active, body=body, pending_count=pending_count,
        interception_down=interception_down,
        message=request.args.get("message"), error=request.args.get("error"),
    )


def flash_redirect(endpoint: str, message: str, error: bool = False, **kwargs):
    return redirect(url_for(endpoint, message=message, error="1" if error else None, **kwargs))


# ==========================================================
# CA CERT (public, unauthenticated)
# ==========================================================

@app.route("/sw.js")
def service_worker():
    # Served from root (not /static/sw.js) so its default scope is the whole
    # app -- a service worker can only control paths at or below where it's
    # served from, and it needs to control every dashboard page, not just
    # /static/ assets.
    resp = send_file(Path(app.static_folder) / "sw.js", mimetype="application/javascript")
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/ca-cert")
def ca_cert():
    if not CA_CERT_PATH.exists():
        return Response(
            "The CA certificate hasn't been generated yet. Start the proxy "
            "container first, then reload this page.", 404,
        )
    return send_file(
        CA_CERT_PATH, mimetype="application/x-x509-ca-cert",
        as_attachment=True, download_name="optigate-ca.crt",
    )


CA_CERT_RESTART_NOTICE = (
    "Restart the proxy container (docker compose restart proxy) for Squid to actually use it -- "
    "unlike everything else in this dashboard, cert=/key= is only read at Squid startup, not live. "
    "Every device also needs the new certificate re-trusted; the old one no longer matches."
)


def _ca_cert_info(path: Path) -> dict | None:
    """Subject/expiry/fingerprint of the current SSL-Bump CA certificate,
    for the Settings page display. Parsed fresh from the file with
    openssl (same tool _validate_ca_cert_pair() below uses -- see its own
    comment on why this shells out rather than adding a Python crypto
    dependency) every time the Settings page loads, rather than caching
    anything, so it always reflects the file Squid will actually load.
    Returns None if the file doesn't exist yet or openssl can't parse it
    -- either way, nothing to show."""
    if not path.exists():
        return None
    try:
        cert_pem = path.read_bytes()
    except OSError:
        return None
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-enddate", "-fingerprint", "-sha256"],
        input=cert_pem, capture_output=True,
    )
    if result.returncode != 0:
        return None
    info: dict[str, str] = {}
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        # Case-insensitive match on the "Fingerprint=" label -- live-
        # verified 2026-09-06 that openssl 3.5 prints "sha256
        # Fingerprint=" (lowercase algorithm name), not the "SHA256
        # Fingerprint=" this originally assumed, which silently left the
        # fingerprint blank on the Settings page with no error anywhere.
        if line.startswith("subject="):
            info["subject"] = line[len("subject="):].strip()
        elif line.startswith("notAfter="):
            info["expires"] = line[len("notAfter="):].strip()
        elif "fingerprint=" in line.lower():
            info["fingerprint"] = line.partition("=")[2].strip()
    return info or None


def _public_key_der(pem_bytes: bytes, *, from_cert: bool) -> bytes | None:
    """DER-encoded public key extracted from a cert or a private key --
    used by _validate_ca_cert_pair() to confirm an uploaded pair actually
    match each other, independent of key algorithm (RSA, EC, ...) rather
    than the RSA-only `openssl x509 -modulus`/`openssl rsa -modulus`
    comparison, since an admin's own CA could reasonably be EC-based.
    Returns None if openssl can't extract a public key at all (already-
    invalid input -- the caller has separately validated the input parses
    as a cert/key at all before ever calling this)."""
    extract = subprocess.run(
        ["openssl", "x509", "-noout", "-pubkey"] if from_cert else ["openssl", "pkey", "-pubout"],
        input=pem_bytes, capture_output=True,
    )
    if extract.returncode != 0:
        return None
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=extract.stdout, capture_output=True,
    )
    return der.stdout if der.returncode == 0 else None


def _validate_ca_cert_pair(cert_pem: bytes, key_pem: bytes) -> str | None:
    """Validates an uploaded CA cert+key pair before ever writing it to
    disk -- Squid reads cert=/key= from squid.conf with zero validation
    of its own (proxy/squid.conf.template), so a malformed or mismatched
    pair fails ssl-bump silently, with nothing in the Report page to
    explain why every bump-mode site suddenly shows certificate errors or
    stops working. Shells out to openssl (same tool
    proxy/entrypoint.sh already uses to generate the default pair)
    rather than adding a new Python crypto dependency for one admin
    action. Returns None if the pair is valid and usable for Squid's
    ssl-bump, or a human-readable reason otherwise."""
    cert_check = subprocess.run(["openssl", "x509", "-noout", "-text"], input=cert_pem, capture_output=True)
    if cert_check.returncode != 0:
        return "That doesn't look like a valid X.509 certificate."
    cert_text = cert_check.stdout.decode("utf-8", "replace")
    # Same two extensions proxy/entrypoint.sh sets explicitly when
    # generating the default CA -- without them Squid can't mint
    # per-site leaf certificates from this key at all.
    if "CA:TRUE" not in cert_text:
        return 'This isn\'t a CA certificate (missing "basicConstraints CA:TRUE") -- Squid can\'t mint per-site certificates from it.'
    if "Certificate Sign" not in cert_text:
        return 'This certificate\'s key usage doesn\'t allow certificate signing ("keyCertSign") -- Squid can\'t mint per-site certificates from it.'

    key_check = subprocess.run(["openssl", "pkey", "-noout"], input=key_pem, capture_output=True)
    if key_check.returncode != 0:
        return "That doesn't look like a valid private key (or it's encrypted/password-protected -- Squid needs an unencrypted key)."

    cert_pubkey = _public_key_der(cert_pem, from_cert=True)
    key_pubkey = _public_key_der(key_pem, from_cert=False)
    if cert_pubkey is None or key_pubkey is None or cert_pubkey != key_pubkey:
        return "The certificate and private key don't match each other."

    return None


def _replace_ca_cert_pair(cert_pem: bytes, key_pem: bytes) -> None:
    """Backs up the current CA cert+key (timestamped, alongside the
    originals) before overwriting, then writes the new pair. A botched
    cert swap makes every previously-trusted device distrust Squid's
    bump-mode connections at once (see CA_CERT_RESTART_NOTICE) -- keeping
    the previous pair trivially recoverable is cheap insurance against a
    bad upload or an admin who regenerated by mistake. Does NOT restart
    or signal the proxy container -- see CA_CERT_RESTART_NOTICE's own
    comment on why that's a deliberate manual step for this one change,
    unlike every other config in this dashboard."""
    CA_CERT_PATH.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if CA_CERT_PATH.exists():
        CA_CERT_PATH.with_name(f"{CA_CERT_PATH.stem}.{stamp}.bak{CA_CERT_PATH.suffix}").write_bytes(
            CA_CERT_PATH.read_bytes()
        )
    if CA_KEY_PATH.exists():
        CA_KEY_PATH.with_name(f"{CA_KEY_PATH.stem}.{stamp}.bak{CA_KEY_PATH.suffix}").write_bytes(
            CA_KEY_PATH.read_bytes()
        )
    CA_CERT_PATH.write_bytes(cert_pem)
    CA_KEY_PATH.write_bytes(key_pem)
    try:
        os.chmod(CA_KEY_PATH, 0o600)
    except OSError:
        pass  # e.g. Windows in local dev -- best-effort only, matches other chmod calls in this codebase


@app.route("/settings/ca-cert/upload", methods=["POST"])
@require_admin
def upload_ca_cert():
    cert_file = request.files.get("ca_cert_file")
    key_file = request.files.get("ca_key_file")
    if not cert_file or not cert_file.filename or not key_file or not key_file.filename:
        return flash_redirect("settings_page", "Pick both a certificate file and a private key file.", error=True)

    cert_pem = cert_file.read()
    key_pem = key_file.read()
    # Real CA certs/keys are a few KB -- generous cap against someone
    # accidentally (or deliberately) picking a huge file, without needing
    # a streaming read for what should always be a tiny upload.
    if len(cert_pem) > 64_000 or len(key_pem) > 64_000:
        return flash_redirect("settings_page", "That file is too large to be a certificate or key.", error=True)

    error = _validate_ca_cert_pair(cert_pem, key_pem)
    if error:
        return flash_redirect("settings_page", error, error=True)

    _replace_ca_cert_pair(cert_pem, key_pem)
    return flash_redirect("settings_page", f"CA certificate replaced. {CA_CERT_RESTART_NOTICE}")


@app.route("/settings/ca-cert/regenerate", methods=["POST"])
@require_admin
def regenerate_ca_cert():
    """One-click 'rotate now' -- generates a fresh self-signed CA with the
    exact same openssl invocation proxy/entrypoint.sh uses on first run
    (RSA 2048, SHA-256, 10-year validity, the same two required
    extensions), just admin-triggered instead of only-if-missing."""
    org = (request.form.get("ca_org") or "OptiGate").strip()[:200]
    common_name = (request.form.get("ca_common_name") or "OptiGate CA").strip()[:200]
    if not org or not common_name:
        return flash_redirect("settings_page", "Org and Common Name can't be empty.", error=True)
    # "/" is openssl -subj's own field separator -- letting it through
    # would let the typed value inject extra RDN fields into the subject
    # rather than just being read as a single Org/CN value.
    if "/" in org or "/" in common_name:
        return flash_redirect("settings_page", "Org and Common Name can't contain \"/\".", error=True)

    with tempfile.TemporaryDirectory() as tmp:
        cert_path = Path(tmp) / "ca_cert.pem"
        key_path = Path(tmp) / "ca_key.pem"
        result = subprocess.run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-days", "3650", "-nodes", "-x509",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-subj", f"/O={org}/CN={common_name}",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            ],
            capture_output=True,
        )
        if result.returncode != 0 or not cert_path.exists() or not key_path.exists():
            log.error("CA cert regeneration failed: %s", result.stderr.decode("utf-8", "replace"))
            return flash_redirect(
                "settings_page", "Certificate generation failed -- see the dashboard container logs.", error=True
            )
        _replace_ca_cert_pair(cert_path.read_bytes(), key_path.read_bytes())

    return flash_redirect("settings_page", f"New CA certificate generated. {CA_CERT_RESTART_NOTICE}")


# Generous but bounded -- a real backup (config only, no access_log/
# system_events/subscription-sourced category_domains -- see
# common/backup.py's own docstring) stays small even for a household
# with thousands of manually-added domains; this just guards against an
# unrelated huge file being uploaded by mistake (or on purpose) without
# needing a streaming parse.
_BACKUP_UPLOAD_MAX_BYTES = 50_000_000


@app.route("/settings/backup/download")
@require_admin
def download_backup():
    """Configuration export -- tracked as a deferred item in RoadMap.md
    since before 2026-09-07 ("no way currently to export the whole
    household's configuration... useful before a risky change, or when
    moving to new hardware"), built 2026-09-08 as the actual mechanism
    for wiping and redeploying the production box clean without losing
    anything. Bundles common/backup.py's own JSON export together with
    the CA certificate/private key (if generated yet) in one zip, so a
    restore elsewhere doesn't need every device to re-trust a new CA --
    see backup.py's own docstring for exactly what is and isn't
    included and why."""
    conn = get_db()
    data = backup.export_config(conn)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", json.dumps(data, indent=2))
        if CA_CERT_PATH.exists():
            zf.writestr("ca_cert.pem", CA_CERT_PATH.read_bytes())
        if CA_KEY_PATH.exists():
            zf.writestr("ca_key.pem", CA_KEY_PATH.read_bytes())
    buf.seek(0)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return send_file(
        buf, mimetype="application/zip", as_attachment=True,
        download_name=f"optigate-backup-{stamp}.zip",
    )


@app.route("/settings/backup/restore", methods=["POST"])
@require_admin
def restore_backup():
    """The other half of download_backup() above. A full replace, not a
    merge -- see common/backup.py's restore_config() docstring -- so the
    confirm() on the Settings page form is deliberately blunt about that
    before this route ever runs. The CA cert/key inside the zip (if
    present) are validated with the exact same _validate_ca_cert_pair()
    the existing manual-upload feature uses, and swapped in via the same
    _replace_ca_cert_pair() (so the previous pair is still backed up
    on-disk first, same safety net as that feature) -- a bad/mismatched
    pair inside the zip just skips the CA half rather than failing the
    whole restore, since the DB configuration is still worth restoring
    either way."""
    upload = request.files.get("backup_file")
    if not upload or not upload.filename:
        return flash_redirect("settings_page", "Pick a backup file to restore.", error=True)

    raw = upload.read()
    if len(raw) > _BACKUP_UPLOAD_MAX_BYTES:
        return flash_redirect("settings_page", "That backup file is too large.", error=True)

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            if "config.json" not in names:
                return flash_redirect(
                    "settings_page", "That doesn't look like an OptiGate backup (missing config.json).", error=True
                )
            try:
                data = json.loads(zf.read("config.json"))
            except json.JSONDecodeError:
                return flash_redirect("settings_page", "That backup's config.json is corrupted.", error=True)
            cert_pem = zf.read("ca_cert.pem") if "ca_cert.pem" in names else None
            key_pem = zf.read("ca_key.pem") if "ca_key.pem" in names else None
    except zipfile.BadZipFile:
        return flash_redirect("settings_page", "That doesn't look like a valid backup file (not a zip archive).", error=True)

    conn = get_db()
    try:
        backup.restore_config(conn, data)
    except backup.RestoreError as exc:
        return flash_redirect("settings_page", str(exc), error=True)

    ca_note = ""
    if cert_pem and key_pem:
        error = _validate_ca_cert_pair(cert_pem, key_pem)
        if error:
            ca_note = f" CA certificate NOT restored ({error}) -- the rest of the configuration was."
        elif CA_CERT_PATH.exists() and CA_CERT_PATH.read_bytes() == cert_pem and \
                CA_KEY_PATH.exists() and CA_KEY_PATH.read_bytes() == key_pem:
            # Live-verified 2026-09-08: restoring the SAME backup a box's
            # own CA cert came from (the common case -- e.g. reverting
            # unrelated config on the same install) must NOT claim every
            # device needs to re-trust a certificate that never actually
            # changed. Also skips a no-op _replace_ca_cert_pair() call, so
            # a repeated restore doesn't pile up identical .bak files.
            ca_note = " CA certificate unchanged (already matched what's currently installed)."
        else:
            _replace_ca_cert_pair(cert_pem, key_pem)
            ca_note = f" {CA_CERT_RESTART_NOTICE}"

    return flash_redirect("settings_page", f"Configuration restored.{ca_note}")


BLOCKED_BODY = """
<!doctype html><html><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Blocked</title>
<style>
:root{color-scheme:light dark;}
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;max-width:28rem;margin:4rem auto;
padding:0 1.25rem;text-align:center;color:#1e293b;}
@media (prefers-color-scheme:dark){body{color:#e5eaf3;}}
.icon{width:56px;height:56px;border-radius:16px;background:#2f6fed;display:inline-flex;
align-items:center;justify-content:center;margin-bottom:1rem;}
h1{font-size:1.15rem;margin:0 0 .5rem;}
p{font-size:.92rem;opacity:.75;}
button{margin-top:1.25rem;padding:.6rem 1.4rem;border-radius:8px;border:none;background:#2f6fed;
color:#fff;font-size:.92rem;font-weight:600;cursor:pointer;font-family:inherit;}
.sent{margin-top:1.25rem;font-size:.88rem;color:#15803d;font-weight:600;}
</style></head><body>
<div class='icon'>
<svg width='28' height='28' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='2.2'
stroke-linecap='round' stroke-linejoin='round'><path d='M12 3l8 3.5v5.2c0 4.7-3.2 8.6-8 9.8
-4.8-1.2-8-5.1-8-9.8V6.5L12 3z'/></svg>
</div>
<h1>This site or show isn't approved.</h1>
<p>Ask a parent to check the dashboard if you think this should be allowed.</p>
{% if row and row.approval_requested_at %}
<p class="sent">Request sent -- a parent will see this on the dashboard.</p>
{% elif row %}
<form method="post" action="{{ url_for('request_approval') }}">
  <input type="hidden" name="log_id" value="{{ row.id }}">
  <button type="submit">Request approval</button>
</form>
{% endif %}
</body></html>
"""

# How long after a denial the /blocked page will still offer to attach a
# "Request approval" click to it. Generous enough for a slow device/redirect,
# short enough that two different people getting blocked seconds apart on a
# small home network essentially never collide.
BLOCKED_REQUEST_LOOKBACK_SECONDS = 30


@app.route("/blocked")
def blocked():
    # Reached two ways: a bump-mode denial (authz_helper.py, always shows a
    # page) or a splice-mode denial when block_page_mode='redirect'. Either
    # way, authz_helper.py/sni_helper.py just wrote the matching access_log
    # row a moment before this page loaded -- correlating by recency instead
    # of by request identity avoids depending on exactly how Squid's
    # deny_info would need to be configured to pass the original URL through
    # the redirect (version-specific behavior not verified against a live
    # Squid instance; see commit notes). Only rows with a user_id are
    # eligible, matching approve_from_report()'s own requirement.
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM access_log WHERE allowed = 0 AND user_id IS NOT NULL AND ts >= ? "
        "ORDER BY id DESC LIMIT 1",
        (db.iso_secs_ago(BLOCKED_REQUEST_LOOKBACK_SECONDS),),
    ).fetchone()
    return render_template_string(BLOCKED_BODY, row=row), 403


@app.route("/blocked/request-approval", methods=["POST"])
def request_approval():
    # Deliberately unauthenticated, same as /blocked itself -- whoever got
    # blocked is the one clicking this. Worst case of abuse is dashboard
    # noise (an extra pending-request row an admin has to dismiss), not any
    # data exposure or access grant: it only sets a timestamp on a row
    # that's already denied and already visible on the Report page.
    log_id = request.form.get("log_id", "")
    conn = get_db()
    row = conn.execute(
        "SELECT id FROM access_log WHERE id = ? AND allowed = 0 AND approval_requested_at IS NULL",
        (log_id,),
    ).fetchone()
    if row is not None:
        conn.execute(
            "UPDATE access_log SET approval_requested_at = ? WHERE id = ?", (db.now_iso(), log_id)
        )
        conn.commit()
    return redirect(url_for("blocked"))


@app.route("/")
def index():
    return redirect(url_for("report"))


# ==========================================================
# USERS
# ==========================================================

USERS_BODY = """
{% if not cert_banner_dismissed %}
<div class="cert-banner">
  <strong>Setting up a new device or user?</strong> Each person needs their
  own login (below) configured in the device's proxy settings, and the
  device needs the CA certificate trusted.
  <br><a class="btn add" href="{{ url_for('ca_cert') }}">Download CA certificate</a>
  <form class="inline" method="post" action="{{ url_for('dismiss_cert_banner') }}">
    <button class="small" type="submit" style="margin-left:.6rem;">Dismiss</button>
  </form>
  <p class="hint" style="margin:.5rem 0 0;">Dismissing moves this permanently to Settings -- it won't come back here.</p>
</div>
{% endif %}

<div class="card">
<h2>Users ({{ users|length }})</h2>
{% if users %}
<div class="toolbar" id="userBulkToolbar">
  <a class="btn small" href="{{ url_for('export_users_csv') }}">&darr; Download users</a>
  <span class="toolbar-sep"></span>
  <form id="bulkUserEnableForm" class="inline" method="post" action="{{ url_for('bulk_resume_users') }}">
    <button class="btn small" type="submit" disabled>Enable</button>
  </form>
  <form id="bulkUserPauseForm" class="inline" method="post" action="{{ url_for('bulk_pause_users') }}">
    <button class="btn small" type="submit" disabled>Disable</button>
  </form>
  <form id="bulkUserDeleteForm" class="inline" method="post" action="{{ url_for('bulk_delete_users') }}"
        onsubmit="return confirm('Delete every checked user? This removes their login, site access, and show approvals, and cannot be undone.');">
    <button class="danger small" type="submit" disabled>Delete</button>
  </form>
  <span class="hint" id="userBulkCount" style="margin:0;">Check users below to Enable/Disable/Delete several at once.</span>
</div>
<p class="hint">"Enable"/"Disable" pause or resume every checked user's own devices -- same as each kid's own Pause card on their Manage page, just for several kids at once.</p>
{% endif %}
{% if users %}<input type="search" data-filter-table="usersTable" placeholder="Search users&hellip;" style="margin-bottom:.6rem; width:100%; max-width:280px;">{% endif %}
<div class="table-scroll">
<table id="usersTable">
  <tr><th>{% if users %}<input type="checkbox" id="userSelectAll" title="Select all">{% endif %}</th><th>Username</th><th>Display name</th><th>Sites</th><th>Shows</th><th></th></tr>
  {% for u in users %}
  <tr>
    <td><input type="checkbox" class="bulk-user-check" value="{{ u.id }}"></td>
    <td><code>{{ u.username }}</code></td>
    <td>{{ u.display_name }}</td>
    <td><a href="{{ url_for('domains', user_id=u.id) }}">{{ u.domain_count }} assigned</a></td>
    <td>{{ u.show_count }} approved</td>
    <td>
      <a class="btn small" href="{{ url_for('user_detail', user_id=u.id) }}">Manage</a>
      <form class="inline" method="post" action="{{ url_for('delete_user') }}">
        <input type="hidden" name="user_id" value="{{ u.id }}">
        <button class="danger small" type="submit" onclick="return confirm('Delete {{ u.username }}? This removes their login, site access, and show approvals.')">Delete</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="6"><em>No users yet.</em></td></tr>
  {% endfor %}
</table>
</div>
<script>
(function () {
  var selectAll = document.getElementById("userSelectAll");
  var countLabel = document.getElementById("userBulkCount");
  var toolbar = document.getElementById("userBulkToolbar");

  // Same toolbar pattern as the Devices page (RoadMap.md's dated entry,
  // referencing Microsoft Entra's admin console) -- extended here to
  // Users/Categories/Schedules for consistency across every list page.
  function updateToolbarState() {
    if (!toolbar) return;
    var n = document.querySelectorAll(".bulk-user-check:checked").length;
    toolbar.querySelectorAll("button").forEach(function (btn) { btn.disabled = n === 0; });
    if (countLabel) {
      countLabel.textContent = n === 0
        ? "Check users below to Enable/Disable/Delete several at once."
        : n + " user" + (n === 1 ? "" : "s") + " selected.";
    }
  }

  if (selectAll) {
    selectAll.addEventListener("change", function () {
      document.querySelectorAll(".bulk-user-check").forEach(function (box) { box.checked = selectAll.checked; });
      updateToolbarState();
    });
  }
  document.querySelectorAll(".bulk-user-check").forEach(function (box) {
    box.addEventListener("change", updateToolbarState);
  });
  updateToolbarState();

  function wireBulkForm(formId) {
    var form = document.getElementById(formId);
    if (!form) return;
    form.addEventListener("submit", function (event) {
      // Checkboxes live in #usersTable, not inside any bulk form --
      // nesting a <form> around the table would break each row's own
      // Delete form (HTML forms can't nest) -- collected into hidden
      // inputs here instead, right before submit. Same pattern as the
      // Devices/Domains pages' own bulk forms.
      var checked = Array.prototype.slice.call(document.querySelectorAll(".bulk-user-check:checked"));
      if (!checked.length) {
        event.preventDefault();
        alert("Check at least one user above first.");
        return;
      }
      form.querySelectorAll("input[name=user_ids]").forEach(function (el) { el.remove(); });
      checked.forEach(function (box) {
        var hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "user_ids";
        hidden.value = box.value;
        form.appendChild(hidden);
      });
    });
  }
  wireBulkForm("bulkUserEnableForm");
  wireBulkForm("bulkUserPauseForm");
  wireBulkForm("bulkUserDeleteForm");
})();
</script>
<form class="add-form" method="post" action="{{ url_for('add_user') }}">
  <input type="text" name="username" placeholder="username, e.g. kid1" required>
  <input type="text" name="display_name" placeholder="Display name, e.g. Alex">
  <input type="password" name="password" placeholder="Password" required>
  <button class="add" type="submit">Add user</button>
</form>
<p class="hint">This username/password is what gets configured in that person's device proxy settings (not the dashboard login).</p>
</div>
"""


@app.route("/users")
@require_admin
def users():
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    out = []
    for u in rows:
        # Matches what the "N assigned" link's ?user_id= filter on /domains
        # actually shows: explicit assignments plus every global domain.
        domain_count = conn.execute(
            "SELECT COUNT(*) c FROM domains d "
            "LEFT JOIN user_domains ud ON ud.domain_id = d.id AND ud.user_id = ? "
            "WHERE d.is_global = 1 OR ud.user_id IS NOT NULL",
            (u["id"],),
        ).fetchone()["c"]
        show_count = conn.execute(
            "SELECT COUNT(*) c FROM user_shows WHERE user_id = ?", (u["id"],)
        ).fetchone()["c"]
        out.append({**dict(u), "domain_count": domain_count, "show_count": show_count})
    cert_banner_dismissed = bool(db.get_setting(conn, "cert_banner_dismissed", ""))
    return render(
        "users", render_template_string(USERS_BODY, users=out, cert_banner_dismissed=cert_banner_dismissed)
    )


@app.route("/users/dismiss-cert-banner", methods=["POST"])
@require_admin
def dismiss_cert_banner():
    conn = get_db()
    db.set_setting(conn, "cert_banner_dismissed", "1")
    conn.commit()
    return flash_redirect("users", "Dismissed -- find the CA certificate under Settings from now on.")


@app.route("/users/add", methods=["POST"])
@require_admin
def add_user():
    username = request.form.get("username", "").strip()
    display_name = request.form.get("display_name", "").strip() or username
    password = request.form.get("password", "")
    if not username or not password:
        return flash_redirect("users", "Username and password are required.", error=True)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        return flash_redirect("users", "Username can only contain letters, numbers, _ . -", error=True)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, display_name, password_hash, created_at) VALUES (?,?,?,?)",
            (username, display_name, auth.hash_password(password), db.now_iso()),
        )
        conn.commit()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return flash_redirect("users", f"Username {username!r} already exists.", error=True)
        raise
    return flash_redirect("users", f"Added user {username}.")


@app.route("/users/delete", methods=["POST"])
@require_admin
def delete_user():
    user_id = request.form.get("user_id", "")
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return flash_redirect("users", "User deleted.")


@app.route("/users/bulk-delete", methods=["POST"])
@require_admin
def bulk_delete_users():
    """Users list's toolbar "Delete" button (RoadMap.md's dated entry --
    extending the Devices/Domains bulk-actions pattern to every list
    page). Plain `DELETE ... WHERE id IN (...)`, same shape as
    `bulk_delete_devices()`."""
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    if not user_ids:
        return flash_redirect("users", "No users selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(user_ids))
    conn.execute(f"DELETE FROM users WHERE id IN ({placeholders})", tuple(user_ids))
    conn.commit()
    return flash_redirect("users", f"Deleted {len(user_ids)} user{'s' if len(user_ids) != 1 else ''}.")


@app.route("/users/bulk-pause", methods=["POST"])
@require_admin
def bulk_pause_users():
    """Users list's toolbar "Disable" button -- pauses every checked
    user's own devices, same `_set_quarantine()` mechanism `pause_user()`
    already uses for one kid at a time, scoped to an `IN (...)` id list."""
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    if not user_ids:
        return flash_redirect("users", "No users selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(user_ids))
    n = _set_quarantine(conn, f"user_id IN ({placeholders}) AND ignored = 0", tuple(user_ids), paused=True)
    return flash_redirect("users", f"Paused {n} device{'s' if n != 1 else ''}.")


@app.route("/users/bulk-resume", methods=["POST"])
@require_admin
def bulk_resume_users():
    """Users list's toolbar "Enable" button -- the resume counterpart to
    bulk_pause_users() above."""
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    if not user_ids:
        return flash_redirect("users", "No users selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(user_ids))
    n = _set_quarantine(
        conn, f"user_id IN ({placeholders}) AND quarantined_at IS NOT NULL", tuple(user_ids), paused=False
    )
    return flash_redirect("users", f"Resumed {n} device{'s' if n != 1 else ''}.")


@app.route("/users/export", methods=["GET"])
@require_admin
def export_users_csv():
    """Users list's toolbar "Download users" button -- a plain CSV of
    every user (username, display name, assigned-sites count, approved-
    shows count), not gated by checkbox selection, same "always
    available regardless of selection" role `export_devices_csv()`
    already established."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Username", "Display name", "Sites assigned", "Shows approved"])
    for u in rows:
        domain_count = conn.execute(
            "SELECT COUNT(*) c FROM domains d "
            "LEFT JOIN user_domains ud ON ud.domain_id = d.id AND ud.user_id = ? "
            "WHERE d.is_global = 1 OR ud.user_id IS NOT NULL",
            (u["id"],),
        ).fetchone()["c"]
        show_count = conn.execute("SELECT COUNT(*) c FROM user_shows WHERE user_id = ?", (u["id"],)).fetchone()["c"]
        writer.writerow([u["username"], u["display_name"], domain_count, show_count])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=users.csv"},
    )


@app.route("/users/reset-password", methods=["POST"])
@require_admin
def reset_password():
    user_id = request.form.get("user_id", "")
    password = request.form.get("password", "")
    if not password:
        return flash_redirect("user_detail", "Password is required.", error=True, user_id=user_id)
    conn = get_db()
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (auth.hash_password(password), user_id),
    )
    conn.commit()
    return flash_redirect("user_detail", "Password updated.", user_id=user_id)


# Shared by user_detail and group_detail's own "Assigned sites" card --
# real live-testing feedback 2026-09-07 (RoadMap.md's dated entry):
# creating a new user shows "27 assigned" on the Users list (the
# is_global count, see users()'s own domain_count query), but that
# user's own Manage page only ever queried user_domains directly, so it
# showed nothing for a brand-new user beyond a vague "(still gets global
# sites)" aside -- no way to see WHAT those 27 domains actually are
# without separately knowing to visit the unfiltered Domains page and
# spot the "Everyone" rows yourself. This card answers that in place,
# using each domain's own `note` (defaults/seed_defaults.py already sets
# one on every seeded global domain -- "Google", "Cookie consent", etc.)
# -- no schema change needed, just surfacing data that already existed.
# Needs global_domains in scope wherever it's used.
GLOBAL_SITES_CARD = """
<div class="card">
<h2>Global sites (apply to everyone, {{ global_domains|length }})</h2>
<p class="hint">
  Always included on top of whatever's assigned above -- shared
  infrastructure (fonts, auth providers, CDNs, etc.) rather than a
  per-person decision. This is why the Users/Groups list's "assigned"
  count is higher than what's shown above alone.
</p>
<div class="table-scroll">
<table>
  <tr><th>Domain</th><th>Mode</th><th>Note</th></tr>
  {% for d in global_domains %}
  <tr>
    <td><code>{{ d.pattern }}</code></td>
    <td><span class="badge mode-{{ d.mode }}">{{ d.mode }}</span></td>
    <td>{{ d.note or '' }}</td>
  </tr>
  {% else %}
  <tr><td colspan="3"><em>No global sites configured.</em></td></tr>
  {% endfor %}
</table>
</div>
<p class="hint">Manage the full list, including which are global, from the <a href="{{ url_for('domains') }}">Domains</a> page.</p>
</div>
"""


USER_DETAIL_BODY = """
<p><a href="{{ url_for('users') }}">&larr; All users</a></p>
<h1>{{ u.display_name }} <code>({{ u.username }})</code></h1>

<div class="card">
<h2>Active right now</h2>
{% if active_schedules %}
<ul style="margin:.3rem 0 0; padding-left:1.2rem;">
{% for s in active_schedules %}
  <li>
    <strong>{{ s.name }}</strong>
    {% if s.lockout_all %}<span class="badge blocked">full lockout</span>{% else %}<span class="badge">category block</span>{% endif %}
    {% if s.is_mode %}<span class="badge" title="Eligible for &quot;Shift mode now&quot;">mode</span>{% endif %}
  </li>
{% endfor %}
</ul>
{% else %}
<p class="hint">Nothing active right now -- no schedule currently applies to {{ u.display_name }}.</p>
{% endif %}
<p class="hint">Computed live from <a href="{{ url_for('schedules') }}">Schedules</a> assigned to {{ u.display_name }} (directly, or Everyone) -- reflects any active "Shift mode now" override, not just the clock.</p>
</div>

<div class="card">
<h2>Pause the internet</h2>
{% if user_devices %}
<p class="hint">
  Pauses every device assigned to {{ u.display_name }} at once ({{ user_devices|length }}
  device{{ 's' if user_devices|length != 1 else '' }}, {{ paused_device_count }} currently paused) --
  immediate and indefinite, until resumed. Manage an individual device's pause from the
  <a href="{{ url_for('devices') }}">Devices</a> page instead if you only want to pause one.
</p>
<form class="inline" method="post" action="{{ url_for('pause_user') }}" onsubmit="return confirm('Pause the internet for all of {{ u.display_name }}\\'s devices?');">
  <input type="hidden" name="user_id" value="{{ u.id }}">
  <button class="danger" type="submit">Pause {{ u.display_name }}'s internet</button>
</form>
<form class="inline" method="post" action="{{ url_for('resume_user') }}">
  <input type="hidden" name="user_id" value="{{ u.id }}">
  <button class="btn" type="submit">Resume</button>
</form>
{% else %}
<p class="hint">{{ u.display_name }} has no devices assigned yet -- assign one from the <a href="{{ url_for('devices') }}">Devices</a> page to pause their internet from here.</p>
{% endif %}
</div>

<div class="card">
<h2>Devices ({{ assigned_devices|length }})</h2>
<div class="table-scroll">
<table>
  <tr><th>MAC address</th><th>Label</th><th>Status</th></tr>
  {% for d in assigned_devices %}
  <tr>
    <td><code>{{ d.mac_address }}</code></td>
    <td>{{ d.label or '' }}</td>
    <td>
      {% if d.ignored %}<span class="badge pending">Ignored</span>
      {% elif d.quarantined_at %}<span class="badge blocked">Paused</span>
      {% else %}<span class="badge allowed">Active</span>{% endif %}
    </td>
  </tr>
  {% else %}
  <tr><td colspan="3"><em>No devices assigned.</em></td></tr>
  {% endfor %}
</table>
</div>
<p class="hint">Assign or reassign a device to {{ u.display_name }} from its own row on the <a href="{{ url_for('devices') }}">Devices</a> page.</p>
</div>

<div class="card">
<h2>Assigned sites ({{ domain_count }})</h2>
{% if domain_count %}
<div class="toolbar" style="justify-content:space-between;">
  <form method="get" action="{{ url_for('user_detail', user_id=u.id) }}" class="inline">
    <input type="hidden" name="page" value="1">
    <label class="hint" style="margin:0;">Show
      <select name="per_page" onchange="this.form.submit()">
        {% for opt in domains_page_size_options %}
        <option value="{{ opt }}" {{ 'selected' if opt == domains_per_page }}>{{ opt }}</option>
        {% endfor %}
      </select>
      per page &mdash; showing {{ domains_range_start }}-{{ domains_range_end }} of {{ domain_count }}
    </label>
  </form>
  {% if domains_total_pages > 1 %}
  <span>
    {% if domains_page > 1 %}<a class="btn small" href="{{ url_for('user_detail', user_id=u.id, page=domains_page-1, per_page=domains_per_page) }}">&larr; Prev</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
    <span class="hint">Page {{ domains_page }} of {{ domains_total_pages }}</span>
    {% if domains_page < domains_total_pages %}<a class="btn small" href="{{ url_for('user_detail', user_id=u.id, page=domains_page+1, per_page=domains_per_page) }}">Next &rarr;</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
  </span>
  {% endif %}
</div>
{% endif %}
<div class="table-scroll">
<table>
  <tr><th>Domain</th><th>Mode</th></tr>
  {% for d in assigned_domains %}
  <tr><td><code>{{ d.pattern }}</code></td><td><span class="badge mode-{{ d.mode }}">{{ d.mode }}</span></td></tr>
  {% else %}
  <tr><td colspan="2"><em>No per-user sites assigned (still gets global sites, see below).</em></td></tr>
  {% endfor %}
</table>
</div>
{% if domains_total_pages > 1 %}
<div class="toolbar" style="justify-content:flex-end;">
  {% if domains_page > 1 %}<a class="btn small" href="{{ url_for('user_detail', user_id=u.id, page=domains_page-1, per_page=domains_per_page) }}">&larr; Prev</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
  <span class="hint">Page {{ domains_page }} of {{ domains_total_pages }}</span>
  {% if domains_page < domains_total_pages %}<a class="btn small" href="{{ url_for('user_detail', user_id=u.id, page=domains_page+1, per_page=domains_per_page) }}">Next &rarr;</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
</div>
{% endif %}
<p class="hint">Manage assignment from the <a href="{{ url_for('domains') }}">Domains</a> page -- pick the site there and check this user.</p>
</div>

""" + GLOBAL_SITES_CARD + """

<div class="card">
<h2>Approved Crunchyroll shows ({{ shows|length }})</h2>
<div class="table-scroll">
<table>
  <tr><th>Series ID</th><th>Name</th><th></th></tr>
  {% for s in shows %}
  <tr>
    <td><code>{{ s.series_id }}</code></td>
    <td>{{ s.series_name }}</td>
    <td>
      <form class="inline" method="post" action="{{ url_for('remove_show') }}">
        <input type="hidden" name="user_id" value="{{ u.id }}">
        <input type="hidden" name="series_id" value="{{ s.series_id }}">
        <button class="danger small" type="submit" onclick="return confirm('Remove {{ s.series_name }}?')">Remove</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="3"><em>No shows approved yet.</em></td></tr>
  {% endfor %}
</table>
</div>
<form class="add-form" method="post" action="{{ url_for('add_show') }}">
  <input type="hidden" name="user_id" value="{{ u.id }}">
  {% if all_approved_shows %}
  <div class="combobox" data-combobox data-mode="single" data-empty="No other shows approved yet." style="max-width:320px;">
    <div class="combobox-current" data-combobox-current></div>
    <input type="search" class="combobox-input" data-combobox-input placeholder="Already approved for someone else&hellip;">
    <div class="combobox-results" data-combobox-results></div>
    <input type="hidden" name="existing_series_id" data-combobox-hidden value="">
    <script type="application/json" data-combobox-items>{{ all_approved_shows|tojson }}</script>
  </div>
  <span class="hint" style="margin:0;">&mdash; or &mdash;</span>
  {% endif %}
  <input type="url" name="url" placeholder="Paste a new Crunchyroll series URL" style="flex:1; min-width:280px;">
  <input type="text" name="name" placeholder="Name (auto-filled, editable)">
  <button class="add" type="submit">Approve show</button>
</form>
<p class="hint">
  Picking one already approved for someone else skips typing/re-resolving
  the URL -- if both a picked show and a URL are given, the picked one wins.
</p>
</div>

<div class="card">
<h2>Change password</h2>
<form class="add-form" method="post" action="{{ url_for('reset_password') }}">
  <input type="hidden" name="user_id" value="{{ u.id }}">
  <input type="password" name="password" placeholder="New password" required>
  <button class="add" type="submit">Update password</button>
</form>
</div>
"""


@app.route("/users/<int:user_id>")
@require_admin
def user_detail(user_id: int):
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if u is None:
        return flash_redirect("users", "That user no longer exists.", error=True)
    # Paginated (added 2026-09-07, RoadMap.md's dated entry, project
    # owner's explicit request, same "these can grow extensively with
    # time" reasoning as Devices/Domains/Categories the same day) -- a
    # heavily-assigned kid's own site list is exactly the kind of thing
    # that only ever grows, one "Approve" click at a time, for as long as
    # the household uses this.
    domain_count = conn.execute(
        "SELECT COUNT(*) AS c FROM user_domains WHERE user_id = ?", (user_id,)
    ).fetchone()["c"]
    domains_page, domains_per_page = _parse_pagination(
        request.args, default_per_page=DEFAULT_LIST_PAGE_SIZE, options=LIST_PAGE_SIZE_OPTIONS,
    )
    domains_total_pages = max(1, math.ceil(domain_count / domains_per_page))
    domains_page = min(domains_page, domains_total_pages)
    assigned_domains = conn.execute(
        "SELECT d.pattern, d.mode FROM domains d "
        "JOIN user_domains ud ON ud.domain_id = d.id "
        "WHERE ud.user_id = ? ORDER BY d.pattern LIMIT ? OFFSET ?",
        (user_id, domains_per_page, (domains_page - 1) * domains_per_page),
    ).fetchall()
    shows = conn.execute(
        "SELECT series_id, series_name FROM user_shows WHERE user_id = ? ORDER BY series_name",
        (user_id,),
    ).fetchall()
    # G6: excludes ignored devices, same reasoning as pause_all_devices() --
    # an ignored device can't actually be paused (BYPASS outranks
    # QUARANTINE in classify_device()), so it shouldn't count toward "how
    # many of this kid's devices are pausable" either.
    user_devices = conn.execute(
        "SELECT id, quarantined_at FROM devices WHERE user_id = ? AND ignored = 0", (user_id,)
    ).fetchall()
    paused_device_count = sum(1 for row in user_devices if row["quarantined_at"])
    # Added 2026-09-08, real live-testing feedback: this page had no way
    # to see WHICH devices are assigned to this user at all -- an admin
    # had to go to the Devices page and search/filter by name instead,
    # the exact gap the Group-detail page's own "Devices in this group"
    # card (added earlier) never had. Deliberately ALL devices with this
    # user_id, including an ignored one if that combination somehow
    # exists (unlike user_devices above, which excludes those for the
    # pause-count's own different reasoning) -- this card's job is
    # accurately answering "what's assigned here", not "what's
    # pausable".
    assigned_devices = conn.execute(
        "SELECT mac_address, label, ignored, quarantined_at FROM devices "
        "WHERE user_id = ? ORDER BY label IS NULL, label, mac_address",
        (user_id,),
    ).fetchall()
    active_schedules = schedule_eval.active_schedules_for_target(
        conn, datetime.now(timezone.utc), user_id=user_id
    )
    # Real live-testing feedback (RoadMap.md's dated entry): approving a
    # show for a second kid meant re-pasting/re-resolving the exact same
    # Crunchyroll URL a first kid had already been approved for. Every
    # OTHER user's already-approved show (deduped by series_id, excluding
    # this user's own -- no point offering to "re-approve" what's already
    # here) becomes a pickable option, skipping the URL entirely; see
    # add_show()'s own handling of the resulting existing_series_id field.
    all_approved_shows = conn.execute(
        "SELECT DISTINCT series_id AS id, series_name FROM user_shows "
        "WHERE user_id != ? ORDER BY series_name", (user_id,)
    ).fetchall()
    body = render_template_string(
        USER_DETAIL_BODY, u=u, assigned_domains=assigned_domains, shows=shows,
        user_devices=user_devices, paused_device_count=paused_device_count,
        assigned_devices=assigned_devices,
        active_schedules=active_schedules, global_domains=_global_domains(conn),
        all_approved_shows=_entity_combo(all_approved_shows, lambda s: s["series_name"]),
        domain_count=domain_count, domains_page=domains_page, domains_per_page=domains_per_page,
        domains_total_pages=domains_total_pages, domains_page_size_options=LIST_PAGE_SIZE_OPTIONS,
        domains_range_start=0 if domain_count == 0 else (domains_page - 1) * domains_per_page + 1,
        domains_range_end=min(domains_page * domains_per_page, domain_count),
    )
    return render("users", body)


@app.route("/shows/add", methods=["POST"])
@require_admin
def add_show():
    """Two ways in: paste a Crunchyroll URL (parsed below, as always), or
    pick a show already approved for a DIFFERENT user (existing_series_id,
    from user_detail()'s own all_approved_shows combobox -- real
    live-testing feedback, RoadMap.md's dated entry, that approving the
    same show for a second kid meant re-pasting/re-resolving the exact
    same URL). The picked show wins if both are somehow submitted at
    once -- an exact match on an already-known series_id needs no URL
    parsing or title lookup at all."""
    user_id = request.form.get("user_id", "")
    existing_series_id = request.form.get("existing_series_id", "").strip()
    conn = get_db()
    if existing_series_id:
        existing = conn.execute(
            "SELECT series_name FROM user_shows WHERE series_id = ? LIMIT 1", (existing_series_id,)
        ).fetchone()
        if existing is None:
            return flash_redirect("user_detail", "That show is no longer on record.", error=True, user_id=user_id)
        series_id, name = existing_series_id, existing["series_name"]
    else:
        url = request.form.get("url", "")
        override_name = request.form.get("name", "").strip()
        series_id, suggested_name = parse_series_url(url)
        if series_id is None:
            return flash_redirect("user_detail", suggested_name, error=True, user_id=user_id)
        name = override_name or cr_api.series_title(series_id) or suggested_name
    conn.execute(
        "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?,?,?) "
        "ON CONFLICT(user_id, series_id) DO UPDATE SET series_name = excluded.series_name",
        (user_id, series_id, name),
    )
    conn.commit()
    return flash_redirect("user_detail", f"Approved {name}.", user_id=user_id)


@app.route("/shows/remove", methods=["POST"])
@require_admin
def remove_show():
    user_id = request.form.get("user_id", "")
    series_id = request.form.get("series_id", "")
    conn = get_db()
    conn.execute(
        "DELETE FROM user_shows WHERE user_id = ? AND series_id = ?", (user_id, series_id)
    )
    conn.commit()
    return flash_redirect("user_detail", "Removed.", user_id=user_id)


SERIES_URL_RE = re.compile(
    r"^https?://www\.crunchyroll\.com/series/([A-Za-z0-9]+)(?:/([^/?#]+))?",
    re.IGNORECASE,
)


def parse_series_url(url: str) -> tuple[str | None, str]:
    """Returns (series_id, name) on success, or (None, error message)."""
    url = (url or "").strip()
    match = SERIES_URL_RE.match(url)
    if not match:
        return None, (
            "That doesn't look like a Crunchyroll series URL. Expected "
            "something like https://www.crunchyroll.com/series/GYE5K0XVR/ace-attorney"
        )
    series_id = match.group(1).upper()
    slug = match.group(2) or ""
    name = " ".join(w.capitalize() for w in slug.split("-") if w) or series_id
    return series_id, name


# ==========================================================
# DOMAINS
# ==========================================================

def path_to_pattern(path: str) -> str:
    """Derive a starting-point regex pattern from a real, literal request
    path -- query string stripped, then anchored to the start and
    regex-escaped so path characters that happen to be regex metacharacters
    (a literal `.` is the common one) are matched literally rather than as
    "any character". No trailing anchor: matches the given path and
    anything after it (e.g. GH #6's motivating case -- approving one
    comic's URL should keep matching future chapters under the same path),
    same convention as the seeded CRUNCHYROLL_PATHS prefixes. This is a
    starting point for the admin to review/edit, not a final answer --
    callers must still let it go through the normal add_path validation.
    """
    return "^" + re.escape((path or "/").split("?", 1)[0])


def _global_domains(conn) -> list:
    """Every is_global=1 domain, for GLOBAL_SITES_CARD -- shared by
    user_detail() and group_detail() (see that constant's own docstring
    for why this exists)."""
    return conn.execute(
        "SELECT pattern, mode, note FROM domains WHERE is_global = 1 ORDER BY pattern"
    ).fetchall()


def _entity_combo(rows, label_fn) -> list[dict]:
    """Turns a list of DB rows into the flat [{"id", "label"}, ...] shape
    the combobox widget's data-combobox-items script expects. Built once
    in Python (rather than in the Jinja template) since the label differs
    per entity type (display_name / name / label-or-mac_address) and
    Jinja has no clean way to build a list of dicts inline before tojson."""
    return [{"id": str(r["id"]), "label": label_fn(r)} for r in rows]


# Shared by the add-domain form and the domain Manage page's Access card --
# one Everyone checkbox plus three independent multi-select comboboxes
# (Users, Groups, Devices), so "single user, multiple users, a device, a
# group, or any combination" is just whatever's picked across these three
# widgets at once. Needs all_users_combo/all_groups_combo/all_devices_combo
# (see _entity_combo) and preselected_user_ids/preselected_group_ids/
# preselected_device_ids/is_global_checked in scope wherever it's used.
ACCESS_SELECTS = """
  <label><input type="checkbox" name="is_global" {{ 'checked' if is_global_checked }}> Everyone</label>
  <div class="access-grid">
    <div>
      <div class="access-label">Users</div>
      <div class="combobox" data-combobox data-mode="multi" data-field="user_ids" data-empty="No users yet.">
        <div class="combobox-tags" data-combobox-tags></div>
        <input type="search" class="combobox-input" data-combobox-input placeholder="Search users&hellip;">
        <div class="combobox-results" data-combobox-results></div>
        <script type="application/json" data-combobox-items>{{ all_users_combo|tojson }}</script>
        <script type="application/json" data-combobox-selected>{{ preselected_user_ids|list|tojson }}</script>
      </div>
    </div>
    <div>
      <div class="access-label">Groups</div>
      <div class="combobox" data-combobox data-mode="multi" data-field="group_ids" data-empty="No groups yet.">
        <div class="combobox-tags" data-combobox-tags></div>
        <input type="search" class="combobox-input" data-combobox-input placeholder="Search groups&hellip;">
        <div class="combobox-results" data-combobox-results></div>
        <script type="application/json" data-combobox-items>{{ all_groups_combo|tojson }}</script>
        <script type="application/json" data-combobox-selected>{{ preselected_group_ids|list|tojson }}</script>
      </div>
    </div>
    <div>
      <div class="access-label">Devices</div>
      <div class="combobox" data-combobox data-mode="multi" data-field="device_ids" data-empty="No devices yet.">
        <div class="combobox-tags" data-combobox-tags></div>
        <input type="search" class="combobox-input" data-combobox-input placeholder="Search devices&hellip;">
        <div class="combobox-results" data-combobox-results></div>
        <script type="application/json" data-combobox-items>{{ all_devices_combo|tojson }}</script>
        <script type="application/json" data-combobox-selected>{{ preselected_device_ids|list|tojson }}</script>
      </div>
    </div>
  </div>
  <p class="hint" style="margin-top:.5rem;">Type to search, then click a result to add it as a tag -- click a tag's &times; to remove it.</p>
"""

# Phase 8: same widget/field shape as ACCESS_SELECTS above (is_global +
# three multi comboboxes, posting user_ids/group_ids/device_ids) -- but
# categories/schedules are a BLOCK-list, the opposite polarity from
# domains' allow-list, so the copy says "Block for" / "Blocked for"
# instead of "Everyone" / the allow-oriented hint text, to avoid this
# reading like the Domains page's grant. Needs the exact same template
# variables in scope (all_users_combo/all_groups_combo/all_devices_combo,
# preselected_*_ids, is_global_checked).
BLOCK_ACCESS_SELECTS = """
  <label><input type="checkbox" name="is_global" {{ 'checked' if is_global_checked }}> Block for Everyone</label>
  <div class="access-grid">
    <div>
      <div class="access-label">Users</div>
      <div class="combobox" data-combobox data-mode="multi" data-field="user_ids" data-empty="No users yet.">
        <div class="combobox-tags" data-combobox-tags></div>
        <input type="search" class="combobox-input" data-combobox-input placeholder="Search users&hellip;">
        <div class="combobox-results" data-combobox-results></div>
        <script type="application/json" data-combobox-items>{{ all_users_combo|tojson }}</script>
        <script type="application/json" data-combobox-selected>{{ preselected_user_ids|list|tojson }}</script>
      </div>
    </div>
    <div>
      <div class="access-label">Groups</div>
      <div class="combobox" data-combobox data-mode="multi" data-field="group_ids" data-empty="No groups yet.">
        <div class="combobox-tags" data-combobox-tags></div>
        <input type="search" class="combobox-input" data-combobox-input placeholder="Search groups&hellip;">
        <div class="combobox-results" data-combobox-results></div>
        <script type="application/json" data-combobox-items>{{ all_groups_combo|tojson }}</script>
        <script type="application/json" data-combobox-selected>{{ preselected_group_ids|list|tojson }}</script>
      </div>
    </div>
    <div>
      <div class="access-label">Devices</div>
      <div class="combobox" data-combobox data-mode="multi" data-field="device_ids" data-empty="No devices yet.">
        <div class="combobox-tags" data-combobox-tags></div>
        <input type="search" class="combobox-input" data-combobox-input placeholder="Search devices&hellip;">
        <div class="combobox-results" data-combobox-results></div>
        <script type="application/json" data-combobox-items>{{ all_devices_combo|tojson }}</script>
        <script type="application/json" data-combobox-selected>{{ preselected_device_ids|list|tojson }}</script>
      </div>
    </div>
  </div>
  <p class="hint" style="margin-top:.5rem;">Type to search, then click a result to add it as a tag -- click a tag's &times; to remove it. Blocked for Everyone always wins regardless of what's checked below.</p>
"""


DOMAINS_BODY = """
<div class="card">
<h2>Filter</h2>
<div class="combobox" data-combobox data-mode="nav" data-empty="No kids, groups, or devices yet.">
  <input type="search" class="combobox-input" data-combobox-input placeholder="Search kids, groups, devices&hellip;">
  <div class="combobox-results" data-combobox-results></div>
  <script type="application/json" data-combobox-items>{{ filter_combo|tojson }}</script>
</div>
{% if filtered_user or filtered_group or filtered_device %}
<p class="hint">
  Showing domains assigned to
  {% if filtered_user %}<strong>{{ filtered_user.display_name }}</strong>
  {% elif filtered_group %}the <strong>{{ filtered_group.name }}</strong> group
  {% else %}<strong>{{ filtered_device.label or filtered_device.mac_address }}</strong>{% endif %}
  (plus everyone's global domains) -- <a href="{{ url_for('domains') }}">clear filter</a>
</p>
{% endif %}
</div>

<div class="card">
<h2>Domains ({{ domain_count }})</h2>
<p class="hint">
  <span class="badge mode-splice">splice</span> host-only, never decrypted &nbsp;
  <span class="badge mode-bump">bump</span> fully decrypted, path/show rules apply &nbsp;
  <span class="badge mode-trusted">trusted</span> always passed through, unchecked
</p>
{% if domains %}
<div class="toolbar" id="domainBulkToolbar">
  <a class="btn small" href="{{ url_for('export_domains_csv') }}">&darr; Download domains</a>
  <span class="toolbar-sep"></span>
  <form id="bulkDomainDeleteForm" class="inline" method="post" action="{{ url_for('bulk_delete_domains') }}"
        onsubmit="return confirm('Delete every checked domain? This cannot be undone.');">
    <button class="danger small" type="submit" disabled>Delete</button>
  </form>
  <button class="btn small" type="button" id="domainBulkManageToggle" disabled>Manage access</button>
  <span class="hint" id="domainBulkCount" style="margin:0;">Check domains below to act on several at once.</span>
</div>
<div id="domainBulkManagePanel" hidden style="margin:-.3rem 0 .6rem;">
  <p class="hint">Pick who gets the checked domains here, then apply -- replaces the ENTIRE access grant for every one checked (same as editing each one's own Manage page, just all at once).</p>
  <form id="bulkDomainAccessForm" class="add-form" method="post" action="{{ url_for('bulk_update_domain_access') }}">
""" + ACCESS_SELECTS + """
    <button class="add small" type="submit">Apply to checked domains</button>
  </form>
</div>
{% endif %}
{% if any_domains_exist %}
<form method="get" action="{{ url_for('domains') }}" class="inline" style="margin-bottom:.3rem; gap:.4rem;">
  <input type="hidden" name="page" value="1">
  {% for k, v in clear_search_args.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
  <input type="search" name="q" value="{{ search }}" placeholder="Search pattern or note&hellip;" style="width:100%; max-width:280px;">
  <button class="btn small" type="submit">Search</button>
  {% if search %}<a class="btn small" href="{{ url_for('domains', **clear_search_args) }}">Clear</a>{% endif %}
</form>
{% if search %}<p class="hint" style="margin:0 0 .6rem;">Searches every matching domain, not just this page &mdash; showing results for &ldquo;{{ search }}&rdquo;.</p>{% endif %}
<div class="toolbar" style="justify-content:space-between;">
  <form method="get" action="{{ url_for('domains') }}" class="inline">
    <input type="hidden" name="page" value="1">
    {% for k, v in filter_query_args.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
    <label class="hint" style="margin:0;">Show
      <select name="per_page" onchange="this.form.submit()">
        {% for opt in page_size_options %}
        <option value="{{ opt }}" {{ 'selected' if opt == per_page }}>{{ opt }}</option>
        {% endfor %}
      </select>
      per page &mdash; showing {{ range_start }}-{{ range_end }} of {{ domain_count }}
    </label>
  </form>
  {% if total_pages > 1 %}
  <span>
    {% if page > 1 %}<a class="btn small" href="{{ url_for('domains', page=page-1, per_page=per_page, **filter_query_args) }}">&larr; Prev</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
    <span class="hint">Page {{ page }} of {{ total_pages }}</span>
    {% if page < total_pages %}<a class="btn small" href="{{ url_for('domains', page=page+1, per_page=per_page, **filter_query_args) }}">Next &rarr;</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
  </span>
  {% endif %}
</div>
{% endif %}
<div class="table-scroll">
<table id="domainsTable">
  <tr><th>{% if domains %}<input type="checkbox" id="domainSelectAll" title="Select all">{% endif %}</th><th>Pattern</th><th>Mode</th><th>Access</th><th>Note</th><th></th></tr>
  {% for d in domains %}
  <tr>
    <td><input type="checkbox" class="bulk-domain-check" value="{{ d.id }}"></td>
    <td><code>{{ d.pattern }}</code></td>
    <td><span class="badge mode-{{ d.mode }}">{{ d.mode }}</span></td>
    <td>{{ 'Everyone' if d.is_global else 'Per-user/group/device' }}</td>
    <td>{{ d.note or '' }}</td>
    <td>
      <a class="btn small" href="{{ url_for('domain_detail', domain_id=d.id) }}">Manage</a>
      <form class="inline" method="post" action="{{ url_for('delete_domain') }}">
        <input type="hidden" name="domain_id" value="{{ d.id }}">
        {% if filtered_user %}<input type="hidden" name="user_id" value="{{ filtered_user.id }}">{% endif %}
        {% if filtered_group %}<input type="hidden" name="group_id" value="{{ filtered_group.id }}">{% endif %}
        {% if filtered_device %}<input type="hidden" name="device_id" value="{{ filtered_device.id }}">{% endif %}
        <button class="danger small" type="submit" onclick="return confirm('Delete this domain rule?')">Delete</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="6"><em>{% if search %}No domains match &ldquo;{{ search }}&rdquo;.{% else %}No domains configured.{% endif %}</em></td></tr>
  {% endfor %}
</table>
</div>
{% if total_pages > 1 %}
<div class="toolbar" style="justify-content:flex-end;">
  {% if page > 1 %}<a class="btn small" href="{{ url_for('domains', page=page-1, per_page=per_page, **filter_query_args) }}">&larr; Prev</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
  <span class="hint">Page {{ page }} of {{ total_pages }}</span>
  {% if page < total_pages %}<a class="btn small" href="{{ url_for('domains', page=page+1, per_page=per_page, **filter_query_args) }}">Next &rarr;</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
</div>
{% endif %}
<script>
(function () {
  var selectAll = document.getElementById("domainSelectAll");
  var countLabel = document.getElementById("domainBulkCount");
  var toolbar = document.getElementById("domainBulkToolbar");
  var manageToggle = document.getElementById("domainBulkManageToggle");
  var managePanel = document.getElementById("domainBulkManagePanel");

  // Same Entra-style toolbar pattern as Devices/Users/Categories/Schedules
  // (RoadMap.md's dated entry) -- replaces this page's old <details>
  // bulk-assign disclosure with the same "buttons above the table,
  // disabled until something's checked" toolbar used everywhere else.
  function updateToolbarState() {
    if (!toolbar) return;
    var n = document.querySelectorAll(".bulk-domain-check:checked").length;
    toolbar.querySelectorAll("button").forEach(function (btn) { btn.disabled = n === 0; });
    if (n === 0 && managePanel) managePanel.hidden = true;
    if (countLabel) {
      countLabel.textContent = n === 0
        ? "Check domains below to act on several at once."
        : n + " domain" + (n === 1 ? "" : "s") + " selected.";
    }
  }

  if (selectAll) {
    selectAll.addEventListener("change", function () {
      document.querySelectorAll(".bulk-domain-check").forEach(function (box) { box.checked = selectAll.checked; });
      updateToolbarState();
    });
  }
  document.querySelectorAll(".bulk-domain-check").forEach(function (box) {
    box.addEventListener("change", updateToolbarState);
  });
  updateToolbarState();

  // "Manage access" doesn't submit anything itself -- it reveals the
  // access-assign panel below, same "click to open further options" role
  // the Devices page's own "Manage" toggle plays for its group-assign panel.
  if (manageToggle && managePanel) {
    manageToggle.addEventListener("click", function () {
      managePanel.hidden = !managePanel.hidden;
    });
  }

  function wireBulkForm(formId) {
    var form = document.getElementById(formId);
    if (!form) return;
    form.addEventListener("submit", function (event) {
      // The row checkboxes live in #domainsTable, not inside either bulk
      // form -- nesting a <form> around the table would break the per-row
      // Delete forms already in each row (HTML forms can't nest) -- so
      // they're collected into hidden inputs here instead, right before
      // submit.
      var checked = Array.prototype.slice.call(document.querySelectorAll(".bulk-domain-check:checked"));
      if (!checked.length) {
        event.preventDefault();
        alert("Check at least one domain above first.");
        return;
      }
      form.querySelectorAll("input[name=domain_ids]").forEach(function (el) { el.remove(); });
      checked.forEach(function (box) {
        var hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "domain_ids";
        hidden.value = box.value;
        form.appendChild(hidden);
      });
    });
  }
  wireBulkForm("bulkDomainDeleteForm");
  wireBulkForm("bulkDomainAccessForm");
})();
</script>
</div>

<div class="card">
<h2>Add a domain</h2>
<form class="add-form" method="post" action="{{ url_for('add_domain') }}">
  {% if filtered_user %}<input type="hidden" name="user_id" value="{{ filtered_user.id }}">{% endif %}
  {% if filtered_group %}<input type="hidden" name="group_id" value="{{ filtered_group.id }}">{% endif %}
  {% if filtered_device %}<input type="hidden" name="device_id" value="{{ filtered_device.id }}">{% endif %}
  <input type="text" name="pattern" placeholder="e.g. example\\.com" required>
  <select name="mode">
    <option value="splice">splice (host-only)</option>
    <option value="bump">bump (decrypt, path rules)</option>
    <option value="trusted">trusted (always pass, unchecked)</option>
  </select>
  <input type="text" name="note" placeholder="Note (optional)">
  <button class="add" type="submit">Add domain</button>
""" + ACCESS_SELECTS + """
</form>
<p class="hint">
  "Everyone" is for shared infrastructure (fonts, auth providers, CDNs). You can adjust any of
  this later from the domain's Manage page.
</p>
</div>

{% if filtered_user %}
<div class="card">
<h2>Approve a specific page for {{ filtered_user.display_name }}</h2>
<p class="hint">Paste a full URL to approve just that page (and anything after it), without opening the rest of the site. Creates the domain in bump mode if it doesn't already exist, adds a path rule derived from the URL, and assigns both to {{ filtered_user.display_name }}.</p>
<form class="add-form" method="post" action="{{ url_for('add_domain_from_url') }}">
  <input type="hidden" name="user_id" value="{{ filtered_user.id }}">
  <input type="url" name="url" placeholder="https://example.com/some/specific/page" required style="flex:1; min-width:320px;">
  <button class="add" type="submit">Approve this page</button>
</form>
</div>
{% endif %}
"""


def _domains_filter_combo(all_users, all_groups, all_devices) -> list[dict]:
    """Items for the Domains page's filter combobox (data-mode="nav") --
    like _entity_combo, but each item also carries the ?target= href to
    navigate to when picked, and there's a leading pseudo-entry for
    clearing back to the unfiltered view."""
    items = [{"id": "", "label": "All domains", "href": url_for("domains")}]
    items += [
        {"id": f"user:{u['id']}", "label": u["display_name"], "href": url_for("domains", target=f"user:{u['id']}")}
        for u in all_users
    ]
    items += [
        {"id": f"group:{g['id']}", "label": g["name"], "href": url_for("domains", target=f"group:{g['id']}")}
        for g in all_groups
    ]
    items += [
        {
            "id": f"device:{d['id']}", "label": d["label"] or d["mac_address"],
            "href": url_for("domains", target=f"device:{d['id']}"),
        }
        for d in all_devices
    ]
    return items


def _parse_filter_target(raw: str) -> dict:
    """Decodes the Domains page's single combined filter picker (radio
    value like 'user:5', matching the same encoding as the device
    assignment picker) into the user_id/group_id/device_id shape
    _get_filtered_target already understands -- one control instead of
    three separate dropdowns that could disagree with each other."""
    if raw.startswith("user:"):
        return {"user_id": raw[len("user:"):]}
    if raw.startswith("group:"):
        return {"group_id": raw[len("group:"):]}
    if raw.startswith("device:"):
        return {"device_id": raw[len("device:"):]}
    return {}


def _report_filter_combo(all_users, all_groups, all_devices) -> list[dict]:
    """Items for the Report page's filter combobox (data-mode="single",
    like DEVICE_ASSIGNMENT_SELECT -- NOT data-mode="nav" like the Domains
    page's _domains_filter_combo above, since this filter has to compose
    with the existing status/days selects in one form and submit together
    on Apply, rather than navigating immediately on pick)."""
    items = [{"id": "", "label": "All kids, groups, devices"}]
    items += [{"id": f"user:{u['id']}", "label": u["display_name"]} for u in all_users]
    items += [{"id": f"group:{g['id']}", "label": g["name"]} for g in all_groups]
    items += [
        {"id": f"device:{d['id']}", "label": d["label"] or d["mac_address"]}
        for d in all_devices
    ]
    return items


def _get_report_filter(conn, args):
    """Resolves the Report page's filter to at most one of (filtered_user,
    filtered_group, filtered_device) -- added 2026-08-31 alongside
    access_log.device_id (RoadMap.md's dated entry, GH #9) so a row with
    no user_id at all (a group- or device-only identity) can still be
    filtered/acted on. ?target= (the same combined combobox encoding the
    Domains page already uses -- 'user:5'/'group:2'/'device:7', decoded by
    _parse_filter_target) takes priority over the legacy ?user=<username>
    param, kept working for any existing bookmarks/links that still point
    at it."""
    target = args.get("target", "")
    if target:
        decoded = _parse_filter_target(target)
        if decoded.get("user_id"):
            return conn.execute("SELECT * FROM users WHERE id = ?", (decoded["user_id"],)).fetchone(), None, None
        if decoded.get("group_id"):
            return None, conn.execute("SELECT * FROM groups WHERE id = ?", (decoded["group_id"],)).fetchone(), None
        if decoded.get("device_id"):
            return None, None, conn.execute("SELECT * FROM devices WHERE id = ?", (decoded["device_id"],)).fetchone()
        return None, None, None
    legacy_username = args.get("user", "")
    if legacy_username:
        return conn.execute("SELECT * FROM users WHERE username = ?", (legacy_username,)).fetchone(), None, None
    return None, None, None


def _get_filtered_target(conn, args_or_form):
    """Resolves the Domains page's filter -- either the combined ?target=
    picker or the older individual ?user_id= / ?group_id= / ?device_id=
    params (still used by "N assigned" / "Manage domains" / "Domains"
    links elsewhere) or the equivalent hidden form fields (add/delete
    actions taken from a filtered view) -- to at most one of
    (filtered_user, filtered_group, filtered_device, error_message).
    ?target=, when present, takes priority over the individual params."""
    target = args_or_form.get("target", "")
    if target:
        decoded = _parse_filter_target(target)
        user_id, group_id, device_id = decoded.get("user_id", ""), decoded.get("group_id", ""), decoded.get("device_id", "")
    else:
        user_id = args_or_form.get("user_id", "")
        group_id = args_or_form.get("group_id", "")
        device_id = args_or_form.get("device_id", "")
    if user_id:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return (row, None, None, None) if row else (None, None, None, "That user no longer exists.")
    if group_id:
        row = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
        return (None, row, None, None) if row else (None, None, None, "That group no longer exists.")
    if device_id:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return (None, None, row, None) if row else (None, None, None, "That device no longer exists.")
    return None, None, None, None


@app.route("/domains")
@require_admin
def domains():
    """Added 2026-09-07 (RoadMap.md's dated entry, project owner's
    explicit request, same "these can grow extensively with time"
    reasoning as Devices/Categories the same day): paginated (page-size
    picker + Prev/Next). Sliced in Python, not a SQL LIMIT/OFFSET --
    unlike Devices, the filtered branch below already has to evaluate
    matching.*_has_domain() per row in Python (there's no SQL-level way
    to express "does this domain resolve for this specific user/group/
    device" without reimplementing that logic as a second copy), so the
    full filtered (or unfiltered) list is already materialized in memory
    before pagination gets a say -- slicing it is simplest and correct,
    and the domains table realistically never approaches the scale a
    subscription-backed category can (that one is genuinely
    hundreds-of-thousands; this one is hand-curated by an admin)."""
    conn = get_db()
    filtered_user, filtered_group, filtered_device, error = _get_filtered_target(conn, request.args)
    if error:
        return flash_redirect("domains", error, error=True)

    if filtered_user or filtered_group or filtered_device:
        # Same rule the proxy itself uses at request time (matching.py),
        # reused here rather than reimplemented as a second copy of the
        # "is this domain visible to this user/group/device" logic.
        all_rows = conn.execute("SELECT * FROM domains ORDER BY is_global DESC, pattern").fetchall()
        if filtered_user:
            rows = [d for d in all_rows if bool(d["is_global"]) or matching.user_has_domain(conn, filtered_user["id"], d["id"])]
        elif filtered_group:
            rows = [d for d in all_rows if bool(d["is_global"]) or matching.group_has_domain(conn, filtered_group["id"], d["id"])]
        else:
            rows = [d for d in all_rows if bool(d["is_global"]) or matching.device_has_domain(conn, filtered_device["id"], d["id"])]
    else:
        rows = conn.execute("SELECT * FROM domains ORDER BY is_global DESC, pattern").fetchall()

    # Added 2026-09-08 (RoadMap.md's dated entry, follow-up to the
    # 2026-09-07 pagination work, project owner's explicit request): now
    # that this list only renders one page at a time, the old
    # client-side search box would have silently only searched whatever
    # page happened to be on screen -- so search moved server-side.
    # Applied here in plain Python rather than SQL: the target-filter
    # branch above already has to materialize the full row list before
    # pagination gets a say (see this function's docstring), so this is
    # just one more filter pass over that same list, not a second,
    # SQL-level implementation of the same logic.
    search = (request.args.get("q") or "").strip()
    if search:
        needle = search.lower()
        rows = [d for d in rows if needle in (d["pattern"] or "").lower() or needle in (d["note"] or "").lower()]

    domain_count = len(rows)
    page, per_page = _parse_pagination(request.args, default_per_page=DEFAULT_LIST_PAGE_SIZE, options=LIST_PAGE_SIZE_OPTIONS)
    total_pages = max(1, math.ceil(domain_count / per_page))
    page = min(page, total_pages)
    page_rows = rows[(page - 1) * per_page : page * per_page]
    # Preserves whatever filter (?target=, or the legacy ?user_id=/
    # ?group_id=/?device_id=) -- and now ?q= -- is active across a
    # page/per_page change, without this, clicking Next on a filtered or
    # searched view would silently drop back to the unfiltered full list.
    filter_query_args = {k: v for k, v in request.args.items() if k not in ("page", "per_page")}
    clear_search_args = {k: v for k, v in filter_query_args.items() if k != "q"}
    any_domains_exist = bool(conn.execute("SELECT EXISTS(SELECT 1 FROM domains) AS c").fetchone()["c"])

    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    all_devices = conn.execute("SELECT * FROM devices ORDER BY COALESCE(label, mac_address)").fetchall()
    return render(
        "domains",
        render_template_string(
            DOMAINS_BODY, domains=page_rows, filtered_user=filtered_user, filtered_group=filtered_group,
            filtered_device=filtered_device, is_global_checked=False,
            filter_combo=_domains_filter_combo(all_users, all_groups, all_devices),
            all_users_combo=_entity_combo(all_users, lambda u: u["display_name"]),
            all_groups_combo=_entity_combo(all_groups, lambda g: g["name"]),
            all_devices_combo=_entity_combo(all_devices, lambda dev: dev["label"] or dev["mac_address"]),
            preselected_user_ids={filtered_user["id"]} if filtered_user else set(),
            preselected_group_ids={filtered_group["id"]} if filtered_group else set(),
            preselected_device_ids={filtered_device["id"]} if filtered_device else set(),
            domain_count=domain_count, page=page, per_page=per_page, total_pages=total_pages,
            page_size_options=LIST_PAGE_SIZE_OPTIONS, filter_query_args=filter_query_args,
            search=search, clear_search_args=clear_search_args, any_domains_exist=any_domains_exist,
            range_start=0 if domain_count == 0 else (page - 1) * per_page + 1,
            range_end=min(page * per_page, domain_count),
        ),
    )


@app.route("/domains/add", methods=["POST"])
@require_admin
def add_domain():
    pattern = request.form.get("pattern", "").strip()
    mode = request.form.get("mode", "splice")
    is_global = 1 if request.form.get("is_global") else 0
    note = request.form.get("note", "").strip() or None
    conn = get_db()

    # Preserves the Users/Domains/Devices-page filter (?user_id=/
    # ?group_id=/?device_id=) across this POST, so adding a domain from a
    # filtered view doesn't silently drop the admin back into the
    # unfiltered list -- and (see below) also assigns the new domain to
    # that filter's subject, not just redirects back to it.
    _, _, _, error = _get_filtered_target(conn, request.form)
    redirect_kwargs = {}
    if request.form.get("user_id"):
        redirect_kwargs["user_id"] = request.form["user_id"]
    elif request.form.get("group_id"):
        redirect_kwargs["group_id"] = request.form["group_id"]
    elif request.form.get("device_id"):
        redirect_kwargs["device_id"] = request.form["device_id"]

    if not pattern:
        return flash_redirect("domains", "Pattern is required.", error=True, **redirect_kwargs)
    if mode not in ("splice", "bump", "trusted"):
        return flash_redirect("domains", "Invalid mode.", error=True, **redirect_kwargs)
    if len(pattern) > 200:
        return flash_redirect("domains", "Pattern too long (200 characters max).", error=True, **redirect_kwargs)
    try:
        re.compile(pattern)
    except re.error as exc:
        return flash_redirect("domains", f"Not a valid regex: {exc}", error=True, **redirect_kwargs)

    # Explicit multi-select assignment (the add-domain form's own Users/
    # Groups/Devices lists) plus the implicit single target from a
    # filtered view -- both can contribute, so a domain added from a
    # filtered view is assigned to that view's subject even if the admin
    # didn't also touch the lists.
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    group_ids = {int(x) for x in request.form.getlist("group_ids") if x.isdigit()}
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}
    if request.form.get("user_id", "").isdigit():
        user_ids.add(int(request.form["user_id"]))
    if request.form.get("group_id", "").isdigit():
        group_ids.add(int(request.form["group_id"]))
    if request.form.get("device_id", "").isdigit():
        device_ids.add(int(request.form["device_id"]))

    try:
        conn.execute(
            "INSERT INTO domains (pattern, mode, kind, is_global, note, created_at) VALUES (?,?,?,?,?,?)",
            (pattern, mode, "generic", is_global, note, db.now_iso()),
        )
        conn.commit()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return flash_redirect("domains", f"{pattern!r} is already configured.", error=True, **redirect_kwargs)
        raise

    domain_id = conn.execute("SELECT id FROM domains WHERE pattern = ?", (pattern,)).fetchone()["id"]
    for uid in user_ids:
        conn.execute("INSERT OR IGNORE INTO user_domains (user_id, domain_id) VALUES (?,?)", (uid, domain_id))
    for gid in group_ids:
        conn.execute("INSERT OR IGNORE INTO group_domains (group_id, domain_id) VALUES (?,?)", (gid, domain_id))
    for did in device_ids:
        conn.execute("INSERT OR IGNORE INTO device_domains (device_id, domain_id) VALUES (?,?)", (did, domain_id))
    conn.commit()
    return flash_redirect("domains", f"Added {pattern}.", **redirect_kwargs)


@app.route("/domains/add-url", methods=["POST"])
@require_admin
def add_domain_from_url():
    """GH #6: approve one specific page without the three separate steps
    (add domain, flip to bump, add a path pattern from a different page).
    Only usable from a user's filtered Domains view (?user_id=), since
    approving a page always means approving it *for someone* -- there's no
    "everyone gets this one page" equivalent the way whole-domain
    assignment has "Everyone gets this"."""
    url = request.form.get("url", "").strip()
    user_id = request.form.get("user_id", "")
    redirect_kwargs = {"user_id": user_id} if user_id else {}
    if not user_id:
        return flash_redirect(
            "domains",
            "This shortcut approves a page for a specific person -- use it from that "
            "person's filtered Domains view (via the Users page's \"N assigned\" link).",
            error=True,
        )
    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return flash_redirect("domains", "That user no longer exists.", error=True)

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    hostname = urlparse(url).hostname
    # urlparse is lenient about what it calls a "hostname" -- it happily
    # returns garbage input as netloc/hostname without validating actual
    # hostname syntax, so a real format check is needed here too.
    if not hostname or not re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$", hostname
    ):
        return flash_redirect("domains", "That doesn't look like a valid URL.", error=True, **redirect_kwargs)
    path = urlparse(url).path or "/"

    domain = matching.find_domain(conn, hostname)
    if domain is None:
        domain_pattern = re.escape(hostname)
        conn.execute(
            "INSERT INTO domains (pattern, mode, kind, is_global, note, created_at) "
            "VALUES (?, 'bump', 'generic', 0, 'Added via the paste-a-URL shortcut', ?)",
            (domain_pattern, db.now_iso()),
        )
        domain = conn.execute("SELECT * FROM domains WHERE pattern = ?", (domain_pattern,)).fetchone()
    elif domain["mode"] != "bump":
        return flash_redirect(
            "domains",
            f"{hostname} is already configured, but in {domain['mode']} mode -- a page-level "
            f"rule needs bump mode. Switch it from Manage first, then try again.",
            error=True, **redirect_kwargs,
        )

    conn.execute(
        "INSERT OR IGNORE INTO domain_paths (domain_id, pattern) VALUES (?, ?)",
        (domain["id"], path_to_pattern(path)),
    )
    conn.execute(
        "INSERT OR IGNORE INTO user_domains (user_id, domain_id) VALUES (?, ?)",
        (user_id, domain["id"]),
    )
    conn.commit()
    return flash_redirect("domains", f"Approved {hostname}{path} for this user.", **redirect_kwargs)


@app.route("/domains/delete", methods=["POST"])
@require_admin
def delete_domain():
    domain_id = request.form.get("domain_id", "")
    redirect_kwargs = {}
    if request.form.get("user_id"):
        redirect_kwargs["user_id"] = request.form["user_id"]
    elif request.form.get("group_id"):
        redirect_kwargs["group_id"] = request.form["group_id"]
    elif request.form.get("device_id"):
        redirect_kwargs["device_id"] = request.form["device_id"]
    conn = get_db()
    row = conn.execute("SELECT kind FROM domains WHERE id = ?", (domain_id,)).fetchone()
    if row and row["kind"] == "crunchyroll":
        return flash_redirect(
            "domains",
            "The Crunchyroll domain is built into the show-approval feature and can't be deleted "
            "(edit its mode/paths from Manage instead).",
            error=True, **redirect_kwargs,
        )
    conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
    conn.commit()
    return flash_redirect("domains", "Domain removed.", **redirect_kwargs)


DOMAIN_DETAIL_BODY = """
<p><a href="{{ url_for('domains') }}">&larr; All domains</a></p>
<h1><code>{{ d.pattern }}</code> <span class="badge mode-{{ d.mode }}">{{ d.mode }}</span></h1>
{% if d.kind == 'crunchyroll' %}
<p class="hint">This is the built-in Crunchyroll domain. Shows are approved per-user from each user's page; the paths below are a defense-in-depth safety net, not the main show filter.</p>
{% endif %}

<div class="card">
<h2>Mode</h2>
<form class="add-form" method="post" action="{{ url_for('update_domain') }}">
  <input type="hidden" name="domain_id" value="{{ d.id }}">
  <select name="mode">
    <option value="splice" {{ 'selected' if d.mode=='splice' }}>splice (host-only)</option>
    <option value="bump" {{ 'selected' if d.mode=='bump' }}>bump (decrypt, path rules)</option>
    <option value="trusted" {{ 'selected' if d.mode=='trusted' }}>trusted (always pass, unchecked)</option>
  </select>
  <input type="text" name="note" value="{{ d.note or '' }}" placeholder="Note">
  <button class="add" type="submit">Save</button>
</form>
</div>

<div class="card">
<h2>Access</h2>
<form method="post" action="{{ url_for('update_domain_access') }}">
  <input type="hidden" name="domain_id" value="{{ d.id }}">
""" + ACCESS_SELECTS + """
  <button class="add" type="submit" style="margin-top:.8rem;">Save access</button>
</form>
<p class="hint">
  Saving replaces the current assignment with exactly what's checked, so removing access is the
  same action as granting it: just uncheck it and save. "Everyone" grants it regardless of what's
  checked below, but those are still saved underneath it, so turning "Everyone" back off later
  doesn't lose them.
</p>
</div>

{% if d.mode == 'bump' %}
<div class="card">
<h2>Allowed paths ({{ paths|length }})</h2>
<p class="hint">
  Paste a page's path or full URL below -- everything from there onward
  is allowed (e.g. adding <code>/comics/foo</code> also allows
  <code>/comics/foo/bar</code> and <code>/comics/foo-anything-else</code>).
  Only enforced for <span class="badge mode-bump">bump</span> domains
  (splice never decrypts far enough to see a path at all).
  <strong>Leave this empty and only the bare homepage (<code>/</code>) is
  allowed</strong> -- deny-by-default beyond that until you add at least
  one path here for whatever else on this site should be reachable.
</p>
{% if prefill_path %}
<p class="hint">A blocked request suggested the path below (the one that was actually denied) -- review it, broaden or narrow it as needed, then save.</p>
{% endif %}
<div class="table-scroll">
<table>
  <tr><th>Pattern</th><th></th></tr>
  {% for p in paths %}
  <tr>
    <td><code>{{ p.pattern }}</code></td>
    <td>
      <form class="inline" method="post" action="{{ url_for('delete_path') }}">
        <input type="hidden" name="path_id" value="{{ p.id }}">
        <button class="danger small" type="submit">Remove</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="2"><em>No path rules yet -- only <code>/</code> (the bare homepage) is currently allowed on this domain.</em></td></tr>
  {% endfor %}
</table>
</div>
<form class="add-form" method="post" action="{{ url_for('add_path') }}">
  <input type="hidden" name="domain_id" value="{{ d.id }}">
  <input type="text" name="pattern" placeholder="e.g. /discover or https://example.com/discover" value="{{ prefill_path or '' }}" required>
  <button class="add" type="submit">Add path</button>
</form>
</div>
{% endif %}
"""


@app.route("/domains/<int:domain_id>")
@require_admin
def domain_detail(domain_id: int):
    conn = get_db()
    d = conn.execute("SELECT * FROM domains WHERE id = ?", (domain_id,)).fetchone()
    if d is None:
        return flash_redirect("domains", "That domain no longer exists.", error=True)
    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    all_devices = conn.execute("SELECT * FROM devices ORDER BY COALESCE(label, mac_address)").fetchall()
    assigned_user_ids = {
        row["user_id"] for row in
        conn.execute("SELECT user_id FROM user_domains WHERE domain_id = ?", (domain_id,))
    }
    assigned_group_ids = {
        row["group_id"] for row in
        conn.execute("SELECT group_id FROM group_domains WHERE domain_id = ?", (domain_id,))
    }
    assigned_device_ids = {
        row["device_id"] for row in
        conn.execute("SELECT device_id FROM device_domains WHERE domain_id = ?", (domain_id,))
    }
    paths = conn.execute(
        "SELECT * FROM domain_paths WHERE domain_id = ? ORDER BY pattern", (domain_id,)
    ).fetchall()
    body = render_template_string(
        DOMAIN_DETAIL_BODY, d=d,
        all_users_combo=_entity_combo(all_users, lambda u: u["display_name"]),
        all_groups_combo=_entity_combo(all_groups, lambda g: g["name"]),
        all_devices_combo=_entity_combo(all_devices, lambda dev: dev["label"] or dev["mac_address"]),
        preselected_user_ids=assigned_user_ids, preselected_group_ids=assigned_group_ids,
        preselected_device_ids=assigned_device_ids, is_global_checked=bool(d["is_global"]),
        paths=paths, prefill_path=request.args.get("prefill_path"),
    )
    return render("domains", body)


@app.route("/domains/update", methods=["POST"])
@require_admin
def update_domain():
    domain_id = request.form.get("domain_id", "")
    mode = request.form.get("mode", "splice")
    note = request.form.get("note", "").strip() or None
    conn = get_db()
    conn.execute(
        "UPDATE domains SET mode = ?, note = ? WHERE id = ?",
        (mode, note, domain_id),
    )
    conn.commit()
    return flash_redirect("domain_detail", "Saved.", domain_id=domain_id)


def _replace_domain_access(conn, domain_id, is_global: int, user_ids: set[int], group_ids: set[int], device_ids: set[int]) -> None:
    """Replaces one domain's entire access grant (Everyone + users +
    groups + devices) with exactly what's passed in -- granting and
    revoking are the same action here, just a changed selection, rather
    than separate add/remove endpoints per assignment type. Shared by
    update_domain_access() (one domain, from its own Manage page) and
    bulk_update_domain_access() (many domains at once, from the Domains
    list) -- deliberately no conn.commit() here, so the bulk caller can
    wrap its whole loop in one transaction rather than committing (and
    fsyncing) once per domain."""
    conn.execute("UPDATE domains SET is_global = ? WHERE id = ?", (is_global, domain_id))
    conn.execute("DELETE FROM user_domains WHERE domain_id = ?", (domain_id,))
    for uid in user_ids:
        conn.execute("INSERT OR IGNORE INTO user_domains (user_id, domain_id) VALUES (?,?)", (uid, domain_id))
    conn.execute("DELETE FROM group_domains WHERE domain_id = ?", (domain_id,))
    for gid in group_ids:
        conn.execute("INSERT OR IGNORE INTO group_domains (group_id, domain_id) VALUES (?,?)", (gid, domain_id))
    conn.execute("DELETE FROM device_domains WHERE domain_id = ?", (domain_id,))
    for did in device_ids:
        conn.execute("INSERT OR IGNORE INTO device_domains (device_id, domain_id) VALUES (?,?)", (did, domain_id))


@app.route("/domains/access", methods=["POST"])
@require_admin
def update_domain_access():
    domain_id = request.form.get("domain_id", "")
    is_global = 1 if request.form.get("is_global") else 0
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    group_ids = {int(x) for x in request.form.getlist("group_ids") if x.isdigit()}
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}

    conn = get_db()
    _replace_domain_access(conn, domain_id, is_global, user_ids, group_ids, device_ids)
    conn.commit()
    return flash_redirect("domain_detail", "Access updated.", domain_id=domain_id)


@app.route("/domains/bulk-access", methods=["POST"])
@require_admin
def bulk_update_domain_access():
    """Domains list's "bulk categorize" action -- real live-testing
    feedback (RoadMap.md's dated entry): with dozens of domains in one
    flat table (27 seeded global ones alone), setting access one at a
    time via each domain's own Manage page doesn't scale. Checks
    multiple domain rows on the list (collected client-side into
    domain_ids -- see the bulk-assign form's own inline <script>, since
    the checkboxes live in the table, not inside this form, to avoid
    nesting <form> elements around the per-row Delete forms) and applies
    the SAME access grant to all of them in one submission, via the same
    _replace_domain_access() the single-domain form uses -- one commit
    for the whole batch, not one per domain, same "batch it, don't
    autocommit per row" discipline as bulk_add_to_group() and (at a much
    larger scale) common/category_fetch.py's own fix."""
    domain_ids = {int(x) for x in request.form.getlist("domain_ids") if x.isdigit()}
    is_global = 1 if request.form.get("is_global") else 0
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    group_ids = {int(x) for x in request.form.getlist("group_ids") if x.isdigit()}
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}

    if not domain_ids:
        return flash_redirect("domains", "No domains selected.", error=True)

    conn = get_db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        for domain_id in domain_ids:
            _replace_domain_access(conn, domain_id, is_global, user_ids, group_ids, device_ids)
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.commit()
    return flash_redirect(
        "domains", f"Access updated for {len(domain_ids)} domain{'s' if len(domain_ids) != 1 else ''}."
    )


@app.route("/domains/export", methods=["GET"])
@require_admin
def export_domains_csv():
    """Domains list's toolbar "Download domains" button (added 2026-09-07,
    RoadMap.md's dated entry -- same Entra-style toolbar redesign already
    applied to Devices/Users/Categories/Schedules, extended here to close
    the last gap). A plain CSV of every domain, not gated by checkbox
    selection, same "always available regardless of selection" role every
    other page's own Download button plays."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM domains ORDER BY is_global DESC, pattern").fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Pattern", "Mode", "Access", "Note"])
    for d in rows:
        writer.writerow([
            d["pattern"], d["mode"],
            "Everyone" if d["is_global"] else "Per-user/group/device",
            d["note"] or "",
        ])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=domains.csv"},
    )


@app.route("/domains/bulk-delete", methods=["POST"])
@require_admin
def bulk_delete_domains():
    """Domains list's toolbar "Delete" button. Same built-in-Crunchyroll
    protection as the single-domain delete_domain() route above: that
    domain is load-bearing for the show-approval feature, so it's silently
    skipped (not deleted) even if checked, rather than erroring out the
    whole batch."""
    domain_ids = {int(x) for x in request.form.getlist("domain_ids") if x.isdigit()}
    if not domain_ids:
        return flash_redirect("domains", "No domains selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(domain_ids))
    protected = {
        row["id"] for row in conn.execute(
            f"SELECT id FROM domains WHERE id IN ({placeholders}) AND kind = 'crunchyroll'",
            tuple(domain_ids),
        ).fetchall()
    }
    deletable = domain_ids - protected
    if deletable:
        del_placeholders = ",".join("?" * len(deletable))
        conn.execute(f"DELETE FROM domains WHERE id IN ({del_placeholders})", tuple(deletable))
        conn.commit()
    message = f"Deleted {len(deletable)} domain{'s' if len(deletable) != 1 else ''}."
    if protected:
        message += " Skipped the built-in Crunchyroll domain (can't be deleted)."
    return flash_redirect("domains", message, error=not deletable and bool(protected))


def _extract_path(raw: str) -> str:
    """Accepts either a bare path (`/comics/foo`) or a full URL
    (`https://example.com/comics/foo`, scheme optional) and returns just
    the path part, always leading-slash. Added 2026-09-07 (RoadMap.md's
    dated entry, project owner's explicit direction) so add_path() below
    can accept a plain pasted URL/path instead of requiring hand-written
    regex -- same `urlparse(...).path` extraction add_domain_from_url()
    already uses for its own "paste a URL" shortcut."""
    raw = raw.strip()
    if "://" not in raw and not raw.startswith("/"):
        # A bare host-and-path with no scheme (e.g. "example.com/x") would
        # otherwise urlparse as an all-path relative URL with no netloc --
        # giving it a scheme first makes urlparse split host from path
        # correctly either way.
        raw = "https://" + raw
    return urlparse(raw).path or "/"


def _extract_domain(raw: str) -> str | None:
    """Given one pasted line -- a bare domain, a domain with a path, or a
    full URL -- returns just the lowercased hostname with any leading
    'www.' stripped, or None if the line has nothing usable on it. Same
    "paste whatever you've got, we'll figure it out" approach as
    _extract_path() above, applied to bulk_add_category_domains() below
    so an admin can paste a whole list of sites (e.g. every link on an
    aggregator page) instead of hand-typing/escaping a regex per domain."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if "://" not in raw:
        raw = "https://" + raw
    host = urlparse(raw).hostname
    if not host:
        return None
    host = host.lower()
    if host.startswith("www."):
        host = host[4:]
    return host or None


@app.route("/domains/paths/add", methods=["POST"])
@require_admin
def add_path():
    """Takes a plain pasted path or URL, not hand-written regex --
    changed 2026-09-07 (RoadMap.md's dated entry): "the admin can just
    paste the URL and everything after what is pasted is allowed."
    Converts it the exact same way the auto-suggested-from-a-blocked-
    request flow already did (`path_to_pattern()`: anchored, fully
    `re.escape()`d, no trailing anchor so it also matches anything
    AFTER the pasted path, e.g. `/comics/foo` also matches
    `/comics/foo/bar` and `/comics/foo-anything-else`) -- there is no
    longer a way to hand-author a custom regex from this form; anyone
    who genuinely needs one can still insert a `domain_paths` row
    directly against the database."""
    domain_id = request.form.get("domain_id", "")
    raw = request.form.get("pattern", "").strip()
    if not raw:
        return flash_redirect("domain_detail", "A path or URL is required.", error=True, domain_id=domain_id)
    if len(raw) > 500:
        return flash_redirect("domain_detail", "That's too long (500 characters max).", error=True, domain_id=domain_id)
    pattern = path_to_pattern(_extract_path(raw))
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO domain_paths (domain_id, pattern) VALUES (?,?)", (domain_id, pattern)
    )
    conn.commit()
    return flash_redirect("domain_detail", "Path added.", domain_id=domain_id)


@app.route("/domains/paths/delete", methods=["POST"])
@require_admin
def delete_path():
    path_id = request.form.get("path_id", "")
    conn = get_db()
    row = conn.execute("SELECT domain_id FROM domain_paths WHERE id = ?", (path_id,)).fetchone()
    if row is None:
        # Fixed 2026-09-02, a real bug found by code review: this used
        # to fall through to flash_redirect("domain_detail", ...,
        # domain_id=None) below, and domain_detail's route requires an
        # <int:domain_id> -- url_for() raises an unhandled
        # werkzeug.routing.BuildError for a None value there (confirmed
        # by reproducing it directly), turning a harmless double-click
        # or stale-page click into an unhandled 500. Every sibling
        # delete route (delete_category_domain, delete_category_override)
        # already redirects to the LIST page with a "no longer exists"
        # flash for the identical situation -- matching that here.
        return flash_redirect("domains", "That path no longer exists.", error=True)
    conn.execute("DELETE FROM domain_paths WHERE id = ?", (path_id,))
    conn.commit()
    return flash_redirect("domain_detail", "Path removed.", domain_id=row["domain_id"])


# ==========================================================
# DEVICES (v2 roadmap groundwork -- see common/db.py's `devices` table
# comment. Nothing in the proxy/dashboard enforcement path reads these
# flags yet; this page just lets an admin start tracking devices and
# curating the future SSL-Bump list ahead of the interception-layer work.)
# ==========================================================

MAC_ADDRESS_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def normalize_mac(value: str) -> str | None:
    """Accepts colon- or hyphen-separated hex pairs, returns lowercase
    colon-separated form, or None if it isn't a MAC address at all."""
    value = (value or "").strip().lower().replace("-", ":")
    return value if MAC_ADDRESS_RE.match(value) else None


_PREVIEW_LIST_MAX = 10


def _preview_list(items: list[str]) -> str:
    """Renders import_devices()'s skipped-item lists as a short,
    comma-separated preview -- capped so a genuinely large CSV (a real
    router export can easily be 50+ devices) doesn't turn the flash
    message (a URL query param) into an unreadable wall of text."""
    shown = items[:_PREVIEW_LIST_MAX]
    text = ", ".join(shown)
    remaining = len(items) - len(shown)
    if remaining > 0:
        text += f", and {remaining} more"
    return text


def _device_assignment_value(d) -> str:
    """The current selection for the composite assignment <select> below,
    given a devices row -- inverse of _parse_device_assignment()."""
    if d["ignored"]:
        return "ignored"
    if d["user_id"]:
        return f"user:{d['user_id']}"
    if d["group_id"]:
        return f"group:{d['group_id']}"
    return ""


def _parse_device_assignment(raw: str) -> tuple[int | None, int | None, int]:
    """Parses the composite assignment <select>'s value into
    (user_id, group_id, ignored). Anything unrecognized (including a
    malformed id) falls back to unassigned rather than raising -- this is
    admin-only input from a dropdown we control, but defend anyway."""
    raw = raw or ""
    try:
        if raw == "ignored":
            return None, None, 1
        if raw.startswith("user:"):
            return int(raw[len("user:"):]), None, 0
        if raw.startswith("group:"):
            return None, int(raw[len("group:"):]), 0
    except ValueError:
        pass
    return None, None, 0


def _assignment_combo(all_users, all_groups) -> list[dict]:
    """Items for the device-assignment combobox -- Unassigned/Ignore are
    always-present pseudo-entries alongside every kid and group, encoded
    the same way _parse_device_assignment() expects to decode them."""
    items = [
        {"id": "", "label": "Unassigned"},
        {"id": "ignored", "label": "Ignore (never filtered)"},
    ]
    items += [{"id": f"user:{u['id']}", "label": u["display_name"]} for u in all_users]
    items += [{"id": f"group:{g['id']}", "label": g["name"]} for g in all_groups]
    return items


# Shared by the add-device form and the per-device Manage form -- one
# control picks "unassigned" / "ignore this device entirely" / a specific
# kid / a specific group, so there's no separate always-visible kid+group
# dropdown pair to keep in sync (this app doesn't use JS to show/hide
# fields based on another field's value). Needs assignment_combo (see
# _assignment_combo) and current (the composite value, e.g. "user:5") in
# scope wherever it's used.
DEVICE_ASSIGNMENT_SELECT = """
  <div class="access-label">Assign to</div>
  <div class="combobox" data-combobox data-mode="single" data-initial="{{ current }}" style="max-width:320px;">
    <div class="combobox-current" data-combobox-current></div>
    <input type="search" class="combobox-input" data-combobox-input placeholder="Search&hellip;">
    <div class="combobox-results" data-combobox-results></div>
    <input type="hidden" name="assignment" data-combobox-hidden value="{{ current }}">
    <script type="application/json" data-combobox-items>{{ assignment_combo|tojson }}</script>
  </div>
"""


DEVICES_BODY = """
{% if pending_devices %}
<div class="card pending-card">
<h2>Devices awaiting login ({{ pending_devices|length }})</h2>
<p class="hint">
  Seen on the network but not yet assigned -- gated to DNS-only access
  until someone logs in via the captive portal, or an admin acts below.
  Use <strong>Bypass</strong> for a device that will never log in on its
  own (a TV, a thermostat), or <strong>Manage</strong> to assign it to a
  kid or group directly instead of waiting on a login.
</p>
<div class="table-scroll">
<table>
  <tr><th>MAC address</th><th>Current IP</th><th>First seen</th><th>Last seen</th><th>Seen via</th><th>Login attempts</th><th></th></tr>
  {% for d in pending_devices %}
  <tr>
    <td><code>{{ d.mac_address }}</code></td>
    <td>{{ d.current_ip or '&mdash;' }}</td>
    <td>{{ d.created_at }}</td>
    <td>{{ d.network_last_seen or '&mdash;' }}</td>
    <td>{{ d.binding_source or '&mdash;' }}</td>
    <td>
      {% set attempts = pending_login_attempts.get(d.mac_address) %}
      {% if attempts %}
      <span class="badge blocked" title="Most recent attempt: {{ attempts.last_attempt }}">
        {{ attempts.count }} failed attempt{{ 's' if attempts.count != 1 else '' }}
      </span>
      {% else %}
      <span class="hint">None yet</span>
      {% endif %}
    </td>
    <td>
      <a class="btn small" href="{{ url_for('device_detail', device_id=d.id) }}">Manage</a>
      <form class="inline" method="post" action="{{ url_for('bypass_login_device') }}">
        <input type="hidden" name="device_id" value="{{ d.id }}">
        <button class="btn small" type="submit" title="Let this device online without ever needing to log in">Bypass</button>
      </form>
      <form class="inline" method="post" action="{{ url_for('dismiss_pending_device') }}">
        <input type="hidden" name="device_id" value="{{ d.id }}">
        <button class="btn small" type="submit" title="Just hide this from the list until it's active again -- doesn't change anything about the device itself">Dismiss</button>
      </form>
    </td>
  </tr>
  {% endfor %}
</table>
</div>
<p class="hint">
  "Login attempts" counts real failed captive-portal sign-ins from this
  device (wrong/unknown username or password) -- a device that
  successfully logs in stops appearing in this list at all (it's no
  longer "awaiting"), so a failed-attempt count here always means
  someone tried and couldn't get in, not that they're not trying.
  "Current IP"/"Last seen"/"Seen via" come from the network's own
  observation of this MAC, independent of anything an admin has entered.
</p>
</div>
{% endif %}

<div class="card" id="groups">
<h2>Groups ({{ groups|length }})</h2>
<p class="hint">A shared-device category (TVs, IoT, Gaming Computers) with its own domain allow-list -- assign devices to a group below, then manage what it can reach from its "Manage domains" link.</p>
{% if groups %}<input type="search" data-filter-table="groupsTable" placeholder="Search groups&hellip;" style="margin-bottom:.6rem; width:100%; max-width:280px;">{% endif %}
<div class="table-scroll">
<table id="groupsTable">
  <tr><th>Name</th><th></th></tr>
  {% for g in groups %}
  <tr>
    <td>{{ g.name }}{% if g.ignored %} <span class="badge pending" title="Every device in this group is treated as Ignore (never filtered)">Ignore mode</span>{% endif %}</td>
    <td>
      <a class="btn small" href="{{ url_for('group_detail', group_id=g.id) }}">Manage</a>
      <a class="btn small" href="{{ url_for('domains', group_id=g.id) }}">Manage domains</a>
      <form class="inline" method="post" action="{{ url_for('delete_group') }}">
        <input type="hidden" name="group_id" value="{{ g.id }}">
        <button class="danger small" type="submit" onclick="return confirm('Delete this group? Its devices become unassigned.')">Delete</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="2"><em>No groups yet.</em></td></tr>
  {% endfor %}
</table>
</div>
<form class="add-form" method="post" action="{{ url_for('add_group') }}">
  <input type="text" name="name" placeholder="e.g. TVs, IoT, Gaming Computers" required>
  <button class="add" type="submit">Add group</button>
</form>
</div>

<div class="card">
<h2>Pause the internet</h2>
<p class="hint">
  Bark Home's one-tap pause, per whole house here -- immediate and
  indefinite, until you resume it. Uses the same <code>quarantined_at</code>
  mechanism as a bedtime <a href="{{ url_for('schedules') }}">schedule</a>'s
  full lockout (live-verified: a paused device loses ALL internet access,
  not just filtered sites), just triggered by hand instead of a clock.
  <strong>Ignored</strong> devices are skipped -- pausing one would have no
  effect (same reason an ignored device isn't gated by a login either).
</p>
<form class="inline" method="post" action="{{ url_for('pause_all_devices') }}" onsubmit="return confirm('Pause the internet for every device in the house (except Ignored ones)?');">
  <button class="danger" type="submit">Pause the whole house</button>
</form>
<form class="inline" method="post" action="{{ url_for('resume_all_devices') }}">
  <button class="btn" type="submit">Resume everyone</button>
</form>
</div>

<div class="card">
<h2>Devices ({{ device_count }})</h2>
<p class="hint">
  Track known devices by MAC address ahead of the interception-layer work.
  <span class="badge mode-bump">SSL-Bump</span> devices will get full
  path/show-level rules on bump-mode domains once that's wired up -- keep
  this list small and deliberate. Everything else will get that domain's
  whole-domain treatment instead. Nothing here is enforced yet.
</p>
{% if devices %}
<div class="toolbar" id="deviceBulkToolbar">
  <a class="btn small" href="{{ url_for('export_devices_csv') }}">&darr; Download devices</a>
  <span class="toolbar-sep"></span>
  <form id="bulkDeviceEnableForm" class="inline" method="post" action="{{ url_for('bulk_resume_devices') }}">
    <button class="btn small" type="submit" disabled>Enable</button>
  </form>
  <form id="bulkDevicePauseForm" class="inline" method="post" action="{{ url_for('bulk_pause_devices') }}">
    <button class="btn small" type="submit" disabled>Disable</button>
  </form>
  <form id="bulkDeviceDeleteForm" class="inline" method="post" action="{{ url_for('bulk_delete_devices') }}"
        onsubmit="return confirm('Delete every checked device? This cannot be undone.');">
    <button class="danger small" type="submit" disabled>Delete</button>
  </form>
  <button class="btn small" type="button" id="deviceBulkManageToggle" disabled>Manage</button>
  <span class="hint" id="deviceBulkCount" style="margin:0;">Check devices below to act on several at once.</span>
</div>
<div id="deviceBulkManagePanel" hidden style="margin:-.3rem 0 .6rem;">
  <form id="bulkDeviceGroupForm" class="add-form" method="post" action="{{ url_for('bulk_assign_devices_to_group') }}">
    <span class="hint" style="margin:0;">Assign checked devices to:</span>
    <select name="group_id" required {{ 'disabled' if not groups }}>
      <option value="" selected disabled>Pick a group&hellip;</option>
      {% for g in groups %}<option value="{{ g.id }}">{{ g.name }}</option>{% endfor %}
    </select>
    <button class="add small" type="submit" {{ 'disabled' if not groups }}>Apply</button>
  </form>
  {% if not groups %}<p class="hint">No groups yet -- add one above first.</p>{% endif %}
  <p class="hint" style="margin:.6rem 0 .3rem;">Or set Ignore status directly (clears any user/group assignment, same as picking Ignore on a single device's own Manage page):</p>
  <form id="bulkDeviceIgnoreForm" class="inline" method="post" action="{{ url_for('bulk_set_ignored_devices') }}"
        onsubmit="return confirm('Set every checked device to Ignore (never filtered)? This clears any user/group assignment on them.');">
    <input type="hidden" name="ignored" value="1">
    <button class="danger small" type="submit">Set to Ignore</button>
  </form>
  <form id="bulkDeviceUnignoreForm" class="inline" method="post" action="{{ url_for('bulk_set_ignored_devices') }}">
    <input type="hidden" name="ignored" value="">
    <button class="btn small" type="submit">Remove Ignore</button>
  </form>
</div>
{% endif %}
{% if any_devices_exist %}
<form method="get" action="{{ url_for('devices') }}" class="inline" style="margin-bottom:.3rem; gap:.4rem;">
  <input type="hidden" name="page" value="1">
  <input type="hidden" name="per_page" value="{{ per_page }}">
  <input type="search" name="q" value="{{ search }}" placeholder="Search MAC, label, assigned kid/group&hellip;" style="width:100%; max-width:280px;">
  <button class="btn small" type="submit">Search</button>
  {% if search %}<a class="btn small" href="{{ url_for('devices', per_page=per_page) }}">Clear</a>{% endif %}
</form>
{% if search %}<p class="hint" style="margin:0 0 .6rem;">Searches every device, not just this page &mdash; showing results for &ldquo;{{ search }}&rdquo;.</p>{% endif %}
<div class="toolbar" style="justify-content:space-between;">
  <form method="get" action="{{ url_for('devices') }}" class="inline">
    <input type="hidden" name="page" value="1">
    {% if search %}<input type="hidden" name="q" value="{{ search }}">{% endif %}
    <label class="hint" style="margin:0;">Show
      <select name="per_page" onchange="this.form.submit()">
        {% for opt in page_size_options %}
        <option value="{{ opt }}" {{ 'selected' if opt == per_page }}>{{ opt }}</option>
        {% endfor %}
      </select>
      per page &mdash; showing {{ range_start }}-{{ range_end }} of {{ device_count }}
    </label>
  </form>
  {% if total_pages > 1 %}
  <span>
    {% if page > 1 %}<a class="btn small" href="{{ url_for('devices', page=page-1, per_page=per_page, **search_query_args) }}">&larr; Prev</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
    <span class="hint">Page {{ page }} of {{ total_pages }}</span>
    {% if page < total_pages %}<a class="btn small" href="{{ url_for('devices', page=page+1, per_page=per_page, **search_query_args) }}">Next &rarr;</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
  </span>
  {% endif %}
</div>
{% endif %}
<div class="table-scroll">
<table id="devicesTable">
  <tr><th>{% if devices %}<input type="checkbox" id="deviceSelectAll" title="Select all">{% endif %}</th><th>MAC address</th><th>Label</th><th>Assigned to</th><th>Status</th><th>SSL-Bump</th><th>Bypass login</th><th>Last seen</th><th></th></tr>
  {% for d in devices %}
  {% set effective_ignored = d.ignored or d.group_ignored %}
  <tr>
    <td><input type="checkbox" class="bulk-device-check" value="{{ d.id }}"></td>
    <td><code>{{ d.mac_address }}</code></td>
    <td>{{ d.label or '' }}</td>
    <td>
      {% if effective_ignored %}<span class="badge pending" title="{{ 'This device is in an Ignore-mode group' if d.group_ignored and not d.ignored else '' }}">Ignored</span>
      {% elif d.display_name %}{{ d.display_name }}
      {% elif d.group_name %}<span class="badge mode-trusted">{{ d.group_name }}</span>
      {% else %}<em>Unassigned</em>{% endif %}
    </td>
    <td>
      {% if d.quarantined_at and not effective_ignored %}<span class="badge blocked" title="Paused since {{ d.quarantined_at }} -- no internet access at all">Paused</span>
      {% elif d.pending %}<span class="badge pending" title="Seen on the network but nobody has logged in on it yet">Awaiting login</span>
      {% elif effective_ignored or d.bypass_login %}&mdash;
      {% else %}<span class="badge allowed">Authenticated</span>{% endif %}
    </td>
    <td>{% if d.bump_enabled %}<span class="badge mode-bump">yes</span>{% else %}<span class="badge mode-splice">no</span>{% endif %}</td>
    <td>{% if d.bypass_login %}<span class="badge pending">yes</span>{% else %}&mdash;{% endif %}</td>
    <td>{{ d.last_seen_at or 'Never' }}</td>
    <td>
      <a class="btn small" href="{{ url_for('device_detail', device_id=d.id) }}">Manage</a>
      <a class="btn small" href="{{ url_for('domains', device_id=d.id) }}">Domains</a>
      {% if d.pending %}
      <form class="inline" method="post" action="{{ url_for('bypass_login_device') }}">
        <input type="hidden" name="device_id" value="{{ d.id }}">
        <button class="btn small" type="submit" title="Let this device online without ever needing to log in">Bypass</button>
      </form>
      {% endif %}
      {% if not effective_ignored %}
        {% if d.quarantined_at %}
        <form class="inline" method="post" action="{{ url_for('resume_device') }}">
          <input type="hidden" name="device_id" value="{{ d.id }}">
          <button class="btn small" type="submit">Resume</button>
        </form>
        {% else %}
        <form class="inline" method="post" action="{{ url_for('pause_device') }}">
          <input type="hidden" name="device_id" value="{{ d.id }}">
          <button class="danger small" type="submit">Pause</button>
        </form>
        {% endif %}
      {% endif %}
      <form class="inline" method="post" action="{{ url_for('delete_device') }}">
        <input type="hidden" name="device_id" value="{{ d.id }}">
        <button class="danger small" type="submit" onclick="return confirm('Remove this device?')">Delete</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="9"><em>{% if search %}No devices match &ldquo;{{ search }}&rdquo;.{% else %}No devices tracked yet.{% endif %}</em></td></tr>
  {% endfor %}
</table>
</div>
{% if total_pages > 1 %}
<div class="toolbar" style="justify-content:flex-end;">
  {% if page > 1 %}<a class="btn small" href="{{ url_for('devices', page=page-1, per_page=per_page, **search_query_args) }}">&larr; Prev</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
  <span class="hint">Page {{ page }} of {{ total_pages }}</span>
  {% if page < total_pages %}<a class="btn small" href="{{ url_for('devices', page=page+1, per_page=per_page, **search_query_args) }}">Next &rarr;</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
</div>
{% endif %}
<script>
(function () {
  var selectAll = document.getElementById("deviceSelectAll");
  var countLabel = document.getElementById("deviceBulkCount");
  var toolbar = document.getElementById("deviceBulkToolbar");

  // Real live-testing feedback (RoadMap.md's dated entry, referencing
  // Microsoft Entra's own admin console as the model): moved the bulk
  // actions here, above the table, from a separate card below it --
  // and the action buttons now start disabled, enabling only once
  // something's actually checked, same "greyed out until a selection
  // exists" pattern Entra's own device/user lists use.
  var manageToggle = document.getElementById("deviceBulkManageToggle");
  var managePanel = document.getElementById("deviceBulkManagePanel");

  function updateToolbarState() {
    if (!toolbar) return;
    var n = document.querySelectorAll(".bulk-device-check:checked").length;
    toolbar.querySelectorAll("button").forEach(function (btn) { btn.disabled = n === 0; });
    if (n === 0 && managePanel) managePanel.hidden = true;
    if (countLabel) {
      countLabel.textContent = n === 0
        ? "Check devices below to act on several at once."
        : n + " device" + (n === 1 ? "" : "s") + " selected.";
    }
  }

  if (selectAll) {
    selectAll.addEventListener("change", function () {
      document.querySelectorAll(".bulk-device-check").forEach(function (box) { box.checked = selectAll.checked; });
      updateToolbarState();
    });
  }
  document.querySelectorAll(".bulk-device-check").forEach(function (box) {
    box.addEventListener("change", updateToolbarState);
  });
  updateToolbarState();

  // "Manage" doesn't submit anything itself -- it reveals the group-assign
  // panel (still needs a target group picked somehow; a plain button
  // alone can't capture that), same "click to open further options"
  // role Entra's own "Manage" button plays for its device/user lists.
  if (manageToggle && managePanel) {
    manageToggle.addEventListener("click", function () {
      managePanel.hidden = !managePanel.hidden;
    });
  }

  function wireBulkForm(formId) {
    var form = document.getElementById(formId);
    if (!form) return;
    form.addEventListener("submit", function (event) {
      // Checkboxes live in #devicesTable, not inside either bulk form --
      // nesting a <form> around the table would break each row's own
      // Bypass/Pause/Resume/Delete forms (HTML forms can't nest) -- so
      // they're collected into hidden inputs here instead, right before
      // submit. Same pattern as the Domains page's own bulk-access form.
      var checked = Array.prototype.slice.call(document.querySelectorAll(".bulk-device-check:checked"));
      if (!checked.length) {
        event.preventDefault();
        alert("Check at least one device above first.");
        return;
      }
      form.querySelectorAll("input[name=device_ids]").forEach(function (el) { el.remove(); });
      checked.forEach(function (box) {
        var hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "device_ids";
        hidden.value = box.value;
        form.appendChild(hidden);
      });
    });
  }
  wireBulkForm("bulkDeviceEnableForm");
  wireBulkForm("bulkDevicePauseForm");
  wireBulkForm("bulkDeviceDeleteForm");
  wireBulkForm("bulkDeviceGroupForm");
  wireBulkForm("bulkDeviceIgnoreForm");
  wireBulkForm("bulkDeviceUnignoreForm");
})();
</script>
</div>

<div class="card">
<h2>Add a device</h2>
<form class="add-form" method="post" action="{{ url_for('add_device') }}">
  <input type="text" name="mac_address" placeholder="aa:bb:cc:dd:ee:ff" required>
  <input type="text" name="label" placeholder="Label, e.g. Alex's iPad">
""" + DEVICE_ASSIGNMENT_SELECT + """
  <button class="add" type="submit">Add device</button>
</form>
</div>
"""


# ==========================================================
# CATEGORIES (Phase 8)
# ==========================================================

CATEGORIES_BODY = """
<div class="card">
<h2>Categories ({{ categories|length }})</h2>
<p class="hint">
  A category BLOCKS a set of domains for whoever it's assigned to (or everyone) --
  the opposite of the <a href="{{ url_for('domains') }}">Domains</a> page, which grants access.
  Domains come from a subscribed list, manual additions, or both.
</p>
{% if categories %}
<div class="toolbar" id="categoryBulkToolbar">
  <a class="btn small" href="{{ url_for('export_categories_csv') }}">&darr; Download categories</a>
  <span class="toolbar-sep"></span>
  <form id="bulkCategorySyncForm" class="inline" method="post" action="{{ url_for('bulk_sync_categories') }}">
    <button class="btn small" type="submit" disabled>Sync</button>
  </form>
  <form id="bulkCategoryDeleteForm" class="inline" method="post" action="{{ url_for('bulk_delete_categories') }}"
        onsubmit="return confirm('Delete every checked category? This cannot be undone.');">
    <button class="danger small" type="submit" disabled>Delete</button>
  </form>
  <button class="btn small" type="button" id="categoryBulkManageToggle" disabled>Manage access</button>
  <span class="hint" id="categoryBulkCount" style="margin:0;">Check categories below to act on several at once.</span>
</div>
<div id="categoryBulkManagePanel" hidden style="margin:-.3rem 0 .6rem;">
  <p class="hint">Pick who the checked categories block, then apply -- replaces the ENTIRE block-target set for every one checked (same as editing each one's own Manage page, just all at once). A checked category over {{ max_scoped }} domains is skipped unless the result is Everyone-only.</p>
  <form id="bulkCategoryAccessForm" class="add-form" method="post" action="{{ url_for('bulk_update_category_access') }}">
""" + BLOCK_ACCESS_SELECTS + """
    <button class="add small" type="submit">Apply to checked categories</button>
  </form>
</div>
{% endif %}
{% if categories %}
<input type="search" data-filter-table="categoriesTable" placeholder="Filter by category name&hellip;" style="margin-bottom:.3rem; width:100%; max-width:280px;">
<p class="hint" style="margin:0 0 .6rem;">This box filters the list below by <strong>category name</strong> only -- to check whether a specific domain (e.g. <code>facebook.com</code>) is blocked by any category, use "Find a domain across categories" below instead.</p>
{% endif %}
<div class="table-scroll">
<table id="categoriesTable">
  <tr><th>{% if categories %}<input type="checkbox" id="categorySelectAll" title="Select all">{% endif %}</th><th>Name</th><th>Domains</th><th>Blocked for</th><th>Last synced</th><th></th></tr>
  {% for c in categories %}
  <tr>
    <td><input type="checkbox" class="bulk-category-check" value="{{ c.id }}"></td>
    <td>{{ c.name }}</td>
    <td>{{ c.domain_count }}{% if c.domain_count > max_scoped %} <span class="badge blocked" title="Over {{ max_scoped }} domains -- can only be blocked for Everyone, see Manage">everyone-only</span>{% endif %}</td>
    <td>{{ 'Everyone' if c.is_global else 'Per-user/group/device' }}</td>
    <td>{{ c.last_synced_at or ('Manual only' if not c.subscription_url else 'Never') }}</td>
    <td>
      <a class="btn small" href="{{ url_for('category_detail', category_id=c.id) }}">Manage</a>
      <form class="inline" method="post" action="{{ url_for('delete_category') }}">
        <input type="hidden" name="category_id" value="{{ c.id }}">
        <button class="danger small" type="submit" onclick="return confirm('Delete this category?')">Delete</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="6"><em>No categories configured.</em></td></tr>
  {% endfor %}
</table>
</div>
<script>
(function () {
  var selectAll = document.getElementById("categorySelectAll");
  var countLabel = document.getElementById("categoryBulkCount");
  var toolbar = document.getElementById("categoryBulkToolbar");
  var manageToggle = document.getElementById("categoryBulkManageToggle");
  var managePanel = document.getElementById("categoryBulkManagePanel");

  function updateToolbarState() {
    if (!toolbar) return;
    var n = document.querySelectorAll(".bulk-category-check:checked").length;
    toolbar.querySelectorAll("button").forEach(function (btn) { btn.disabled = n === 0; });
    if (n === 0 && managePanel) managePanel.hidden = true;
    if (countLabel) {
      countLabel.textContent = n === 0
        ? "Check categories below to act on several at once."
        : n + " categor" + (n === 1 ? "y" : "ies") + " selected.";
    }
  }

  if (selectAll) {
    selectAll.addEventListener("change", function () {
      document.querySelectorAll(".bulk-category-check").forEach(function (box) { box.checked = selectAll.checked; });
      updateToolbarState();
    });
  }
  document.querySelectorAll(".bulk-category-check").forEach(function (box) {
    box.addEventListener("change", updateToolbarState);
  });
  updateToolbarState();

  // "Manage access" doesn't submit anything itself -- it reveals the
  // access-assign panel below, same toggle-reveals-a-panel pattern as
  // the Devices/Domains pages' own "Manage"/"Manage access" buttons.
  if (manageToggle && managePanel) {
    manageToggle.addEventListener("click", function () {
      managePanel.hidden = !managePanel.hidden;
    });
  }

  function wireBulkForm(formId) {
    var form = document.getElementById(formId);
    if (!form) return;
    form.addEventListener("submit", function (event) {
      // The row checkboxes live in #categoriesTable, not inside any bulk
      // form -- nesting a <form> around the table would break each row's
      // own Delete form (HTML forms can't nest) -- so they're collected
      // into hidden inputs here instead, right before submit.
      var checked = Array.prototype.slice.call(document.querySelectorAll(".bulk-category-check:checked"));
      if (!checked.length) {
        event.preventDefault();
        alert("Check at least one category above first.");
        return;
      }
      form.querySelectorAll("input[name=category_ids]").forEach(function (el) { el.remove(); });
      checked.forEach(function (box) {
        var hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "category_ids";
        hidden.value = box.value;
        form.appendChild(hidden);
      });
    });
  }
  wireBulkForm("bulkCategorySyncForm");
  wireBulkForm("bulkCategoryDeleteForm");
  wireBulkForm("bulkCategoryAccessForm");
})();
</script>

<form class="add-form" method="post" action="{{ url_for('add_category') }}">
  <input type="text" name="name" placeholder="e.g. Gambling" required>
  <input type="text" name="subscription_url" placeholder="Subscription URL (optional -- leave blank for a manual-only category)" style="flex:1; min-width:320px;">
  <button class="add" type="submit">Add category</button>
</form>
<p class="hint">A category over {{ max_scoped }} domains (a large subscribed list) can only ever be blocked for Everyone -- AdGuard Home has no way to scope a list that size to specific people/devices. Smaller categories can be assigned however you like.</p>
<p class="hint">
  <strong>Subscription URL must be a raw domain-list file, not a webpage.</strong>
  Supported formats: a bare domain on each line, a hosts file
  (<code>0.0.0.0 example.com</code>), an AdGuard/uBlock rule list
  (<code>||example.com^</code>), or a full URL on each line
  (<code>http://example.com</code>). A documentation or article page --
  even one that lists domains in a table, like Microsoft's AI-sites
  page -- won't parse into anything, since none of its lines are in one
  of those four shapes. Example that works:
  <code>https://blocklistproject.github.io/Lists/adguard/gambling-ags.txt</code>.
</p>
</div>

<div class="card">
<h2>Find a domain across categories</h2>
<p class="hint">
  <strong>Type a full domain, not a category name</strong> (e.g.
  <code>facebook.com</code>, not "Facebook") to check whether any
  category currently blocks it -- useful for spotting overlaps (the same
  domain listed in more than one category) or confirming a domain landed
  where you expected after a sync. This is a different search than the
  "Filter by category name" box above, which only filters the table by
  name and never looks inside any category's domain list.
</p>
<form method="get" action="{{ url_for('categories') }}" onsubmit="var b=this.querySelector('button'); b.disabled=true; b.textContent='Searching…';">
  <input type="text" name="domain" value="{{ lookup_domain or '' }}" placeholder="e.g. facebook.com" style="min-width:260px;">
  <button class="add" type="submit">Search</button>
</form>
{% if lookup_domain %}
  {% if lookup_results %}
  <ul style="margin:.6rem 0 0; padding-left:1.2rem;">
  {% for m in lookup_results %}
    <li>
      <a href="{{ url_for('category_detail', category_id=m.category.id) }}">{{ m.category.name }}</a>
      -- matched via <code>{{ m.pattern }}</code>
      {% if m.overridden %}<span class="badge" title="An override in this category exempts this domain -- it's a member by pattern but never actually blocked by it">exempted by override</span>{% endif %}
    </li>
  {% endfor %}
  </ul>
  {% else %}
  <p class="hint">No category currently lists <code>{{ lookup_domain }}</code> (or any parent domain of it).</p>
  {% endif %}
{% endif %}
</div>

{% if categories|selectattr('subscription_url')|list %}
<div class="card">
<h2>Refresh subscriptions</h2>
<p class="hint">Re-fetches every category's subscription list right now, instead of waiting for the daily background refresh. A slow or unreachable source is skipped without affecting the others.</p>
<form method="post" action="{{ url_for('sync_all_categories_now') }}">
  <button class="add" type="submit">Sync all subscriptions now</button>
</form>
</div>
{% endif %}
"""


def _category_row_context(conn, category) -> dict:
    domain_count = conn.execute(
        "SELECT COUNT(*) AS c FROM category_domains WHERE category_id = ?", (category["id"],)
    ).fetchone()["c"]
    return {**dict(category), "domain_count": domain_count}


@app.route("/categories")
@require_admin
def categories():
    conn = get_db()
    rows = conn.execute("SELECT * FROM categories ORDER BY is_global DESC, name").fetchall()
    lookup_domain = request.args.get("domain", "").strip()
    lookup_results = matching.find_categories_for_hostname(conn, lookup_domain) if lookup_domain else None
    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    all_devices = conn.execute("SELECT * FROM devices ORDER BY COALESCE(label, mac_address)").fetchall()
    body = render_template_string(
        CATEGORIES_BODY,
        categories=[_category_row_context(conn, c) for c in rows],
        max_scoped=matching.MAX_SCOPED_CATEGORY_DOMAINS,
        lookup_domain=lookup_domain, lookup_results=lookup_results,
        is_global_checked=False,
        all_users_combo=_entity_combo(all_users, lambda u: u["display_name"]),
        all_groups_combo=_entity_combo(all_groups, lambda g: g["name"]),
        all_devices_combo=_entity_combo(all_devices, lambda dev: dev["label"] or dev["mac_address"]),
        preselected_user_ids=set(), preselected_group_ids=set(), preselected_device_ids=set(),
    )
    return render("categories", body)


_PRIVATE_SUBSCRIPTION_HOST_ERROR = (
    "That URL points at a private/internal address, which isn't allowed for a "
    "subscription URL -- it gets fetched automatically by a background job with "
    "no further checks."
)


def _validate_subscription_url(raw: str) -> tuple[str | None, str | None]:
    """Validates an admin-supplied category subscription_url before it's
    ever stored. Returns (normalized_url, None) on success, or
    (None, error_message) on failure.

    Added 2026-09-02, a real gap found by code review: this field used
    to be stored with ZERO validation, unlike the sibling
    add_domain_from_url()'s URL-accepting flow (which strictly checks
    hostname syntax), despite being fetched server-side later by
    controller/category_fetch.py's own background sync job with no
    restriction applied at the point of entry -- an SSRF-adjacent risk
    if this field is ever pointed at an internal/link-local address
    (this box's own AdGuard admin API, a router's admin page, a cloud
    metadata endpoint).

    Mirrors add_domain_from_url()'s scheme/hostname-syntax checks, then
    goes further: an IP-literal hostname is resolved via the stdlib
    `ipaddress` module and rejected if it's loopback/link-local/private/
    reserved -- no legitimate public blocklist subscription is ever a
    private IP literal. Deliberately NOT a full SSRF fix: a hostname
    that only RESOLVES to a private address at fetch time (DNS
    rebinding) isn't caught here, since that needs checking the actual
    resolved IP at fetch time, in category_fetch.py, not just the
    stored string -- tracked as a known, smaller residual gap rather
    than silently claimed as fully closed.
    """
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    hostname = urlparse(raw).hostname
    if not hostname or not re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$", hostname
    ):
        return None, "That doesn't look like a valid URL."
    # "localhost"/"*.localhost" are the obvious non-IP-literal way to
    # target this same box -- ipaddress.ip_address() below only
    # recognizes an actual numeric IP string, not a hostname that
    # merely resolves to loopback, so this needs its own explicit check.
    lower_host = hostname.lower()
    if lower_host == "localhost" or lower_host.endswith(".localhost"):
        return None, _PRIVATE_SUBSCRIPTION_HOST_ERROR
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None  # a real hostname, not an IP literal -- nothing further to check here
    if ip is not None and (
        ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_multicast
    ):
        return None, _PRIVATE_SUBSCRIPTION_HOST_ERROR
    return raw, None


@app.route("/categories/add", methods=["POST"])
@require_admin
def add_category():
    name = request.form.get("name", "").strip()
    subscription_url = request.form.get("subscription_url", "").strip() or None
    if not name:
        return flash_redirect("categories", "Name is required.", error=True)
    if subscription_url:
        subscription_url, error = _validate_subscription_url(subscription_url)
        if error:
            return flash_redirect("categories", error, error=True)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO categories (name, subscription_url, is_global, created_at) VALUES (?, ?, 0, ?)",
            (name, subscription_url, db.now_iso()),
        )
        conn.commit()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return flash_redirect("categories", f"{name!r} already exists.", error=True)
        raise
    return flash_redirect("categories", f"Added {name}.")


@app.route("/categories/delete", methods=["POST"])
@require_admin
def delete_category():
    category_id = request.form.get("category_id", "")
    conn = get_db()
    conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
    conn.commit()
    return flash_redirect("categories", "Category removed.")


@app.route("/categories/bulk-delete", methods=["POST"])
@require_admin
def bulk_delete_categories():
    """Categories list's toolbar "Delete" button (RoadMap.md's dated
    entry -- extending the Devices/Domains/Users bulk-actions pattern to
    every list page). No Enable/Disable here -- a category's `is_global`
    flag is a real per-target assignment, not a simple on/off toggle the
    way a device's pause state is, so there's no clean equivalent."""
    category_ids = {int(x) for x in request.form.getlist("category_ids") if x.isdigit()}
    if not category_ids:
        return flash_redirect("categories", "No categories selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(category_ids))
    conn.execute(f"DELETE FROM categories WHERE id IN ({placeholders})", tuple(category_ids))
    conn.commit()
    return flash_redirect(
        "categories", f"Deleted {len(category_ids)} categor{'y' if len(category_ids) == 1 else 'ies'}."
    )


@app.route("/categories/export", methods=["GET"])
@require_admin
def export_categories_csv():
    """Categories list's toolbar "Download categories" button -- a
    plain CSV overview (name, domain count, blocked-for, subscription
    URL, last synced), same "always available regardless of selection"
    role `export_devices_csv()`/`export_users_csv()` already
    established."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Name", "Domain count", "Blocked for", "Subscription URL", "Last synced"])
    for c in rows:
        domain_count = conn.execute(
            "SELECT COUNT(*) c FROM category_domains WHERE category_id = ?", (c["id"],)
        ).fetchone()["c"]
        writer.writerow([
            c["name"], domain_count, "Everyone" if c["is_global"] else "Per-user/group/device",
            c["subscription_url"] or "", c["last_synced_at"] or "",
        ])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=categories.csv"},
    )


CATEGORY_DETAIL_BODY = """
<p><a href="{{ url_for('categories') }}">&larr; All categories</a></p>
<h1>{{ c.name }}</h1>

<div class="card">
<h2>Subscription</h2>
{% if c.subscription_url %}
<p class="hint"><code>{{ c.subscription_url }}</code></p>
<p class="hint">Last synced: {{ c.last_synced_at or 'never' }}. {{ domain_count }} domain{{ 's' if domain_count != 1 else '' }} from this source (plus any manual additions below).</p>
<form method="post" action="{{ url_for('sync_category_now', category_id=c.id) }}">
  <button class="add" type="submit">Sync now</button>
</form>
{% else %}
<p class="hint">Manual-only -- no subscription set. Add one below, or keep curating this category's domains by hand.</p>
{% endif %}
<p class="hint">Must be a raw domain-list file: a bare domain on each line, a hosts file (<code>0.0.0.0 example.com</code>), an AdGuard/uBlock rule list (<code>||example.com^</code>), or a full URL per line (<code>http://example.com</code>) -- a webpage or documentation page won't parse into anything, even if it visibly lists domains.</p>
<details {{ 'open' if not c.subscription_url }} style="margin-top:.6rem;">
<summary>{{ 'Change' if c.subscription_url else 'Add' }} subscription URL</summary>
<form class="add-form" method="post" action="{{ url_for('update_category_subscription', category_id=c.id) }}">
  <input type="text" name="subscription_url" value="{{ c.subscription_url or '' }}" placeholder="Leave blank to make this category manual-only" style="flex:1; min-width:320px;">
  <button class="add" type="submit">Save</button>
</form>
<p class="hint">Changing or clearing the URL drops this category's currently-synced (not manually-added) domains -- click "Sync now" afterward to fetch the new source.</p>
</details>
</div>

<div class="card">
<h2>Blocked for</h2>
{% if over_threshold %}
<p class="hint"><strong>This category has {{ domain_count }} domains -- over the {{ max_scoped }}-domain limit for per-target scoping.</strong> AdGuard Home has no way to apply a list this size to just some people/devices, so it can only be blocked for Everyone or not at all.</p>
<form method="post" action="{{ url_for('update_category_access') }}">
  <input type="hidden" name="category_id" value="{{ c.id }}">
  <label><input type="checkbox" name="is_global" {{ 'checked' if c.is_global }}> Block for Everyone</label>
  <button class="add" type="submit" style="margin-top:.8rem; display:block;">Save</button>
</form>
{% else %}
<form method="post" action="{{ url_for('update_category_access') }}">
  <input type="hidden" name="category_id" value="{{ c.id }}">
""" + BLOCK_ACCESS_SELECTS + """
  <button class="add" type="submit" style="margin-top:.8rem;">Save</button>
</form>
{% endif %}
</div>

<div class="card">
<h2>Domains ({{ filtered_domain_count }}{% if search %} of {{ domain_count }}{% endif %})</h2>
{% if any_category_domains_exist %}
<form method="get" action="{{ url_for('category_detail', category_id=c.id) }}" class="inline" style="margin-bottom:.3rem; gap:.4rem;">
  <input type="hidden" name="page" value="1">
  <input type="hidden" name="per_page" value="{{ domains_per_page }}">
  <input type="search" name="q" value="{{ search }}" placeholder="Search domains&hellip;" style="width:100%; max-width:280px;">
  <button class="btn small" type="submit">Search</button>
  {% if search %}<a class="btn small" href="{{ url_for('category_detail', category_id=c.id, per_page=domains_per_page) }}">Clear</a>{% endif %}
</form>
{% if search %}<p class="hint" style="margin:0 0 .6rem;">Searches every domain in this category, not just this page &mdash; showing results for &ldquo;{{ search }}&rdquo;.</p>{% endif %}
<div class="toolbar" style="justify-content:space-between;">
  <form method="get" action="{{ url_for('category_detail', category_id=c.id) }}" class="inline">
    <input type="hidden" name="page" value="1">
    {% if search %}<input type="hidden" name="q" value="{{ search }}">{% endif %}
    <label class="hint" style="margin:0;">Show
      <select name="per_page" onchange="this.form.submit()">
        {% for opt in domains_page_size_options %}
        <option value="{{ opt }}" {{ 'selected' if opt == domains_per_page }}>{{ opt }}</option>
        {% endfor %}
      </select>
      per page &mdash; showing {{ domains_range_start }}-{{ domains_range_end }} of {{ filtered_domain_count }}
    </label>
  </form>
  {% if domains_total_pages > 1 %}
  <span>
    {% if domains_page > 1 %}<a class="btn small" href="{{ url_for('category_detail', category_id=c.id, page=domains_page-1, per_page=domains_per_page, **search_query_args) }}">&larr; Prev</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
    <span class="hint">Page {{ domains_page }} of {{ domains_total_pages }}</span>
    {% if domains_page < domains_total_pages %}<a class="btn small" href="{{ url_for('category_detail', category_id=c.id, page=domains_page+1, per_page=domains_per_page, **search_query_args) }}">Next &rarr;</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
  </span>
  {% endif %}
</div>
{% endif %}
<div class="table-scroll">
<table>
  <tr><th>Pattern</th><th>Source</th><th></th></tr>
  {% for d in category_domains %}
  <tr>
    <td><code>{{ d.pattern }}</code></td>
    <td><span class="badge {{ 'mode-bump' if d.source == 'manual' else 'mode-splice' }}">{{ d.source }}</span></td>
    <td>
      {% if d.source == 'manual' %}
      <form class="inline" method="post" action="{{ url_for('delete_category_domain') }}">
        <input type="hidden" name="category_domain_id" value="{{ d.id }}">
        <button class="danger small" type="submit">Remove</button>
      </form>
      {% endif %}
    </td>
  </tr>
  {% else %}
  <tr><td colspan="3"><em>{% if search %}No domains match &ldquo;{{ search }}&rdquo;.{% else %}No domains yet.{% endif %}</em></td></tr>
  {% endfor %}
</table>
</div>
{% if domains_total_pages > 1 %}
<div class="toolbar" style="justify-content:flex-end;">
  {% if domains_page > 1 %}<a class="btn small" href="{{ url_for('category_detail', category_id=c.id, page=domains_page-1, per_page=domains_per_page, **search_query_args) }}">&larr; Prev</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
  <span class="hint">Page {{ domains_page }} of {{ domains_total_pages }}</span>
  {% if domains_page < domains_total_pages %}<a class="btn small" href="{{ url_for('category_detail', category_id=c.id, page=domains_page+1, per_page=domains_per_page, **search_query_args) }}">Next &rarr;</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
</div>
{% endif %}
<form class="add-form" method="post" action="{{ url_for('add_category_domain') }}">
  <input type="hidden" name="category_id" value="{{ c.id }}">
  <input type="text" name="pattern" placeholder="e.g. example\\.com" required>
  <button class="add" type="submit">Add domain</button>
</form>
<p class="hint">Manually-added domains are never touched by a subscription sync.</p>
<details style="margin-top:.6rem;">
<summary>Add many domains at once</summary>
<p class="hint">Paste one per line -- a bare domain, a domain with a path, or a full URL all work (handy for importing every link off an aggregator/listing page). "www." is stripped automatically and duplicates are skipped.</p>
<form class="add-form" method="post" action="{{ url_for('bulk_add_category_domains') }}">
  <input type="hidden" name="category_id" value="{{ c.id }}">
  <textarea name="patterns" rows="6" style="flex:1; min-width:280px; width:100%;" placeholder="example.com&#10;https://another-example.com/some/page&#10;a-third-example.net"></textarea>
  <button class="add" type="submit">Add pasted domains</button>
</form>
</details>
</div>

<div class="card">
<h2>Allow-exceptions ({{ overrides|length }})</h2>
<p class="hint">A domain listed here is never blocked by this category, even if it's also in the subscribed list.</p>
<div class="table-scroll">
<table>
  <tr><th>Pattern</th><th>Note</th><th></th></tr>
  {% for o in overrides %}
  <tr>
    <td><code>{{ o.pattern }}</code></td>
    <td>{{ o.note or '' }}</td>
    <td>
      <form class="inline" method="post" action="{{ url_for('delete_category_override') }}">
        <input type="hidden" name="override_id" value="{{ o.id }}">
        <button class="danger small" type="submit">Remove</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="3"><em>No exceptions.</em></td></tr>
  {% endfor %}
</table>
</div>
<form class="add-form" method="post" action="{{ url_for('add_category_override') }}">
  <input type="hidden" name="category_id" value="{{ c.id }}">
  <input type="text" name="pattern" placeholder="Exact pattern to allow, e.g. example\\.com" style="flex:1; min-width:280px;" required>
  <input type="text" name="note" placeholder="Note (optional)">
  <button class="add" type="submit">Add exception</button>
</form>
<p class="hint">Must match a pattern's exact text as stored above (see the Domains column) -- not a broader or narrower pattern that happens to overlap it.</p>
</div>
"""


# Added 2026-09-07, project owner's explicit request: clicking "Manage"
# on a large category (a real subscription list can run past 900,000
# rows -- see idx_category_domains_pattern's own comment in db.py) used
# to render every single domain into the page at once, which is slow to
# generate, slow for the browser to lay out, made scrolling janky, and
# buried the "Allow-exceptions" card at the bottom of a huge table no
# one could practically scroll past. Paginated like a modern list/detail
# view instead (https://design.infor.com/patterns/page-layouts/list-and-details/
# was the reference the project owner pointed at): a page-size picker
# plus Prev/Next, entirely server-side (LIMIT/OFFSET), so the page never
# renders more than one page's worth of rows regardless of how large the
# category actually is. **Generalized the same day** to Devices, Domains,
# and a user's own Assigned sites list -- same "these lists all grow
# without bound over time" reasoning, same shared (page, per_page)
# parsing and options list, so every paginated list on this site behaves
# identically rather than each page inventing its own page-size choices.
LIST_PAGE_SIZE_OPTIONS = [25, 50, 100, 250]
DEFAULT_LIST_PAGE_SIZE = 50

# Must match controller/network_sweep.py's own DEFAULT_INTERVAL_MINUTES
# -- kept as a separate constant here rather than an import, since
# dashboard's own image never has controller/*.py copied into it (see
# settings_page()'s own comment on this exact point).
DEFAULT_NETWORK_SWEEP_INTERVAL_MINUTES = 60


def _parse_pagination(args, *, default_per_page: int, options: list[int]) -> tuple[int, int]:
    """Parses `?page=`/`?per_page=` into a validated (page, per_page) pair
    -- page defaults to 1 and is clamped to >=1 (a stale bookmark/back-
    button to page 0 or a negative number doesn't become a SQL OFFSET of
    the wrong sign); per_page falls back to `default_per_page` unless the
    request asked for one of the real `options` specifically, so a
    hand-edited URL can't ask for an arbitrary (e.g. huge) page size."""
    try:
        page = int(args.get("page", "1"))
    except ValueError:
        page = 1
    page = max(1, page)
    try:
        per_page = int(args.get("per_page", str(default_per_page)))
    except ValueError:
        per_page = default_per_page
    if per_page not in options:
        per_page = default_per_page
    return page, per_page


@app.route("/categories/<int:category_id>")
@require_admin
def category_detail(category_id: int):
    conn = get_db()
    c = conn.execute("SELECT * FROM categories WHERE id = ?", (category_id,)).fetchone()
    if c is None:
        return flash_redirect("categories", "That category no longer exists.", error=True)
    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    all_devices = conn.execute("SELECT * FROM devices ORDER BY COALESCE(label, mac_address)").fetchall()
    domain_count = conn.execute(
        "SELECT COUNT(*) AS c FROM category_domains WHERE category_id = ?", (category_id,)
    ).fetchone()["c"]
    # Added 2026-09-08 (RoadMap.md's dated entry, follow-up to the
    # 2026-09-07 pagination work): a category's own domain list is the
    # one paginated list on this site that can genuinely reach the
    # hundreds of thousands of rows (a real subscription source), so
    # finding one specific domain by paging through by hand doesn't
    # scale at all. `?q=` searches `pattern` via SQL `LIKE` before the
    # `LIMIT`/`OFFSET`. Honest tradeoff, unlike Devices/Domains' search:
    # a leading-wildcard LIKE can't use the `UNIQUE(category_id,
    # pattern)` index the unfiltered path is built to exploit, so an
    # active search on a 900K-row category does a real sequential scan
    # per page load -- still bounded to returning one page's worth of
    # rows, and still far faster than manually paging through thousands
    # of pages, but not index-backed the way browsing unfiltered is.
    search = (request.args.get("q") or "").strip()
    domain_where_sql = "WHERE category_id = ? "
    domain_where_params: list = [category_id]
    if search:
        domain_where_sql += "AND pattern LIKE ? "
        domain_where_params.append(f"%{search}%")
    filtered_domain_count = conn.execute(
        "SELECT COUNT(*) AS c FROM category_domains " + domain_where_sql, domain_where_params
    ).fetchone()["c"]
    domains_page, domains_per_page = _parse_pagination(
        request.args, default_per_page=DEFAULT_LIST_PAGE_SIZE, options=LIST_PAGE_SIZE_OPTIONS,
    )
    domains_total_pages = max(1, math.ceil(filtered_domain_count / domains_per_page))
    domains_page = min(domains_page, domains_total_pages)
    any_category_domains_exist = domain_count > 0
    search_query_args = {"q": search} if search else {}
    body = render_template_string(
        CATEGORY_DETAIL_BODY, c=c, domain_count=domain_count,
        filtered_domain_count=filtered_domain_count, search=search,
        any_category_domains_exist=any_category_domains_exist, search_query_args=search_query_args,
        over_threshold=domain_count > matching.MAX_SCOPED_CATEGORY_DOMAINS,
        max_scoped=matching.MAX_SCOPED_CATEGORY_DOMAINS,
        # ORDER BY pattern alone (not source, pattern) so the unfiltered
        # (no search) path can be served straight off the
        # UNIQUE(category_id, pattern) index -- source, pattern would
        # force a full sort of every matching row on every page load
        # regardless of LIMIT/OFFSET, defeating the whole point of
        # paginating a 900,000-row category in the first place.
        category_domains=conn.execute(
            "SELECT * FROM category_domains " + domain_where_sql + "ORDER BY pattern LIMIT ? OFFSET ?",
            domain_where_params + [domains_per_page, (domains_page - 1) * domains_per_page],
        ).fetchall(),
        domains_page=domains_page, domains_per_page=domains_per_page,
        domains_total_pages=domains_total_pages,
        domains_page_size_options=LIST_PAGE_SIZE_OPTIONS,
        domains_range_start=0 if filtered_domain_count == 0 else (domains_page - 1) * domains_per_page + 1,
        domains_range_end=min(domains_page * domains_per_page, filtered_domain_count),
        overrides=conn.execute(
            "SELECT * FROM category_overrides WHERE category_id = ? ORDER BY pattern", (category_id,)
        ).fetchall(),
        all_users_combo=_entity_combo(all_users, lambda u: u["display_name"]),
        all_groups_combo=_entity_combo(all_groups, lambda g: g["name"]),
        all_devices_combo=_entity_combo(all_devices, lambda dev: dev["label"] or dev["mac_address"]),
        preselected_user_ids={
            row["user_id"] for row in conn.execute(
                "SELECT user_id FROM category_users WHERE category_id = ?", (category_id,)
            )
        },
        preselected_group_ids={
            row["group_id"] for row in conn.execute(
                "SELECT group_id FROM category_groups WHERE category_id = ?", (category_id,)
            )
        },
        preselected_device_ids={
            row["device_id"] for row in conn.execute(
                "SELECT device_id FROM category_devices WHERE category_id = ?", (category_id,)
            )
        },
        is_global_checked=bool(c["is_global"]),
    )
    return render("categories", body)


def _replace_category_access(conn, category_id, is_global: int, user_ids: set[int], group_ids: set[int], device_ids: set[int]) -> None:
    """Replaces one category's entire block-target set (Everyone + users +
    groups + devices) with exactly what's passed in -- same grant-and-
    revoke-are-the-same-action shape as _replace_domain_access(), just
    BLOCK instead of allow. Shared by update_category_access() (one
    category, from its own Manage page) and bulk_update_category_access()
    (many categories at once, from the Categories list) -- deliberately no
    conn.commit() here, so the bulk caller can wrap its whole loop in one
    transaction rather than committing (and fsyncing) once per category.
    Callers are responsible for their own matching.MAX_SCOPED_CATEGORY_DOMAINS
    check -- this function applies whatever it's given unconditionally."""
    conn.execute("UPDATE categories SET is_global = ? WHERE id = ?", (is_global, category_id))
    conn.execute("DELETE FROM category_users WHERE category_id = ?", (category_id,))
    for uid in user_ids:
        conn.execute("INSERT OR IGNORE INTO category_users (category_id, user_id) VALUES (?,?)", (category_id, uid))
    conn.execute("DELETE FROM category_groups WHERE category_id = ?", (category_id,))
    for gid in group_ids:
        conn.execute("INSERT OR IGNORE INTO category_groups (category_id, group_id) VALUES (?,?)", (category_id, gid))
    conn.execute("DELETE FROM category_devices WHERE category_id = ?", (category_id,))
    for did in device_ids:
        conn.execute("INSERT OR IGNORE INTO category_devices (category_id, device_id) VALUES (?,?)", (category_id, did))


@app.route("/categories/access", methods=["POST"])
@require_admin
def update_category_access():
    """Replaces a category's entire block-target set (Everyone + users +
    groups + devices) with exactly what was submitted -- same
    grant-and-revoke-are-the-same-action shape as update_domain_access(),
    just BLOCK instead of allow. A category over
    matching.MAX_SCOPED_CATEGORY_DOMAINS is rejected unless the result is
    is_global-only (see controller/adguard_sync.py's docstring for why:
    AdGuard Home can't scope a list that size to a subset of clients)."""
    category_id = request.form.get("category_id", "")
    is_global = 1 if request.form.get("is_global") else 0
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    group_ids = {int(x) for x in request.form.getlist("group_ids") if x.isdigit()}
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}

    conn = get_db()
    domain_count = conn.execute(
        "SELECT COUNT(*) AS c FROM category_domains WHERE category_id = ?", (category_id,)
    ).fetchone()["c"]
    if domain_count > matching.MAX_SCOPED_CATEGORY_DOMAINS and not is_global and (user_ids or group_ids or device_ids):
        return flash_redirect(
            "category_detail", "This category is too large to scope to specific people/devices -- "
            "it can only be blocked for Everyone.", error=True, category_id=category_id,
        )

    _replace_category_access(conn, category_id, is_global, user_ids, group_ids, device_ids)
    conn.commit()
    return flash_redirect("category_detail", "Access updated.", category_id=category_id)


@app.route("/categories/bulk-access", methods=["POST"])
@require_admin
def bulk_update_category_access():
    """Categories list's "Manage access" bulk action -- added 2026-09-07,
    project owner's explicit request: "Add the ability for me to bulk
    assign categories to users, groups, or everyone." Same shape as
    bulk_update_domain_access(): checkboxes on the list (collected
    client-side, since the checkboxes live in the table, not inside this
    form, to avoid nesting <form> elements around each row's own Delete
    form) plus the same is_global/user_ids/group_ids/device_ids fields as
    the single-category form. One BEGIN IMMEDIATE transaction for the
    whole batch via the shared _replace_category_access() helper, same
    "one commit, not one per row" discipline as every other bulk route
    in this file.

    Each category's own matching.MAX_SCOPED_CATEGORY_DOMAINS check is
    applied individually -- a batch can freely mix small and huge
    categories, so an oversized one requesting a non-global scope is
    silently skipped (not applied) rather than failing the whole batch,
    and named in the result message so it's not a silent no-op."""
    category_ids = {int(x) for x in request.form.getlist("category_ids") if x.isdigit()}
    is_global = 1 if request.form.get("is_global") else 0
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    group_ids = {int(x) for x in request.form.getlist("group_ids") if x.isdigit()}
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}

    if not category_ids:
        return flash_redirect("categories", "No categories selected.", error=True)

    conn = get_db()
    placeholders = ",".join("?" * len(category_ids))
    rows = conn.execute(
        f"SELECT c.id, c.name, (SELECT COUNT(*) FROM category_domains cd WHERE cd.category_id = c.id) AS domain_count "
        f"FROM categories c WHERE c.id IN ({placeholders})",
        tuple(category_ids),
    ).fetchall()

    wants_scoped = not is_global and (user_ids or group_ids or device_ids)
    too_large = [r["name"] for r in rows if wants_scoped and r["domain_count"] > matching.MAX_SCOPED_CATEGORY_DOMAINS]
    applicable_ids = [r["id"] for r in rows if not (wants_scoped and r["domain_count"] > matching.MAX_SCOPED_CATEGORY_DOMAINS)]

    if applicable_ids:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for category_id in applicable_ids:
                _replace_category_access(conn, category_id, is_global, user_ids, group_ids, device_ids)
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.commit()

    message = f"Access updated for {len(applicable_ids)} categor{'y' if len(applicable_ids) != 1 else 'ies'}."
    if too_large:
        message += f" Skipped (too large to scope to specific people/devices): {', '.join(too_large)}."
    return flash_redirect("categories", message, error=not applicable_ids and bool(too_large))


@app.route("/categories/bulk-sync", methods=["POST"])
@require_admin
def bulk_sync_categories():
    """Categories list's "Sync" bulk action -- added 2026-09-07, project
    owner's explicit request: "Add the ability for me to bulk sync
    categories." Distinct from the pre-existing "Sync all subscriptions
    now" card (sync_all_categories_now(), which always syncs literally
    every subscription-backed category) -- this one respects the
    checkbox selection, same as every other bulk route on this page. A
    manual-only category (no subscription_url) has nothing to sync and
    is silently skipped, named in the result rather than attempted and
    failing. One bad source is skipped, not fatal to the rest -- same
    "one failure doesn't take down the batch" discipline as
    category_fetch.sync_all_categories()."""
    category_ids = {int(x) for x in request.form.getlist("category_ids") if x.isdigit()}
    if not category_ids:
        return flash_redirect("categories", "No categories selected.", error=True)

    conn = get_db()
    placeholders = ",".join("?" * len(category_ids))
    rows = conn.execute(f"SELECT * FROM categories WHERE id IN ({placeholders})", tuple(category_ids)).fetchall()

    manual_only = [r["name"] for r in rows if not r["subscription_url"]]
    synced: dict[str, int] = {}
    failed: dict[str, str] = {}
    for row in rows:
        if not row["subscription_url"]:
            continue
        try:
            synced[row["name"]] = category_fetch.fetch_and_sync_category(conn, row)
        except category_fetch.CategoryFetchError as exc:
            failed[row["name"]] = str(exc)

    total = sum(synced.values())
    message = f"Synced {len(synced)} categor{'y' if len(synced) != 1 else 'ies'}, {total} domains total."
    empty = [name for name, count in synced.items() if count == 0]
    if empty:
        message += f" 0 domains found (likely an unsupported URL format): {', '.join(empty)}."
    if failed:
        message += f" Failed: {', '.join(f'{name} ({reason})' for name, reason in failed.items())}."
    if manual_only:
        message += f" Skipped (manual-only, no subscription set): {', '.join(manual_only)}."
    return flash_redirect("categories", message, error=not synced and bool(failed or manual_only))


@app.route("/categories/domains/add", methods=["POST"])
@require_admin
def add_category_domain():
    category_id = request.form.get("category_id", "")
    pattern = request.form.get("pattern", "").strip()
    if not pattern:
        return flash_redirect("category_detail", "Pattern is required.", error=True, category_id=category_id)
    if len(pattern) > 200:
        return flash_redirect("category_detail", "Pattern too long (200 characters max).", error=True, category_id=category_id)
    try:
        re.compile(pattern)
    except re.error as exc:
        return flash_redirect("category_detail", f"Not a valid regex: {exc}", error=True, category_id=category_id)
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO category_domains (category_id, pattern, source, created_at) "
        "VALUES (?, ?, 'manual', ?)",
        (category_id, pattern, db.now_iso()),
    )
    conn.commit()
    return flash_redirect("category_detail", "Domain added.", category_id=category_id)


@app.route("/categories/domains/bulk-add", methods=["POST"])
@require_admin
def bulk_add_category_domains():
    """Category detail page's "Add many domains at once" panel -- added
    2026-09-07 (RoadMap.md's dated entry, project owner's explicit
    request: import every site from an aggregator page as one category
    in a single paste, rather than one add_category_domain() call per
    domain). Accepts one bare domain, domain+path, or full URL per
    line -- same "paste whatever you've got" extraction _extract_path()
    already uses for bump-mode paths -- de-dupes, strips a leading
    'www.', and stores each as an escaped literal (re.escape()), the
    same regex-pattern shape add_category_domain() stores, just derived
    instead of hand-typed/hand-escaped. One transaction for the whole
    paste, not one commit per line, same discipline as
    bulk_update_domain_access()."""
    category_id = request.form.get("category_id", "")
    raw_lines = request.form.get("patterns", "").splitlines()
    hosts = sorted({h for h in (_extract_domain(line) for line in raw_lines) if h})
    if not hosts:
        return flash_redirect(
            "category_detail", "No usable domains found in the pasted text.", error=True, category_id=category_id,
        )
    conn = get_db()
    conn.execute("BEGIN IMMEDIATE")
    try:
        for host in hosts:
            conn.execute(
                "INSERT OR IGNORE INTO category_domains (category_id, pattern, source, created_at) "
                "VALUES (?, ?, 'manual', ?)",
                (category_id, re.escape(host), db.now_iso()),
            )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.commit()
    return flash_redirect(
        "category_detail", f"Added {len(hosts)} domain{'s' if len(hosts) != 1 else ''}.", category_id=category_id,
    )


@app.route("/categories/domains/delete", methods=["POST"])
@require_admin
def delete_category_domain():
    category_domain_id = request.form.get("category_domain_id", "")
    conn = get_db()
    row = conn.execute("SELECT category_id FROM category_domains WHERE id = ?", (category_domain_id,)).fetchone()
    if row is None:
        return flash_redirect("categories", "That domain no longer exists.", error=True)
    conn.execute("DELETE FROM category_domains WHERE id = ? AND source = 'manual'", (category_domain_id,))
    conn.commit()
    return flash_redirect("category_detail", "Domain removed.", category_id=row["category_id"])


@app.route("/categories/overrides/add", methods=["POST"])
@require_admin
def add_category_override():
    category_id = request.form.get("category_id", "")
    pattern = request.form.get("pattern", "").strip()
    note = request.form.get("note", "").strip() or None
    if not pattern:
        return flash_redirect("category_detail", "Pattern is required.", error=True, category_id=category_id)
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO category_overrides (category_id, pattern, note, created_at) VALUES (?, ?, ?, ?)",
        (category_id, pattern, note, db.now_iso()),
    )
    conn.commit()
    return flash_redirect("category_detail", "Exception added.", category_id=category_id)


@app.route("/categories/overrides/delete", methods=["POST"])
@require_admin
def delete_category_override():
    override_id = request.form.get("override_id", "")
    conn = get_db()
    row = conn.execute("SELECT category_id FROM category_overrides WHERE id = ?", (override_id,)).fetchone()
    if row is None:
        return flash_redirect("categories", "That exception no longer exists.", error=True)
    conn.execute("DELETE FROM category_overrides WHERE id = ?", (override_id,))
    conn.commit()
    return flash_redirect("category_detail", "Exception removed.", category_id=row["category_id"])


@app.route("/categories/<int:category_id>/sync", methods=["POST"])
@require_admin
def sync_category_now(category_id: int):
    conn = get_db()
    category = conn.execute("SELECT * FROM categories WHERE id = ?", (category_id,)).fetchone()
    if category is None:
        return flash_redirect("categories", "That category no longer exists.", error=True)
    try:
        count = category_fetch.fetch_and_sync_category(conn, category)
    except category_fetch.CategoryFetchError as exc:
        return flash_redirect("category_detail", f"Sync failed: {exc}", error=True, category_id=category_id)
    if count == 0:
        # Real gap found 2026-09-06: the fetch itself can succeed
        # against a URL that isn't actually a supported blocklist format
        # (a webpage, a documentation page) -- parse_hostlist() then
        # legitimately finds zero recognizable lines, which used to read
        # as an unexplained "Synced 0 domains." with no hint anything
        # was wrong. Almost every real subscription source has domains,
        # so 0 is worth flagging as likely-wrong-format rather than
        # treated the same as a normal non-zero refresh.
        return flash_redirect(
            "category_detail",
            "Fetched successfully but found 0 recognizable domains -- this almost always means the URL "
            "isn't a supported format (see the hint above), not that the list is genuinely empty.",
            error=True, category_id=category_id,
        )
    return flash_redirect("category_detail", f"Synced {count} domains.", category_id=category_id)


@app.route("/categories/<int:category_id>/subscription", methods=["POST"])
@require_admin
def update_category_subscription(category_id: int):
    """Real gap fixed 2026-09-08: previously the only way to change a
    category's subscription_url once set was to delete and recreate the
    whole category (losing its access assignments, manual domains, and
    overrides in the process) -- add_category() could set it, but
    nothing could ever edit it. Also covers going the other direction
    (manual-only -> subscribed) or clearing it entirely (subscribed ->
    manual-only), from the same one field."""
    raw_url = request.form.get("subscription_url", "").strip()
    conn = get_db()
    category = conn.execute("SELECT * FROM categories WHERE id = ?", (category_id,)).fetchone()
    if category is None:
        return flash_redirect("categories", "That category no longer exists.", error=True)

    new_url = None
    if raw_url:
        new_url, error = _validate_subscription_url(raw_url)
        if error:
            return flash_redirect("category_detail", error, error=True, category_id=category_id)

    if new_url == category["subscription_url"]:
        return flash_redirect("category_detail", "No change.", category_id=category_id)

    # The old subscription-sourced domains belong to whatever source WAS
    # configured, not what's configured now -- same "replace, don't
    # accumulate" rule fetch_and_sync_category() already applies on every
    # real sync, just triggered here instead of by a fetch. Manual rows
    # (source='manual') are never touched, matching that same convention.
    # last_synced_at is cleared too so the page doesn't keep describing a
    # sync that happened against a source that's no longer configured.
    conn.execute(
        "DELETE FROM category_domains WHERE category_id = ? AND source = 'subscription'", (category_id,)
    )
    conn.execute(
        "UPDATE categories SET subscription_url = ?, last_synced_at = NULL WHERE id = ?",
        (new_url, category_id),
    )
    conn.commit()
    message = (
        'Subscription URL updated -- click "Sync now" to fetch it.' if new_url
        else "Subscription removed -- this category is manual-only now. Existing manually-added domains are untouched."
    )
    return flash_redirect("category_detail", message, category_id=category_id)


@app.route("/categories/sync-all", methods=["POST"])
@require_admin
def sync_all_categories_now():
    conn = get_db()
    results = category_fetch.sync_all_categories(conn)
    total = sum(results.values())
    message = f"Synced {len(results)} categor{'y' if len(results) == 1 else 'ies'}, {total} domains total."
    # Same "0 is suspicious, not normal" flag as sync_category_now() --
    # naming which categories came back empty here, since this route's
    # single aggregate total would otherwise hide which specific one(s)
    # need a closer look.
    empty = [name for name, count in results.items() if count == 0]
    if empty:
        message += (
            f" {', '.join(empty)} came back with 0 domains -- likely means that URL isn't a "
            "supported format (see the hint on the category's own page), not that the list is empty."
        )
    return flash_redirect("categories", message, error=bool(empty))


# ==========================================================
# SCHEDULES (Phase 8)
# ==========================================================

_DAY_CODES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_DAY_LABELS = {"mon": "Mon", "tue": "Tue", "wed": "Wed", "thu": "Thu", "fri": "Fri", "sat": "Sat", "sun": "Sun"}

DAY_CHECKBOXES = """
  <div class="access-label" style="margin-top:.6rem;">Days</div>
  <div style="display:flex; gap:.8rem; flex-wrap:wrap; margin:.3rem 0 .6rem;">
  {% for code in day_codes %}
    <label><input type="checkbox" name="days" value="{{ code }}" {{ 'checked' if code in selected_days }}> {{ day_labels[code] }}</label>
  {% endfor %}
  </div>
"""

SCHEDULES_BODY = """
<div class="card">
<h2>Schedules ({{ schedules|length }})</h2>
<p class="hint">A schedule blocks categories (or everything) for whoever it's assigned to, only while its time window is open -- e.g. "block Social Media on school days 08:00-15:00" or "no internet at all, every night 21:00-06:00."</p>
{% if schedules %}
<div class="toolbar" id="scheduleBulkToolbar">
  <a class="btn small" href="{{ url_for('export_schedules_csv') }}">&darr; Download schedules</a>
  <span class="toolbar-sep"></span>
  <form id="bulkScheduleDeleteForm" class="inline" method="post" action="{{ url_for('bulk_delete_schedules') }}"
        onsubmit="return confirm('Delete every checked schedule? This cannot be undone.');">
    <button class="danger small" type="submit" disabled>Delete</button>
  </form>
  <span class="hint" id="scheduleBulkCount" style="margin:0;">Check schedules below to delete several at once.</span>
</div>
{% endif %}
{% if schedules %}<input type="search" data-filter-table="schedulesTable" placeholder="Search schedules&hellip;" style="margin-bottom:.6rem; width:100%; max-width:280px;">{% endif %}
<div class="table-scroll">
<table id="schedulesTable">
  <tr><th>{% if schedules %}<input type="checkbox" id="scheduleSelectAll" title="Select all">{% endif %}</th><th>Name</th><th>Days</th><th>Window</th><th>Effect</th><th>Applies to</th><th></th></tr>
  {% for s in schedules %}
  <tr>
    <td><input type="checkbox" class="bulk-schedule-check" value="{{ s.id }}"></td>
    <td>{{ s.name }}{% if s.is_mode %} <span class="badge" title="Eligible for &quot;Shift mode now&quot;">mode</span>{% endif %}</td>
    <td>{{ s.days_of_week }}</td>
    <td>{{ s.start_time }}&ndash;{{ s.end_time }} {{ s.time_zone }}</td>
    <td>{% if s.lockout_all %}<span class="badge blocked">full lockout</span>{% else %}{{ s.category_count }} categor{{ 'y' if s.category_count == 1 else 'ies' }}{% endif %}</td>
    <td>{{ 'Everyone' if s.is_global else 'Per-user/group/device' }}</td>
    <td>
      <a class="btn small" href="{{ url_for('schedule_detail', schedule_id=s.id) }}">Manage</a>
      <form class="inline" method="post" action="{{ url_for('delete_schedule') }}">
        <input type="hidden" name="schedule_id" value="{{ s.id }}">
        <button class="danger small" type="submit" onclick="return confirm('Delete this schedule?')">Delete</button>
      </form>
    </td>
  </tr>
  {% else %}
  <tr><td colspan="7"><em>No schedules configured.</em></td></tr>
  {% endfor %}
</table>
</div>
<script>
(function () {
  var selectAll = document.getElementById("scheduleSelectAll");
  var countLabel = document.getElementById("scheduleBulkCount");
  var toolbar = document.getElementById("scheduleBulkToolbar");

  function updateToolbarState() {
    if (!toolbar) return;
    var n = document.querySelectorAll(".bulk-schedule-check:checked").length;
    toolbar.querySelectorAll("button").forEach(function (btn) { btn.disabled = n === 0; });
    if (countLabel) {
      countLabel.textContent = n === 0
        ? "Check schedules below to delete several at once."
        : n + " schedule" + (n === 1 ? "" : "s") + " selected.";
    }
  }

  if (selectAll) {
    selectAll.addEventListener("change", function () {
      document.querySelectorAll(".bulk-schedule-check").forEach(function (box) { box.checked = selectAll.checked; });
      updateToolbarState();
    });
  }
  document.querySelectorAll(".bulk-schedule-check").forEach(function (box) {
    box.addEventListener("change", updateToolbarState);
  });
  updateToolbarState();

  var form = document.getElementById("bulkScheduleDeleteForm");
  if (form) {
    form.addEventListener("submit", function (event) {
      var checked = Array.prototype.slice.call(document.querySelectorAll(".bulk-schedule-check:checked"));
      if (!checked.length) {
        event.preventDefault();
        alert("Check at least one schedule above first.");
        return;
      }
      form.querySelectorAll("input[name=schedule_ids]").forEach(function (el) { el.remove(); });
      checked.forEach(function (box) {
        var hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "schedule_ids";
        hidden.value = box.value;
        form.appendChild(hidden);
      });
    });
  }
})();
</script>

<form class="add-form" method="post" action="{{ url_for('add_schedule') }}" style="flex-wrap:wrap;">
  <input type="text" name="name" placeholder="e.g. Bedtime" required style="flex:1; min-width:200px;">
""" + DAY_CHECKBOXES + """
  <input type="time" name="start_time" value="21:00" required>
  <span class="hint" style="margin:0;">to</span>
  <input type="time" name="end_time" value="06:00" required>
  <select name="time_zone">
    {% for tz in available_time_zones %}
    <option value="{{ tz }}" {{ 'selected' if tz == household_time_zone }}>{{ tz }}</option>
    {% endfor %}
  </select>
  <label><input type="checkbox" name="lockout_all"> Full lockout (no internet at all)</label>
  <label><input type="checkbox" name="is_mode"> Mode schedule</label>
  <button class="add" type="submit">Add schedule</button>
</form>
<p class="hint">An end time earlier than the start time means an overnight window (like the Bedtime example above) -- it's treated as running past midnight into the next day.</p>
<p class="hint"><strong>Mode schedule</strong> marks this as one of a kid's mutually-exclusive daily modes (e.g. School / Free Time / Bedtime) -- only mode schedules can be manually forced on or off early with "Shift mode now" below. Leave unchecked for a standing rule (a safety-net category block, say) that should never be affected by a manual shift.</p>
</div>

{% if mode_schedules %}
<div class="card">
<h2>Shift mode now</h2>
<p class="hint">Force a mode schedule active for someone right now, for a set amount of time -- e.g. school let out early, so give Free Time now instead of waiting for School's window to end. Every other mode schedule normally targeting the same kid/group/device is suppressed for the duration; anything not marked "Mode schedule" is untouched.</p>
<form class="add-form" method="post" action="{{ url_for('add_schedule_override') }}" style="flex-wrap:wrap;">
  <div class="combobox" data-combobox data-mode="single" style="max-width:280px;">
    <div class="combobox-current" data-combobox-current></div>
    <input type="search" class="combobox-input" data-combobox-input placeholder="Who&hellip;">
    <div class="combobox-results" data-combobox-results></div>
    <input type="hidden" name="target" data-combobox-hidden value="">
    <script type="application/json" data-combobox-items>{{ override_target_combo|tojson }}</script>
  </div>
  <select name="schedule_id">
    {% for s in mode_schedules %}
    <option value="{{ s.id }}">{{ s.name }}</option>
    {% endfor %}
  </select>
  <input type="number" name="duration_minutes" value="120" min="1" max="1440" style="width:6rem;">
  <span class="hint" style="margin:0;">minutes</span>
  <span style="display:flex; gap:.3rem;">
    {% for label, mins in [('30m', 30), ('1h', 60), ('2h', 120), ('4h', 240), ('rest of day', 1440)] %}
    <button class="btn small" type="button" onclick="this.form.duration_minutes.value={{ mins }}">{{ label }}</button>
    {% endfor %}
  </span>
  <button class="add" type="submit">Shift now</button>
</form>
</div>
{% endif %}

{% if active_overrides %}
<div class="card">
<h2>Active overrides ({{ active_overrides|length }})</h2>
<div class="table-scroll">
<table>
  <tr><th>Forcing</th><th>For</th><th>Until</th><th></th></tr>
  {% for o in active_overrides %}
  <tr>
    <td>{{ o.schedule_name }}</td>
    <td>{{ o.user_name or o.group_name or o.device_name }}</td>
    <td>{{ o.expires_at }}</td>
    <td>
      <form class="inline" method="post" action="{{ url_for('cancel_schedule_override') }}">
        <input type="hidden" name="override_id" value="{{ o.id }}">
        <button class="danger small" type="submit">Cancel</button>
      </form>
    </td>
  </tr>
  {% endfor %}
</table>
</div>
</div>
{% endif %}
"""


def _schedule_row_context(conn, schedule) -> dict:
    category_count = conn.execute(
        "SELECT COUNT(*) AS c FROM schedule_categories WHERE schedule_id = ?", (schedule["id"],)
    ).fetchone()["c"]
    return {**dict(schedule), "category_count": category_count}


def _parse_days(raw_days: list[str]) -> str | None:
    days = [d for d in raw_days if d in _DAY_CODES]
    return ",".join(days) if days else None


def _valid_time(value: str) -> bool:
    return bool(re.match(r"^\d{2}:\d{2}$", value or ""))


def _override_target_combo(all_users, all_groups, all_devices) -> list[dict]:
    """Items for the 'Shift mode now' target combobox -- a flat list
    across all three target kinds (a schedule_overrides row's target is a
    single ad hoc user/group/device pick, not a saved multi-select the
    way schedule_users/groups/devices is), id-encoded the same
    "kind:id" way _assignment_combo() already encodes device assignment."""
    items = [{"id": f"user:{u['id']}", "label": f"{u['display_name']} (kid)"} for u in all_users]
    items += [{"id": f"group:{g['id']}", "label": f"{g['name']} (group)"} for g in all_groups]
    items += [
        {"id": f"device:{d['id']}", "label": f"{d['label'] or d['mac_address']} (device)"} for d in all_devices
    ]
    return items


def _parse_override_target(value: str) -> tuple[int | None, int | None, int | None]:
    """Decodes the 'Shift mode now' target combobox's composite value
    ("user:5" / "group:2" / "device:9") into (user_id, group_id,
    device_id) -- exactly one set, the other two None. Anything
    unrecognized (empty, malformed) comes back as all-None, which the
    caller treats as "no target picked"."""
    kind, _, raw_id = value.partition(":")
    if not raw_id.isdigit():
        return None, None, None
    entity_id = int(raw_id)
    if kind == "user":
        return entity_id, None, None
    if kind == "group":
        return None, entity_id, None
    if kind == "device":
        return None, None, entity_id
    return None, None, None


def _schedule_targets_selection(
    conn, schedule_id: str, *, user_id: int | None, group_id: int | None, device_id: int | None
) -> bool:
    """Whether `schedule_id` already targets the exact user/group/device
    picked for a 'Shift mode now' override -- same is_global-or-junction-
    table logic as matching.schedule_applies_to_device(), just checked
    directly against a chosen target instead of resolved from a devices
    row (an override's target can be a user or group directly, not only a
    single device). Required before creating an override: forcing a
    schedule that was never assigned to this target would silently do
    nothing at enforcement time (schedule_is_active_for_device() still
    gates on this same targeting check for every other caller), so the
    route rejects that case with an actionable message instead of a
    mystery no-op."""
    schedule = conn.execute("SELECT is_global FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    if schedule is None:
        return False
    if schedule["is_global"]:
        return True
    if user_id is not None and conn.execute(
        "SELECT 1 FROM schedule_users WHERE schedule_id = ? AND user_id = ?", (schedule_id, user_id)
    ).fetchone():
        return True
    if group_id is not None and conn.execute(
        "SELECT 1 FROM schedule_groups WHERE schedule_id = ? AND group_id = ?", (schedule_id, group_id)
    ).fetchone():
        return True
    if device_id is not None and conn.execute(
        "SELECT 1 FROM schedule_devices WHERE schedule_id = ? AND device_id = ?", (schedule_id, device_id)
    ).fetchone():
        return True
    return False


def _clear_overrides_for_target(
    conn, *, user_id: int | None, group_id: int | None, device_id: int | None
) -> None:
    """Deletes any existing schedule_overrides row(s) for the exact same
    target a new override is about to be created for -- only one override
    can be in effect per target at a time, same "grant and revoke are the
    same action" shape as update_schedule()'s own replace-the-whole-
    access-set pattern. Also opportunistically clears out any already-
    expired row for that target, since nothing else ever prunes those
    (see schedule_overrides' own comment in common/db.py)."""
    if user_id is not None:
        conn.execute("DELETE FROM schedule_overrides WHERE user_id = ?", (user_id,))
    elif group_id is not None:
        conn.execute("DELETE FROM schedule_overrides WHERE group_id = ?", (group_id,))
    elif device_id is not None:
        conn.execute("DELETE FROM schedule_overrides WHERE device_id = ?", (device_id,))


@app.route("/schedules")
@require_admin
def schedules():
    conn = get_db()
    rows = conn.execute("SELECT * FROM schedules ORDER BY is_global DESC, name").fetchall()
    household_time_zone = db.get_setting(conn, "household_time_zone", "UTC")
    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    all_devices = conn.execute("SELECT * FROM devices ORDER BY COALESCE(label, mac_address)").fetchall()
    active_overrides = conn.execute(
        "SELECT so.*, s.name AS schedule_name, u.display_name AS user_name, "
        "g.name AS group_name, COALESCE(d.label, d.mac_address) AS device_name "
        "FROM schedule_overrides so "
        "JOIN schedules s ON s.id = so.schedule_id "
        "LEFT JOIN users u ON u.id = so.user_id "
        "LEFT JOIN groups g ON g.id = so.group_id "
        "LEFT JOIN devices d ON d.id = so.device_id "
        "WHERE so.expires_at > ? ORDER BY so.expires_at",
        (db.now_iso(),),
    ).fetchall()
    body = render_template_string(
        SCHEDULES_BODY,
        schedules=[_schedule_row_context(conn, s) for s in rows],
        day_codes=_DAY_CODES, day_labels=_DAY_LABELS, selected_days=set(),
        household_time_zone=household_time_zone,
        available_time_zones=sorted(zoneinfo.available_timezones()),
        mode_schedules=[s for s in rows if s["is_mode"]],
        override_target_combo=_override_target_combo(all_users, all_groups, all_devices),
        active_overrides=active_overrides,
    )
    return render("schedules", body)


@app.route("/schedules/add", methods=["POST"])
@require_admin
def add_schedule():
    name = request.form.get("name", "").strip()
    days = _parse_days(request.form.getlist("days"))
    start_time = request.form.get("start_time", "")
    end_time = request.form.get("end_time", "")
    time_zone = request.form.get("time_zone", "UTC")
    lockout_all = 1 if request.form.get("lockout_all") else 0
    is_mode = 1 if request.form.get("is_mode") else 0

    if not name:
        return flash_redirect("schedules", "Name is required.", error=True)
    if not days:
        return flash_redirect("schedules", "Pick at least one day.", error=True)
    if not (_valid_time(start_time) and _valid_time(end_time)):
        return flash_redirect("schedules", "Start and end time are required.", error=True)
    if time_zone not in zoneinfo.available_timezones():
        return flash_redirect("schedules", "That doesn't look like a real time zone.", error=True)

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO schedules (name, days_of_week, start_time, end_time, time_zone, "
            "lockout_all, is_global, is_mode, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
            (name, days, start_time, end_time, time_zone, lockout_all, is_mode, db.now_iso()),
        )
        conn.commit()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return flash_redirect("schedules", f"{name!r} already exists.", error=True)
        raise
    return flash_redirect("schedules", f"Added {name}.")


@app.route("/schedules/delete", methods=["POST"])
@require_admin
def delete_schedule():
    schedule_id = request.form.get("schedule_id", "")
    conn = get_db()
    conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
    conn.commit()
    return flash_redirect("schedules", "Schedule removed.")


@app.route("/schedules/bulk-delete", methods=["POST"])
@require_admin
def bulk_delete_schedules():
    """Schedules list's toolbar "Delete" button (RoadMap.md's dated
    entry -- extending the Devices/Domains/Users/Categories bulk-actions
    pattern to every list page). No Enable/Disable here either -- a
    schedule's own time window already governs when it's active; there's
    no separate on/off flag to toggle in bulk."""
    schedule_ids = {int(x) for x in request.form.getlist("schedule_ids") if x.isdigit()}
    if not schedule_ids:
        return flash_redirect("schedules", "No schedules selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(schedule_ids))
    conn.execute(f"DELETE FROM schedules WHERE id IN ({placeholders})", tuple(schedule_ids))
    conn.commit()
    return flash_redirect(
        "schedules", f"Deleted {len(schedule_ids)} schedule{'s' if len(schedule_ids) != 1 else ''}."
    )


@app.route("/schedules/export", methods=["GET"])
@require_admin
def export_schedules_csv():
    """Schedules list's toolbar "Download schedules" button -- a plain
    CSV overview (name, days, window, time zone, effect, applies-to),
    same "always available regardless of selection" role the other
    list pages' own export buttons already established."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM schedules ORDER BY name").fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Name", "Days", "Start", "End", "Time zone", "Effect", "Applies to", "Mode schedule"])
    for s in rows:
        if s["lockout_all"]:
            effect = "Full lockout"
        else:
            category_count = conn.execute(
                "SELECT COUNT(*) c FROM schedule_categories WHERE schedule_id = ?", (s["id"],)
            ).fetchone()["c"]
            effect = f"{category_count} categories"
        writer.writerow([
            s["name"], s["days_of_week"], s["start_time"], s["end_time"], s["time_zone"], effect,
            "Everyone" if s["is_global"] else "Per-user/group/device", "yes" if s["is_mode"] else "no",
        ])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=schedules.csv"},
    )


SCHEDULE_DETAIL_BODY = """
<p><a href="{{ url_for('schedules') }}">&larr; All schedules</a></p>
<h1>{{ s.name }}</h1>

<!-- Merged into one Save button 2026-09-09 (RoadMap.md item 3, "one Save
     button per settings-shaped page, not several"): "When", "Blocked
     for", and "Categories blocked" used to be three independent
     forms/routes, saved one at a time. All three describe ONE
     schedule -- unlike Settings' many genuinely-unrelated topics (see
     SETTINGS_BODY's own comment on why those stayed separate), there's
     no "isolate the blast radius" argument against merging these. One
     form, one route (update_schedule()), one atomic save: a bad value
     anywhere (an invalid time zone, say) leaves the whole schedule
     completely unchanged, never partially saved. -->
<form method="post" action="{{ url_for('update_schedule') }}">
<input type="hidden" name="schedule_id" value="{{ s.id }}">

<div class="card">
<h2>When</h2>
<div class="add-form" style="flex-wrap:wrap;">
""" + DAY_CHECKBOXES + """
  <input type="time" name="start_time" value="{{ s.start_time }}" required>
  <span class="hint" style="margin:0;">to</span>
  <input type="time" name="end_time" value="{{ s.end_time }}" required>
  <select name="time_zone">
    {% for tz in available_time_zones %}
    <option value="{{ tz }}" {{ 'selected' if tz == s.time_zone }}>{{ tz }}</option>
    {% endfor %}
  </select>
  <label><input type="checkbox" name="lockout_all" {{ 'checked' if s.lockout_all }}> Full lockout (no internet at all)</label>
  <label><input type="checkbox" name="is_mode" {{ 'checked' if s.is_mode }}> Mode schedule</label>
</div>
<p class="hint">An end time earlier than the start time runs past midnight into the next day.</p>
<p class="hint"><strong>Mode schedule</strong>: eligible to be manually forced on or off early from the <a href="{{ url_for('schedules') }}">Schedules</a> page's "Shift mode now".</p>
</div>

<div class="card">
<h2>Blocked for</h2>
""" + BLOCK_ACCESS_SELECTS + """
</div>

{% if not s.lockout_all %}
<div class="card">
<h2>Categories blocked during this window</h2>
<input type="hidden" name="categories_section_present" value="1">
<p class="hint">Ignored while "Full lockout" is checked above -- a full lockout blocks everything, categories included.</p>
<p class="hint">Every category is listed below -- check the ones to block while this schedule is active, uncheck the rest. Categories are a short, fixed list you set up once (unlike kids/groups/devices, which can grow large), so this shows everything at a glance instead of a search-to-find picker.</p>
  {% if all_categories %}
  <div style="display:flex; flex-wrap:wrap; gap:.4rem 1.4rem; margin:.5rem 0;">
  {% for cat in all_categories %}
    <label><input type="checkbox" name="category_ids" value="{{ cat.id }}" {{ 'checked' if cat.id in preselected_category_ids }}> {{ cat.name }}</label>
  {% endfor %}
  </div>
  {% else %}
  <p class="hint">No categories yet -- add one from the <a href="{{ url_for('categories') }}">Categories</a> page first.</p>
  {% endif %}
</div>
{% endif %}

<div class="card">
<button class="add" type="submit" style="font-size:1.05em; padding:.6rem 1.6rem;">Save schedule</button>
</div>
</form>
"""


@app.route("/schedules/<int:schedule_id>")
@require_admin
def schedule_detail(schedule_id: int):
    conn = get_db()
    s = conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    if s is None:
        return flash_redirect("schedules", "That schedule no longer exists.", error=True)
    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    all_devices = conn.execute("SELECT * FROM devices ORDER BY COALESCE(label, mac_address)").fetchall()
    all_categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    body = render_template_string(
        SCHEDULE_DETAIL_BODY, s=s,
        day_codes=_DAY_CODES, day_labels=_DAY_LABELS,
        selected_days=set(s["days_of_week"].split(",")),
        available_time_zones=sorted(zoneinfo.available_timezones()),
        all_users_combo=_entity_combo(all_users, lambda u: u["display_name"]),
        all_groups_combo=_entity_combo(all_groups, lambda g: g["name"]),
        all_devices_combo=_entity_combo(all_devices, lambda dev: dev["label"] or dev["mac_address"]),
        all_categories=all_categories,
        preselected_user_ids={
            row["user_id"] for row in conn.execute(
                "SELECT user_id FROM schedule_users WHERE schedule_id = ?", (schedule_id,)
            )
        },
        preselected_group_ids={
            row["group_id"] for row in conn.execute(
                "SELECT group_id FROM schedule_groups WHERE schedule_id = ?", (schedule_id,)
            )
        },
        preselected_device_ids={
            row["device_id"] for row in conn.execute(
                "SELECT device_id FROM schedule_devices WHERE schedule_id = ?", (schedule_id,)
            )
        },
        preselected_category_ids={
            row["category_id"] for row in conn.execute(
                "SELECT category_id FROM schedule_categories WHERE schedule_id = ?", (schedule_id,)
            )
        },
        is_global_checked=bool(s["is_global"]),
    )
    return render("schedules", body)


@app.route("/schedules/update", methods=["POST"])
@require_admin
def update_schedule():
    """Single merged Save for the Schedule detail page (RoadMap.md item
    3, "one Save button per settings-shaped page, not several"). Used
    to be three independent forms/routes -- this one for the time
    window, a separate update_schedule_access() for who it applies to,
    a separate update_schedule_categories() for which categories it
    blocks -- saved one at a time. Merged into one atomic save: a bad
    value anywhere (an invalid time zone, say) leaves the WHOLE
    schedule unchanged, never partially saved. All three areas describe
    one schedule, unlike Settings' many genuinely-unrelated topics (see
    SETTINGS_BODY's own comment on why those stayed separate) -- no
    "isolate the blast radius" argument applies here.

    categories_section_present distinguishes "the categories checkbox
    list was on the page and got submitted with nothing checked" from
    "the categories section wasn't even rendered" (SCHEDULE_DETAIL_BODY
    hides it entirely while lockout_all is checked) -- without that
    guard, saving a lockout_all schedule would silently wipe out
    whatever categories were previously configured, only discovered
    once lockout was turned back off again."""
    schedule_id = request.form.get("schedule_id", "")
    days = _parse_days(request.form.getlist("days"))
    start_time = request.form.get("start_time", "")
    end_time = request.form.get("end_time", "")
    time_zone = request.form.get("time_zone", "UTC")
    lockout_all = 1 if request.form.get("lockout_all") else 0
    is_mode = 1 if request.form.get("is_mode") else 0
    is_global = 1 if request.form.get("is_global") else 0
    user_ids = {int(x) for x in request.form.getlist("user_ids") if x.isdigit()}
    group_ids = {int(x) for x in request.form.getlist("group_ids") if x.isdigit()}
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}
    categories_section_present = bool(request.form.get("categories_section_present"))
    category_ids = {int(x) for x in request.form.getlist("category_ids") if x.isdigit()}

    if not days:
        return flash_redirect("schedule_detail", "Pick at least one day.", error=True, schedule_id=schedule_id)
    if not (_valid_time(start_time) and _valid_time(end_time)):
        return flash_redirect("schedule_detail", "Start and end time are required.", error=True, schedule_id=schedule_id)
    if time_zone not in zoneinfo.available_timezones():
        return flash_redirect("schedule_detail", "That doesn't look like a real time zone.", error=True, schedule_id=schedule_id)

    conn = get_db()
    conn.execute(
        "UPDATE schedules SET days_of_week = ?, start_time = ?, end_time = ?, time_zone = ?, "
        "lockout_all = ?, is_mode = ?, is_global = ? WHERE id = ?",
        (days, start_time, end_time, time_zone, lockout_all, is_mode, is_global, schedule_id),
    )
    conn.execute("DELETE FROM schedule_users WHERE schedule_id = ?", (schedule_id,))
    for uid in user_ids:
        conn.execute("INSERT OR IGNORE INTO schedule_users (schedule_id, user_id) VALUES (?,?)", (schedule_id, uid))
    conn.execute("DELETE FROM schedule_groups WHERE schedule_id = ?", (schedule_id,))
    for gid in group_ids:
        conn.execute("INSERT OR IGNORE INTO schedule_groups (schedule_id, group_id) VALUES (?,?)", (schedule_id, gid))
    conn.execute("DELETE FROM schedule_devices WHERE schedule_id = ?", (schedule_id,))
    for did in device_ids:
        conn.execute("INSERT OR IGNORE INTO schedule_devices (schedule_id, device_id) VALUES (?,?)", (schedule_id, did))
    if categories_section_present:
        conn.execute("DELETE FROM schedule_categories WHERE schedule_id = ?", (schedule_id,))
        for cid in category_ids:
            conn.execute(
                "INSERT OR IGNORE INTO schedule_categories (schedule_id, category_id) VALUES (?,?)",
                (schedule_id, cid),
            )
    conn.commit()
    return flash_redirect("schedule_detail", "Saved.", schedule_id=schedule_id)


@app.route("/schedules/override", methods=["POST"])
@require_admin
def add_schedule_override():
    """Phase 12: 'Shift mode now' -- a one-off, time-boxed action that
    forces a specific is_mode schedule active for a single target
    (user/group/device) for a chosen duration, superseding every other
    is_mode schedule that would otherwise apply to that same target for
    the window. See common/schedule_eval.py's schedule_is_active_for_device()
    for the enforcement side; this route only ever writes one row to
    schedule_overrides. Deliberately not a saved/reusable preset -- see
    RoadMap.md's design discussion."""
    schedule_id = request.form.get("schedule_id", "")
    target = request.form.get("target", "")
    try:
        minutes = int(request.form.get("duration_minutes", ""))
    except ValueError:
        minutes = 0

    conn = get_db()
    schedule = conn.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    if schedule is None:
        return flash_redirect("schedules", "That schedule no longer exists.", error=True)
    if not schedule["is_mode"]:
        return flash_redirect(
            "schedules",
            f'"{schedule["name"]}" isn\'t a mode schedule -- check "Mode schedule" on it first.',
            error=True,
        )
    if minutes <= 0 or minutes > 1440:
        return flash_redirect("schedules", "Pick a duration between 1 minute and 24 hours.", error=True)

    user_id, group_id, device_id = _parse_override_target(target)
    if user_id is None and group_id is None and device_id is None:
        return flash_redirect("schedules", "Pick who this applies to.", error=True)

    if not _schedule_targets_selection(conn, schedule_id, user_id=user_id, group_id=group_id, device_id=device_id):
        return flash_redirect(
            "schedules",
            f'"{schedule["name"]}" isn\'t assigned to that kid/group/device yet -- '
            "assign it from the schedule's Manage page first.",
            error=True,
        )

    _clear_overrides_for_target(conn, user_id=user_id, group_id=group_id, device_id=device_id)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    conn.execute(
        "INSERT INTO schedule_overrides (schedule_id, user_id, group_id, device_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (schedule_id, user_id, group_id, device_id, db.now_iso(), expires_at),
    )
    conn.commit()
    return flash_redirect(
        "schedules", f'"{schedule["name"]}" forced active for {minutes} minute{"s" if minutes != 1 else ""}.'
    )


@app.route("/schedules/override/cancel", methods=["POST"])
@require_admin
def cancel_schedule_override():
    override_id = request.form.get("override_id", "")
    conn = get_db()
    conn.execute("DELETE FROM schedule_overrides WHERE id = ?", (override_id,))
    conn.commit()
    return flash_redirect("schedules", "Override cancelled -- normal schedule resumed.")


def _failed_login_attempts(conn, mac_address: str) -> dict | None:
    """How many times this MAC has failed the captive-portal kid login,
    and when most recently -- lets the pending-devices card distinguish
    "never tried" from "tried and got denied because nobody's assigned
    this device yet" (added 2026-09-07, real gap found by live user
    testing). Correlates via `system_events.detail`, which
    `captive_portal_server.py`'s `_log_failed_login()` now stores the
    attempting device's MAC into for the `captive_portal_login` source
    specifically (not the separate portal admin-bypass action -- a
    different kind of attempt). Returns None (not a zero count) when
    there's nothing to report, so the template can cleanly show "None
    yet" instead of a bare 0."""
    row = conn.execute(
        "SELECT COUNT(*) AS c, MAX(ts) AS last_ts FROM system_events "
        "WHERE source = 'captive_portal_login' AND detail = ?",
        (mac_address,),
    ).fetchone()
    if not row["c"]:
        return None
    return {"count": row["c"], "last_attempt": row["last_ts"]}


_DEVICE_LIST_SELECT = (
    "SELECT d.*, u.display_name, g.name AS group_name, COALESCE(g.ignored, 0) AS group_ignored, "
    # Fixed 2026-09-08 (real bug found live, RoadMap.md's dated entry):
    # this used to only check d.ignored, not the device's GROUP being in
    # Ignore mode -- a device made effectively-ignored only via group
    # membership (see the `effective_ignored` Jinja variable elsewhere on
    # this page, which already accounts for both) still read `pending`
    # here, so it kept showing up in "Devices awaiting login" and kept
    # its "Awaiting login" badge in the main table even though it was,
    # in every other respect, already treated as ignored.
    "(d.ignored = 0 AND COALESCE(g.ignored, 0) = 0 "
    " AND d.bypass_login = 0 AND d.is_authenticated = 0) AS pending, "
    # devices.last_seen_at is never actually populated by anything
    # (see common/db.py's own schema comment) -- device_bindings is
    # where a real network-observed last-seen/current-IP/source
    # actually lives, so the pending-devices card reads from there
    # instead, via the most-recently-updated binding for this MAC
    # (active or not -- a device that's gone stale is still worth
    # showing its last-known info for, not blanking out entirely).
    "(SELECT ipv4_address FROM device_bindings WHERE mac_address = d.mac_address "
    " ORDER BY last_seen_at DESC LIMIT 1) AS current_ip, "
    "(SELECT last_seen_at FROM device_bindings WHERE mac_address = d.mac_address "
    " ORDER BY last_seen_at DESC LIMIT 1) AS network_last_seen, "
    "(SELECT source FROM device_bindings WHERE mac_address = d.mac_address "
    " ORDER BY last_seen_at DESC LIMIT 1) AS binding_source "
    "FROM devices d "
    "LEFT JOIN users u ON u.id = d.user_id "
    "LEFT JOIN groups g ON g.id = d.group_id "
)


@app.route("/devices")
@require_admin
def devices():
    """Added 2026-09-07 (RoadMap.md's dated entry, project owner's
    explicit request, same reasoning as the Categories domain-list
    pagination the same day: "these can grow extensively with time"):
    the main device roster is paginated (page-size picker + Prev/Next),
    but the "Devices awaiting login" card above it deliberately is NOT --
    it needs every currently-pending device regardless of which page of
    the full roster is showing, so it's a genuinely separate,
    independent query rather than a Python filter over the (now only
    partial) paginated list the way it used to be."""
    conn = get_db()
    pending_devices = conn.execute(
        _DEVICE_LIST_SELECT + "WHERE d.ignored = 0 AND COALESCE(g.ignored, 0) = 0 "
        "AND d.bypass_login = 0 AND d.is_authenticated = 0 "
        # "Dismiss" (2026-09-08, project owner's explicit request):
        # pending_dismissed_at hides a device from this card ONLY until
        # something genuinely newer happens to it -- a fresh network
        # sighting, or a new captive-portal login attempt -- at which
        # point it reappears on its own. Nothing ever resets the column
        # back to NULL; this comparison is what makes a dismissal
        # self-expiring instead of permanent. Deliberately does NOT
        # affect the main roster's own `pending`/"Awaiting login" badge
        # above -- dismissal only declutters this summary card, it
        # doesn't change what the device's real state actually is.
        "AND (d.pending_dismissed_at IS NULL "
        "     OR EXISTS (SELECT 1 FROM device_bindings b WHERE b.mac_address = d.mac_address "
        "                AND b.last_seen_at > d.pending_dismissed_at) "
        "     OR EXISTS (SELECT 1 FROM system_events e WHERE e.source = 'captive_portal_login' "
        "                AND e.detail = d.mac_address AND e.ts > d.pending_dismissed_at)) "
        "ORDER BY d.created_at DESC"
    ).fetchall()
    # Added 2026-09-08 (RoadMap.md's dated entry, follow-up to the
    # 2026-09-07 pagination work, project owner's explicit request): now
    # that the main roster only renders one page at a time, the old
    # client-side search box would have silently only searched whatever
    # page happened to be on screen -- so search moved server-side, as a
    # SQL WHERE applied before the LIMIT/OFFSET (this page already
    # queries via SQL, unlike Domains' Python-list-slicing). Deliberately
    # does NOT filter pending_devices above -- that card is intentionally
    # every pending device regardless of what's searched for below.
    search = (request.args.get("q") or "").strip()
    where_sql = ""
    where_params: list = []
    if search:
        like = f"%{search}%"
        where_sql = "WHERE (d.mac_address LIKE ? OR d.label LIKE ? OR u.display_name LIKE ? OR g.name LIKE ?) "
        where_params = [like, like, like, like]
    device_count = conn.execute(
        "SELECT COUNT(*) AS c FROM devices d "
        "LEFT JOIN users u ON u.id = d.user_id LEFT JOIN groups g ON g.id = d.group_id " + where_sql,
        where_params,
    ).fetchone()["c"]
    page, per_page = _parse_pagination(request.args, default_per_page=DEFAULT_LIST_PAGE_SIZE, options=LIST_PAGE_SIZE_OPTIONS)
    total_pages = max(1, math.ceil(device_count / per_page))
    page = min(page, total_pages)
    rows = conn.execute(
        _DEVICE_LIST_SELECT + where_sql + "ORDER BY pending DESC, d.created_at DESC LIMIT ? OFFSET ?",
        where_params + [per_page, (page - 1) * per_page],
    ).fetchall()
    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    pending_login_attempts = {
        row["mac_address"]: _failed_login_attempts(conn, row["mac_address"])
        for row in pending_devices
    }
    any_devices_exist = bool(conn.execute("SELECT EXISTS(SELECT 1 FROM devices) AS c").fetchone()["c"])
    search_query_args = {"q": search} if search else {}
    return render(
        "devices",
        render_template_string(
            DEVICES_BODY, devices=rows, pending_devices=pending_devices, groups=all_groups,
            assignment_combo=_assignment_combo(all_users, all_groups), current="",
            pending_login_attempts=pending_login_attempts,
            device_count=device_count, page=page, per_page=per_page, total_pages=total_pages,
            page_size_options=LIST_PAGE_SIZE_OPTIONS,
            range_start=0 if device_count == 0 else (page - 1) * per_page + 1,
            range_end=min(page * per_page, device_count),
            search=search, any_devices_exist=any_devices_exist, search_query_args=search_query_args,
        ),
    )


@app.route("/devices/add", methods=["POST"])
@require_admin
def add_device():
    # Deliberately does NOT set is_authenticated -- it falls through to
    # the devices table's own schema default of 1 (fully authenticated,
    # zero captive-portal gate), unlike common/identity.py's
    # _create_pending_device() which explicitly sets 0 for an
    # auto-discovered MAC. This is NOT the same bug that path was fixed
    # for -- verified live 2026-09-02 and confirmed intentional: an
    # admin manually typing in a MAC IS the vouching act (the same way
    # "never seen this MAC before" is treated as NOT vouched-for and
    # gated), and it's the only way a browser-less device (a smart
    # plug, a thermostat -- anything that can never render the captive
    # portal's login page) can ever get online at all. Auto-discovered
    # = unknown = gated; admin-entered = known = trusted. Do not "fix"
    # this to match discovery's default without re-reading
    # docs/database/schema.md's `devices` section first -- doing so
    # would permanently lock out real household IoT devices.
    mac = normalize_mac(request.form.get("mac_address", ""))
    if mac is None:
        return flash_redirect(
            "devices", "Enter a valid MAC address, e.g. aa:bb:cc:dd:ee:ff.", error=True
        )
    label = request.form.get("label", "").strip() or None
    user_id, group_id, ignored = _parse_device_assignment(request.form.get("assignment", ""))
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO devices (mac_address, label, user_id, group_id, ignored, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (mac, label, user_id, group_id, ignored, db.now_iso()),
        )
        conn.commit()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return flash_redirect("devices", f"{mac} is already tracked.", error=True)
        raise
    return flash_redirect("devices", f"Added {mac}.")


@app.route("/devices/import", methods=["POST"])
@require_admin
def import_devices():
    """G7 follow-on (2026-09-01): a fresh setup starts with zero devices
    (the project owner's own decision -- see docs/deployment/setup.md),
    so this exists purely as a setup-time convenience for entering many
    already-known devices (e.g. exported from the router's client list)
    faster than one at a time, not to solve any gating/migration problem.

    Every imported row lands as a plain Unassigned device, same shape as
    add_device() above (no user/group/ignored) -- the actual "select the
    desired profile/group" step this was asked for is just the existing
    Devices list's per-row Manage link; deliberately not a second,
    parallel assignment UI duplicating what's already there.

    Also same as add_device() above: is_authenticated is never set here
    either, so it falls through to the schema default of 1 -- verified
    live 2026-09-02 that a bulk-imported device lands fully authenticated
    with zero captive-portal gate, and confirmed intentional, not a gap.
    This is the actual point of bulk import for a real household: a
    browser-less IoT device (a smart plug, a thermostat) can never
    render the captive portal's login page, so admin-imported = known/
    trusted = immediate access is the only way such a device can ever
    get online at all. See add_device()'s own comment and
    docs/database/schema.md's `devices` section before changing this.

    CSV format: one row per device, `mac_address,label` (label
    optional). A header row is auto-detected and skipped -- if the
    first row's first cell doesn't parse as a MAC (normalize_mac()),
    it's treated as a header rather than a data row. `INSERT OR IGNORE`
    on the mac_address UNIQUE constraint means an already-known MAC is
    silently skipped (not overwritten) rather than erroring out the
    whole batch or clobbering an existing assignment -- but "silently"
    only means the DATA isn't touched, not that the ADMIN isn't told:
    the flash message names which MACs were skipped as duplicates and
    which raw cells failed to parse as a MAC at all (`_preview_list()`,
    capped so a real 50+ device router export doesn't turn into an
    unreadable message), not just an aggregate count -- a plain "3
    already known" gives an admin nothing to actually act on.
    """
    file = request.files.get("csv_file")
    if not file or not file.filename:
        return flash_redirect("devices", "Choose a CSV file first.", error=True)
    try:
        content = file.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        return flash_redirect("devices", "Couldn't read that file as text -- is it really a CSV?", error=True)

    rows = [row for row in csv.reader(io.StringIO(content)) if row and any(cell.strip() for cell in row)]
    if not rows:
        return flash_redirect("devices", "That CSV had no rows.", error=True)

    # Known, low-blast-radius edge case: a genuinely malformed first DATA
    # row is indistinguishable from a real header by this heuristic alone
    # (both fail to parse as a MAC) -- such a row is silently dropped
    # WITHOUT being counted in invalid_cells below, unlike the same
    # malformed content anywhere else in the file. Capped at exactly one
    # row (only ever the first), not a systemic gap.
    start = 1 if normalize_mac(rows[0][0]) is None else 0

    conn = get_db()
    added = 0
    duplicate_macs = []
    invalid_cells = []
    now = db.now_iso()
    for row in rows[start:]:
        mac = normalize_mac(row[0]) if row else None
        if mac is None:
            invalid_cells.append(row[0] if row else "")
            continue
        label = row[1].strip() if len(row) > 1 and row[1].strip() else None
        cur = conn.execute(
            "INSERT OR IGNORE INTO devices (mac_address, label, created_at) VALUES (?, ?, ?)",
            (mac, label, now),
        )
        if cur.rowcount:
            added += 1
        else:
            duplicate_macs.append(mac)
    conn.commit()

    # Named, not just counted -- an aggregate "3 already known" gives an
    # admin nothing to act on for a real 20-50 device router export; they
    # need to know WHICH ones to go check. Capped so a genuinely huge CSV
    # doesn't blow out the flash message (rendered as a URL query param).
    parts = [f"Imported {added} device{'s' if added != 1 else ''}."]
    if duplicate_macs:
        parts.append(f"Already known ({_preview_list(duplicate_macs)}).")
    if invalid_cells:
        parts.append(f"No valid MAC address ({_preview_list(invalid_cells)}).")
    return flash_redirect("devices", " ".join(parts), error=(added == 0))


@app.route("/devices/bypass_login", methods=["POST"])
@require_admin
def bypass_login_device():
    """Quick-action from the devices list for a device awaiting login
    (Phase 4's admin-facing quick-add path, RoadMap.md): sets
    bypass_login=1 without touching label/bump_enabled -- unlike
    update_device()'s wholesale form submit, this only ever changes a
    couple fields, so it's safe to fire from a single button in the list
    row without re-submitting the device's other settings.

    **Also defaults `ignored=1` (2026-08-31, project owner's explicit
    direction)**: a device that will never log in (this button's whole
    purpose) commonly has no real user/group assignment either -- a smart
    TV, a thermostat -- so defaulting it straight to `ignored` (AdGuard's
    baseline-protection exemption, see common/policy_class.py's
    classify_device()) saves a second manual step. Deliberately only a
    DEFAULT: the `CASE` below skips it entirely if the device already has
    a real `user_id`/`group_id`, so this quick action never clobbers an
    existing assignment -- and since this only runs once, here, an admin
    who later assigns the device (or explicitly un-ignores it) via
    update_device() is never fought by this route re-asserting `ignored`
    on some later, unrelated save."""
    device_id = request.form.get("device_id", "")
    conn = get_db()
    conn.execute(
        "UPDATE devices SET bypass_login = 1, "
        "ignored = CASE WHEN user_id IS NULL AND group_id IS NULL THEN 1 ELSE ignored END "
        "WHERE id = ?",
        (device_id,),
    )
    conn.commit()
    return flash_redirect("devices", "Device will no longer be asked to log in.")


@app.route("/devices/dismiss_pending", methods=["POST"])
@require_admin
def dismiss_pending_device():
    """"Dismiss" on the "Devices awaiting login" card (2026-09-08,
    RoadMap.md's dated entry, project owner's explicit request):
    "I don't want it to do anything but clear the device showing as
    awaiting logon until it attempts to logon again." Deliberately NOT
    the same as Bypass above -- this is purely a display suppression
    (see the pending_devices query's own comment in devices() for
    exactly how the self-expiring comparison works), never touches
    ignored/bypass_login/is_authenticated, and grants no access at all.
    Harmless to call on a device that isn't actually pending (e.g. a
    stale request replayed after the device already logged in) --
    pending_dismissed_at is only ever read back for devices the pending
    filter already excludes for every other reason too."""
    device_id = request.form.get("device_id", "")
    conn = get_db()
    conn.execute("UPDATE devices SET pending_dismissed_at = ? WHERE id = ?", (db.now_iso(), device_id))
    conn.commit()
    return flash_redirect("devices", "Dismissed -- it'll reappear here on its own if it's active again.")


# G6: ad-hoc "pause the internet" -- Bark Home has one-tap pause per
# device/kid/whole-house; `devices.quarantined_at` + the QUARANTINE
# nftables set already existed for exactly this (Phase 3) with no
# dashboard control wired to it until now. All three variants below are
# plain writes to that one column -- `common/policy_class.py`'s
# `classify_device()` already treats a non-NULL `quarantined_at` as
# QUARANTINE (second-highest precedence, below only BYPASS/`ignored`),
# and `controller/policy_state.py` already computes it into the real
# nftables `quarantine_v4` set every cycle, live-verified 2026-09-01
# (RoadMap.md's Phase 8 entry) with real packet loss and real recovery.
# No new enforcement code needed anywhere -- this is purely wiring an
# admin control onto plumbing that was already real.
#
# There is deliberately no separate "why was this paused" column: manual
# pause and a schedule-driven lockout both express through the exact
# same `quarantined_at`/QUARANTINE mechanism (matching the schedule
# overlay's own "two independent axes" design, which never writes this
# column itself -- see controller/policy_state.py). Resuming a device
# therefore always means "un-pause it," full stop, regardless of how
# many different actions might have paused it.
#
# An `ignored` device is a no-op to pause -- BYPASS outranks QUARANTINE
# in classify_device()'s own precedence, so setting `quarantined_at` on
# one would silently do nothing. The three routes below all exclude
# `ignored` devices from a bulk pause for this reason; the single-device
# route doesn't need to (the UI simply doesn't offer the button for one).
#
# Added 2026-09-07 alongside `groups.ignored` (db.py's own schema
# comment): a device sitting in an ignored GROUP is exactly as much of a
# pause no-op as one directly marked `ignored` itself, even though its
# own `devices.ignored` column may read 0 -- same BYPASS-outranks-
# QUARANTINE reasoning, just via the group axis instead of the device
# one. Every route below that spans more than one specific
# already-known group (pause_all_devices, bulk_pause_devices; NOT
# pause_user/pause_group -- a user-assigned device is never
# group-assigned at all per the user_id/group_id CHECK constraint, and
# pause_group already knows which single group it's acting on) ANDs
# this fragment in alongside the plain `ignored = 0` check.
_NOT_GROUP_IGNORED_SQL = "(group_id IS NULL OR group_id NOT IN (SELECT id FROM groups WHERE ignored = 1))"


def _set_quarantine(conn, where_sql: str, params: tuple, *, paused: bool) -> int:
    value = db.now_iso() if paused else None
    cur = conn.execute(f"UPDATE devices SET quarantined_at = ? WHERE {where_sql}", (value, *params))
    conn.commit()
    return cur.rowcount


@app.route("/devices/pause", methods=["POST"])
@require_admin
def pause_device():
    device_id = request.form.get("device_id", "")
    redirect_to = request.form.get("redirect_to", "devices")
    conn = get_db()
    _set_quarantine(conn, "id = ?", (device_id,), paused=True)
    if redirect_to == "device_detail":
        return flash_redirect("device_detail", "Paused.", device_id=device_id)
    return flash_redirect("devices", "Paused.")


@app.route("/devices/resume", methods=["POST"])
@require_admin
def resume_device():
    device_id = request.form.get("device_id", "")
    redirect_to = request.form.get("redirect_to", "devices")
    conn = get_db()
    _set_quarantine(conn, "id = ?", (device_id,), paused=False)
    if redirect_to == "device_detail":
        return flash_redirect("device_detail", "Resumed.", device_id=device_id)
    return flash_redirect("devices", "Resumed.")


@app.route("/devices/pause-all", methods=["POST"])
@require_admin
def pause_all_devices():
    conn = get_db()
    n = _set_quarantine(conn, f"ignored = 0 AND {_NOT_GROUP_IGNORED_SQL}", (), paused=True)
    return flash_redirect("devices", f"Paused the internet for {n} device{'s' if n != 1 else ''}.")


@app.route("/devices/resume-all", methods=["POST"])
@require_admin
def resume_all_devices():
    conn = get_db()
    n = _set_quarantine(conn, "quarantined_at IS NOT NULL", (), paused=False)
    return flash_redirect("devices", f"Resumed {n} device{'s' if n != 1 else ''}.")


@app.route("/users/pause", methods=["POST"])
@require_admin
def pause_user():
    user_id = request.form.get("user_id", "")
    conn = get_db()
    n = _set_quarantine(conn, "user_id = ? AND ignored = 0", (user_id,), paused=True)
    return flash_redirect(
        "user_detail", f"Paused the internet for {n} device{'s' if n != 1 else ''}.", user_id=user_id
    )


@app.route("/users/resume", methods=["POST"])
@require_admin
def resume_user():
    user_id = request.form.get("user_id", "")
    conn = get_db()
    n = _set_quarantine(conn, "user_id = ? AND quarantined_at IS NOT NULL", (user_id,), paused=False)
    return flash_redirect("user_detail", f"Resumed {n} device{'s' if n != 1 else ''}.", user_id=user_id)


@app.route("/groups/pause", methods=["POST"])
@require_admin
def pause_group():
    """Same shape as pause_user() above -- added 2026-09-06, closing a
    real gap: per-device and per-user pause both already existed, but a
    group had no pause control at all (no group_detail page even
    existed to put one on).

    Added 2026-09-07: if THIS group itself is in Ignore mode
    (`groups.ignored`), pausing it is a guaranteed no-op for every
    member device (BYPASS outranks QUARANTINE) -- skip the write
    entirely and say so, rather than reporting devices "paused" that
    are actually still unfiltered."""
    group_id = request.form.get("group_id", "")
    conn = get_db()
    group = conn.execute("SELECT ignored FROM groups WHERE id = ?", (group_id,)).fetchone()
    if group is not None and group["ignored"]:
        return flash_redirect(
            "group_detail", "This group is in Ignore mode -- pausing it would have no effect.",
            error=True, group_id=group_id,
        )
    n = _set_quarantine(conn, "group_id = ? AND ignored = 0", (group_id,), paused=True)
    return flash_redirect(
        "group_detail", f"Paused the internet for {n} device{'s' if n != 1 else ''}.", group_id=group_id
    )


@app.route("/groups/resume", methods=["POST"])
@require_admin
def resume_group():
    group_id = request.form.get("group_id", "")
    conn = get_db()
    n = _set_quarantine(conn, "group_id = ? AND quarantined_at IS NOT NULL", (group_id,), paused=False)
    return flash_redirect("group_detail", f"Resumed {n} device{'s' if n != 1 else ''}.", group_id=group_id)


DEVICE_DETAIL_BODY = """
<p><a href="{{ url_for('devices') }}">&larr; All devices</a></p>
<h1>{{ d.label or 'Unnamed device' }}</h1>
<table>
  <tr><th>MAC address</th><td><code>{{ d.mac_address }}</code></td></tr>
  <tr><th>Current IP</th><td>{{ d.current_ip or '&mdash;' }}</td></tr>
  <tr><th>Last seen</th><td>{{ d.network_last_seen or 'never' }}</td></tr>
  <tr><th>Seen via</th><td>{{ d.binding_source or '&mdash;' }}</td></tr>
</table>

{% if not d.ignored %}
<div class="card">
<h2>Pause the internet</h2>
{% if d.quarantined_at %}
<p class="hint">Paused since <strong>{{ d.quarantined_at }}</strong> -- no internet access at all, not just filtered sites.</p>
<form method="post" action="{{ url_for('resume_device') }}">
  <input type="hidden" name="device_id" value="{{ d.id }}">
  <input type="hidden" name="redirect_to" value="device_detail">
  <button class="btn" type="submit">Resume</button>
</form>
{% else %}
<p class="hint">Immediate, indefinite -- until you resume it. Same mechanism a bedtime schedule's full lockout uses, just triggered by hand.</p>
<form method="post" action="{{ url_for('pause_device') }}">
  <input type="hidden" name="device_id" value="{{ d.id }}">
  <input type="hidden" name="redirect_to" value="device_detail">
  <button class="danger" type="submit">Pause this device</button>
</form>
{% endif %}
</div>
{% endif %}

<div class="card">
<form class="add-form" method="post" action="{{ url_for('update_device') }}">
  <input type="hidden" name="device_id" value="{{ d.id }}">
  <input type="text" name="label" value="{{ d.label or '' }}" placeholder="Label, e.g. Alex's iPad">
""" + DEVICE_ASSIGNMENT_SELECT + """
  <label><input type="checkbox" name="bump_enabled" {{ 'checked' if d.bump_enabled }}
    onchange="if(this.checked && !confirm('Has the CA certificate already been installed on this device? Until it has, SSL-Bump will show it certificate warnings instead of working normally.')){this.checked=false;}"
    > SSL-Bump enabled</label>
  <label><input type="checkbox" name="bypass_login" {{ 'checked' if d.bypass_login }}> Bypass login</label>
  <button class="add" type="submit">Save</button>
</form>
<p class="hint">
  <strong>Ignore</strong> means this device is never touched at all -- stronger
  than "Unassigned" (a known device with no policy decided yet). <strong>SSL-Bump
  enabled</strong> marks this as one of the small, deliberately curated devices
  that will get full path/show-level rules on bump-mode domains -- everything
  else will fall back to whole-domain treatment once the DNS/interception tier
  exists. Checking it prompts a reminder to install the CA certificate (Users
  page download link) first -- an un-installed cert means this device sees a
  certificate warning instead of working normally, not a silent failure, but
  still worth avoiding. <strong>Bypass login</strong> is for a device that can
  never complete a login flow (a smart TV, Echo, thermostat) -- it's exempted
  from the captive-portal gate (`dashboard/captive_portal_server.py`, live as
  of 2026-08-31) and falls back to its assignment above instead of a personal
  login. Turning this on defaults the assignment above to <strong>Ignore</strong>
  too (skipped if you've already picked a user or group here) -- change it
  back to a real assignment any time afterward if this device should still
  get AdGuard's baseline content filtering despite never logging in.
  <strong>SSL-Bump enabled</strong> and the device's user/group
  assignment are now real, enforced settings once Phase 3's ARP-spoof +
  nftables + Squid-intercept stack (see RoadMap.md) is actually running --
  that stack is fully built and tested but has not yet been deployed against
  a real household network (Milestone 10, a deliberate, owner-only decision,
  is still pending).
</p>
</div>
"""


@app.route("/devices/<int:device_id>")
@require_admin
def device_detail(device_id: int):
    conn = get_db()
    # Same correlated-subquery pattern as devices()'s own list query --
    # devices.last_seen_at is never actually populated by anything (see
    # common/db.py's own schema comment), so IP/last-seen/discovery
    # source all come from device_bindings instead. Fixed 2026-09-07:
    # this page used to show only the bare MAC address, forcing anyone
    # troubleshooting a specific device back to the list page (Ctrl+F on
    # 50+ rows) just to find its current IP.
    d = conn.execute(
        "SELECT d.*, "
        "(SELECT ipv4_address FROM device_bindings WHERE mac_address = d.mac_address "
        " ORDER BY last_seen_at DESC LIMIT 1) AS current_ip, "
        "(SELECT last_seen_at FROM device_bindings WHERE mac_address = d.mac_address "
        " ORDER BY last_seen_at DESC LIMIT 1) AS network_last_seen, "
        "(SELECT source FROM device_bindings WHERE mac_address = d.mac_address "
        " ORDER BY last_seen_at DESC LIMIT 1) AS binding_source "
        "FROM devices d WHERE d.id = ?",
        (device_id,),
    ).fetchone()
    if d is None:
        return flash_redirect("devices", "That device no longer exists.", error=True)
    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    return render(
        "devices",
        render_template_string(
            DEVICE_DETAIL_BODY, d=d, assignment_combo=_assignment_combo(all_users, all_groups),
            current=_device_assignment_value(d),
        ),
    )


@app.route("/devices/update", methods=["POST"])
@require_admin
def update_device():
    device_id = request.form.get("device_id", "")
    label = request.form.get("label", "").strip() or None
    user_id, group_id, ignored = _parse_device_assignment(request.form.get("assignment", ""))
    bump_enabled = 1 if request.form.get("bump_enabled") else 0
    bypass_login = 1 if request.form.get("bypass_login") else 0
    conn = get_db()

    # Defaults bypass_login -> ignored (2026-08-31, project owner's
    # explicit direction) -- same reasoning as bypass_login_device()'s own
    # comment: a device that will never log in commonly has no meaningful
    # assignment either, so default it to `ignored` the moment bypass_login
    # is newly turned on. Deliberately narrow, so it only ever nudges a
    # genuine default rather than fighting an admin's explicit choice:
    #   - only fires on the actual 0->1 transition (checked against the
    #     row's CURRENT value, not just "is the checkbox ticked this
    #     time") -- once set, saving the form again with bypass_login
    #     already 1 never re-forces `ignored` back on, so the admin's own
    #     later "actually, un-ignore it" edit sticks.
    #   - skipped entirely if this same submission explicitly picked a
    #     user or group assignment -- an explicit assignment always wins
    #     over the default, never silently overridden.
    if bypass_login and not ignored and user_id is None and group_id is None:
        current = conn.execute("SELECT bypass_login FROM devices WHERE id = ?", (device_id,)).fetchone()
        if current is not None and not current["bypass_login"]:
            ignored = 1

    conn.execute(
        "UPDATE devices SET label = ?, user_id = ?, group_id = ?, ignored = ?, "
        "bump_enabled = ?, bypass_login = ? WHERE id = ?",
        (label, user_id, group_id, ignored, bump_enabled, bypass_login, device_id),
    )
    conn.commit()
    return flash_redirect("device_detail", "Saved.", device_id=device_id)


@app.route("/devices/delete", methods=["POST"])
@require_admin
def delete_device():
    device_id = request.form.get("device_id", "")
    conn = get_db()
    conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    return flash_redirect("devices", "Device removed.")


@app.route("/groups/add", methods=["POST"])
@require_admin
def add_group():
    name = request.form.get("name", "").strip()
    if not name:
        return flash_redirect("devices", "Group name is required.", error=True)
    if len(name) > 100:
        return flash_redirect("devices", "Group name too long (100 characters max).", error=True)
    conn = get_db()
    try:
        conn.execute("INSERT INTO groups (name, created_at) VALUES (?,?)", (name, db.now_iso()))
        conn.commit()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            return flash_redirect("devices", f"A group named {name!r} already exists.", error=True)
        raise
    return flash_redirect("devices", f"Added group {name}.")


@app.route("/groups/delete", methods=["POST"])
@require_admin
def delete_group():
    group_id = request.form.get("group_id", "")
    conn = get_db()
    conn.execute("DELETE FROM groups WHERE id = ?", (group_id,))
    conn.commit()
    return flash_redirect("devices", "Group removed.")


@app.route("/groups/ignored", methods=["POST"])
@require_admin
def update_group_ignored():
    """Group detail page's "Ignore mode" toggle -- added 2026-09-07,
    project owner's explicit request: "For Device groups, I need to be
    able to enable 'ignore mode' for specific device groups." Additive
    with each member device's own `ignored` bit, not a replacement for
    it (see db.py's schema comment on `groups.ignored`) -- a device
    keeps whatever its own flag says; this only adds a second way for
    the whole group to count as BYPASS at once, everywhere
    classify_device() (or one of the raw-SQL BYPASS filters that
    doesn't go through it) is consulted."""
    group_id = request.form.get("group_id", "")
    ignored = 1 if request.form.get("ignored") else 0
    conn = get_db()
    conn.execute("UPDATE groups SET ignored = ? WHERE id = ?", (ignored, group_id))
    conn.commit()
    return flash_redirect(
        "group_detail", "Ignore mode enabled for this group." if ignored else "Ignore mode disabled for this group.",
        group_id=group_id,
    )


GROUP_DETAIL_BODY = """
<p><a href="{{ url_for('devices') }}">&larr; All devices</a></p>
<h1>{{ g.name }}{% if g.ignored %} <span class="badge pending">Ignore mode</span>{% endif %}</h1>

<div class="card">
<h2>Ignore mode</h2>
<p class="hint">
  When on, every device in {{ g.name }} is treated as
  <strong>Ignore (never filtered)</strong> -- the same "outside the whole
  system, for good" state as a single device's own Ignore setting, just
  applied to the whole group at once. This is additive with each
  device's own setting, not a replacement for it: turning this back off
  doesn't un-ignore a device that was ALSO individually set to Ignore on
  its own Manage page.
</p>
<form class="inline" method="post" action="{{ url_for('update_group_ignored') }}">
  <input type="hidden" name="group_id" value="{{ g.id }}">
  <input type="hidden" name="ignored" value="{{ '' if g.ignored else '1' }}">
  {% if g.ignored %}
  <button class="btn" type="submit">Turn off Ignore mode</button>
  {% else %}
  <button class="danger" type="submit" onclick="return confirm('Ignore mode makes every device in {{ g.name }} invisible to all filtering. Continue?');">Turn on Ignore mode</button>
  {% endif %}
</form>
</div>

<div class="card">
<h2>Active right now</h2>
{% if active_schedules %}
<ul style="margin:.3rem 0 0; padding-left:1.2rem;">
{% for s in active_schedules %}
  <li>
    <strong>{{ s.name }}</strong>
    {% if s.lockout_all %}<span class="badge blocked">full lockout</span>{% else %}<span class="badge">category block</span>{% endif %}
    {% if s.is_mode %}<span class="badge" title="Eligible for &quot;Shift mode now&quot;">mode</span>{% endif %}
  </li>
{% endfor %}
</ul>
{% else %}
<p class="hint">Nothing active right now -- no schedule currently applies to {{ g.name }}.</p>
{% endif %}
<p class="hint">Computed live from <a href="{{ url_for('schedules') }}">Schedules</a> assigned to {{ g.name }} (directly, or Everyone) -- reflects any active "Shift mode now" override, not just the clock.</p>
</div>

<div class="card">
<h2>Pause the internet</h2>
{% if g.ignored %}
<p class="hint">{{ g.name }} is in Ignore mode -- its devices are never filtered in the first place, so pausing them would have no effect (BYPASS outranks a pause). Turn off Ignore mode above first if you want to pause this group.</p>
{% elif group_devices %}
<p class="hint">
  Pauses every device in {{ g.name }} at once ({{ group_devices|length }}
  device{{ 's' if group_devices|length != 1 else '' }}, {{ paused_device_count }} currently paused) --
  immediate and indefinite, until resumed. Manage an individual device's pause from the
  <a href="{{ url_for('devices') }}">Devices</a> page instead if you only want to pause one.
</p>
<form class="inline" method="post" action="{{ url_for('pause_group') }}" onsubmit="return confirm('Pause the internet for every device in {{ g.name }}?');">
  <input type="hidden" name="group_id" value="{{ g.id }}">
  <button class="danger" type="submit">Pause {{ g.name }}'s internet</button>
</form>
<form class="inline" method="post" action="{{ url_for('resume_group') }}">
  <input type="hidden" name="group_id" value="{{ g.id }}">
  <button class="btn" type="submit">Resume</button>
</form>
{% else %}
<p class="hint">No devices in {{ g.name }} yet -- assign one from the <a href="{{ url_for('devices') }}">Devices</a> page to pause it from here.</p>
{% endif %}
</div>

<div class="card">
<h2>Devices in this group ({{ group_devices|length }})</h2>
<div class="table-scroll">
<table>
  <tr><th>MAC address</th><th>Label</th><th>Status</th></tr>
  {% for d in group_devices %}
  <tr>
    <td><code>{{ d.mac_address }}</code></td>
    <td>{{ d.label or '' }}</td>
    <td>{% if d.quarantined_at %}<span class="badge blocked">Paused</span>{% else %}<span class="badge">Active</span>{% endif %}</td>
  </tr>
  {% else %}
  <tr><td colspan="3"><em>No devices assigned.</em></td></tr>
  {% endfor %}
</table>
</div>
<p class="hint">
  Add several at once below instead of opening each device individually --
  this moves every device picked here into {{ g.name }} (clearing any
  previous user assignment, same as picking this group from a single
  device's own assignment dropdown), without touching its label or any
  other setting.
</p>
<form class="add-form" method="post" action="{{ url_for('bulk_add_to_group') }}">
  <input type="hidden" name="group_id" value="{{ g.id }}">
  <div class="combobox" data-combobox data-mode="multi" data-field="device_ids" data-empty="No other devices to add.">
    <div class="combobox-tags" data-combobox-tags></div>
    <input type="search" class="combobox-input" data-combobox-input placeholder="Search devices&hellip;">
    <div class="combobox-results" data-combobox-results></div>
    <script type="application/json" data-combobox-items>{{ addable_devices_combo|tojson }}</script>
    <script type="application/json" data-combobox-selected>[]</script>
  </div>
  <button class="add" type="submit">Add to {{ g.name }}</button>
</form>
</div>

<div class="card">
<h2>Assigned sites ({{ domain_count }})</h2>
{% if domain_count %}
<div class="toolbar" style="justify-content:space-between;">
  <form method="get" action="{{ url_for('group_detail', group_id=g.id) }}" class="inline">
    <input type="hidden" name="page" value="1">
    <label class="hint" style="margin:0;">Show
      <select name="per_page" onchange="this.form.submit()">
        {% for opt in domains_page_size_options %}
        <option value="{{ opt }}" {{ 'selected' if opt == domains_per_page }}>{{ opt }}</option>
        {% endfor %}
      </select>
      per page &mdash; showing {{ domains_range_start }}-{{ domains_range_end }} of {{ domain_count }}
    </label>
  </form>
  {% if domains_total_pages > 1 %}
  <span>
    {% if domains_page > 1 %}<a class="btn small" href="{{ url_for('group_detail', group_id=g.id, page=domains_page-1, per_page=domains_per_page) }}">&larr; Prev</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
    <span class="hint">Page {{ domains_page }} of {{ domains_total_pages }}</span>
    {% if domains_page < domains_total_pages %}<a class="btn small" href="{{ url_for('group_detail', group_id=g.id, page=domains_page+1, per_page=domains_per_page) }}">Next &rarr;</a>
    {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
  </span>
  {% endif %}
</div>
{% endif %}
<div class="table-scroll">
<table>
  <tr><th>Domain</th><th>Mode</th></tr>
  {% for d in assigned_domains %}
  <tr><td><code>{{ d.pattern }}</code></td><td><span class="badge mode-{{ d.mode }}">{{ d.mode }}</span></td></tr>
  {% else %}
  <tr><td colspan="2"><em>No per-group sites assigned (still gets global sites, see below).</em></td></tr>
  {% endfor %}
</table>
</div>
{% if domains_total_pages > 1 %}
<div class="toolbar" style="justify-content:flex-end;">
  {% if domains_page > 1 %}<a class="btn small" href="{{ url_for('group_detail', group_id=g.id, page=domains_page-1, per_page=domains_per_page) }}">&larr; Prev</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">&larr; Prev</span>{% endif %}
  <span class="hint">Page {{ domains_page }} of {{ domains_total_pages }}</span>
  {% if domains_page < domains_total_pages %}<a class="btn small" href="{{ url_for('group_detail', group_id=g.id, page=domains_page+1, per_page=domains_per_page) }}">Next &rarr;</a>
  {% else %}<span class="btn small" style="opacity:.4; pointer-events:none;">Next &rarr;</span>{% endif %}
</div>
{% endif %}
<p class="hint">Manage assignment from the <a href="{{ url_for('domains', group_id=g.id) }}">Domains</a> page -- pick the site there and check this group.</p>
</div>

""" + GLOBAL_SITES_CARD


@app.route("/groups/<int:group_id>")
@require_admin
def group_detail(group_id: int):
    conn = get_db()
    g = conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if g is None:
        return flash_redirect("devices", "That group no longer exists.", error=True)
    # Paginated (added 2026-09-08, RoadMap.md's dated entry, natural
    # follow-up to user_detail()'s identical "Assigned sites" pagination
    # the day before -- same shape, same reasoning: a heavily-assigned
    # group's own site list only ever grows).
    domain_count = conn.execute(
        "SELECT COUNT(*) AS c FROM group_domains WHERE group_id = ?", (group_id,)
    ).fetchone()["c"]
    domains_page, domains_per_page = _parse_pagination(
        request.args, default_per_page=DEFAULT_LIST_PAGE_SIZE, options=LIST_PAGE_SIZE_OPTIONS,
    )
    domains_total_pages = max(1, math.ceil(domain_count / domains_per_page))
    domains_page = min(domains_page, domains_total_pages)
    assigned_domains = conn.execute(
        "SELECT d.pattern, d.mode FROM domains d "
        "JOIN group_domains gd ON gd.domain_id = d.id "
        "WHERE gd.group_id = ? ORDER BY d.pattern LIMIT ? OFFSET ?",
        (group_id, domains_per_page, (domains_page - 1) * domains_per_page),
    ).fetchall()
    # Same ignored-device exclusion as user_detail()'s user_devices query
    # -- an ignored device can't actually be paused (BYPASS outranks
    # QUARANTINE in classify_device()), so it shouldn't count here either.
    group_devices = conn.execute(
        "SELECT id, mac_address, label, quarantined_at FROM devices WHERE group_id = ? AND ignored = 0",
        (group_id,),
    ).fetchall()
    paused_device_count = sum(1 for row in group_devices if row["quarantined_at"])
    active_schedules = schedule_eval.active_schedules_for_target(
        conn, datetime.now(timezone.utc), group_id=group_id
    )
    # Excludes devices already in this group -- nothing useful about
    # re-picking one that's already here, and it keeps the list shorter
    # for a household with 50+ devices.
    addable_devices = conn.execute(
        "SELECT id, mac_address, label FROM devices WHERE group_id IS NULL OR group_id != ? "
        "ORDER BY label IS NULL, label, mac_address",
        (group_id,),
    ).fetchall()
    body = render_template_string(
        GROUP_DETAIL_BODY, g=g, assigned_domains=assigned_domains,
        group_devices=group_devices, paused_device_count=paused_device_count,
        active_schedules=active_schedules,
        addable_devices_combo=_entity_combo(addable_devices, lambda dev: dev["label"] or dev["mac_address"]),
        global_domains=_global_domains(conn),
        domain_count=domain_count, domains_page=domains_page, domains_per_page=domains_per_page,
        domains_total_pages=domains_total_pages, domains_page_size_options=LIST_PAGE_SIZE_OPTIONS,
        domains_range_start=0 if domain_count == 0 else (domains_page - 1) * domains_per_page + 1,
        domains_range_end=min(domains_page * domains_per_page, domain_count),
    )
    return render("devices", body)


def _batch_assign_devices_to_group(conn, device_ids: set[int], group_id) -> None:
    """Mirrors update_device()'s own "group:<id>" assignment exactly --
    user_id/group_id stay mutually exclusive (see
    _parse_device_assignment's own doc comment), and ignored is cleared
    since picking a real group is an explicit un-ignore, same as the
    single-device form already does. Label/bump_enabled/bypass_login
    deliberately untouched -- this only ever changes the assignment,
    nothing else about a device already set up. One explicit transaction
    for the whole batch (conn opens with isolation_level=None -- see
    common/db.py -- so an un-wrapped executemany here would autocommit
    per row, the same bug class common/category_fetch.py's own fix
    closed at a much larger scale), shared by bulk_add_to_group() and
    bulk_assign_devices_to_group() below."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.executemany(
            "UPDATE devices SET user_id = NULL, group_id = ?, ignored = 0 WHERE id = ?",
            [(group_id, device_id) for device_id in device_ids],
        )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.commit()


@app.route("/groups/add-devices", methods=["POST"])
@require_admin
def bulk_add_to_group():
    group_id = request.form.get("group_id", "")
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}
    conn = get_db()
    g = conn.execute("SELECT name FROM groups WHERE id = ?", (group_id,)).fetchone()
    if g is None:
        return flash_redirect("devices", "That group no longer exists.", error=True)
    if not device_ids:
        return flash_redirect("group_detail", "No devices selected.", error=True, group_id=group_id)
    _batch_assign_devices_to_group(conn, device_ids, group_id)
    return flash_redirect(
        "group_detail",
        f"Added {len(device_ids)} device{'s' if len(device_ids) != 1 else ''} to {g['name']}.",
        group_id=group_id,
    )


@app.route("/devices/bulk-assign-group", methods=["POST"])
@require_admin
def bulk_assign_devices_to_group():
    """Devices list's own bulk-actions panel -- real live-testing
    feedback (RoadMap.md's dated entry): the devices table was "getting
    really clunky" and needed real bulk actions (assign several devices
    to a group, or delete several at once) instead of one-row-at-a-time.
    Same _batch_assign_devices_to_group() as bulk_add_to_group() above,
    just redirecting back to `devices` (not `group_detail`) -- picked
    from the full device list, not a specific group's own page, so
    staying there to keep working the list makes more sense than being
    bounced to whichever group was just picked. Supersedes the previous
    per-row quick-add-to-group select (2026-09-07 same day) -- that
    row-level form added exactly the clutter this was meant to fix; the
    bulk bar below the table handles both the one-device and many-device
    case with a single control."""
    group_id = request.form.get("group_id", "")
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}
    if not group_id:
        return flash_redirect("devices", "Pick a group first.", error=True)
    conn = get_db()
    g = conn.execute("SELECT name FROM groups WHERE id = ?", (group_id,)).fetchone()
    if g is None:
        return flash_redirect("devices", "That group no longer exists.", error=True)
    if not device_ids:
        return flash_redirect("devices", "No devices selected.", error=True)
    _batch_assign_devices_to_group(conn, device_ids, group_id)
    return flash_redirect(
        "devices", f"Added {len(device_ids)} device{'s' if len(device_ids) != 1 else ''} to {g['name']}."
    )


@app.route("/devices/bulk-ignore", methods=["POST"])
@require_admin
def bulk_set_ignored_devices():
    """Devices list's "Set to Ignore" / "Remove Ignore" bulk actions --
    added 2026-09-07, project owner's explicit request: "I need a bulk
    action that allows me to assign ignore to a selection of devices...
    The bulk add to group exists, but the bulk add to ignore does not."
    Same semantics as the single-device assignment combo
    (_parse_device_assignment("ignored")) and _batch_assign_devices_to_group()
    above (its mirror image): setting ignored=1 clears user_id/group_id
    too, since a real assignment and Ignore are mutually exclusive at
    the UI level even though the column itself is independent (see
    db.py's schema comment). Clearing it back to 0 leaves the device
    Unassigned rather than guessing at a previous assignment to
    restore -- same as picking any other option in that combo would."""
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}
    ignored = 1 if request.form.get("ignored") else 0
    if not device_ids:
        return flash_redirect("devices", "No devices selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(device_ids))
    if ignored:
        conn.execute(
            f"UPDATE devices SET ignored = 1, user_id = NULL, group_id = NULL WHERE id IN ({placeholders})",
            tuple(device_ids),
        )
        message = f"Set {len(device_ids)} device{'s' if len(device_ids) != 1 else ''} to Ignore."
    else:
        conn.execute(f"UPDATE devices SET ignored = 0 WHERE id IN ({placeholders})", tuple(device_ids))
        message = f"Removed Ignore from {len(device_ids)} device{'s' if len(device_ids) != 1 else ''}."
    conn.commit()
    return flash_redirect("devices", message)


@app.route("/devices/bulk-pause", methods=["POST"])
@require_admin
def bulk_pause_devices():
    """Devices list's toolbar "Disable" button (RoadMap.md's dated
    entry, referencing Microsoft Entra's own admin console) -- pauses
    exactly the checked devices' internet access, same `_set_quarantine()`
    mechanism as the whole-house/per-user/per-group pause buttons
    elsewhere, just scoped to an explicit `IN (...)` id list. Excludes
    `ignored` devices from the count/effect, same reasoning as every
    other bulk-pause route (`BYPASS` outranks `QUARANTINE`, so pausing
    one would silently do nothing)."""
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}
    if not device_ids:
        return flash_redirect("devices", "No devices selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(device_ids))
    n = _set_quarantine(
        conn, f"id IN ({placeholders}) AND ignored = 0 AND {_NOT_GROUP_IGNORED_SQL}", tuple(device_ids), paused=True,
    )
    return flash_redirect("devices", f"Paused {n} device{'s' if n != 1 else ''}.")


@app.route("/devices/bulk-resume", methods=["POST"])
@require_admin
def bulk_resume_devices():
    """Devices list's toolbar "Enable" button -- the resume counterpart
    to bulk_pause_devices() above."""
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}
    if not device_ids:
        return flash_redirect("devices", "No devices selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(device_ids))
    n = _set_quarantine(conn, f"id IN ({placeholders}) AND quarantined_at IS NOT NULL", tuple(device_ids), paused=False)
    return flash_redirect("devices", f"Resumed {n} device{'s' if n != 1 else ''}.")


@app.route("/devices/export", methods=["GET"])
@require_admin
def export_devices_csv():
    """Devices list's toolbar "Download devices" button (same live-
    testing feedback as the bulk actions above) -- a plain CSV of every
    device, not gated by checkbox selection (this is a whole-list export,
    same "always available regardless of selection" role Microsoft
    Entra's own reference screenshot shows for its equivalent button,
    unlike Enable/Disable/Delete/Manage which need something checked).
    Richer than bulk-import's own `mac_address,label` format (that one's
    designed to be re-imported elsewhere; this one's for an admin's own
    record-keeping/audit, so it includes assignment/status/flags too)."""
    conn = get_db()
    rows = conn.execute(
        "SELECT d.*, u.display_name, g.name AS group_name FROM devices d "
        "LEFT JOIN users u ON u.id = d.user_id LEFT JOIN groups g ON g.id = d.group_id "
        "ORDER BY d.mac_address"
    ).fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "MAC address", "Label", "Assigned to", "Ignored", "SSL-Bump", "Bypass login", "Paused", "Last seen",
    ])
    for d in rows:
        if d["ignored"]:
            assigned = "Ignored"
        else:
            assigned = d["display_name"] or d["group_name"] or ""
        writer.writerow([
            d["mac_address"], d["label"] or "", assigned,
            "yes" if d["ignored"] else "no", "yes" if d["bump_enabled"] else "no",
            "yes" if d["bypass_login"] else "no", "yes" if d["quarantined_at"] else "no",
            d["last_seen_at"] or "",
        ])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=devices.csv"},
    )


@app.route("/devices/bulk-delete", methods=["POST"])
@require_admin
def bulk_delete_devices():
    """Devices list's bulk-delete -- see bulk_assign_devices_to_group()'s
    own docstring for the same live-testing feedback this answers.
    Plain `DELETE ... WHERE id IN (...)` in one statement (not a Python
    loop) -- SQLite's own atomicity covers a single statement without
    needing an explicit BEGIN IMMEDIATE wrapper the way a multi-statement
    executemany loop does elsewhere in this file."""
    device_ids = {int(x) for x in request.form.getlist("device_ids") if x.isdigit()}
    if not device_ids:
        return flash_redirect("devices", "No devices selected.", error=True)
    conn = get_db()
    placeholders = ",".join("?" * len(device_ids))
    conn.execute(f"DELETE FROM devices WHERE id IN ({placeholders})", tuple(device_ids))
    conn.commit()
    return flash_redirect(
        "devices", f"Deleted {len(device_ids)} device{'s' if len(device_ids) != 1 else ''}."
    )


# ==========================================================
# REPORT
# ==========================================================

REPORT_BODY = """
{% if resolver_error %}
<div class="flash error">
  Crunchyroll metadata lookups are currently failing
  (<code>{{ resolver_error }}</code>). Shows already resolved keep working from
  cache; newly approved shows can't be verified until this clears. If it
  persists, the anonymous Crunchyroll client id in
  <code>common/cr_api.py</code> may need re-deriving.
</div>
{% endif %}

{% if pending_requests %}
<div class="card pending-card">
<h2>Pending approval requests ({{ pending_requests|length }})</h2>
<p class="hint">Someone tapped "Request approval" on a blocked page. These stay listed (regardless of the filter below) until you act on them.</p>
<div class="table-scroll">
<table>
  <tr><th>Requested (UTC)</th><th>Kid</th><th>Domain</th><th>Show / Path</th><th></th></tr>
  {% for row in pending_requests %}
  <tr>
    <td>{{ row.approval_requested_at }}</td>
    <td>{{ row.username }}</td>
    <td><code>{{ row.domain }}</code></td>
    <td>{{ row.series_name or row.series_id or row.path or '' }}</td>
    <td>
      {% if row.reason == 'path_not_allowed' %}
      <form class="inline" method="post" action="{{ url_for('approve_from_report') }}">
        <input type="hidden" name="log_id" value="{{ row.id }}">
        {% for k, v in redirect_kwargs.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
        <button class="add small" type="submit">Review path</button>
      </form>
      {% else %}
      <form class="inline" method="post" action="{{ url_for('approve_from_report') }}">
        <input type="hidden" name="log_id" value="{{ row.id }}">
        <input type="hidden" name="scope" value="user">
        {% for k, v in redirect_kwargs.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
        <button class="add small" type="submit">Approve</button>
      </form>
      <form class="inline" method="post" action="{{ url_for('approve_from_report') }}">
        <input type="hidden" name="log_id" value="{{ row.id }}">
        <input type="hidden" name="scope" value="global">
        {% for k, v in redirect_kwargs.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
        <button class="small" type="submit">Approve for everyone</button>
      </form>
      {% endif %}
      <form class="inline" method="post" action="{{ url_for('dismiss_request') }}">
        <input type="hidden" name="log_id" value="{{ row.id }}">
        {% for k, v in redirect_kwargs.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
        <button class="small" type="submit">Dismiss</button>
      </form>
    </td>
  </tr>
  {% endfor %}
</table>
</div>
</div>
{% endif %}

<div class="card">
<h2>Filter</h2>
<form class="add-form" method="get" action="{{ url_for('report') }}">
  <div class="combobox" data-combobox data-mode="single" data-initial="{{ report_target }}" style="max-width:280px;">
    <div class="combobox-current" data-combobox-current></div>
    <input type="search" class="combobox-input" data-combobox-input placeholder="All kids, groups, devices&hellip;">
    <div class="combobox-results" data-combobox-results></div>
    <input type="hidden" name="target" data-combobox-hidden value="{{ report_target }}">
    <script type="application/json" data-combobox-items>{{ report_filter_combo|tojson }}</script>
  </div>
  <select name="status">
    <option value="">All</option>
    <option value="blocked" {{ 'selected' if filter_status=='blocked' }}>Blocked only</option>
    <option value="allowed" {{ 'selected' if filter_status=='allowed' }}>Allowed only</option>
  </select>
  <select name="days">
    {% for d in day_options %}
    <option value="{{ d }}" {{ 'selected' if days==d }}>Last {{ d }} day{{ 's' if d != 1 else '' }}</option>
    {% endfor %}
  </select>
  <button class="add" type="submit">Apply</button>
  {% if filters_active %}<a class="btn" href="{{ url_for('report') }}">Clear filters</a>{% endif %}
</form>
<p class="hint">Applies to everything below -- the totals, both graphs, and the activity table. Click Allowed or Blocked below to filter to just that.</p>
</div>

<div class="stat-strip">
  <div class="stat"><div class="stat-value">{{ total }}</div><div class="stat-label">Requests shown</div></div>
  <a class="stat-link {{ 'active' if filter_status=='allowed' }}" href="{{ url_for('report', target=report_target, status='allowed', days=days) }}">
    <div class="stat"><div class="stat-value">{{ allowed_total }}</div><div class="stat-label">Allowed</div></div>
  </a>
  <a class="stat-link {{ 'active' if filter_status=='blocked' }}" href="{{ url_for('report', target=report_target, status='blocked', days=days) }}">
    <div class="stat"><div class="stat-value">{{ blocked_total }}</div><div class="stat-label">Blocked</div></div>
  </a>
  <div class="stat"><div class="stat-value">{{ (blocked_pct ~ '%') if total else '--' }}</div><div class="stat-label">% blocked</div></div>
</div>

<div class="chart-grid">
  <div class="card">
    <h2>Activity, last {{ days }} day{{ 's' if days != 1 else '' }}</h2>
    <div class="chart-card">
      {% if total %}<canvas id="activity-chart"></canvas>{% else %}<div class="empty-note">No activity logged yet.</div>{% endif %}
    </div>
  </div>
  <div class="card">
    <h2>Top domains</h2>
    <div class="chart-card">
      {% if top_domains %}<canvas id="domains-chart"></canvas>{% else %}<div class="empty-note">No activity logged yet.</div>{% endif %}
    </div>
  </div>
</div>

<div class="card">
<h2>Recent activity</h2>
<p class="hint">
  "Device" shows the resolved device (label + MAC) when known; for a
  domain that was never assigned to a recognized device, it falls back
  to the raw source IP address instead -- use that to track down which
  physical device it was (check your router's client list) and decide
  whether to add it or leave it offline. IP capture currently only
  covers the DNS-tier block page; a device already going through the
  Squid proxy tier will show its resolved identity as before, or a bare
  dash for a very old row from before this was added.
</p>
<div class="table-scroll">
<table>
  <tr><th>Time (UTC)</th><th>User</th><th>Device</th><th>Domain</th><th>Show / Path</th><th>Result</th><th></th></tr>
  {% for row in rows %}
  <tr>
    <td>{{ row.ts }}</td>
    <td>{{ row.username }}</td>
    <td>
      {% if row.device_id %}
      <a href="{{ url_for('device_detail', device_id=row.device_id) }}">{{ row.device_label or row.device_mac or ('#' ~ row.device_id) }}</a>
      {% if row.device_mac %}<br><code class="hint" style="font-size:.8em;">{{ row.device_mac }}</code>{% endif %}
      {% elif row.ip_address %}
      <code>{{ row.ip_address }}</code>
      <br><a class="hint" style="font-size:.8em;" href="{{ url_for('devices') }}">Not a known device -- add it?</a>
      {% else %}&mdash;{% endif %}
    </td>
    <td><code>{{ row.domain }}</code></td>
    <td>{{ row.series_name or row.series_id or row.path or '' }}</td>
    <td>
      <span class="badge {{ 'allowed' if row.allowed else 'blocked' }}">{{ 'allowed' if row.allowed else 'blocked' }}</span>
      {% set label = reason_label(row.reason) %}
      {% if label %}<br><span class="hint" style="font-size:.8em;">{{ label }}</span>{% endif %}
    </td>
    <td>
      {% if not row.allowed and row.user_id %}
      <form class="inline" method="post" action="{{ url_for('approve_from_report') }}">
        <input type="hidden" name="log_id" value="{{ row.id }}">
        <input type="hidden" name="scope" value="user">
        {% for k, v in redirect_kwargs.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
        <button class="add small" type="submit">Approve for {{ row.username }}</button>
      </form>
      {% elif not row.allowed and row.device_id %}
      <form class="inline" method="post" action="{{ url_for('approve_from_report') }}">
        <input type="hidden" name="log_id" value="{{ row.id }}">
        <input type="hidden" name="scope" value="device">
        {% for k, v in redirect_kwargs.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
        <button class="add small" type="submit">Approve for {{ row.username }}</button>
      </form>
      {% endif %}
    </td>
  </tr>
  {% else %}
  <tr><td colspan="7"><em>No activity logged yet.</em></td></tr>
  {% endfor %}
</table>
</div>
</div>

{% if total %}
<script src="{{ url_for('static', filename='vendor/chart.umd.min.js') }}"></script>
<script>
(function () {
  var style = getComputedStyle(document.documentElement);
  var cGreen = style.getPropertyValue('--success').trim() || '#15803d';
  var cRed = style.getPropertyValue('--danger').trim() || '#b91c1c';
  var cBrand = style.getPropertyValue('--brand').trim() || '#2f6fed';
  var cMuted = style.getPropertyValue('--text-muted').trim() || '#64748b';
  var cGrid = style.getPropertyValue('--border').trim() || '#e2e8f0';

  Chart.defaults.color = cMuted;
  Chart.defaults.borderColor = cGrid;

  var activityEl = document.getElementById('activity-chart');
  if (activityEl) {
    new Chart(activityEl, {
      type: 'bar',
      data: {
        labels: {{ day_labels|tojson }},
        datasets: [
          { label: 'Allowed', data: {{ daily_allowed|tojson }}, backgroundColor: cGreen, stack: 's' },
          { label: 'Blocked', data: {{ daily_blocked|tojson }}, backgroundColor: cRed, stack: 's' }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { stacked: true },
          y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }
        },
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }

  var domainsEl = document.getElementById('domains-chart');
  if (domainsEl) {
    new Chart(domainsEl, {
      type: 'bar',
      data: {
        labels: {{ top_domain_labels|tojson }},
        datasets: [{ label: 'Requests', data: {{ top_domain_counts|tojson }}, backgroundColor: cBrand }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
        plugins: { legend: { display: false } }
      }
    });
  }
})();
</script>
{% endif %}
"""


REPORT_DAY_OPTIONS = (1, 7, 14, 30)
REPORT_DEFAULT_DAYS = 7


def _parse_report_days(value) -> int:
    try:
        days = int(value)
    except (TypeError, ValueError):
        return REPORT_DEFAULT_DAYS
    return days if days in REPORT_DAY_OPTIONS else REPORT_DEFAULT_DAYS


def _report_redirect_kwargs(source) -> dict:
    """Pulls the current target/status/days filter off `source`
    (request.args for the page itself, request.form for an action taken
    from it) so every approve/dismiss click redirects back to the same
    filtered view instead of silently resetting it to the defaults.
    `target` (the combined user/group/device combobox encoding) takes
    priority over the legacy `user` param, same as _get_report_filter."""
    kwargs = {}
    if source.get("target"):
        kwargs["target"] = source["target"]
    elif source.get("user"):
        kwargs["user"] = source["user"]
    if source.get("status"):
        kwargs["status"] = source["status"]
    if source.get("days"):
        kwargs["days"] = _parse_report_days(source.get("days"))
    return kwargs


# Fixed 2026-09-08, real gap found live (RoadMap.md's dated entry,
# project owner's own example: "speedtest.net was blocked on Matthews
# device but I need to know WHY"): access_log.reason was already
# populated with a specific, real value for essentially every ALLOW
# and DENY decision this project makes (authz_helper.py's decide() and
# _decide_crunchyroll(), block_page_server.py's DNS-tier denial log,
# common/matching.py's device_domain_reason()) -- the gap was never
# missing data, it was that the Report page's Activity table only ever
# rendered a bare "allowed"/"blocked" badge and never looked at
# row.reason at all. This is every reason code that actually gets
# logged anywhere in the codebase (grepped for `reason="` and
# `reason=reason`/ternaries across proxy/, dashboard/, common/) --
# keep this in sync if a new one is ever added; an unrecognized code
# falls back to showing the raw value verbatim (REPORT_BODY's own
# `or row.reason` fallback) rather than silently hiding it.
_ACCESS_LOG_REASON_LABELS = {
    # Allowed
    "global_domain": "globally allowed domain",
    "user_domain": "assigned directly to this user",
    "group_domain": "assigned to this device's group",
    "device_domain": "assigned directly to this device",
    "show_approved": "this show is approved",
    # Added 2026-09-08 alongside the SSL-Bump default-allow fix
    # (proxy/authz_helper.py, proxy/sni_helper.py): a domain with no
    # `domains` row at all is allowed by default, same as the DNS tier
    # already does for every other device -- not something a user/group
    # explicitly granted, so it gets its own label rather than reusing
    # one of the assignment-based ones above.
    "unconfigured_domain": "not configured anywhere -- allowed by default (not on any blocklist)",
    # Blocked
    "outside_lan": "request didn't come from the configured LAN range",
    # unknown_domain/not_bump_mode: kept for OLD rows logged before the
    # 2026-09-08 fix above -- neither is written anymore (an
    # unconfigured or splice-mode domain is now allowed by default
    # instead, see "unconfigured_domain"/"global_domain"/etc.), but
    # historical entries still carry these values.
    "unknown_domain": "not a domain configured anywhere in this system (pre-2026-09-08 entry)",
    "not_bump_mode": "domain wasn't in bump mode (pre-2026-09-08 entry)",
    "domain_not_assigned": "domain exists, but isn't assigned to this user/group/device",
    "show_requires_user": "Crunchyroll show rules need a real user, this device has none assigned",
    "path_not_allowed": "this specific path isn't in the allowed list for this domain",
    "blocked_shape": "Crunchyroll URL shape this project deliberately never allows",
    "resolution_failed": "couldn't resolve show/episode metadata to check it",
    "show_not_approved": "this specific show hasn't been approved for this user",
    "dns_tier_denied": "blocked at the DNS/category layer (AdGuard) before reaching the proxy",
}


def _reason_label(reason: str | None) -> str | None:
    if not reason:
        return None
    return _ACCESS_LOG_REASON_LABELS.get(reason, reason)


@app.route("/report")
@require_admin
def report():
    conn = get_db()
    filtered_user, filtered_group, filtered_device = _get_report_filter(conn, request.args)
    filter_status = request.args.get("status", "")
    days = _parse_report_days(request.args.get("days"))
    report_target = (
        f"user:{filtered_user['id']}" if filtered_user else
        f"group:{filtered_group['id']}" if filtered_group else
        f"device:{filtered_device['id']}" if filtered_device else ""
    )

    # The date range applies to literally everything below (stat strip, both
    # charts, and the activity table) -- one `where_sql` built once, reused
    # by every query, so there's no way for the charts and the table to
    # disagree about what date/kid/status window "the Report page" means.
    where_sql = "WHERE ts >= ?"
    params: list = [db.iso_secs_ago(days * 86400)]
    if filtered_user:
        where_sql += " AND username = ?"
        params.append(filtered_user["username"])
    elif filtered_group:
        # access_log has no group_id of its own -- resolve through the
        # device that made the request, same join direction devices.group_id
        # already establishes everywhere else in this app.
        where_sql += " AND device_id IN (SELECT id FROM devices WHERE group_id = ?)"
        params.append(filtered_group["id"])
    elif filtered_device:
        where_sql += " AND device_id = ?"
        params.append(filtered_device["id"])
    if filter_status == "blocked":
        where_sql += " AND allowed = 0"
    elif filter_status == "allowed":
        where_sql += " AND allowed = 1"

    # Real live-testing feedback (RoadMap.md's dated entry): a blocked row
    # for an unauthenticated device shows "(unauthenticated)" as its
    # "User" -- true, but useless for tracking down WHICH physical device
    # is having trouble without separately cross-referencing device_id
    # against the Devices page. access_log already carries device_id for
    # exactly this (see log_identity_fields()'s own docstring); this just
    # surfaces it. LEFT JOIN (not INNER) -- a device later deleted must
    # still show its historical rows, just without the MAC/label alongside.
    rows = conn.execute(
        f"SELECT access_log.*, devices.mac_address AS device_mac, devices.label AS device_label "
        f"FROM access_log LEFT JOIN devices ON devices.id = access_log.device_id {where_sql} "
        "ORDER BY access_log.id DESC LIMIT 200", params
    ).fetchall()

    # Chart/stat data reflects every matching row under the current filter,
    # not just the 200 most recent shown in the table below -- these are
    # separate aggregate queries, not derived from `rows`.
    status_counts = conn.execute(
        f"SELECT allowed, COUNT(*) c FROM access_log {where_sql} GROUP BY allowed", params
    ).fetchall()
    allowed_total = next((r["c"] for r in status_counts if r["allowed"]), 0)
    blocked_total = next((r["c"] for r in status_counts if not r["allowed"]), 0)
    total = allowed_total + blocked_total
    blocked_pct = round(blocked_total / total * 100) if total else 0

    top_domains = conn.execute(
        f"SELECT domain, COUNT(*) c FROM access_log {where_sql} GROUP BY domain ORDER BY c DESC LIMIT 8",
        params,
    ).fetchall()

    today = datetime.now(timezone.utc).date()
    chart_days = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]
    daily_rows = conn.execute(
        f"SELECT substr(ts,1,10) day, allowed, COUNT(*) c FROM access_log {where_sql} "
        "GROUP BY day, allowed ORDER BY day",
        params,
    ).fetchall()
    allowed_by_day = {r["day"]: r["c"] for r in daily_rows if r["allowed"]}
    blocked_by_day = {r["day"]: r["c"] for r in daily_rows if not r["allowed"]}

    # Independent of the user/status/days filter above -- this is a
    # persistent "needs attention" list, not part of the filtered activity
    # view, so it stays visible regardless of what window is being browsed.
    pending_requests = conn.execute(
        "SELECT * FROM access_log WHERE approval_requested_at IS NOT NULL "
        "ORDER BY approval_requested_at DESC"
    ).fetchall()

    all_users = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    all_groups = conn.execute("SELECT * FROM groups ORDER BY name").fetchall()
    all_devices = conn.execute("SELECT * FROM devices ORDER BY COALESCE(label, mac_address)").fetchall()
    body = render_template_string(
        REPORT_BODY, rows=rows, all_users=all_users, pending_requests=pending_requests,
        reason_label=_reason_label,
        report_target=report_target, report_filter_combo=_report_filter_combo(all_users, all_groups, all_devices),
        filter_status=filter_status, days=days, day_options=REPORT_DAY_OPTIONS,
        filters_active=bool(filtered_user or filtered_group or filtered_device or filter_status or days != REPORT_DEFAULT_DAYS),
        redirect_kwargs=_report_redirect_kwargs(request.args),
        resolver_error=db.get_setting(conn, "cr_resolver_last_error"),
        total=total, allowed_total=allowed_total, blocked_total=blocked_total, blocked_pct=blocked_pct,
        top_domains=top_domains,
        top_domain_labels=[r["domain"] for r in top_domains],
        top_domain_counts=[r["c"] for r in top_domains],
        day_labels=[d.strftime("%m/%d") for d in chart_days],
        daily_allowed=[allowed_by_day.get(d.isoformat(), 0) for d in chart_days],
        daily_blocked=[blocked_by_day.get(d.isoformat(), 0) for d in chart_days],
    )
    return render("report", body)


@app.route("/report/approve", methods=["POST"])
@require_admin
def approve_from_report():
    log_id = request.form.get("log_id", "")
    # "user" = the person who hit this (the default, and what the plain
    # Recent-activity table's inline button offers for a user-identified
    # row). "device"/"group" (added 2026-08-31, GH #9): the same button
    # for a device- or group-only row (no user_id at all -- see
    # common/matching.py's device_domain_reason()). "global" = approve for
    # everyone -- only offered from the pending-requests card, since
    # that's the one place a per-request choice makes sense to surface.
    scope = request.form.get("scope", "user")
    redirect_kwargs = _report_redirect_kwargs(request.form)
    conn = get_db()
    row = conn.execute("SELECT * FROM access_log WHERE id = ?", (log_id,)).fetchone()
    if row is None:
        return flash_redirect("report", "Couldn't find that log entry.", error=True, **redirect_kwargs)

    device = (
        conn.execute("SELECT * FROM devices WHERE id = ?", (row["device_id"],)).fetchone()
        if row["device_id"] else None
    )
    if scope == "user" and row["user_id"] is None:
        return flash_redirect("report", "This entry has no associated user.", error=True, **redirect_kwargs)
    if scope in ("device", "group") and device is None:
        return flash_redirect("report", "This entry has no associated device.", error=True, **redirect_kwargs)
    if scope == "group" and device is not None and device["group_id"] is None:
        return flash_redirect("report", "This device isn't in a group.", error=True, **redirect_kwargs)

    # Whatever happens below, the admin has now acted on this row -- clear
    # any outstanding "Request approval" flag so it drops off the pending
    # list. Harmless no-op if it was never set.
    conn.execute("UPDATE access_log SET approval_requested_at = NULL WHERE id = ?", (log_id,))
    conn.commit()

    if row["series_id"]:
        if scope in ("device", "group"):
            # user_shows is keyed by user_id only -- there's no group/
            # device-level show list (see authz_helper.decide()'s own
            # "show_requires_user" denial for the enforcement side of this
            # same constraint). Nothing sensible to grant here.
            return flash_redirect(
                "report", "Shows can only be approved for a specific kid or everyone, not a device or group.",
                error=True, **redirect_kwargs,
            )
        name = cr_api.series_title(row["series_id"]) or row["series_id"]
        if scope == "global":
            # user_shows has no is_global concept (unlike domains) -- "for
            # everyone" means literally granting every existing user.
            for user_row in conn.execute("SELECT id FROM users"):
                conn.execute(
                    "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?,?,?) "
                    "ON CONFLICT(user_id, series_id) DO UPDATE SET series_name = excluded.series_name",
                    (user_row["id"], row["series_id"], name),
                )
            conn.commit()
            return flash_redirect("report", f"Approved {name} for everyone.", **redirect_kwargs)
        conn.execute(
            "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?,?,?) "
            "ON CONFLICT(user_id, series_id) DO UPDATE SET series_name = excluded.series_name",
            (row["user_id"], row["series_id"], name),
        )
        conn.commit()
        return flash_redirect("report", f"Approved {name} for {row['username']}.", **redirect_kwargs)

    if row["reason"] == "path_not_allowed":
        # The domain is already assigned to this user -- that's *why* the
        # request reached the path check at all -- so INSERT OR IGNORE into
        # user_domains below would be a silent no-op and the identical
        # request would be denied again immediately (GH #6). A path pattern
        # governs future access, not a one-time yes/no, so send the admin
        # to review a derived starting pattern rather than auto-saving one.
        # Path rules are already domain-wide (see domain_paths' schema
        # comment), so there's no separate "for everyone" version of this.
        domain = matching.find_domain(conn, row["domain"])
        if domain is None:
            return flash_redirect("report", "Couldn't find that domain anymore.", error=True, **redirect_kwargs)
        return redirect(url_for(
            "domain_detail", domain_id=domain["id"], prefill_path=path_to_pattern(row["path"]),
        ))

    domain = matching.find_domain(conn, row["domain"])
    if domain is None:
        # Never seen this domain before (it wasn't blocked by an existing
        # rule -- it just wasn't configured at all). Create it rather than
        # dead-ending: splice mode (host-only, matches the default for any
        # new domain), scoped per `scope` -- global if approved for
        # everyone, otherwise just this user, the safest default for
        # something approved reactively from a block.
        pattern = re.escape(row["domain"])
        is_global = 1 if scope == "global" else 0
        conn.execute(
            "INSERT OR IGNORE INTO domains (pattern, mode, kind, is_global, note, created_at) "
            "VALUES (?, 'splice', 'generic', ?, 'Auto-added from report approval', ?)",
            (pattern, is_global, db.now_iso()),
        )
        domain = conn.execute("SELECT * FROM domains WHERE pattern = ?", (pattern,)).fetchone()
    if scope == "global":
        if not domain["is_global"]:
            conn.execute("UPDATE domains SET is_global = 1 WHERE id = ?", (domain["id"],))
        label = "everyone"
    elif scope == "device":
        conn.execute(
            "INSERT OR IGNORE INTO device_domains (device_id, domain_id) VALUES (?,?)",
            (device["id"], domain["id"]),
        )
        label = row["username"]  # already the device's own label/MAC, see log_identity_fields()
    elif scope == "group":
        conn.execute(
            "INSERT OR IGNORE INTO group_domains (group_id, domain_id) VALUES (?,?)",
            (device["group_id"], domain["id"]),
        )
        label = "this group"
    else:  # "user"
        conn.execute(
            "INSERT OR IGNORE INTO user_domains (user_id, domain_id) VALUES (?,?)",
            (row["user_id"], domain["id"]),
        )
        label = row["username"]
    conn.commit()
    return flash_redirect("report", f"Approved {row['domain']} for {label}.", **redirect_kwargs)


@app.route("/report/dismiss-request", methods=["POST"])
@require_admin
def dismiss_request():
    """Clears a pending 'Request approval' flag without granting anything --
    the site/show stays exactly as denied as it was before the request. This
    is the admin's "no" -- distinct from Approve, and distinct from doing
    nothing (which would leave it cluttering the pending list forever)."""
    log_id = request.form.get("log_id", "")
    redirect_kwargs = _report_redirect_kwargs(request.form)
    conn = get_db()
    conn.execute("UPDATE access_log SET approval_requested_at = NULL WHERE id = ?", (log_id,))
    conn.commit()
    return flash_redirect("report", "Dismissed.", **redirect_kwargs)


# ==========================================================
# SETTINGS
# ==========================================================

# ==========================================================
# HEALTH (interception_runtime -- see common/db.py's schema comment)
# ==========================================================

HEALTH_BODY = """
{% if not runtime_row %}
<div class="card">
<h2>Interception layer</h2>
<p class="hint">
  Not running. This dashboard's device-classification enforcement (ARP-based
  traffic redirection and nftables policy sets) is an optional layer on top
  of the proxy -- it's brought up with
  <code>docker compose --profile interception up -d</code> and is deliberately
  a separate opt-in, since it changes how traffic on the LAN is routed. If
  you meant to have it running, check <code>docker compose ps</code> for the
  <code>arp-worker</code>, <code>nftables-manager</code>, and
  <code>controller</code> containers.
</p>
</div>
{% else %}
<div class="card">
<h2>Device tracking &amp; blocking <span class="hint" style="font-weight:normal;">(controller &amp; arp-worker)</span></h2>
<p>
  <span class="badge {{ 'pending' if mode_stale else mode_badge_class }}">{{ 'stale' if mode_stale else runtime_row.mode }}</span>
  {% if runtime_row.last_healthy_at %}&mdash; last healthy {{ runtime_row.last_healthy_at }}{% endif %}
</p>
{% if runtime_row.mode == 'fail_open' %}
<p class="hint"><strong>Fail-open: devices are NOT being tracked or blocked right now.</strong> Reason: {{ runtime_row.fail_open_reason or 'unknown' }}. Traffic is passed through unrestricted rather than silently dropped -- see RoadMap.md's "Fail-open engineering" section for why this is the deliberate choice on this failure path.</p>
{% elif mode_stale %}
<p class="hint"><strong>Stale: last reported healthy over {{ stale_after_seconds }}s ago, but its status is still "{{ runtime_row.mode }}".</strong> A crashed or crash-looping controller can't self-report its own failure -- the reporting call lives in the same process that died -- so a status frozen well past its normal reconciliation interval is itself the signal something's wrong. Check <code>docker compose ps controller</code> and <code>docker compose logs controller</code>.</p>
{% elif not runtime_row.last_healthy_at %}
<p class="hint">Never reported healthy yet -- the controller container may still be starting, or hasn't completed a reconciliation cycle.</p>
{% else %}
<p class="hint">Applied ARP-worker generation: {{ runtime_row.applied_generation }}.</p>
{% endif %}
<p class="hint">
  {% if controller_up %}Currently running -- to turn it off, run on the host:{% else %}Currently off -- to turn it on, run on the host:{% endif %}
  <br><code>{{ controller_toggle_command }}</code>
</p>
</div>

<div class="card">
<h2>Traffic redirection <span class="hint" style="font-weight:normal;">(nftables-manager)</span></h2>
<p>
  <span class="badge {{ 'pending' if nft_mode_stale else nft_mode_badge_class }}">{{ 'stale' if nft_mode_stale else runtime_row.nft_mode }}</span>
  {% if runtime_row.nft_last_healthy_at %}&mdash; last healthy {{ runtime_row.nft_last_healthy_at }}{% endif %}
</p>
{% if runtime_row.nft_mode == 'fail_open' %}
<p class="hint"><strong>Fail-open: nftables policy sets are NOT being kept in sync right now.</strong> Reason: {{ runtime_row.nft_fail_reason or 'unknown' }}. Whatever sets were last applied stay in place; devices' access won't reflect changes made since.</p>
{% elif nft_mode_stale %}
<p class="hint"><strong>Stale: last reported healthy over {{ stale_after_seconds }}s ago, but its status is still "{{ runtime_row.nft_mode }}".</strong> Same reasoning as the controller card above -- a crashed nftables-manager can't self-report its own failure.</p>
{% elif not runtime_row.nft_last_healthy_at %}
<p class="hint">Never reported healthy yet -- the nftables-manager container may still be starting.</p>
{% endif %}
<p class="hint">
  {% if nft_up %}Currently running -- to turn it off, run on the host:{% else %}Currently off -- to turn it on, run on the host:{% endif %}
  <br><code>{{ nft_toggle_command }}</code>
</p>
</div>

<div class="card">
<h2>Auto-refresh</h2>
<p class="hint">This page doesn't poll live -- reload to see the latest status.</p>
</div>
{% endif %}
"""


# Both the controller's reconcile loop and nftables-manager's poll loop
# default to a 5s interval (controller/main.py's --poll-interval,
# phase3/nftables-manager's -poll-interval); 30s is 6x that -- generous
# enough to absorb normal jitter/startup without false-flagging, tight
# enough to surface a genuinely dead process well within one dashboard
# reload. See health_page()'s docstring-equivalent comment below for why
# staleness needs its own check at all (a dead process can't self-report).
HEALTH_STALE_AFTER_SECONDS = 30

# Badge classes reuse the report page's allowed/blocked/pending palette --
# green for healthy, red for fail-open, amber for repair-only (ARP side
# only; nft_mode has no repair_only state), gray for not-yet-started. Fully
# static, so it's a module-level constant (like HEALTH_STALE_AFTER_SECONDS
# above) rather than rebuilt inside health_page() on every request.
HEALTH_MODE_BADGE_CLASS = {
    "running": "allowed", "fail_open": "blocked",
    "repair_only": "pending", "stopped": "mode-trusted",
}


def _is_stale(last_healthy_at: str | None) -> bool:
    if not last_healthy_at:
        return False  # "never reported" has its own, separate message
    return last_healthy_at < db.iso_secs_ago(HEALTH_STALE_AFTER_SECONDS)


def _subsystem_stale(mode: str, last_healthy_at: str | None) -> bool:
    """True when this subsystem's last_healthy_at has gone stale -- but
    only when it isn't ALREADY reporting fail_open, which is its own,
    stronger, explicit signal with its own UI treatment (see
    HEALTH_BODY's fail_open branch vs. its stale branch). A crashed or
    crash-looping process can't write its own fail_open row: the
    reporting call lives in the same process that died, so `mode`/
    `nft_mode` stay frozen at whatever they were the moment it went
    down, with an ever-more-outdated last_healthy_at -- confirmed live
    2026-08-30 via a sustained OOM-kill test, see RoadMap.md's
    fault-campaign notes. Only wall-clock staleness on last_healthy_at
    itself can catch that; the mode column alone cannot, by
    construction."""
    return mode != "fail_open" and _is_stale(last_healthy_at)


def _subsystem_unhealthy(mode: str, last_healthy_at: str | None) -> bool:
    """True when this subsystem is either explicitly fail_open or stale
    -- the one predicate both the sidebar alarm badge (render(), below)
    and the health page itself (health_page()) need, expressed once
    instead of independently in two different shapes that could drift
    apart (found via code review 2026-08-30)."""
    return mode == "fail_open" or _subsystem_stale(mode, last_healthy_at)


def _subsystem_is_up(mode: str, stale: bool) -> bool:
    """Whether this subsystem's own container is (probably) actually
    running right now -- added 2026-09-07 for the Health page's "run
    this command" toggle (project owner's explicit request, in place of
    a riskier dashboard-driven start/stop control: granting the
    dashboard container Docker socket access to actually flip these
    containers itself was explicitly declined the same day -- see
    RoadMap.md's dated entry). `running`/`fail_open`/`repair_only` all
    mean the process is actively self-reporting, even if degraded --
    only an explicitly `stopped` mode (the schema default, never
    actually written by any real code path today, but a legitimate
    value per the CHECK constraint) or a stale (frozen -- presumably
    crashed) status count as "down" here. Callers must also treat a
    missing `runtime_row` entirely as down (this function assumes one
    exists)."""
    return mode in ("running", "fail_open", "repair_only") and not stale


def _get_runtime_row(conn):
    """The interception_runtime singleton row, in full -- shared by
    render() (which only needs a subset, for the sidebar alarm badge)
    and health_page() (which needs all of it), so the row is only ever
    queried once per request instead of twice against the same
    `singleton_id = 1` primary-key lookup (found via code review
    2026-08-30)."""
    return conn.execute(
        "SELECT mode, last_healthy_at, fail_open_reason, applied_generation, "
        "nft_mode, nft_last_healthy_at, nft_fail_reason "
        "FROM interception_runtime WHERE singleton_id = 1"
    ).fetchone()


EVENTS_BODY = """
<div class="card">
<h2>System events</h2>
<p class="hint">
  Real failures and recoveries from this box's own background sync/
  discovery loops (AdGuard sync, category subscription fetch, active ARP
  scan, device discovery, the controller&harr;arp-worker heartbeat) --
  added 2026-09-01 so there's somewhere to look besides
  <code>docker compose logs</code> when something's wrong. Deliberately
  NOT a firehose: a routine successful cycle is never logged here, only
  an actual failure (one row per occurrence, so consecutive timestamps
  show how long something's been broken), the specific moment it
  recovers, and (added 2026-09-09) a small number of genuinely rare,
  admin-relevant <strong>info</strong> events -- an admin's own manual
  action actually completing (e.g. the network discovery sweep's "Run
  now"), or a brand-new device being seen for the very first time.
  This is a smaller, more focused source than the Report page's own
  activity log, which is about kids' browsing, not this box's own
  operational health.
</p>
{% if events %}<input type="search" data-filter-table="eventsTable" placeholder="Search events&hellip;" style="margin-bottom:.6rem; width:100%; max-width:280px;">{% endif %}
<div class="table-scroll">
<table id="eventsTable">
  <tr><th>When</th><th>Source</th><th>Severity</th><th>Message</th></tr>
  {% for e in events %}
  <tr>
    <td>{{ e.ts }}</td>
    <td><code>{{ e.source }}</code></td>
    <td>
      <span class="badge {{ 'blocked' if e.severity == 'error' else 'pending' if e.severity == 'info' else 'allowed' }}">{{ e.severity }}</span>
    </td>
    <td>{{ e.message }}</td>
  </tr>
  {% else %}
  <tr><td colspan="4"><em>No events recorded yet -- nothing has failed since this table existed, or the interception layer isn't running (see <a href="{{ url_for('health_page') }}">Health</a>).</em></td></tr>
  {% endfor %}
</table>
</div>
{% if events|length >= event_limit %}
<p class="hint">Showing the most recent {{ event_limit }} events.</p>
{% endif %}
</div>
"""

EVENT_DISPLAY_LIMIT = 200


@app.route("/events")
@require_admin
def events_page():
    conn = get_db()
    events = conn.execute(
        "SELECT ts, source, severity, message FROM system_events ORDER BY id DESC LIMIT ?",
        (EVENT_DISPLAY_LIMIT,),
    ).fetchall()
    body = render_template_string(EVENTS_BODY, events=events, event_limit=EVENT_DISPLAY_LIMIT)
    return render("events", body)


@app.route("/health")
@require_admin
def health_page():
    runtime_row = _get_runtime_row(get_db())
    nft_mode_badge_class = mode_badge_class = "mode-trusted"
    mode_stale = nft_mode_stale = False
    controller_up = nft_up = False
    if runtime_row:
        mode_stale = _subsystem_stale(runtime_row["mode"], runtime_row["last_healthy_at"])
        nft_mode_stale = _subsystem_stale(runtime_row["nft_mode"], runtime_row["nft_last_healthy_at"])
        mode_badge_class = HEALTH_MODE_BADGE_CLASS.get(runtime_row["mode"], "mode-trusted")
        nft_mode_badge_class = HEALTH_MODE_BADGE_CLASS.get(runtime_row["nft_mode"], "mode-trusted")
        controller_up = _subsystem_is_up(runtime_row["mode"], mode_stale)
        nft_up = _subsystem_is_up(runtime_row["nft_mode"], nft_mode_stale)
    body = render_template_string(
        HEALTH_BODY, runtime_row=runtime_row,
        mode_badge_class=mode_badge_class, nft_mode_badge_class=nft_mode_badge_class,
        mode_stale=mode_stale, nft_mode_stale=nft_mode_stale,
        controller_up=controller_up, nft_up=nft_up,
        controller_toggle_command=(
            "docker compose stop controller arp-worker" if controller_up
            else "docker compose up -d controller arp-worker"
        ),
        nft_toggle_command=(
            "docker compose stop nftables-manager" if nft_up
            else "docker compose up -d nftables-manager"
        ),
        stale_after_seconds=HEALTH_STALE_AFTER_SECONDS,
    )
    return render("health", body)


SETTINGS_BODY = """
<!-- Redesigned 2026-09-09, project owner's explicit request ("fewer,
     more logical groupings... cohesive... not just bolt-on of separate
     items"): the 12 independent one-topic cards this page used to have
     (each its own border, each grown on incrementally over many
     sessions) are grouped into 5 named sections below -- one .card per
     section, containing one .settings-subsection per original topic.

     RoadMap.md item 3 ("one Save button per settings-shaped page, not
     several") went further the same day: every genuinely PERSISTED
     setting within Filtering & AdGuard, Network, and Household is now
     one merged form/one Save button per section (update_filtering_
     settings(), update_network_settings(), update_household_settings())
     -- a bad value anywhere in a section now blocks saving the whole
     section, atomically, rather than silently leaving the rest saved.
     Security and Devices & data each already had only one persisted-
     setting form to begin with, so nothing needed merging there.

     Deliberately NOT merged into that same submit anywhere: one-off
     ACTIONS with their own, different consequences from a persisted
     setting -- "check for filter updates now", "Run now" (the network
     sweep), CA cert regenerate/upload, backup restore, stale-device
     cleanup. Each stays its own separate button/form/route. Folding one
     of these into an unrelated field-save would mean clicking Save on a
     checkbox also silently re-triggers a live AdGuard check, restores a
     backup, or regenerates a certificate -- or the reverse, a
     genuinely destructive action hiding behind what looks like an
     ordinary settings save. -->


<div class="card">
<h2>Security</h2>

<div class="settings-subsection">
<h3>Dashboard admin login</h3>
<form class="add-form" method="post" action="{{ url_for('update_admin') }}">
  <input type="text" name="admin_username" value="{{ admin_username }}" placeholder="Admin username">
  <input type="password" name="admin_password" placeholder="New password (leave blank to keep current)">
  <button class="add" type="submit">Save</button>
</form>
</div>

<div class="settings-subsection">
<h3>SSL-Bump CA certificate</h3>
<p class="hint">Every device needs this certificate trusted to use bump-mode filtering (Crunchyroll, or any other domain switched to bump mode) -- same certificate for every device, no per-user certs.</p>
{% if ca_cert_info %}
<p class="hint"><strong>Current:</strong> {{ ca_cert_info.subject }}<br>Expires {{ ca_cert_info.expires }}<br><code style="font-size:.75em; word-break:break-all;">{{ ca_cert_info.fingerprint }}</code></p>
{% else %}
<p class="hint"><strong>Not generated yet</strong> -- start the proxy container first.</p>
{% endif %}
<a class="btn add" href="{{ url_for('ca_cert') }}">Download CA certificate</a>

<details style="margin-top:1rem;">
<summary>Regenerate (create a fresh self-signed CA)</summary>
<form class="add-form" method="post" action="{{ url_for('regenerate_ca_cert') }}"
      onsubmit="return confirm('This replaces the CA certificate every device currently trusts. Every device will need to re-trust the new one, and bump-mode sites will show certificate errors until they do -- the proxy container also needs a restart afterward. Continue?')">
  <input type="text" name="ca_org" placeholder="Org" value="OptiGate">
  <input type="text" name="ca_common_name" placeholder="Common name" value="OptiGate CA">
  <button class="danger" type="submit">Regenerate CA certificate</button>
</form>
</details>

<details style="margin-top:.6rem;">
<summary>Upload your own CA certificate</summary>
<p class="hint">Bring an existing CA cert+key pair instead of the auto-generated one -- must have CA:TRUE and keyCertSign, unencrypted key, and the two files must actually match.</p>
<form class="add-form" method="post" action="{{ url_for('upload_ca_cert') }}" enctype="multipart/form-data"
      onsubmit="return confirm('This replaces the CA certificate every device currently trusts. Every device will need to re-trust the new one, and bump-mode sites will show certificate errors until they do -- the proxy container also needs a restart afterward. Continue?')">
  <label>Certificate (PEM) <input type="file" name="ca_cert_file" accept=".pem,.crt,.cer" required></label>
  <label>Private key (PEM) <input type="file" name="ca_key_file" accept=".pem,.key" required></label>
  <button class="danger" type="submit">Upload and replace</button>
</form>
</details>
<p class="hint" style="margin-top:.6rem;"><strong>After either action:</strong> restart the proxy container (<code>docker compose restart proxy</code>) for Squid to actually use it -- cert=/key= is only read at Squid startup, not live like everything else in this dashboard.</p>
</div>
</div>

<div class="card">
<h2>Filtering &amp; AdGuard</h2>

<div class="settings-subsection">
<h3>Ad-block filter lists (AdGuard Home)</h3>
<p class="hint">
  AdGuard Home checks its subscribed filter lists (its own default list,
  plus the curated uBlockOrigin/uAssets lists added on first run) on its
  own schedule -- once a week by default
  (<code>ADGUARD_FILTERS_UPDATE_INTERVAL_HOURS</code> in <code>.env</code>).
  Use this to check right now instead of waiting.
</p>
<form method="post" action="{{ url_for('refresh_adguard_filters') }}">
  <button class="add" type="submit" {{ 'disabled' if not adguard_configured }}>Check for filter updates now</button>
</form>
{% if not adguard_configured %}
<p class="hint"><strong>Not configured yet</strong> -- set the dashboard's own admin login above (the "Security" section's "Dashboard admin login"); AdGuard's login is kept in sync with it automatically.</p>
{% endif %}
{% if adguard_ui_url %}
<p class="hint" style="margin-top:.6rem;">
  <a class="btn add" href="{{ adguard_ui_url }}" target="_blank" rel="noopener">Open AdGuard's own dashboard &rarr;</a><br>
  Full query log, blocked-domain stats, and charts this project doesn't duplicate. Tighter integration (pulling those numbers into this dashboard directly) is a planned future improvement, not built yet.
  <strong>Only reachable if <code>ADGUARD_WEB_BIND</code> in <code>.env</code> is set to something other than the default <code>127.0.0.1</code></strong> (same idea as this dashboard's own <code>DASHBOARD_BIND</code>) -- otherwise this link only works from the Beelink itself, not your browser.
  <strong>Logs in with the same username/password as this dashboard's own admin login</strong> (above) -- there's only one credential to remember now.
</p>
{% endif %}
</div>

<!-- Merged into one Save button 2026-09-09 (RoadMap.md item 3): AdGuard's
     connection address, SafeSearch/Restricted Mode, and the blocked-site
     experience used to be three independent forms/routes -- merged into
     one atomic save (see update_filtering_settings()). Deliberately does
     NOT include "Check for filter updates now" above -- that's a one-off
     action against AdGuard's live API right now, not a persisted setting,
     and folding an action into an unrelated field-save would mean
     clicking Save on a checkbox also silently re-triggers that check (or
     vice versa). -->
<form method="post" action="{{ url_for('update_filtering_settings') }}">

<div class="settings-subsection">
<h3>AdGuard connection address</h3>
<p class="hint">
  Only the address (host/port) is set here -- AdGuard's login itself is
  always the dashboard's own admin username/password (see "Security"
  above); changing that automatically writes the matching
  credential into AdGuard's own config too (a restart of the
  <code>adguard</code> container is needed for it to take effect --
  AdGuard only reads its config at startup, it has no live-reload).
</p>
<div class="add-form">
  <input type="text" name="adguard_url" value="{{ adguard_url }}" placeholder="http://127.0.0.1:3000" style="flex:1; min-width:280px;">
</div>
</div>

<div class="settings-subsection">
<h3>SafeSearch &amp; YouTube Restricted Mode</h3>
<p class="hint">
  Forces Google/Bing/DuckDuckGo/Ecosia/Yandex/Pixabay SafeSearch and
  YouTube Restricted Mode for every device on the network, via AdGuard
  Home's own built-in feature -- the same DNS-rewrite mechanism Bark
  Home uses, and just as network-wide (there's no per-kid/per-device
  version of this). Takes effect on the controller's next sync cycle,
  not instantly.
</p>
<label><input type="checkbox" name="safesearch_enabled" value="1" {{ 'checked' if safesearch_enabled }}> Force SafeSearch &amp; Restricted Mode</label>
{% if not adguard_configured %}
<p class="hint"><strong>Not configured yet</strong> -- set AdGuard's connection details above first.</p>
{% endif %}
</div>

<div class="settings-subsection">
<h3>Blocked-site experience</h3>
<select name="block_page_mode">
  <option value="terminate" {{ 'selected' if block_page_mode=='terminate' }}>Just fail the connection (default -- safe for devices that haven't installed the certificate yet)</option>
  <option value="redirect" {{ 'selected' if block_page_mode=='redirect' }}>Show a friendly page (requires the CA certificate already trusted on the device)</option>
</select>
<p class="hint">
  <strong>Only switch to "Show a friendly page" after confirming the CA certificate is installed and trusted on every device this applies to.</strong>
  Showing a page requires decrypting that connection with the proxy's own certificate -- exactly like Crunchyroll already does. If a device hasn't trusted that certificate yet, it'll see a security warning ("connection not private") instead of a clean block message, which is more alarming than the plain connection failure it replaces. A simple way to check: if Crunchyroll itself loads correctly on a device, that device's certificate trust is set up correctly and this mode will work fine for it too. This is one setting for every device on the network -- there's no per-device override.
</p>
<p class="hint">
  Bump-mode domains (Crunchyroll, or anything else you've set to bump mode) always show a page when blocked regardless of this setting, since they're already decrypted either way. This setting only affects splice-mode sites. To get an actual custom page here rather than Squid's generic one, also set <code>DASHBOARD_URL</code> in <code>.env</code> to this machine's address (e.g. <code>http://192.168.1.50:8787</code>) and restart the proxy container.
</p>
</div>

<div class="settings-subsection">
<button class="add" type="submit">Save</button>
</div>
</form>
</div>

<div class="card">
<h2>Network</h2>

<!-- Merged into one Save button 2026-09-09 (RoadMap.md item 3): the
     local-network CIDR and the discovery-sweep enable/interval used to
     be two independent forms/routes -- merged into one atomic save (see
     update_network_settings()). Deliberately does NOT include "Run
     now" below -- that's a one-off action (queues an immediate sweep
     right now), not a persisted setting; see run_network_sweep_now(). -->
<form method="post" action="{{ url_for('update_network_settings') }}">

<div class="settings-subsection">
<h3>Local network</h3>
<div class="add-form">
  <input type="text" name="local_network" value="{{ local_network }}" style="flex:1; min-width:280px;">
</div>
<p class="hint">Space-separated CIDRs, e.g. <code>192.168.1.0/24 192.168.0.0/24</code>. Requests from outside these ranges are denied regardless of user/site rules. <strong>Leave blank to disable this check</strong> and rely only on per-person proxy logins &mdash; do that if the proxy runs under Docker Desktop or bridge networking, where it sees an internal gateway address instead of the real client IP and this check would otherwise block everyone.</p>
</div>

<div class="settings-subsection">
<h3>Network discovery sweep</h3>
<p class="hint">
  Every other way this project notices a device is passive -- it only
  learns about one once that device happens to make some traffic this
  box's own network stack overhears on its own. A device that joins
  quietly and never triggers that can sit on the network invisibly,
  indefinitely, with none of your rules ever applying to it. This
  actively probes every address in the network range above on a
  schedule, forcing even a silent device to reveal itself so it gets
  picked up the same way any other device is.
</p>
<label><input type="checkbox" name="network_sweep_enabled" value="1" {{ 'checked' if network_sweep_enabled }}> Enabled</label>
<label>Every <input type="number" name="network_sweep_interval_minutes" value="{{ network_sweep_interval_minutes }}" min="1" style="width:5rem;"> minutes</label>
</div>

<div class="settings-subsection">
<button class="add" type="submit">Save</button>
</div>
</form>

<div class="settings-subsection">
<form class="inline" method="post" action="{{ url_for('run_network_sweep_now') }}">
  <button class="btn small" type="submit" {{ 'disabled' if not local_network }}>Run now</button>
</form>
<p class="hint">
  {% if not local_network %}
  <strong>Nothing to sweep</strong> -- the network range above is empty, so there's no address list to probe. Set it first.
  {% elif network_sweep_status.startswith('never') %}
  <span class="badge blocked">{{ network_sweep_status }}</span> -- runs once immediately whenever the controller (interception profile) is running, then on the interval above.
  {% else %}
  <span class="badge allowed">{{ network_sweep_status }}</span>
  {% endif %}
  This is a <code>controller</code>-side feature (same as the ARP worker and nftables-manager) -- it only runs at all while the <code>interception</code> profile is up.
  {% if interception_controller_is_up %}
  <span class="badge allowed">interception profile: running</span>
  {% else %}
  <span class="badge blocked">interception profile: not running</span> -- Save and Run now both still work, but nothing will act on them until it's started.
  {% endif %}
  <strong>Run now</strong> works even while the toggle above is off (a one-off check, not a schedule change).
</p>
</div>
</div>

<div class="card">
<h2>Household</h2>

<!-- Merged into one Save button 2026-09-09 (RoadMap.md item 3): the
     default time zone and the memorable troubleshooting hostname used
     to be two independent forms/routes -- merged into one atomic save
     (see update_household_settings()). The auto-detect script below
     posts to this same merged endpoint, supplying the current hostname
     prefix unchanged, so it behaves exactly like a normal Save rather
     than needing its own separate endpoint. -->
<form method="post" action="{{ url_for('update_household_settings') }}" id="householdSettingsForm">

<div class="settings-subsection">
<h3>Household time zone</h3>
<p class="hint">The default time zone new <a href="{{ url_for('schedules') }}">schedules</a> are created with. Each schedule stores its own time zone once created, so changing this later never moves an existing schedule's meaning.</p>
<div class="add-form">
  <select name="household_time_zone" id="householdTimeZoneSelect">
    {% for tz in available_time_zones %}
    <option value="{{ tz }}" {{ 'selected' if tz == household_time_zone }}>{{ tz }}</option>
    {% endfor %}
  </select>
</div>
<p class="hint" id="tzAutoDetectNote"></p>
{% if household_time_zone_unset %}
<script>
(function () {
  // Real live-testing feedback (RoadMap.md's dated entry): this never
  // had any real default before -- every fresh install silently started
  // at UTC until an admin happened to visit this page and pick their
  // own zone by hand out of a ~400-entry list. Runs only while
  // household_time_zone has never been explicitly saved (server-side
  // flag, household_time_zone_unset): detects the browser's own IANA
  // zone and, if it's one of the options this <select> actually offers,
  // both shows it selected AND saves it as the real default immediately
  // (a plain background POST to the same route the Save button uses,
  // including the hostname prefix's current value unchanged so this
  // background save doesn't touch that field) -- "default to wherever
  // the admin's own device is" only means something if it happens
  // before they'd otherwise have to pick UTC by hand first. Never fires
  // again once a real value is on record, including whatever this save
  // itself just set -- the admin's own later choice from the dropdown
  // always wins from here on.
  var detected;
  try { detected = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { return; }
  var select = document.getElementById("householdTimeZoneSelect");
  var note = document.getElementById("tzAutoDetectNote");
  if (!detected || !select) return;
  var matched = Array.prototype.some.call(select.options, function (o) { return o.value === detected; });
  if (!matched) return;
  select.value = detected;
  var body = new URLSearchParams();
  body.set("household_time_zone", detected);
  var prefixField = document.getElementById("optigateHostnamePrefixInput");
  body.set("optigate_hostname_prefix", prefixField ? prefixField.value : "");
  fetch(document.getElementById("householdSettingsForm").action, { method: "POST", body: body })
    .then(function () {
      if (note) note.textContent = "Detected your device's time zone (" + detected + ") and set it as the default.";
    })
    .catch(function () {});
})();
</script>
{% endif %}
</div>

<div class="settings-subsection">
<h3>Memorable troubleshooting address</h3>
<p class="hint">
  A device that's already connected to the WiFi but lost internet access
  (or just wants to self-check) can go to this address in a browser to
  see its own Label, User/Group, IP address, and MAC address -- point
  anyone who loses internet at it instead of walking them through
  finding those yourself. The <code>.home</code> suffix is fixed; only
  the first part is yours to change.
</p>
<div class="add-form">
  <input type="text" name="optigate_hostname_prefix" id="optigateHostnamePrefixInput" value="{{ optigate_hostname_prefix }}" style="max-width:12rem;">
  <span class="hint" style="margin:0;">.home</span>
</div>
<p class="hint">
  Currently <code>{{ optigate_hostname_prefix }}.home</code> --
  {% if optigate_rewrite_status.startswith('live') %}<span class="badge allowed">{{ optigate_rewrite_status }}</span>
  {% else %}<span class="badge blocked">{{ optigate_rewrite_status }}</span>{% endif %}
  <br>Visit it plain, with <strong>no port</strong> --
  <code>http://{{ optigate_hostname_prefix }}.home</code>, not
  <code>{{ optigate_hostname_prefix }}.home:8787</code> or any other port
  (that reaches this admin login instead, which is a real gap found live
  2026-09-08: nothing here previously said this, and the DASHBOARD_URL
  hint just below shows a port right next to this hostname, an easy mix-up).
</p>
<p class="hint">
  <strong>Requires <code>DASHBOARD_URL</code> set in <code>.env</code></strong> (this
  machine's own address, e.g. <code>http://192.168.1.50:8787</code> --
  <em>that port is for DASHBOARD_URL only, never for visiting the
  troubleshooting address above</em>) so AdGuard knows which IP to
  resolve this hostname to -- same requirement the "Blocked-site
  experience" section above already has. Pushed to AdGuard
  immediately when you click Save (and again automatically whenever
  this dashboard container starts) -- no need to wait on anything else.
</p>
</div>

<div class="settings-subsection">
<button class="add" type="submit">Save</button>
</div>
</form>
</div>

<div class="card">
<h2>Devices &amp; data</h2>

<div class="settings-subsection">
<h3>Bulk import devices</h3>
<p class="hint">
  A CSV of known devices -- one row per device, <code>MAC address,Device name</code>
  (a header row is fine and gets skipped automatically). Useful for a
  fresh setup: export your router's client list, or type one up by hand,
  rather than adding devices one at a time. Every row becomes a plain
  <strong>Unassigned</strong> device (same as adding one by hand) --
  nothing is auto-assigned to a kid or group. After importing, assign
  each one from the <a href="{{ url_for('devices') }}">Devices</a> page.
</p>
<form class="add-form" method="post" action="{{ url_for('import_devices') }}" enctype="multipart/form-data">
  <input type="file" name="csv_file" accept=".csv,text/csv" required>
  <button class="add" type="submit">Import</button>
</form>
</div>

<div class="settings-subsection">
<h3>Remove outdated devices</h3>
<p class="hint">
  Devices whose real last-seen time (from network observation -- ARP/DHCP
  discovery, active scans, or AdGuard's own query log; NOT the unused
  <code>devices.last_seen_at</code> column) is older than this many days
  can be reviewed below and cleaned up in one click. A device that's
  never been seen at all is left alone regardless of this setting --
  only a real, old timestamp counts, never "we don't know."
</p>
<form class="add-form" method="post" action="{{ url_for('update_device_stale_days') }}">
  <input type="number" name="device_stale_days" min="1" step="1" value="{{ device_stale_days or '' }}" placeholder="e.g. 90" style="width:6rem;">
  <span class="hint" style="margin:0;">days</span>
  <button class="add" type="submit">Save</button>
</form>
{% if device_stale_days %}
<p class="hint">
  <strong>{{ stale_devices|length }}</strong> device{{ 's' if stale_devices|length != 1 else '' }}
  currently not seen in over {{ device_stale_days }} day{{ 's' if device_stale_days != 1 else '' }}.
</p>
{% if stale_devices %}
<div class="table-scroll">
<table>
  <tr><th>MAC address</th><th>Label</th><th>Assigned to</th><th>Last seen</th><th></th></tr>
  {% for d in stale_devices %}
  <tr>
    <td><code>{{ d.mac_address }}</code></td>
    <td>{{ d.label or '' }}</td>
    <td>
      {% if d.ignored %}<span class="badge pending">Ignored</span>
      {% elif d.display_name %}{{ d.display_name }}
      {% elif d.group_name %}<span class="badge mode-trusted">{{ d.group_name }}</span>
      {% else %}<em>Unassigned</em>{% endif %}
    </td>
    <td>{{ d.network_last_seen }}</td>
    <td><a class="btn small" href="{{ url_for('device_detail', device_id=d.id) }}">Manage</a></td>
  </tr>
  {% endfor %}
</table>
</div>
{% endif %}
<form method="post" action="{{ url_for('cleanup_stale_devices') }}" onsubmit="return confirm('Delete these outdated devices? This cannot be undone.');">
  <button class="danger" type="submit" {{ 'disabled' if not stale_devices }}>Clean up all {{ stale_devices|length }} now</button>
</form>
{% endif %}
</div>

<div class="settings-subsection">
<h3>Backup &amp; restore</h3>
<p class="hint">
  Exports every admin-configured setting -- users, devices, domains,
  categories, schedules, and the SSL-Bump CA certificate itself -- into
  one file. Restoring it (even on completely fresh hardware) puts back
  the exact same CA certificate too, so no device needs to re-trust
  anything afterward. Does NOT include the Report page's history, the
  Events log, or a subscription category's fetched domain list (that
  re-syncs on its own from the URL already saved in the backup).
</p>
<p class="hint"><strong>Treat this file like a password vault, not a plain config export</strong> -- it contains the CA certificate's private key and AdGuard's own admin password in plain text (AdGuard's API needs the real password, not a hash), plus every login's password hash. Store it somewhere only you can reach.</p>
<a class="btn add" href="{{ url_for('download_backup') }}">Download backup</a>

<details style="margin-top:1rem;">
<summary>Restore from a backup file</summary>
<p class="hint"><strong>This replaces every user, device, domain, category, schedule, and setting on this install with whatever's in the file</strong> -- anything not in the backup is deleted, not merged with what's here now. Meant for a fresh install or reverting to an earlier snapshot, not routine use.</p>
<form class="add-form" method="post" action="{{ url_for('restore_backup') }}" enctype="multipart/form-data"
      onsubmit="return confirm('This REPLACES every user, device, domain, category, schedule, and setting with what&#39;s in this backup file -- anything not in the file is deleted. This cannot be undone. Continue?')">
  <input type="file" name="backup_file" accept=".zip" required>
  <button class="danger" type="submit">Restore from backup</button>
</form>
</details>
</div>
</div>
"""


def _adguard_ui_url(adguard_url: str) -> str | None:
    """Best-effort link to AdGuard Home's OWN admin UI (a separate
    login, separate application from this dashboard) for the Settings
    page's "Open AdGuard's dashboard" link -- added 2026-09-07 at the
    project owner's request for a quick click-through to AdGuard's own
    stats/query-log view (real stats integration *into* this dashboard
    was explicitly deferred to a future phase, not built here).

    Deliberately does NOT reuse the stored `adguard_url` setting's host
    as-is: that's the dashboard-container-to-AdGuard API address, always
    loopback (`127.0.0.1`) under this project's shared `network_mode:
    host` setup regardless of `ADGUARD_WEB_BIND` (see `.env.example`'s
    own comment on `ADGUARD_URL`) -- correct for a server-to-server API
    call, but a link built from it would send the ADMIN'S OWN browser to
    port 3000 on *their* machine, not the Beelink, which is never right
    for a remote browser. Instead, borrows the hostname the browser
    actually used to reach THIS page (`request.host`) -- since the
    dashboard and AdGuard run on the same host, whatever address got you
    here should also reach AdGuard, on its own port -- and only takes
    the PORT from the stored `adguard_url` setting.

    Returns None if `adguard_url` isn't configured yet (nothing to link
    to). Does not and cannot confirm the link will actually load --that
    also requires `ADGUARD_WEB_BIND` to be something other than its
    secure-by-default `127.0.0.1` (see `.env.example`), an operator
    decision this function has no way to detect from here.
    """
    if not adguard_url:
        return None
    try:
        adguard_port = urlparse(adguard_url).port
    except ValueError:
        return None
    if not adguard_port:
        return None
    browser_host = request.host.split(":")[0]
    return f"http://{browser_host}:{adguard_port}"


def _optigate_rewrite_status(conn, adguard_url: str, adguard_username: str, adguard_password: str) -> str:
    """Read-only status check for the Settings page's "Memorable
    troubleshooting address" card -- never writes anything (see
    _sync_optigate_rewrite_now() for the actual push). Exists so a gap
    (AdGuard reset externally, DASHBOARD_URL changed without re-saving
    this form, etc.) is visible on the page itself rather than silently
    invisible until someone notices the address just doesn't work and
    has no way to tell why -- the exact failure mode that prompted this
    whole feature (RoadMap.md's dated entry, 2026-09-08: a real
    production wipe left this silently broken, with the page still
    showing "optigate.home" as if nothing were wrong)."""
    block_page_ip = optigate_rewrite.parse_block_page_ip(os.environ.get("DASHBOARD_URL"))
    if not block_page_ip:
        return "not active -- DASHBOARD_URL isn't set to a plain IP address"
    if not adguard_url or not adguard_password:
        return "not active -- AdGuard's connection details aren't set"
    desired_domain = db.optigate_hostname(conn)
    try:
        current = adguard_client.get_rewrites(adguard_url, adguard_username, adguard_password)
    except adguard_client.AdGuardError as exc:
        # Fixed 2026-09-08, real gap found investigating an "AdGuard
        # username/password not synced" report: a 401 here (AdGuard is
        # up, but rejects the credentials stored in this project's own
        # DB -- exactly what happens after an admin password change via
        # update_admin() until someone restarts the adguard container,
        # since AdGuard only reads its config at startup) used to show
        # the exact same message as AdGuard being genuinely offline,
        # sending whoever's troubleshooting down the wrong path
        # entirely (checking the container/network instead of just
        # restarting adguard).
        if exc.status_code == 401:
            return (
                "couldn't check -- AdGuard rejected this login. If you changed the admin "
                "password recently, run 'docker compose restart adguard' (it only reads "
                "new credentials at startup)"
            )
        return "couldn't check -- AdGuard isn't reachable right now"
    if any(
        isinstance(r, dict) and r.get("domain") == desired_domain and r.get("answer") == block_page_ip
        for r in current
    ):
        return f"live -- resolves to {block_page_ip}"
    return "not active yet -- click Save below to push it"


def _interception_controller_is_up(conn) -> bool:
    """Whether the `controller` process (where network_sweep.py's own
    background loop actually lives) is up and self-reporting right now
    -- reuses the EXACT same interception_runtime.mode/last_healthy_at
    liveness check the Health page already relies on
    (_get_runtime_row()/_is_stale()/_subsystem_is_up(), all defined
    above), rather than inventing a second way to answer "is this
    process actually alive." `nft_mode`/`nft_last_healthy_at` (the
    OTHER half of that same row) is nftables-manager's own, separate
    process's health -- irrelevant here, since network_sweep.py runs
    inside `controller` itself, not nftables-manager.

    Added 2026-09-09, real gap found live: the project owner clicked
    "Run now" while `controller` wasn't running at all (interception
    off for the night) and the request just silently queued with a
    generic "will run within about 30 seconds" message -- true only if
    something is actually alive to run it. Their own words: "we can't
    just let it go off into nothingness." A missing runtime_row (a
    brand-new install where controller has genuinely never run even
    once) counts as down, same as a stale one."""
    row = _get_runtime_row(conn)
    if row is None:
        return False
    return _subsystem_is_up(row["mode"], _is_stale(row["last_healthy_at"]))


def _network_sweep_status(conn) -> str:
    """Read-only status line for the Settings page's "Network discovery
    sweep" card -- never writes anything, mirrors
    _optigate_rewrite_status()'s own "make the real state visible, not
    just a static settings echo" approach. controller/network_sweep.py
    itself writes network_sweep_last_run_at/_last_host_count on every
    real sweep (whether or not it's currently running here in the
    dashboard container -- these two processes only share the DB, not
    memory), so this can genuinely be stale or "never" if the
    interception profile isn't running at all."""
    last_run_at = db.get_setting(conn, "network_sweep_last_run_at", "")
    if not last_run_at:
        return "never run yet"
    host_count = db.get_setting(conn, "network_sweep_last_host_count", "0")
    return f"last ran {last_run_at} -- {host_count} address{'es' if host_count != '1' else ''} probed"


def _stale_devices(conn, days: int) -> list:
    """Devices whose REAL last-seen time (device_bindings, populated by
    ARP/DHCP discovery, active scans, or AdGuard's own query log) is
    older than `days` -- NOT `devices.last_seen_at`, which is never
    written by anything (see common/db.py's own schema comment; this was
    a genuinely dormant feature before this fix, since cleanup_stale_
    devices()'s old query against that dead column could never match a
    single row, in any configuration). A device that's never been seen
    at all (network_last_seen IS NULL) is excluded, same "only a real,
    old timestamp counts" policy as before this fix -- never treating
    "we don't know" the same as "definitely stale". Shared by
    settings_page() (the review table) and cleanup_stale_devices()
    (deletes exactly what's shown), so the two can never disagree about
    which devices qualify."""
    cutoff = db.iso_secs_ago(days * 86400)
    return conn.execute(
        "SELECT d.*, u.display_name, g.name AS group_name, "
        "(SELECT MAX(last_seen_at) FROM device_bindings WHERE mac_address = d.mac_address) AS network_last_seen "
        "FROM devices d "
        "LEFT JOIN users u ON u.id = d.user_id "
        "LEFT JOIN groups g ON g.id = d.group_id "
        "WHERE (SELECT MAX(last_seen_at) FROM device_bindings WHERE mac_address = d.mac_address) < ? "
        "ORDER BY network_last_seen",
        (cutoff,),
    ).fetchall()


@app.route("/settings")
@require_admin
def settings_page():
    conn = get_db()
    local_network = db.get_setting(conn, "local_network", "")
    network_sweep_enabled = db.get_setting(conn, "network_sweep_enabled", "1") == "1"
    # DEFAULT_NETWORK_SWEEP_INTERVAL_MINUTES, not
    # controller.network_sweep.DEFAULT_INTERVAL_MINUTES: dashboard's
    # own image never has controller/*.py copied into it (each
    # container flat-copies only its own directory + common/ -- same
    # "same-named module, different image" split as
    # common/category_fetch.py's own docstring already documents),
    # so importing that module here would work locally but fail at
    # runtime in the real deployment. This one constant is simple
    # enough to just keep in sync by hand across the two files rather
    # than adding a common/ module for a single shared integer.
    network_sweep_interval_minutes = db.get_setting(
        conn, "network_sweep_interval_minutes", str(DEFAULT_NETWORK_SWEEP_INTERVAL_MINUTES)
    )
    admin_username = db.get_setting(conn, "admin_username", "")
    block_page_mode = db.get_setting(conn, "block_page_mode", "terminate")
    device_stale_days = db.get_setting(conn, "device_stale_days", "")
    stale_devices = _stale_devices(conn, int(device_stale_days)) if device_stale_days else []
    adguard_url = db.get_setting(conn, "adguard_url", "")
    # adguard_username is no longer read here -- since 2026-09-07 it's
    # always identical to admin_username above (see update_admin()),
    # nothing on this page needs it independently anymore.
    adguard_password = db.get_setting(conn, "adguard_password", "")
    # "" (genuinely never saved) vs "UTC" (explicitly saved as UTC) are
    # deliberately distinguished here -- see bootstrap_admin()'s own
    # comment on why this setting isn't seeded with a hardcoded UTC
    # fallback at boot. household_time_zone_unset drives the Settings
    # page's own browser-side auto-detect (SETTINGS_BODY's inline
    # <script>); household_time_zone still falls back to "UTC" for the
    # <select>'s own pre-JS rendering either way.
    household_time_zone_raw = db.get_setting(conn, "household_time_zone", "")
    household_time_zone = household_time_zone_raw or "UTC"
    safesearch_enabled = db.get_setting(conn, "safesearch_enabled", "0") == "1"
    body = render_template_string(
        SETTINGS_BODY, local_network=local_network, admin_username=admin_username,
        network_sweep_enabled=network_sweep_enabled,
        network_sweep_interval_minutes=network_sweep_interval_minutes,
        network_sweep_status=_network_sweep_status(conn),
        interception_controller_is_up=_interception_controller_is_up(conn),
        block_page_mode=block_page_mode, device_stale_days=device_stale_days,
        stale_devices=stale_devices, adguard_url=adguard_url,
        adguard_configured=bool(adguard_url and adguard_password),
        adguard_ui_url=_adguard_ui_url(adguard_url),
        household_time_zone=household_time_zone,
        household_time_zone_unset=not household_time_zone_raw,
        available_time_zones=sorted(zoneinfo.available_timezones()),
        safesearch_enabled=safesearch_enabled,
        ca_cert_info=_ca_cert_info(CA_CERT_PATH),
        optigate_hostname_prefix=db.get_setting(
            conn, "optigate_hostname_prefix", db.DEFAULT_OPTIGATE_HOSTNAME_PREFIX
        ),
        optigate_rewrite_status=_optigate_rewrite_status(conn, adguard_url, admin_username, adguard_password),
    )
    return render("settings", body)


# A DNS label: letters/digits/hyphens, 1-63 chars, never starting or
# ending with a hyphen -- standard hostname-label rules, since this
# becomes the first part of a real DNS name (db.optigate_hostname()
# appends the fixed ".home" suffix). No dots allowed, deliberately: the
# project owner's own words were "force the use of .home so the
# administrator can only change the first part of the URL."
_OPTIGATE_PREFIX_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _sync_optigate_rewrite_now(conn) -> str | None:
    """Pushes the optigate.home DNS rewrite to AdGuard directly from the
    dashboard, instead of only ever happening via controller's periodic
    cycle (the `interception` profile, off by default for most installs
    -- see common/optigate_rewrite.py's own docstring for the real gap
    this closes: without this, the feature silently never worked at all
    for anyone not running that profile, with a "Saved" message implying
    otherwise). Returns None on success (including the deliberate no-op
    when DASHBOARD_URL isn't a plain IP -- see
    optigate_rewrite.parse_block_page_ip's own docstring), or a
    human-readable reason it didn't happen, for callers that want to
    surface that to the admin. Never raises -- every caller (a request
    handler, or main()'s own best-effort startup call) treats this as
    optional, not load-bearing."""
    block_page_ip = optigate_rewrite.parse_block_page_ip(os.environ.get("DASHBOARD_URL"))
    if not block_page_ip:
        return "DASHBOARD_URL isn't set to a plain IP address (see the hint below)"
    url = db.get_setting(conn, "adguard_url", "")
    username = db.get_setting(conn, "adguard_username", "admin")
    password = db.get_setting(conn, "adguard_password", "")
    if not url or not password:
        return "AdGuard's connection details aren't set (see the Ad-block card below)"
    try:
        optigate_rewrite.sync_optigate_rewrite(conn, url, username, password, block_page_ip)
    except adguard_client.AdGuardError as exc:
        return f"couldn't reach AdGuard: {exc}"
    return None


@app.route("/settings/household", methods=["POST"])
@require_admin
def update_household_settings():
    """Merged Save for the "Household" section (RoadMap.md item 3, "one
    Save button per settings-shaped page, not several"). The default
    time zone and the memorable troubleshooting hostname used to be two
    independent forms/routes (update_household_time_zone(),
    update_optigate_hostname()) -- merged into one atomic save: a bad
    time zone no longer saves the hostname alone, or vice versa. The
    time-zone auto-detect script (SETTINGS_BODY) posts here too,
    reading the hostname field's own live value at post time so its
    background save never clobbers an unsaved edit sitting in that
    field."""
    tz = request.form.get("household_time_zone", "UTC").strip()
    if tz not in zoneinfo.available_timezones():
        return flash_redirect("settings_page", "That doesn't look like a real time zone.", error=True)
    hostname_value = request.form.get("optigate_hostname_prefix", "").strip().lower()
    if not hostname_value:
        hostname_value = db.DEFAULT_OPTIGATE_HOSTNAME_PREFIX
    if not _OPTIGATE_PREFIX_RE.match(hostname_value):
        return flash_redirect(
            "settings_page",
            "Invalid address -- letters, numbers, and hyphens only (no dots; "
            "the .home suffix is fixed and can't be changed).",
            error=True,
        )
    conn = get_db()
    db.set_setting(conn, "household_time_zone", tz)
    db.set_setting(conn, "optigate_hostname_prefix", hostname_value)
    conn.commit()
    problem = _sync_optigate_rewrite_now(conn)
    if problem is None:
        return flash_redirect("settings_page", f"Saved and pushed to AdGuard -- {hostname_value}.home is live now.")
    return flash_redirect(
        "settings_page",
        f"Saved -- {hostname_value}.home will take effect once you fix this: {problem}.",
        error=True,
    )


@app.route("/settings/filtering", methods=["POST"])
@require_admin
def update_filtering_settings():
    """Merged Save for the "Filtering & AdGuard" section (RoadMap.md
    item 3): AdGuard's connection address, SafeSearch/Restricted Mode,
    and the blocked-site experience used to be three independent
    forms/routes (update_adguard_settings(), update_safesearch(),
    update_block_page_mode()) -- merged into one atomic save. Only the
    connection ADDRESS is set here for AdGuard -- since 2026-09-07
    (RoadMap.md's dated entry), the username/password half moved
    entirely to update_admin() (the dashboard's own admin-login form),
    which keeps AdGuard's real credential in sync automatically instead
    of letting the two drift independently the way this used to allow.
    G3's SafeSearch/Restricted-Mode setting: only writes the setting --
    controller/adguard_sync.py's sync_safesearch() picks it up and
    reconciles AdGuard's real config on its own next cycle, same
    "dashboard writes intent, controller applies it" pattern as every
    other AdGuard-facing setting on this page. Deliberately does NOT
    include "Check for filter updates now" (refresh_adguard_filters())
    -- that's a one-off action against AdGuard's live API right now,
    not a persisted setting."""
    url = request.form.get("adguard_url", "").strip()
    safesearch_enabled = "1" if request.form.get("safesearch_enabled") else "0"
    block_page_mode = request.form.get("block_page_mode", "redirect")
    if block_page_mode not in ("redirect", "terminate"):
        return flash_redirect("settings_page", "Invalid blocked-site experience option.", error=True)
    conn = get_db()
    db.set_setting(conn, "adguard_url", url)
    db.set_setting(conn, "safesearch_enabled", safesearch_enabled)
    db.set_setting(conn, "block_page_mode", block_page_mode)
    conn.commit()
    return flash_redirect("settings_page", "Saved. Blocked-site experience takes effect on the next new connection, no restart needed.")


@app.route("/settings/adguard/refresh", methods=["POST"])
@require_admin
def refresh_adguard_filters():
    conn = get_db()
    url = db.get_setting(conn, "adguard_url", "")
    username = db.get_setting(conn, "adguard_username", "admin")
    password = db.get_setting(conn, "adguard_password", "")
    if not url or not password:
        return flash_redirect("settings_page", "Set AdGuard's connection details below first.", error=True)
    try:
        updated = adguard_client.refresh_filters(url, username, password)
    except adguard_client.AdGuardError as exc:
        return flash_redirect("settings_page", f"Couldn't reach AdGuard: {exc}", error=True)
    # Piggybacks the optigate.home rewrite push onto this same button --
    # a manual "fix it now" path (beyond re-saving the hostname form, or
    # restarting the whole dashboard container) for exactly the gap
    # RoadMap.md's 2026-09-08 entry describes: AdGuard reset or
    # reconfigured independently of this dashboard, with nothing else
    # prompting a re-push.
    rewrite_problem = _sync_optigate_rewrite_now(conn)
    rewrite_note = "" if rewrite_problem is None else f" (optigate.home not active: {rewrite_problem})"
    if updated:
        return flash_redirect("settings_page", f"Checked now -- {updated} list(s) had new content.{rewrite_note}")
    return flash_redirect("settings_page", f"Checked now -- everything was already up to date.{rewrite_note}")


@app.route("/settings/device-stale-days", methods=["POST"])
@require_admin
def update_device_stale_days():
    value = request.form.get("device_stale_days", "").strip()
    conn = get_db()
    if not value:
        db.set_setting(conn, "device_stale_days", "")
        conn.commit()
        return flash_redirect("settings_page", "Saved. Outdated-device cleanup is now off.")
    try:
        days = int(value)
        if days < 1:
            raise ValueError
    except ValueError:
        return flash_redirect("settings_page", "Enter a whole number of days (1 or more).", error=True)
    db.set_setting(conn, "device_stale_days", str(days))
    conn.commit()
    return flash_redirect("settings_page", "Saved.")


@app.route("/devices/cleanup", methods=["POST"])
@require_admin
def cleanup_stale_devices():
    """Deletes exactly what the Settings page's own review table just
    showed -- same _stale_devices() query, so what an admin reviewed
    before clicking "Clean up" is exactly what gets removed, never a
    silently different set. Fixed 2026-09-07 (RoadMap.md's dated entry):
    this used to filter on devices.last_seen_at, a column nothing ever
    writes to -- meaning this button had never actually deleted anything,
    in any configuration, the entire time it existed."""
    conn = get_db()
    days = db.get_setting(conn, "device_stale_days", "")
    if not days:
        return flash_redirect("settings_page", "Set a threshold first.", error=True)
    stale = _stale_devices(conn, int(days))
    if not stale:
        return flash_redirect("settings_page", "Nothing to clean up.")
    placeholders = ",".join("?" * len(stale))
    conn.execute(f"DELETE FROM devices WHERE id IN ({placeholders})", tuple(d["id"] for d in stale))
    conn.commit()
    return flash_redirect("settings_page", f"Removed {len(stale)} device{'s' if len(stale) != 1 else ''}.")


@app.route("/settings/network", methods=["POST"])
@require_admin
def update_network_settings():
    """Merged Save for the "Network" section (RoadMap.md item 3): the
    local-network CIDR and the discovery-sweep enable/interval used to
    be two independent forms/routes (update_local_network(),
    update_network_sweep()) -- merged into one atomic save: a bad
    interval no longer blocks saving the CIDR change alongside it, or
    vice versa -- either both save or neither does. Controls
    controller/network_sweep.py's own background sweep -- see that
    module's docstring for the feature itself. The controller process
    re-reads both sweep settings fresh on every check tick (see that
    module's own run_loop()), so a save here takes effect within
    _CHECK_INTERVAL_SECONDS, without a controller restart. Validates the
    interval defensively even though the form's own `min="1"` already
    blocks most bad input client-side -- a hand-crafted POST (or a very
    old cached page) must not be able to write a zero/negative/
    non-numeric value the controller would then have to defend against
    itself. Deliberately does NOT include "Run now"
    (run_network_sweep_now()) -- that's a one-off action, not a
    persisted setting."""
    local_network_value = request.form.get("local_network", "").strip()
    sweep_enabled = request.form.get("network_sweep_enabled") == "1"
    raw_interval = request.form.get("network_sweep_interval_minutes", "").strip()
    try:
        interval_minutes = int(raw_interval)
        if interval_minutes < 1:
            raise ValueError
    except ValueError:
        return flash_redirect(
            "settings_page", "Interval must be a whole number of minutes, 1 or more.", error=True
        )
    conn = get_db()
    db.set_setting(conn, "local_network", local_network_value)
    db.set_setting(conn, "network_sweep_enabled", "1" if sweep_enabled else "0")
    db.set_setting(conn, "network_sweep_interval_minutes", str(interval_minutes))
    conn.commit()
    if not local_network_value:
        return flash_redirect(
            "settings_page",
            "Saved. LAN restriction disabled -- access is now controlled only "
            "by each person's proxy login.",
        )
    if not sweep_enabled:
        return flash_redirect("settings_page", "Saved. Network discovery sweep is now off.")
    return flash_redirect("settings_page", f"Saved. Sweeping every {interval_minutes} minute(s).")


@app.route("/settings/network-sweep/run-now", methods=["POST"])
@require_admin
def run_network_sweep_now():
    """Dashboard can't call into the controller process directly (a
    separate container, separate memory) -- this just writes a fresh
    timestamp that controller/network_sweep.py's own background loop
    notices and consumes on its next check tick (~30s), the same
    write-a-timestamp-and-let-the-other-process's-own-loop-notice-it
    pattern already used elsewhere in this project (the optigate.home
    rewrite, the pending-devices dismiss feature). See
    network_sweep._run_now_requested()'s own docstring for exactly how
    it's consumed -- deliberately works even when the automatic
    schedule (network_sweep_enabled) is off, matching every other
    one-off "check/refresh now" button on this page.

    Fixed 2026-09-09, real gap found live: this used to say "will run
    within about 30 seconds" unconditionally, even when `controller`
    (the only thing that would ever act on this) wasn't running at
    all -- the project owner's own words: "we can't just let it go off
    into nothingness." Now checks _interception_controller_is_up()
    FIRST and says so plainly if it's down, rather than implying success
    it can't back up. The request is still queued either way (harmless,
    and correct if the profile gets started moments later) -- only the
    MESSAGE changes, matching what will actually happen."""
    conn = get_db()
    db.set_setting(conn, "network_sweep_run_now_requested_at", db.now_iso())
    conn.commit()
    if not _interception_controller_is_up(conn):
        return flash_redirect(
            "settings_page",
            "Queued, but the interception profile isn't running right now, so nothing will act on "
            "it yet -- start it first (docker compose --profile interception up -d). This request "
            "will still run the moment it comes up.",
            error=True,
        )
    return flash_redirect(
        "settings_page",
        "Requested -- will run within about 30 seconds.",
    )


@app.route("/settings/admin", methods=["POST"])
@require_admin
def update_admin():
    """The dashboard's own admin login -- and, since 2026-09-07
    (RoadMap.md's dated entry), the SAME action that keeps AdGuard's
    real login in sync, replacing the earlier "just show the plaintext
    AdGuard password on screen" approach the project owner correctly
    flagged as insecure. There is deliberately no separate way to set a
    different AdGuard username/password anymore -- one admin identity
    governs both, so they can never drift apart the way they did before.

    Only touches AdGuard when a NEW password is actually submitted (same
    "blank means keep current" convention this form already had) --
    changing just the username without changing the password would
    otherwise force a password re-sync using nothing (there's no
    current plaintext password ever stored anymore to re-hash with)."""
    username = request.form.get("admin_username", "").strip()
    password = request.form.get("admin_password", "")
    if not username:
        return flash_redirect("settings_page", "Admin username can't be empty.", error=True)
    conn = get_db()
    db.set_setting(conn, "admin_username", username)
    message = "Saved."
    if password:
        db.set_setting(conn, "admin_password_hash", auth.hash_password(password))
        # Kept only for common/adguard_client.py's own REST calls (filter
        # refresh, category sync, SafeSearch, etc.), which need to replay
        # this as HTTP Basic Auth -- never displayed back to the admin
        # anymore (that was the insecure part); they already know it,
        # since they're the one who just set it.
        db.set_setting(conn, "adguard_username", username)
        db.set_setting(conn, "adguard_password", password)
        try:
            adguard_config_sync.sync_adguard_credentials(username, password)
        except adguard_config_sync.AdGuardConfigSyncError as exc:
            log.warning("AdGuard credential sync failed: %s", exc)
            message = (
                "Saved. Could not update AdGuard's own login automatically "
                f"({exc}) -- AdGuard-dependent features (filter updates, "
                "SafeSearch, category blocking) may stop working until this "
                "is resolved."
            )
        else:
            message = (
                "Saved. AdGuard's own login was updated too -- run "
                "'docker compose restart adguard' for it to take effect "
                "(AdGuard only reads its config at startup)."
            )
    conn.commit()
    return flash_redirect("settings_page", message)


db.init_db()  # once per process, not per request -- see get_db()'s own comment above
bootstrap_admin()

_boot_conn = db.get_conn()
app.secret_key = db.get_setting(_boot_conn, "secret_key") or secrets.token_hex(32)
_boot_conn.close()


def main() -> None:
    # Found 2026-09-02 while auditing brute-force protection: this
    # container never called logging.basicConfig() anywhere (unlike
    # controller/main.py, which does), so every log.info()/log.warning()
    # call in this file AND in captive_portal_server.py/
    # block_page_server.py -- including the pre-existing failed-login
    # log.info() calls in captive_portal_server.py -- silently never
    # reached `docker compose logs dashboard` at all for INFO-level
    # calls; only WARNING+ ones surfaced, via Python's own bare
    # last-resort handler. In main() (not at module import time) so
    # importing this module for tests never installs a handler on the
    # root logger.
    logging.basicConfig(level=logging.INFO)

    host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("DASHBOARD_PORT", "8787"))
    from waitress import serve

    # Only started when DASHBOARD_URL is actually set -- same gating
    # condition proxy/entrypoint.sh already uses for Squid's own
    # deny_info line, and for the same reason: with nothing configured
    # to point traffic here, this would just be an idle listener. See
    # block_page_server.py's own module docstring for why this is a
    # separate tiny server on port 80, not a Flask route, and why there's
    # deliberately no HTTPS (port 443) equivalent.
    if os.environ.get("DASHBOARD_URL"):
        import block_page_server

        block_page_server.start(host="0.0.0.0", port=80)
        print("block page server listening on http://0.0.0.0:80", file=sys.stderr, flush=True)

        # Real gap found live 2026-09-08: this used to be pushed ONLY by
        # controller's periodic cycle (the interception profile, off by
        # default for most installs), so a fresh AdGuard instance --
        # including one that just came from a wipe/redeploy, not just a
        # brand-new install -- silently never got this rewrite at all,
        # with the Settings page still showing "optigate.home" as if
        # nothing were wrong. One best-effort attempt at every dashboard
        # start (not a retry loop -- AdGuard might not be up yet on a
        # cold multi-container boot; the Settings page's own live status
        # check, and simply re-saving the hostname form, both retry this
        # on demand) means a fresh install self-heals without anyone
        # needing to know this route even exists.
        _boot_settings_conn = get_db()
        try:
            _problem = _sync_optigate_rewrite_now(_boot_settings_conn)
            if _problem:
                log.info("optigate.home rewrite not pushed at startup: %s", _problem)
        except Exception:
            # Best-effort, genuinely optional -- never let a bug or an
            # unanticipated failure mode here take down dashboard
            # startup entirely over a cosmetic DNS convenience feature.
            log.exception("optigate.home rewrite push at startup failed unexpectedly")
        finally:
            _boot_settings_conn.close()

    # Phase 4 milestone 3: the captive-portal login server nftables'
    # own baseline rules have redirected unauthenticated_v4's plain-HTTP
    # traffic to since Phase 3 was designed (see
    # captive_portal_server.py's own module docstring for the full
    # design). Unlike block_page_server above, this isn't gated behind
    # DASHBOARD_URL -- it's part of the interception feature itself, not
    # an optional cosmetic enhancement -- but CAPTIVE_PORTAL_DISABLED
    # gives an operator a fast, no-redeploy kill switch if something
    # about the live rollout needs to be turned off in a hurry.
    if not os.environ.get("CAPTIVE_PORTAL_DISABLED"):
        import captive_portal_server

        captive_portal_server.start(host="0.0.0.0", port=3131)
        print("captive portal server listening on http://0.0.0.0:3131", file=sys.stderr, flush=True)

    print(f"dashboard listening on http://{host}:{port}", file=sys.stderr, flush=True)
    serve(app, host=host, port=port, threads=8)


if __name__ == "__main__":
    main()
