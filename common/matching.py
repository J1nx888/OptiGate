#!/usr/bin/env python3
"""Pattern matching helpers shared by the Squid helper scripts."""
from __future__ import annotations

import functools
import ipaddress
import multiprocessing
import re
import signal
import sqlite3


@functools.lru_cache(maxsize=1024)
def _domain_regex(pattern: str) -> re.Pattern[str] | None:
    """Compile a stored domain pattern as an anchored domain-suffix match.

    A stored pattern (e.g. ``crunchyroll\\.com``) matches that host and any
    subdomain of it, but NOT ``evilcrunchyroll.com`` and NOT
    ``crunchyroll.com.attacker.example`` -- the match has to begin on a
    label boundary and run to the end of the hostname. Without this,
    ``re.search`` treated every pattern as an unanchored substring and any
    FQDN containing an allowed string (``evil-jsdelivr.net`` vs the seeded
    ``jsdelivr\\.net``) slipped through the allowlist.

    Returns None for a pattern that isn't a valid regex; find_domain then
    skips it rather than raising.
    """
    try:
        return re.compile(r"(?:^|\.)(?:" + pattern + r")\Z", re.IGNORECASE)
    except re.error:
        return None


@functools.lru_cache(maxsize=2048)
def _path_regex(pattern: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


class _RegexTimedOut(Exception):
    """Raised internally by _search_with_timeout()'s own alarm handler --
    never escapes that function."""


_PATH_MATCH_TIMEOUT_SECONDS = 0.5

# "spawn", not the platform default ("fork" on Linux) -- see
# _search_with_timeout()'s own comment on why. Created once at module
# load (cheap -- spawn doesn't fork/start anything until .Process() is
# actually called) and reused, rather than calling
# multiprocessing.get_context("spawn") fresh on every guarded search.
_MP_SPAWN_CONTEXT = multiprocessing.get_context("spawn")


def _regex_matches_worker(pattern: str, flags: int, text: str, result_queue) -> None:
    """Runs in a separate SPAWNED process -- see _search_in_subprocess()
    for why a process, not a thread. Recompiles the pattern here rather
    than trying to pass the already-compiled re.Pattern across the
    process boundary: multiprocessing has to pickle everything crossing
    that boundary regardless, and re.Pattern's own pickling support
    already just stores/recompiles the pattern+flags under the hood, so
    doing it explicitly is no less efficient and keeps this worker's
    inputs plain, uncomplicated types."""
    try:
        result_queue.put(re.compile(pattern, flags).search(text) is not None)
    except Exception:
        result_queue.put(False)


def _search_in_subprocess(rx: re.Pattern[str], text: str) -> bool:
    """The non-main-thread fallback for _search_with_timeout() -- see
    that function's own comment for the full reasoning on why this
    exists. A real OS process stands in for the SIGALRM-based timeout
    that only works on the main thread, specifically because Python
    threads can't be forcibly killed: an abandoned worker THREAD stuck
    in catastrophic backtracking would peg one CPU core forever (Python
    has no safe thread-kill API), while an abandoned PROCESS can
    actually be terminated. Fails closed (returns False) on a timeout
    or any unexpected error, same convention as the SIGALRM path below.
    """
    result_queue = _MP_SPAWN_CONTEXT.Queue()
    proc = _MP_SPAWN_CONTEXT.Process(
        target=_regex_matches_worker, args=(rx.pattern, rx.flags, text, result_queue)
    )
    proc.start()
    proc.join(_PATH_MATCH_TIMEOUT_SECONDS)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return False
    try:
        return result_queue.get_nowait()
    except Exception:
        return False


def _search_with_timeout(rx: re.Pattern[str], text: str) -> bool:
    """Same as rx.search(text) is not None, but bounded: domain_paths
    patterns are admin-supplied and only validated by re.compile()
    succeeding, never checked for a catastrophic-backtracking shape
    (e.g. nested/overlapping quantifiers). Python's stdlib `re` has no
    linear-time guarantee the way RE2 does, and this project's common/
    modules are deliberately stdlib-only (see common/auth.py's own
    docstring on why -- the proxy container must never need pip), so a
    third-party guaranteed-linear engine isn't an option here.

    Returns bool, not re.Match -- every call site only ever checks
    truthiness, and a real re.Match object isn't picklable across the
    subprocess boundary the non-main-thread path uses.

    The actual attacker-facing risk: proxy/authz_helper.py's decide()
    (the only hot-path caller, via path_allowed() below) runs this
    against the CLIENT-controlled request path on every bump-mode HTTP
    request, inside one of Squid's pooled `children-max=20` helper
    subprocesses -- a hung match there stalls that one child
    indefinitely, and enough hung children measurably degrade every
    other in-flight bump-mode decision.

    Uses SIGALRM (Unix only, and only callable from the interpreter's
    main thread) since that's the actual context authz_helper.py runs
    in -- a single-threaded subprocess reading stdin in a loop, never
    multi-threaded. Falls back to an UNGUARDED search (never silently
    skipping the match, just not time-bounding it) on Windows (SIGALRM
    doesn't exist there -- fine, since proxy/ only ever actually runs on
    Linux, see AGENTS.md).

    On a non-main thread (`signal.signal()` raises ValueError there),
    routes to _search_in_subprocess() instead of an unguarded search --
    see that function's own comment for why a process. This matters
    because find_categories_for_hostname() below is called live from
    dashboard.py's route handlers and adguard_report_sync.py, both
    running on waitress's multi-threaded worker pool. A timeout (either
    path) denies (fails closed), consistent with this project's
    fail-closed convention, rather than treating an unmatchable-in-time
    pattern as an allow.
    """
    if not hasattr(signal, "SIGALRM"):
        return rx.search(text) is not None

    def _on_alarm(signum, frame):
        raise _RegexTimedOut()

    try:
        previous_handler = signal.signal(signal.SIGALRM, _on_alarm)
    except ValueError:
        # Not the main thread -- signal handlers can't be installed
        # here at all.
        return _search_in_subprocess(rx, text)

    try:
        signal.setitimer(signal.ITIMER_REAL, _PATH_MATCH_TIMEOUT_SECONDS)
        try:
            return rx.search(text) is not None
        except _RegexTimedOut:
            return False
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def find_domain(conn: sqlite3.Connection, hostname: str) -> sqlite3.Row | None:
    """Return the first domains row whose pattern matches hostname, or None.

    Patterns are regexes anchored as a domain suffix (see _domain_regex).
    Rows are checked in insertion order (id ASC); first match wins.
    """
    hostname = (hostname or "").strip().rstrip(".").lower()
    if not hostname:
        return None
    for row in conn.execute("SELECT * FROM domains ORDER BY id"):
        rx = _domain_regex(row["pattern"])
        # Same _search_with_timeout() guard as path_allowed() below, for
        # consistency -- the practical exposure here is smaller (a
        # hostname is DNS-length-bounded at 253 chars, unlike an
        # arbitrary request path), but the underlying stdlib-`re`
        # backtracking risk from an admin-supplied pattern is identical
        # in kind, so this is guarded the same way rather than leaving
        # one of the two domain-matching call sites unprotected.
        if rx is not None and _search_with_timeout(rx, hostname):
            return row
    return None


def path_allowed(conn: sqlite3.Connection, domain_id: int, path: str) -> bool:
    path = path or "/"
    for row in conn.execute(
        "SELECT pattern FROM domain_paths WHERE domain_id = ?", (domain_id,)
    ):
        rx = _path_regex(row["pattern"])
        if rx is not None and _search_with_timeout(rx, path):
            return True
    return False


def user_has_domain(conn: sqlite3.Connection, user_id: int, domain_id: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM user_domains WHERE user_id = ? AND domain_id = ?",
        (user_id, domain_id),
    ).fetchone()
    return row is not None


def group_has_domain(conn: sqlite3.Connection, group_id: int, domain_id: int) -> bool:
    """group_domains mirrors user_domains exactly. Consulted by proxy
    enforcement via device_domain_reason() below."""
    row = conn.execute(
        "SELECT 1 FROM group_domains WHERE group_id = ? AND domain_id = ?",
        (group_id, domain_id),
    ).fetchone()
    return row is not None


def device_has_domain(conn: sqlite3.Connection, device_id: int, domain_id: int) -> bool:
    """device_domains grants one specific device access directly,
    independent of any user/group assignment. Consulted by proxy
    enforcement via device_domain_reason() below."""
    row = conn.execute(
        "SELECT 1 FROM device_domains WHERE device_id = ? AND domain_id = ?",
        (device_id, domain_id),
    ).fetchone()
    return row is not None


def device_domain_reason(conn: sqlite3.Connection, device: sqlite3.Row, domain: sqlite3.Row) -> str | None:
    """The specific reason `device` is authorized for `domain`, or None if
    it isn't authorized by any axis. Checked in this order: is_global, then
    per-user (if device has a user_id), then per-group (if device has a
    group_id), then per-device direct assignment -- the first thing that
    matches wins.

    The single shared source of truth for this check, used by both proxy
    helpers (which resolve the *device* first, see
    device_identity.resolve_device()) and controller/adguard_sync.py's
    build_splice_deny_rules() -- one place that knows all four axes, so
    Squid and AdGuard can never drift out of sync on what "authorized"
    means.

    Returns a reason string (not a bare bool) so callers get their log
    line's reason for free, matching the existing "global_domain"/
    "user_domain" vocabulary and extending it with "group_domain"/
    "device_domain" for the other two axes.
    """
    if domain["is_global"]:
        return "global_domain"
    if device["user_id"] is not None and user_has_domain(conn, device["user_id"], domain["id"]):
        return "user_domain"
    if device["group_id"] is not None and group_has_domain(conn, device["group_id"], domain["id"]):
        return "group_domain"
    if device_has_domain(conn, device["id"], domain["id"]):
        return "device_domain"
    return None


# Real category blocklists range from tens to ~953K domains. Scoping a
# list that size to a subset of clients via AdGuard's `$client=` custom-rule
# modifier is exactly what AdGuard's own team calls "unworkable" for
# per-client blocklist assignment (AdguardTeam/AdGuardHome#8103) -- a
# category at or under this many domains can be assigned to a specific
# user/group/device (controller/adguard_sync.py's
# build_category_deny_rules(), same `$client=` mechanism as domain-level
# rules); a category over it can only ever be `is_global` (enforced by
# dashboard/dashboard.py's category routes), pushed to AdGuard as one of
# its OWN native filter subscriptions instead
# (controller/adguard_sync.py's sync_category_subscriptions()). Shared
# here (not just in adguard_sync.py) since dashboard.py -- a separate
# container image -- needs the same number for its own validation and can
# only import from common/.
MAX_SCOPED_CATEGORY_DOMAINS = 5000


def category_applies_to_device(conn: sqlite3.Connection, device: sqlite3.Row, category: sqlite3.Row) -> bool:
    """Whether `category` is blocked for `device` -- the OPPOSITE polarity
    from device_domain_reason() above (that's an allow-list; this is a
    block-list). True if `category.is_global`, or device's user/group/id
    has a row in category_users/category_groups/category_devices. Mirrors
    device_domain_reason()'s explicit per-axis style rather than one
    generic parameterized helper, matching this module's own established
    idiom."""
    if category["is_global"]:
        return True
    if device["user_id"] is not None:
        row = conn.execute(
            "SELECT 1 FROM category_users WHERE category_id = ? AND user_id = ?",
            (category["id"], device["user_id"]),
        ).fetchone()
        if row is not None:
            return True
    if device["group_id"] is not None:
        row = conn.execute(
            "SELECT 1 FROM category_groups WHERE category_id = ? AND group_id = ?",
            (category["id"], device["group_id"]),
        ).fetchone()
        if row is not None:
            return True
    row = conn.execute(
        "SELECT 1 FROM category_devices WHERE category_id = ? AND device_id = ?",
        (category["id"], device["id"]),
    ).fetchone()
    return row is not None


# GLOB (SQLite shell-style wildcards, not regex) matching any character
# that only ever shows up in a hand-typed custom regex, never in a plain
# re.escape()'d domain literal -- re.escape() only ever produces
# alphanumerics/underscore plus escaped dots and hyphens (`\.`, `\-`),
# so a raw (unescaped-context) `*`, `+`, `?`, `(`, `|`, or `[` is a
# reliable signal this row is a genuine custom pattern, not a plain
# domain. Used by find_categories_for_hostname()'s slow path below to
# cheaply skip the overwhelming majority of rows.
_COMPLEX_PATTERN_GLOB = "*[*+?(|[]*"


def _candidate_exact_patterns(hostname: str) -> list[str]:
    """Every re.escape()'d suffix of `hostname`, most-specific first --
    e.g. "www.example.com" -> ["www\\.example\\.com", "example\\.com",
    "com"]. Exact string equality against one of these reproduces
    _domain_regex()'s suffix-anchored match semantics
    (`(?:^|\\.)(?:pattern)\\Z`) for the common case where the stored
    pattern is a plain re.escape()'d literal domain, letting
    find_categories_for_hostname() check it via an indexed SQL equality
    lookup instead of compiling and running a regex per row."""
    labels = hostname.split(".")
    return [re.escape(".".join(labels[i:])) for i in range(len(labels))]


def find_categories_for_hostname(conn: sqlite3.Connection, hostname: str) -> list[dict]:
    """Every category whose domain list currently matches `hostname` --
    i.e. would block it, once that category is actually assigned to
    someone (is_global, or via category_users/groups/devices; this
    function doesn't check that part, only "is this domain a member").
    Backs the Categories page's cross-category lookup tool, letting an
    admin check whether a domain (e.g. facebook.com) is listed in more
    than one category without opening each one individually.

    Two passes instead of one linear scan, since a single category can
    have hundreds of thousands of domains:

    1. **Fast path**: every candidate suffix of `hostname`
       (`_candidate_exact_patterns()`) is re.escape()'d and checked via
       one indexed `pattern IN (...)` SQL query across ALL categories at
       once (`idx_category_domains_pattern`, common/db.py) -- an exact
       string-equality lookup, not a regex, correctly reproducing
       `_domain_regex()`'s suffix-anchored semantics for any row that's
       a plain literal domain. This alone resolves essentially every
       real row: every `category_fetch.py`-synced and
       `seed_defaults.py`-seeded row is a plain `re.escape()`d literal.
    2. **Slow path**, only for categories the fast path didn't already
       match: real `_domain_regex()` + `_search_with_timeout()`
       evaluation, but scoped to just the rows flagged by
       `_COMPLEX_PATTERN_GLOB` as NOT looking like a plain literal -- a
       hand-typed custom regex the fast path can't recognize via exact
       equality. This is a tiny fraction of rows in any real deployment,
       so the remaining linear scan stays cheap.

    Flags a match that's also covered by that category's own
    `category_overrides` (an admin-added exception -- the category's
    list technically includes it, but it's never actually blocked by
    that category) rather than silently omitting or including it
    unqualified, so the result reflects what's really configured either
    way.

    Returns one dict per matching category: {"category": <row>,
    "pattern": <the specific category_domains pattern that matched>,
    "overridden": <bool>}, sorted by category name -- there's no "first
    match wins" concept here, every matching category matters.
    """
    hostname = (hostname or "").strip().rstrip(".").lower()
    if not hostname:
        return []

    categories_by_id = {row["id"]: row for row in conn.execute("SELECT * FROM categories")}
    if not categories_by_id:
        return []

    matched_pattern_by_category: dict[int, str] = {}

    candidates = _candidate_exact_patterns(hostname)
    placeholders = ",".join("?" for _ in candidates)
    for row in conn.execute(
        f"SELECT category_id, pattern FROM category_domains WHERE pattern IN ({placeholders})",
        candidates,
    ):
        matched_pattern_by_category.setdefault(row["category_id"], row["pattern"])

    still_unmatched = [cid for cid in categories_by_id if cid not in matched_pattern_by_category]
    if still_unmatched:
        # source = 'manual' narrows this scan further, safely: every
        # category_fetch.py-synced ('subscription') row is always
        # re.escape()'d by construction, so it can NEVER match the
        # complex-pattern GLOB -- only a hand-typed manual addition
        # ever could. Subscription rows are the huge majority of real
        # data, so skipping them here matters.
        id_placeholders = ",".join("?" for _ in still_unmatched)
        for row in conn.execute(
            f"SELECT category_id, pattern FROM category_domains "
            f"WHERE category_id IN ({id_placeholders}) AND source = 'manual' AND pattern GLOB ?",
            (*still_unmatched, _COMPLEX_PATTERN_GLOB),
        ):
            if row["category_id"] in matched_pattern_by_category:
                continue  # already matched by another complex row in this same category
            rx = _domain_regex(row["pattern"])
            if rx is not None and _search_with_timeout(rx, hostname):
                matched_pattern_by_category[row["category_id"]] = row["pattern"]

    matches = []
    for category_id, pattern in matched_pattern_by_category.items():
        overridden = False
        for row in conn.execute(
            "SELECT pattern FROM category_overrides WHERE category_id = ?", (category_id,)
        ):
            rx = _domain_regex(row["pattern"])
            if rx is not None and _search_with_timeout(rx, hostname):
                overridden = True
                break
        matches.append({"category": categories_by_id[category_id], "pattern": pattern, "overridden": overridden})
    matches.sort(key=lambda m: m["category"]["name"])
    return matches


def schedule_applies_to_target(
    conn: sqlite3.Connection, schedule: sqlite3.Row,
    *, user_id: int | None = None, group_id: int | None = None, device_id: int | None = None,
) -> bool:
    """Whether `schedule` targets this user/group/device -- same
    is_global-or-junction-table logic schedule_applies_to_device() below
    uses, but for a caller that only has a user id (no specific device in
    hand -- e.g. the user detail page's "what's active for this kid right
    now" display) and doesn't need to fabricate one. Says nothing about
    whether the schedule's time window is currently active -- see
    common/schedule_eval.py's schedule_is_active() for that, a
    deliberately separate concern (this is "who," that is "when")."""
    if schedule["is_global"]:
        return True
    if user_id is not None:
        row = conn.execute(
            "SELECT 1 FROM schedule_users WHERE schedule_id = ? AND user_id = ?",
            (schedule["id"], user_id),
        ).fetchone()
        if row is not None:
            return True
    if group_id is not None:
        row = conn.execute(
            "SELECT 1 FROM schedule_groups WHERE schedule_id = ? AND group_id = ?",
            (schedule["id"], group_id),
        ).fetchone()
        if row is not None:
            return True
    if device_id is not None:
        row = conn.execute(
            "SELECT 1 FROM schedule_devices WHERE schedule_id = ? AND device_id = ?",
            (schedule["id"], device_id),
        ).fetchone()
        if row is not None:
            return True
    return False


def schedule_applies_to_device(conn: sqlite3.Connection, device: sqlite3.Row, schedule: sqlite3.Row) -> bool:
    """Whether `schedule` targets `device` -- thin wrapper over
    schedule_applies_to_target() using the device's own user_id/group_id/
    id, kept as the device-shaped entry point every existing enforcement
    call site (controller/policy_state.py, controller/adguard_sync.py)
    already uses."""
    return schedule_applies_to_target(
        conn, schedule, user_id=device["user_id"], group_id=device["group_id"], device_id=device["id"]
    )


def user_has_show(conn: sqlite3.Connection, user_id: int, series_id: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM user_shows WHERE user_id = ? AND series_id = ?",
        (user_id, series_id.upper()),
    ).fetchone()
    return row is not None


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def ip_in_configured_lan(conn: sqlite3.Connection, ip_str: str) -> bool:
    """Check a client IP against the (dashboard-editable) local_network
    setting -- space-separated CIDRs, e.g. "192.168.1.0/24 10.0.0.0/24".

    An empty setting means the operator has disabled the LAN check (access
    is then controlled by the per-person proxy login alone). This matters
    under Docker bridge / Docker Desktop, where the proxy sees an internal
    gateway address rather than the real client IP and every request would
    otherwise be rejected as outside_lan.
    """
    from db import get_setting  # local import: callers that don't need db stay light

    raw = (get_setting(conn, "local_network") or "").strip()
    if not raw:
        return True  # check disabled
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for cidr in raw.split():
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
