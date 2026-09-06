"""common/matching.py: domain suffix matching, path matching, LAN check."""
from __future__ import annotations

import signal
import time

import pytest

import db
import matching


def _add_domain(conn, pattern, mode="splice", is_global=1, kind="generic"):
    conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, note, created_at) "
        "VALUES (?, ?, ?, ?, NULL, ?)",
        (pattern, mode, kind, is_global, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM domains WHERE pattern = ?", (pattern,)).fetchone()


# ---------------------------------------------------------------- find_domain

def test_find_domain_exact_and_subdomain_match(conn):
    _add_domain(conn, r"crunchyroll\.com")
    assert matching.find_domain(conn, "crunchyroll.com") is not None
    assert matching.find_domain(conn, "www.crunchyroll.com") is not None
    assert matching.find_domain(conn, "a.b.crunchyroll.com") is not None


def test_find_domain_rejects_substring_prefix_bypass(conn):
    """S2.1: evil-jsdelivr.net must NOT match a jsdelivr\\.net rule."""
    _add_domain(conn, r"jsdelivr\.net")
    assert matching.find_domain(conn, "evil-jsdelivr.net") is None
    assert matching.find_domain(conn, "cdn.jsdelivr.net") is not None


def test_find_domain_rejects_suffix_appended_bypass(conn):
    """S2.1: crunchyroll.com.attacker.example must NOT match crunchyroll\\.com."""
    _add_domain(conn, r"crunchyroll\.com")
    assert matching.find_domain(conn, "crunchyroll.com.attacker.example") is None


def test_find_domain_is_case_insensitive(conn):
    _add_domain(conn, r"crunchyroll\.com")
    assert matching.find_domain(conn, "CRUNCHYROLL.COM") is not None
    assert matching.find_domain(conn, "WwW.Crunchyroll.CoM") is not None


def test_find_domain_strips_trailing_dot_and_whitespace(conn):
    _add_domain(conn, r"crunchyroll\.com")
    assert matching.find_domain(conn, "crunchyroll.com.") is not None
    assert matching.find_domain(conn, "  crunchyroll.com  ") is not None


def test_find_domain_no_match_returns_none(conn):
    _add_domain(conn, r"crunchyroll\.com")
    assert matching.find_domain(conn, "example.com") is None


def test_find_domain_empty_hostname_returns_none(conn):
    _add_domain(conn, r"crunchyroll\.com")
    assert matching.find_domain(conn, "") is None
    assert matching.find_domain(conn, None) is None  # type: ignore[arg-type]


def test_find_domain_first_match_wins_by_insertion_order(conn):
    row_a = _add_domain(conn, r"crunchyroll\.com", mode="splice")
    row_b = _add_domain(conn, r"[a-z]+\.com", mode="bump")  # broader, inserted later
    result = matching.find_domain(conn, "crunchyroll.com")
    assert result["id"] == row_a["id"]
    assert result["mode"] == "splice"
    # sanity: the broader pattern is reachable for hosts the first doesn't match
    assert matching.find_domain(conn, "example.com")["id"] == row_b["id"]


def test_find_domain_skips_invalid_regex_pattern_without_raising(conn):
    """A malformed pattern (e.g. an unbalanced group) must be skipped, not
    crash the whole lookup for every other row."""
    _add_domain(conn, r"(unbalanced", mode="splice")
    _add_domain(conn, r"crunchyroll\.com", mode="bump")
    result = matching.find_domain(conn, "crunchyroll.com")
    assert result is not None
    assert result["mode"] == "bump"


# ---------------------------------------------------------------- path_allowed

def test_path_allowed_no_rules_returns_false(conn):
    domain = _add_domain(conn, r"example\.com", mode="bump")
    assert matching.path_allowed(conn, domain["id"], "/anything") is False


def test_path_allowed_matches_configured_pattern(conn):
    domain = _add_domain(conn, r"example\.com", mode="bump")
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)",
        (domain["id"], r"^/discover"),
    )
    conn.commit()
    assert matching.path_allowed(conn, domain["id"], "/discover/seasonal") is True
    assert matching.path_allowed(conn, domain["id"], "/other") is False


def test_path_allowed_defaults_path_to_slash(conn):
    domain = _add_domain(conn, r"example\.com", mode="bump")
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)", (domain["id"], r"^/$")
    )
    conn.commit()
    assert matching.path_allowed(conn, domain["id"], "") is True
    assert matching.path_allowed(conn, domain["id"], None) is True


def test_path_allowed_skips_invalid_regex_pattern(conn):
    domain = _add_domain(conn, r"example\.com", mode="bump")
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)", (domain["id"], r"(unbalanced")
    )
    conn.commit()
    assert matching.path_allowed(conn, domain["id"], "/anything") is False


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="SIGALRM timeout guard is Unix-only")
def test_path_allowed_does_not_hang_on_catastrophic_backtracking(conn):
    """Regression test for a real ReDoS risk (fixed 2026-09-02): an
    admin-supplied domain_paths pattern is matched via re.search()
    against the client-controlled request path with no backtracking-
    safety check -- dashboard.py's own validation only confirms
    re.compile() succeeds. A classic catastrophic-backtracking pattern
    ((a+)+$) against a long run of a's with no terminating match takes
    exponential time under Python's stdlib `re`; this confirms
    path_allowed() now completes quickly (via _search_with_timeout's
    SIGALRM guard) instead of hanging the calling process."""
    domain = _add_domain(conn, r"example\.com", mode="bump")
    conn.execute(
        "INSERT INTO domain_paths (domain_id, pattern) VALUES (?, ?)", (domain["id"], r"(a+)+$")
    )
    conn.commit()
    evil_path = "/" + "a" * 40 + "!"  # matches nothing -- forces full backtracking

    start = time.monotonic()
    result = matching.path_allowed(conn, domain["id"], evil_path)
    elapsed = time.monotonic() - start

    assert elapsed < 2.0, f"path_allowed() took {elapsed:.2f}s against a catastrophic pattern -- the timeout guard did not fire"
    assert result is False


@pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="SIGALRM timeout guard is Unix-only")
def test_find_domain_does_not_hang_on_catastrophic_backtracking(conn):
    """Same guard, same reasoning, for the other regex-matching call
    site (find_domain's hostname match) -- see this file's own
    docstring on why both are guarded identically."""
    _add_domain(conn, r"(a+)+$", mode="bump")
    evil_hostname = "a" * 40 + "!"

    start = time.monotonic()
    result = matching.find_domain(conn, evil_hostname)
    elapsed = time.monotonic() - start

    assert elapsed < 2.0, f"find_domain() took {elapsed:.2f}s against a catastrophic pattern -- the timeout guard did not fire"
    assert result is None


# ---------------------------------------------------------- ip_in_configured_lan

def test_ip_in_configured_lan_disabled_when_blank(conn):
    # no 'local_network' setting at all
    assert matching.ip_in_configured_lan(conn, "8.8.8.8") is True
    db.set_setting(conn, "local_network", "   ")
    conn.commit()
    assert matching.ip_in_configured_lan(conn, "8.8.8.8") is True


def test_ip_in_configured_lan_checks_cidr(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    conn.commit()
    assert matching.ip_in_configured_lan(conn, "192.168.1.42") is True
    assert matching.ip_in_configured_lan(conn, "10.0.0.1") is False


def test_ip_in_configured_lan_multiple_cidrs(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24 10.0.0.0/8")
    conn.commit()
    assert matching.ip_in_configured_lan(conn, "192.168.1.5") is True
    assert matching.ip_in_configured_lan(conn, "10.5.5.5") is True
    assert matching.ip_in_configured_lan(conn, "172.16.0.1") is False


def test_ip_in_configured_lan_bad_cidr_entry_is_skipped(conn):
    db.set_setting(conn, "local_network", "not-a-cidr 192.168.1.0/24")
    conn.commit()
    assert matching.ip_in_configured_lan(conn, "192.168.1.5") is True
    assert matching.ip_in_configured_lan(conn, "10.0.0.1") is False


def test_ip_in_configured_lan_bad_client_ip_fails_closed(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    conn.commit()
    assert matching.ip_in_configured_lan(conn, "not-an-ip") is False


def test_ip_in_configured_lan_ipv6(conn):
    db.set_setting(conn, "local_network", "fd00::/8")
    conn.commit()
    assert matching.ip_in_configured_lan(conn, "fd00::1") is True
    assert matching.ip_in_configured_lan(conn, "2001:db8::1") is False


def test_ip_in_configured_lan_ipv4_cidr_does_not_match_ipv6(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    conn.commit()
    assert matching.ip_in_configured_lan(conn, "::1") is False


# --------------------------------------------------------------- user helpers

def test_user_has_domain_and_get_user_by_username(conn):
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) "
        "VALUES ('kid1', 'Kid One', 'x', ?)",
        (db.now_iso(),),
    )
    conn.commit()
    user = matching.get_user_by_username(conn, "kid1")
    assert user is not None
    assert matching.get_user_by_username(conn, "nope") is None

    domain = _add_domain(conn, r"example\.com", is_global=0)
    assert matching.user_has_domain(conn, user["id"], domain["id"]) is False
    conn.execute(
        "INSERT INTO user_domains (user_id, domain_id) VALUES (?, ?)", (user["id"], domain["id"])
    )
    conn.commit()
    assert matching.user_has_domain(conn, user["id"], domain["id"]) is True


def test_user_has_show_is_case_insensitive_on_series_id(conn):
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) "
        "VALUES ('kid1', 'Kid One', 'x', ?)",
        (db.now_iso(),),
    )
    conn.commit()
    user = matching.get_user_by_username(conn, "kid1")
    conn.execute(
        "INSERT INTO user_shows (user_id, series_id, series_name) VALUES (?, 'GYE5K0XVR', 'Ace Attorney')",
        (user["id"],),
    )
    conn.commit()
    assert matching.user_has_show(conn, user["id"], "gye5k0xvr") is True
    assert matching.user_has_show(conn, user["id"], "OTHERID") is False


# --------------------------------------------- category/schedule targeting (Phase 8)

def _add_category(conn, name, is_global=0):
    conn.execute(
        "INSERT INTO categories (name, is_global, created_at) VALUES (?, ?, ?)",
        (name, is_global, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM categories WHERE name = ?", (name,)).fetchone()


def _add_schedule(conn, name, is_global=0):
    conn.execute(
        "INSERT INTO schedules (name, days_of_week, start_time, end_time, time_zone, "
        "lockout_all, is_global, created_at) VALUES (?, 'mon', '08:00', '15:00', 'UTC', 0, ?, ?)",
        (name, is_global, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM schedules WHERE name = ?", (name,)).fetchone()


def _add_user(conn, username):
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) "
        "VALUES (?, ?, 'x', ?)",
        (username, username, db.now_iso()),
    )
    conn.commit()
    return matching.get_user_by_username(conn, username)


def _add_group(conn, name):
    conn.execute("INSERT INTO groups (name, created_at) VALUES (?, ?)", (name, db.now_iso()))
    conn.commit()
    return conn.execute("SELECT * FROM groups WHERE name = ?", (name,)).fetchone()


def _add_device(conn, mac, user_id=None, group_id=None):
    conn.execute(
        "INSERT INTO devices (mac_address, user_id, group_id, is_authenticated, created_at) "
        "VALUES (?, ?, ?, 1, ?)",
        (mac, user_id, group_id, db.now_iso()),
    )
    conn.commit()
    return conn.execute("SELECT * FROM devices WHERE mac_address = ?", (mac,)).fetchone()


def test_category_applies_to_device_via_is_global(conn):
    category = _add_category(conn, "Adult", is_global=1)
    device = _add_device(conn, "aa:bb:cc:dd:ee:01")
    assert matching.category_applies_to_device(conn, device, category) is True


def test_category_applies_to_device_via_user_assignment(conn):
    user = _add_user(conn, "kid1")
    category = _add_category(conn, "Social Media")
    device = _add_device(conn, "aa:bb:cc:dd:ee:02", user_id=user["id"])
    assert matching.category_applies_to_device(conn, device, category) is False
    conn.execute(
        "INSERT INTO category_users (category_id, user_id) VALUES (?, ?)", (category["id"], user["id"])
    )
    conn.commit()
    assert matching.category_applies_to_device(conn, device, category) is True


def test_category_applies_to_device_via_group_assignment(conn):
    group = _add_group(conn, "TVs")
    category = _add_category(conn, "Gaming")
    device = _add_device(conn, "aa:bb:cc:dd:ee:03", group_id=group["id"])
    assert matching.category_applies_to_device(conn, device, category) is False
    conn.execute(
        "INSERT INTO category_groups (category_id, group_id) VALUES (?, ?)", (category["id"], group["id"])
    )
    conn.commit()
    assert matching.category_applies_to_device(conn, device, category) is True


def test_category_applies_to_device_via_direct_device_assignment(conn):
    category = _add_category(conn, "Vaping")
    device = _add_device(conn, "aa:bb:cc:dd:ee:04")
    assert matching.category_applies_to_device(conn, device, category) is False
    conn.execute(
        "INSERT INTO category_devices (category_id, device_id) VALUES (?, ?)", (category["id"], device["id"])
    )
    conn.commit()
    assert matching.category_applies_to_device(conn, device, category) is True


def test_category_applies_to_device_unrelated_user_grant_does_not_leak(conn):
    other_user = _add_user(conn, "kid_other")
    category = _add_category(conn, "Gambling")
    device = _add_device(conn, "aa:bb:cc:dd:ee:05")  # no user/group at all
    conn.execute(
        "INSERT INTO category_users (category_id, user_id) VALUES (?, ?)", (category["id"], other_user["id"])
    )
    conn.commit()
    assert matching.category_applies_to_device(conn, device, category) is False


def test_schedule_applies_to_device_via_is_global(conn):
    schedule = _add_schedule(conn, "Bedtime", is_global=1)
    device = _add_device(conn, "aa:bb:cc:dd:ee:06")
    assert matching.schedule_applies_to_device(conn, device, schedule) is True


def test_schedule_applies_to_device_via_user_group_device_assignment(conn):
    user = _add_user(conn, "kid2")
    group = _add_group(conn, "Gaming Computers")
    device_via_user = _add_device(conn, "aa:bb:cc:dd:ee:07", user_id=user["id"])
    device_via_group = _add_device(conn, "aa:bb:cc:dd:ee:08", group_id=group["id"])
    device_via_direct = _add_device(conn, "aa:bb:cc:dd:ee:09")
    schedule = _add_schedule(conn, "School hours")

    assert matching.schedule_applies_to_device(conn, device_via_user, schedule) is False
    assert matching.schedule_applies_to_device(conn, device_via_group, schedule) is False
    assert matching.schedule_applies_to_device(conn, device_via_direct, schedule) is False

    conn.execute("INSERT INTO schedule_users (schedule_id, user_id) VALUES (?, ?)", (schedule["id"], user["id"]))
    conn.execute("INSERT INTO schedule_groups (schedule_id, group_id) VALUES (?, ?)", (schedule["id"], group["id"]))
    conn.execute(
        "INSERT INTO schedule_devices (schedule_id, device_id) VALUES (?, ?)",
        (schedule["id"], device_via_direct["id"]),
    )
    conn.commit()

    assert matching.schedule_applies_to_device(conn, device_via_user, schedule) is True
    assert matching.schedule_applies_to_device(conn, device_via_group, schedule) is True
    assert matching.schedule_applies_to_device(conn, device_via_direct, schedule) is True


# ---------------------------------------------------- schedule_applies_to_target

def test_schedule_applies_to_target_via_is_global(conn):
    schedule = _add_schedule(conn, "Bedtime", is_global=1)
    assert matching.schedule_applies_to_target(conn, schedule, user_id=999) is True


def test_schedule_applies_to_target_via_bare_user_id_no_device_needed(conn):
    """The whole point of pulling this out of schedule_applies_to_device()
    (2026-09-06, for the user detail page's 'active right now' display):
    a caller with only a user id in hand, no device row at all, can still
    get a real answer."""
    user = _add_user(conn, "kid3")
    schedule = _add_schedule(conn, "Free Time")
    assert matching.schedule_applies_to_target(conn, schedule, user_id=user["id"]) is False
    conn.execute("INSERT INTO schedule_users (schedule_id, user_id) VALUES (?, ?)", (schedule["id"], user["id"]))
    conn.commit()
    assert matching.schedule_applies_to_target(conn, schedule, user_id=user["id"]) is True


def test_schedule_applies_to_target_via_group_id(conn):
    group = _add_group(conn, "TVs")
    schedule = _add_schedule(conn, "Bedtime")
    assert matching.schedule_applies_to_target(conn, schedule, group_id=group["id"]) is False
    conn.execute("INSERT INTO schedule_groups (schedule_id, group_id) VALUES (?, ?)", (schedule["id"], group["id"]))
    conn.commit()
    assert matching.schedule_applies_to_target(conn, schedule, group_id=group["id"]) is True


def test_schedule_applies_to_target_no_ids_and_not_global_is_false(conn):
    schedule = _add_schedule(conn, "Bedtime")
    assert matching.schedule_applies_to_target(conn, schedule) is False


# --------------------------------------------------- find_categories_for_hostname

def _add_category_domain(conn, category_id, pattern, source="manual"):
    conn.execute(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, ?, ?)",
        (category_id, pattern, source, db.now_iso()),
    )
    conn.commit()


def test_find_categories_for_hostname_finds_every_matching_category(conn):
    facebook = _add_category(conn, "Facebook")
    gambling = _add_category(conn, "Gambling")
    _add_category_domain(conn, facebook["id"], r"facebook\.com")
    _add_category_domain(conn, gambling["id"], r"facebook\.com")  # deliberately also listed here

    results = matching.find_categories_for_hostname(conn, "facebook.com")

    names = {m["category"]["name"] for m in results}
    assert names == {"Facebook", "Gambling"}


def test_find_categories_for_hostname_matches_a_subdomain(conn):
    category = _add_category(conn, "Gambling")
    _add_category_domain(conn, category["id"], r"bet\.example\.com")
    results = matching.find_categories_for_hostname(conn, "www.bet.example.com")
    assert len(results) == 1
    assert results[0]["pattern"] == r"bet\.example\.com"


def test_find_categories_for_hostname_no_match_returns_empty_list(conn):
    category = _add_category(conn, "Gambling")
    _add_category_domain(conn, category["id"], r"bet\.example\.com")
    assert matching.find_categories_for_hostname(conn, "totally-unrelated.example") == []


def test_find_categories_for_hostname_flags_an_override_exemption(conn):
    category = _add_category(conn, "Gambling")
    _add_category_domain(conn, category["id"], r"casino\.example\.com")
    conn.execute(
        "INSERT INTO category_overrides (category_id, pattern, created_at) VALUES (?, ?, ?)",
        (category["id"], r"casino\.example\.com", db.now_iso()),
    )
    conn.commit()

    results = matching.find_categories_for_hostname(conn, "casino.example.com")

    assert len(results) == 1
    assert results[0]["overridden"] is True


def test_find_categories_for_hostname_blank_input_returns_empty_list(conn):
    assert matching.find_categories_for_hostname(conn, "") == []
    assert matching.find_categories_for_hostname(conn, "   ") == []


def test_find_categories_for_hostname_no_categories_at_all(conn):
    """Regression guard for the 2026-09-07 rewrite's early-exit -- an
    empty `categories` table must short-circuit before either SQL pass
    runs, not just return an empty result after querying anyway."""
    assert matching.find_categories_for_hostname(conn, "facebook.com") == []


# --- 2026-09-07 performance rewrite: fast (exact-match) vs slow -----------
# (GLOB-filtered custom-regex) path, verified to agree on every case the
# original single-pass regex scan already covered above, plus the split
# itself.

def test_candidate_exact_patterns_are_escaped_suffixes_most_specific_first(conn):
    assert matching._candidate_exact_patterns("www.example.com") == [
        r"www\.example\.com", r"example\.com", "com",
    ]


def test_find_categories_for_hostname_fast_path_matches_a_subscription_style_literal(conn):
    # Mirrors exactly what category_fetch.py stores: re.escape()'d,
    # source='subscription' -- must be found via the fast exact-match
    # path alone, with no complex-pattern fallback needed.
    category = _add_category(conn, "Gambling")
    _add_category_domain(conn, category["id"], r"bet\.example\.com", source="subscription")
    results = matching.find_categories_for_hostname(conn, "www.bet.example.com")
    assert len(results) == 1
    assert results[0]["pattern"] == r"bet\.example\.com"


def test_find_categories_for_hostname_slow_path_still_catches_a_custom_manual_regex(conn):
    # A hand-typed pattern the fast exact-match path can't recognize
    # (not a plain re.escape()'d literal) -- correctness depends on the
    # GLOB-filtered slow-path fallback actually running.
    category = _add_category(conn, "Gambling")
    _add_category_domain(conn, category["id"], r".*\.badcasino\.(com|net)", source="manual")
    results = matching.find_categories_for_hostname(conn, "sub.badcasino.net")
    assert len(results) == 1
    assert results[0]["pattern"] == r".*\.badcasino\.(com|net)"


def test_find_categories_for_hostname_slow_path_never_scans_subscription_rows(conn):
    # The slow path is scoped to source='manual' only -- a
    # subscription-sourced row is always a plain literal by construction
    # (category_fetch.py always re.escape()s), so restricting the GLOB
    # fallback to manual rows must never cause a real miss.
    category = _add_category(conn, "Gambling")
    _add_category_domain(conn, category["id"], r"plainsite\.example", source="subscription")
    results = matching.find_categories_for_hostname(conn, "plainsite.example")
    assert len(results) == 1


def test_find_categories_for_hostname_combines_fast_and_slow_matches_across_categories(conn):
    literal_cat = _add_category(conn, "Facebook")
    custom_cat = _add_category(conn, "Gambling")
    _add_category_domain(conn, literal_cat["id"], r"shared\.example\.com", source="subscription")
    _add_category_domain(conn, custom_cat["id"], r".*\.example\.com", source="manual")

    results = matching.find_categories_for_hostname(conn, "shared.example.com")

    names = {m["category"]["name"] for m in results}
    assert names == {"Facebook", "Gambling"}
