"""controller/adguard_sync.py: the hard-deny rule builder, the managed-block
merge logic, and the periodic sync loop. Network access always goes through
adguard_client, which every test here fakes -- consistent with
test_controller_discovery.py not shelling out to a real `ip neigh show`.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

import adguard_sync
import db
import optigate_rewrite


def _insert_domain(conn, pattern: str, mode: str = "bump", is_global: bool = True) -> int:
    conn.execute(
        "INSERT INTO domains (pattern, mode, kind, is_global, created_at) "
        "VALUES (?, ?, 'generic', ?, datetime('now'))",
        (pattern, mode, int(is_global)),
    )
    conn.commit()
    return conn.execute("SELECT id FROM domains WHERE pattern = ?", (pattern,)).fetchone()["id"]


def _insert_device_with_binding(
    conn, mac: str, ip: str, *, bump_enabled: bool = False, active: bool = True,
    is_authenticated: bool = True, user_id: int | None = None, group_id: int | None = None,
    ignored: bool = False,
) -> int:
    conn.execute(
        "INSERT INTO devices (mac_address, bump_enabled, is_authenticated, user_id, group_id, ignored, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, datetime('now'))",
        (mac, int(bump_enabled), int(is_authenticated), user_id, group_id, int(ignored)),
    )
    device_id = conn.execute("SELECT id FROM devices WHERE mac_address = ?", (mac,)).fetchone()["id"]
    conn.execute(
        "INSERT INTO device_bindings "
        "(device_id, mac_address, ipv4_address, first_seen_at, last_seen_at, source, active) "
        "VALUES (?, ?, ?, datetime('now'), datetime('now'), 'active_scan', ?)",
        (device_id, mac, ip, int(active)),
    )
    conn.commit()
    return device_id


def _insert_group(conn, name: str, *, ignored: bool = False) -> int:
    conn.execute(
        "INSERT INTO groups (name, ignored, created_at) VALUES (?, ?, datetime('now'))", (name, int(ignored)),
    )
    conn.commit()
    return conn.execute("SELECT id FROM groups WHERE name = ?", (name,)).fetchone()["id"]


def _insert_category(conn, name: str, *, is_global: bool = False, subscription_url: str | None = None) -> int:
    conn.execute(
        "INSERT INTO categories (name, subscription_url, is_global, created_at) VALUES (?, ?, ?, datetime('now'))",
        (name, subscription_url, int(is_global)),
    )
    conn.commit()
    return conn.execute("SELECT id FROM categories WHERE name = ?", (name,)).fetchone()["id"]


def _insert_category_domains(conn, category_id: int, patterns: list[str], source: str = "manual") -> None:
    conn.executemany(
        "INSERT INTO category_domains (category_id, pattern, source, created_at) VALUES (?, ?, ?, datetime('now'))",
        [(category_id, p, source) for p in patterns],
    )
    conn.commit()


def _insert_schedule(
    conn, name: str, *, is_global: bool = False, lockout_all: bool = False, is_mode: bool = False,
    days: str = "mon", start: str = "00:00", end: str = "23:59",
) -> int:
    conn.execute(
        "INSERT INTO schedules (name, days_of_week, start_time, end_time, time_zone, "
        "lockout_all, is_global, is_mode, created_at) VALUES (?, ?, ?, ?, 'UTC', ?, ?, ?, datetime('now'))",
        (name, days, start, end, int(lockout_all), int(is_global), int(is_mode)),
    )
    conn.commit()
    return conn.execute("SELECT id FROM schedules WHERE name = ?", (name,)).fetchone()["id"]


def _insert_override(conn, schedule_id: int, *, minutes: int = 60, device_id: int) -> None:
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    conn.execute(
        "INSERT INTO schedule_overrides (schedule_id, device_id, created_at, expires_at) "
        "VALUES (?, ?, datetime('now'), ?)",
        (schedule_id, device_id, expires_at),
    )
    conn.commit()


# ============================================================
# _domain_rule
# ============================================================

def test_domain_rule_shape_mirrors_matching_pys_own_anchoring():
    rule = adguard_sync._domain_rule("crunchyroll\\.com", ["192.168.1.10"])
    assert rule == "/(?i)(?:^|\\.)(?:crunchyroll\\.com)$/$client=192.168.1.10"


def test_domain_rule_joins_multiple_client_ips_with_commas():
    rule = adguard_sync._domain_rule("example\\.com", ["10.0.0.1", "10.0.0.2"])
    assert rule.endswith("$client=10.0.0.1,10.0.0.2")


def test_domain_rule_without_block_page_ip_has_no_dnsrewrite():
    rule = adguard_sync._domain_rule("example\\.com", ["10.0.0.1"])
    assert "dnsrewrite" not in rule


def test_domain_rule_with_block_page_ip_adds_dnsrewrite():
    rule = adguard_sync._domain_rule("example\\.com", ["10.0.0.1"], block_page_ip="192.168.1.50")
    assert rule == "/(?i)(?:^|\\.)(?:example\\.com)$/$client=10.0.0.1,dnsrewrite=NOERROR;A;192.168.1.50"


# ============================================================
# build_rules
# ============================================================

def test_build_rules_empty_when_no_bump_domains(conn):
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)
    assert adguard_sync.build_rules(conn) == []


def test_build_rules_empty_when_no_non_bump_device_has_an_ip(conn):
    _insert_domain(conn, "crunchyroll\\.com")
    # Only a bump_enabled device is bound -- nothing to deny it from.
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True)
    assert adguard_sync.build_rules(conn) == []


def test_build_rules_covers_every_non_bump_device(conn):
    _insert_domain(conn, "crunchyroll\\.com")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:02", "192.168.1.11", bump_enabled=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:03", "192.168.1.12", bump_enabled=True)

    rules = adguard_sync.build_rules(conn)

    assert len(rules) == 1
    assert "192.168.1.10" in rules[0]
    assert "192.168.1.11" in rules[0]
    assert "192.168.1.12" not in rules[0], "a bump_enabled device must never be added to the deny list"


def test_build_rules_still_denies_a_bump_enabled_device_that_is_not_yet_authenticated(conn):
    """Regression test for a real gap found and fixed 2026-08-31 (same
    class of bug as classify_device()/bypass_login -- see RoadMap.md):
    build_rules() used to select on the raw bump_enabled column alone,
    so a device with bump_enabled=1 but is_authenticated=0 (a genuinely
    new PREAUTH device, or one pre-configured for bump ahead of its
    first login) was excluded from the hard-deny list -- while ALSO not
    being nftables bump_v4-eligible (bump_eligible() requires
    AUTHENTICATED too) -- a full, unfiltered bypass of the hard-deny
    invariant this module exists to enforce. Must now be denied, same
    as any other non-bump-eligible device, until it actually logs in."""
    _insert_domain(conn, "crunchyroll\\.com")
    _insert_device_with_binding(
        conn, "aa:bb:cc:dd:ee:04", "192.168.1.13", bump_enabled=True, is_authenticated=False
    )

    rules = adguard_sync.build_rules(conn)

    assert len(rules) == 1
    assert "192.168.1.13" in rules[0]


def test_build_rules_threads_block_page_ip_into_every_rule(conn):
    _insert_domain(conn, "crunchyroll\\.com")
    _insert_domain(conn, "example\\.com")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    rules = adguard_sync.build_rules(conn, block_page_ip="192.168.1.50")

    assert len(rules) == 2
    assert all("dnsrewrite=NOERROR;A;192.168.1.50" in r for r in rules)


def test_build_rules_ignores_inactive_bindings(conn):
    _insert_domain(conn, "crunchyroll\\.com")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False, active=False)
    assert adguard_sync.build_rules(conn) == [], "a stale (inactive) binding must not contribute an IP"


def test_build_rules_emits_one_rule_per_bump_domain(conn):
    _insert_domain(conn, "crunchyroll\\.com")
    _insert_domain(conn, "some-other-bump-site\\.com")
    _insert_domain(conn, "a-splice-domain\\.com", mode="splice")  # must be ignored entirely
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    rules = adguard_sync.build_rules(conn)

    assert len(rules) == 2
    assert any("crunchyroll" in r for r in rules)
    assert any("some-other-bump-site" in r for r in rules)


def test_build_rules_denies_a_bump_eligible_device_from_an_unassigned_non_global_domain(conn):
    """The core 2026-08-31 rework: a bump-eligible device used to get a
    free DNS pass to ANY bump-mode domain -- now AdGuard also checks
    whether this SPECIFIC domain is actually assigned to it, same as
    Squid's own authz_helper.decide() does after decryption."""
    domain_id = _insert_domain(conn, "example\\.com", is_global=False)
    _insert_device_with_binding(
        conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True,
    )

    rules = adguard_sync.build_rules(conn)

    assert len(rules) == 1
    assert "192.168.1.10" in rules[0]


def test_build_rules_allows_a_bump_eligible_device_once_the_domain_is_assigned(conn):
    domain_id = _insert_domain(conn, "example\\.com", is_global=False)
    device_id = _insert_device_with_binding(
        conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True,
    )
    conn.execute("INSERT INTO device_domains (device_id, domain_id) VALUES (?, ?)", (device_id, domain_id))
    conn.commit()

    assert adguard_sync.build_rules(conn) == []


def test_build_rules_still_denies_a_non_bump_eligible_device_even_on_a_global_domain(conn):
    """is_global on a bump-mode domain means "assigned to everyone" --
    it must never also mean "skip the bump-eligibility gate"."""
    _insert_domain(conn, "example\\.com", is_global=True)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    rules = adguard_sync.build_rules(conn)

    assert len(rules) == 1
    assert "192.168.1.10" in rules[0]


def test_build_rules_excludes_an_ignored_device(conn):
    """2026-08-31, project owner's explicit direction: "AdGuard should
    apply a baseline of protection... unless the device/user/group is
    set to bypass/ignore." An ignored device must never appear in a deny
    rule, even one that would otherwise clearly be denied."""
    _insert_domain(conn, "example\\.com", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False, ignored=True)

    assert adguard_sync.build_rules(conn) == []


def test_build_rules_excludes_a_device_in_an_ignored_group(conn):
    """Group-level ignore (added 2026-09-07, db.py's schema comment on
    groups.ignored) must exclude a device from AdGuard's own deny rules
    exactly like the device's own `ignored` bit does above, even though
    the device's own column reads 0."""
    group_id = _insert_group(conn, "IoT", ignored=True)
    _insert_domain(conn, "example\\.com", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False, group_id=group_id)

    assert adguard_sync.build_rules(conn) == []


# ============================================================
# _ech_strip_rule / build_ech_strip_rules (added 2026-09-09, RoadMap.md
# item 17 -- see build_ech_strip_rules()'s own docstring for the full,
# live-verified story: ECH-carrying bump-mode domains defeat Squid's
# own bump/splice decision, and the fix is withholding just the
# HTTPS-type DNS record for the exact devices that need Squid to
# actually inspect that domain.)
# ============================================================

def test_ech_strip_rule_shape():
    rule = adguard_sync._ech_strip_rule("crunchyroll\\.com", ["192.168.1.10"])
    assert rule == "/(?i)(?:^|\\.)(?:crunchyroll\\.com)$/$client=192.168.1.10,dnstype=HTTPS"


def test_ech_strip_rule_joins_multiple_client_ips_with_commas():
    rule = adguard_sync._ech_strip_rule("example\\.com", ["10.0.0.1", "10.0.0.2"])
    assert rule == "/(?i)(?:^|\\.)(?:example\\.com)$/$client=10.0.0.1,10.0.0.2,dnstype=HTTPS"


def test_build_ech_strip_rules_empty_when_no_bump_domains(conn):
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True)
    assert adguard_sync.build_ech_strip_rules(conn) == []


def test_build_ech_strip_rules_empty_when_no_device_is_authorized(conn):
    _insert_domain(conn, "crunchyroll\\.com", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True)
    assert adguard_sync.build_ech_strip_rules(conn) == []


def test_build_ech_strip_rules_covers_an_authorized_bump_eligible_device(conn):
    _insert_domain(conn, "crunchyroll\\.com", is_global=True)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True)

    rules = adguard_sync.build_ech_strip_rules(conn)

    assert len(rules) == 1
    assert "192.168.1.10" in rules[0]
    assert "dnstype=HTTPS" in rules[0]


def test_build_ech_strip_rules_excludes_a_non_bump_eligible_device(conn):
    """A device not bump_enabled (or not yet authenticated) never has
    its traffic routed through Squid for this domain -- withholding its
    ECH/HTTP-3 hint would be pure downside for it, zero benefit."""
    _insert_domain(conn, "crunchyroll\\.com", is_global=True)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    assert adguard_sync.build_ech_strip_rules(conn) == []


def test_build_ech_strip_rules_excludes_a_bump_enabled_device_not_yet_authenticated(conn):
    _insert_domain(conn, "crunchyroll\\.com", is_global=True)
    _insert_device_with_binding(
        conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=False
    )

    assert adguard_sync.build_ech_strip_rules(conn) == []


def test_build_ech_strip_rules_excludes_a_bump_eligible_device_not_assigned_a_non_global_domain(conn):
    _insert_domain(conn, "example\\.com", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True)

    assert adguard_sync.build_ech_strip_rules(conn) == []


def test_build_ech_strip_rules_covers_a_bump_eligible_device_once_assigned(conn):
    domain_id = _insert_domain(conn, "example\\.com", is_global=False)
    device_id = _insert_device_with_binding(
        conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True,
    )
    conn.execute("INSERT INTO device_domains (device_id, domain_id) VALUES (?, ?)", (device_id, domain_id))
    conn.commit()

    rules = adguard_sync.build_ech_strip_rules(conn)

    assert len(rules) == 1
    assert "192.168.1.10" in rules[0]


def test_build_ech_strip_rules_ignores_splice_mode_domains(conn):
    _insert_domain(conn, "a-splice-domain\\.com", mode="splice", is_global=True)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True)

    assert adguard_sync.build_ech_strip_rules(conn) == []


def test_build_ech_strip_rules_excludes_an_ignored_device(conn):
    _insert_domain(conn, "crunchyroll\\.com", is_global=True)
    _insert_device_with_binding(
        conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True, ignored=True,
    )

    assert adguard_sync.build_ech_strip_rules(conn) == []


def test_build_ech_strip_rules_emits_one_rule_per_bump_domain(conn):
    _insert_domain(conn, "crunchyroll\\.com", is_global=True)
    _insert_domain(conn, "asurascans\\.com", is_global=True)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True)

    rules = adguard_sync.build_ech_strip_rules(conn)

    assert len(rules) == 2
    assert any("crunchyroll" in r for r in rules)
    assert any("asurascans" in r for r in rules)


def test_build_ech_strip_rules_accepts_a_shared_eligible_devices_list(conn):
    """Same efficiency contract as build_rules()/build_splice_deny_rules()
    -- sync_once() fetches eligible_devices once and threads it through
    every builder, this one included."""
    _insert_domain(conn, "crunchyroll\\.com", is_global=True)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=True, is_authenticated=True)

    shared = adguard_sync._fetch_eligible_devices(conn)
    rules = adguard_sync.build_ech_strip_rules(conn, eligible_devices=shared)

    assert len(rules) == 1
    assert "192.168.1.10" in rules[0]


# ============================================================
# build_splice_deny_rules (added 2026-08-31, see its own docstring / GH #9)
# ============================================================

def test_build_splice_deny_rules_denies_a_device_with_no_assignment(conn):
    _insert_domain(conn, "example\\.com", mode="splice", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")

    rules = adguard_sync.build_splice_deny_rules(conn)

    assert len(rules) == 1
    assert "192.168.1.10" in rules[0]


def test_build_splice_deny_rules_excludes_a_user_assigned_device(conn):
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) "
        "VALUES ('kid1', 'kid1', 'x', datetime('now'))"
    )
    conn.commit()
    user_id = conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    domain_id = _insert_domain(conn, "example\\.com", mode="splice", is_global=False)
    conn.execute("INSERT INTO user_domains (user_id, domain_id) VALUES (?, ?)", (user_id, domain_id))
    conn.commit()
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", user_id=user_id)

    assert adguard_sync.build_splice_deny_rules(conn) == []


def test_build_splice_deny_rules_excludes_a_group_assigned_device(conn):
    """The other half of the same fix common/matching.py's
    device_domain_reason() shipped for Squid -- AdGuard now respects a
    group_domains grant too, not just user_domains."""
    group_id = _insert_group(conn, "TVs")
    domain_id = _insert_domain(conn, "example\\.com", mode="splice", is_global=False)
    conn.execute("INSERT INTO group_domains (group_id, domain_id) VALUES (?, ?)", (group_id, domain_id))
    conn.commit()
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", group_id=group_id)

    assert adguard_sync.build_splice_deny_rules(conn) == []


def test_build_splice_deny_rules_ignores_global_domains(conn):
    _insert_domain(conn, "example\\.com", mode="splice", is_global=True)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    assert adguard_sync.build_splice_deny_rules(conn) == []


def test_build_splice_deny_rules_ignores_bump_mode_domains(conn):
    """Bump-mode domains are build_rules()'s own job -- this function only
    ever touches splice-mode, is_global=0 domains."""
    _insert_domain(conn, "crunchyroll\\.com", mode="bump", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10")
    assert adguard_sync.build_splice_deny_rules(conn) == []


def test_build_splice_deny_rules_empty_when_no_device_has_an_ip(conn):
    _insert_domain(conn, "example\\.com", mode="splice", is_global=False)
    assert adguard_sync.build_splice_deny_rules(conn) == []


def test_build_splice_deny_rules_excludes_an_ignored_device(conn):
    """Same exclusion as build_rules() -- see its own test and
    _build_domain_deny_rules()'s docstring."""
    _insert_domain(conn, "example\\.com", mode="splice", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", ignored=True)

    assert adguard_sync.build_splice_deny_rules(conn) == []


def test_sync_once_pushes_both_bump_and_splice_rule_sets(conn, monkeypatch):
    _insert_domain(conn, "crunchyroll\\.com", mode="bump")
    _insert_domain(conn, "example\\.com", mode="splice", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})
    pushed = {}
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: pushed.setdefault("rules", rules),
    )

    count = adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    # one bump hard-deny + one splice deny (same device denied both ways)
    # + the always-on anti-DoH baseline (build_anti_doh_rules(), added
    # 2026-09-02 -- see that function's own docstring).
    assert count == 2 + len(adguard_sync.build_anti_doh_rules())
    managed = pushed["rules"][1:-1]  # strip the begin/end markers
    assert any("crunchyroll" in r for r in managed)
    assert any("example" in r for r in managed)
    assert any("use-application-dns" in r for r in managed)


def test_sync_once_includes_ech_strip_rules_for_a_bump_eligible_authorized_device(conn, monkeypatch):
    _insert_domain(conn, "crunchyroll\\.com", mode="bump", is_global=True)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:02", "192.168.1.20", bump_enabled=True, is_authenticated=True)

    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})
    pushed = {}
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: pushed.setdefault("rules", rules),
    )

    count = adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    # 1 ECH-strip rule + the always-on anti-DoH baseline -- no bump
    # hard-deny here (the device IS authorized, is_global=True), no
    # splice-deny (no splice-mode domains configured).
    assert count == 1 + len(adguard_sync.build_anti_doh_rules())
    managed = pushed["rules"][1:-1]
    assert any("192.168.1.20" in r and "dnstype=HTTPS" in r for r in managed)


def test_sync_once_fetches_the_device_list_exactly_once(conn, monkeypatch):
    """Regression test for a real efficiency gap (fixed 2026-09-02):
    build_rules()/build_splice_deny_rules()/build_category_deny_rules()
    each independently re-ran the identical devices JOIN device_bindings
    query and re-classified every row, so one sync_once() cycle issued
    that query 3 times instead of once. Confirms _fetch_eligible_devices()
    -- the extracted, now-shared query -- is called exactly once per
    cycle regardless of how many of the three builders end up needing
    the result."""
    _insert_domain(conn, "crunchyroll\\.com", mode="bump")
    _insert_domain(conn, "example\\.com", mode="splice", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})
    monkeypatch.setattr(adguard_sync.adguard_client, "set_custom_rules", lambda *a, **k: None)

    calls = []
    real_fetch = adguard_sync._fetch_eligible_devices

    def counting_fetch(conn_arg):
        calls.append(1)
        return real_fetch(conn_arg)

    monkeypatch.setattr(adguard_sync, "_fetch_eligible_devices", counting_fetch)

    adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    assert len(calls) == 1, f"expected _fetch_eligible_devices() called exactly once per cycle, got {len(calls)}"


def test_build_rules_and_build_splice_deny_rules_accept_a_shared_eligible_devices_list(conn):
    """Confirms passing a pre-fetched eligible_devices list produces the
    identical result to letting each function fetch its own -- the
    actual property sync_once()'s sharing depends on."""
    _insert_domain(conn, "crunchyroll\\.com", mode="bump")
    _insert_domain(conn, "example\\.com", mode="splice", is_global=False)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    shared = adguard_sync._fetch_eligible_devices(conn)

    assert adguard_sync.build_rules(conn, eligible_devices=shared) == adguard_sync.build_rules(conn)
    assert adguard_sync.build_splice_deny_rules(conn, eligible_devices=shared) == adguard_sync.build_splice_deny_rules(conn)
    assert adguard_sync.build_category_deny_rules(conn, eligible_devices=shared) == adguard_sync.build_category_deny_rules(conn)


# ============================================================
# _strip_managed_block
# ============================================================

def test_strip_managed_block_removes_only_the_bracketed_lines():
    rules = [
        "! admin's own rule",
        adguard_sync._MARKER_BEGIN,
        "/(?i)(?:^|\\.)(?:crunchyroll\\.com)$/$client=192.168.1.10",
        adguard_sync._MARKER_END,
        "||another-admin-rule.com^",
    ]
    assert adguard_sync._strip_managed_block(rules) == [
        "! admin's own rule",
        "||another-admin-rule.com^",
    ]


def test_strip_managed_block_is_a_noop_when_no_marker_present():
    rules = ["||some-rule.com^"]
    assert adguard_sync._strip_managed_block(rules) == rules


def test_strip_managed_block_handles_a_dangling_begin_marker():
    """An interrupted previous sync (or a hand-edit) could leave a begin
    marker with no matching end -- drop from there to the end of the
    list rather than leave a permanently-dangling block."""
    rules = ["||kept.com^", adguard_sync._MARKER_BEGIN, "/some-rule/$client=1.2.3.4"]
    assert adguard_sync._strip_managed_block(rules) == ["||kept.com^"]


# ============================================================
# sync_once
# ============================================================

def test_sync_once_preserves_admin_rules_and_replaces_the_managed_block(conn, monkeypatch):
    _insert_domain(conn, "crunchyroll\\.com")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    existing = [
        "! an admin's own rule",
        adguard_sync._MARKER_BEGIN,
        "/some-stale-rule/$client=10.0.0.1",
        adguard_sync._MARKER_END,
    ]
    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: list(existing))
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})

    pushed = {}
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: pushed.setdefault("rules", rules),
    )

    count = adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    # 1 bump hard-deny + the always-on anti-DoH baseline (2026-09-02).
    assert count == 1 + len(adguard_sync.build_anti_doh_rules())
    assert pushed["rules"][0] == "! an admin's own rule"
    assert pushed["rules"][1] == adguard_sync._MARKER_BEGIN
    assert "192.168.1.10" in pushed["rules"][2]
    assert pushed["rules"][-1] == adguard_sync._MARKER_END


def test_sync_once_with_nothing_to_deny_still_clears_a_stale_managed_block(conn, monkeypatch):
    """No bump/splice/category domains configured (or no non-bump device
    known yet) -- build_rules()/build_splice_deny_rules()/
    build_category_deny_rules() all return []. A previous cycle's now-
    stale managed block must still be cleared, not left in place
    forever. build_anti_doh_rules() is unconditional (2026-09-02), so
    the managed block itself is never fully empty anymore -- this test
    now checks that ONLY the anti-DoH baseline survives, not that
    nothing does."""
    existing = ["! kept", adguard_sync._MARKER_BEGIN, "/stale/$client=1.2.3.4", adguard_sync._MARKER_END]
    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: list(existing))
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})

    pushed = {}
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: pushed.setdefault("rules", rules),
    )

    count = adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    anti_doh = adguard_sync.build_anti_doh_rules()
    assert count == len(anti_doh)
    assert pushed["rules"] == ["! kept", adguard_sync._MARKER_BEGIN, *anti_doh, adguard_sync._MARKER_END]


# ============================================================
# sync_once: skip the write when nothing actually changed (real gap
# found live 2026-09-11 -- see this function's own dated docstring).
# set_custom_rules() has no incremental API: every call is a full
# tear-down-and-rebuild of AdGuard's rule engine, which needs a brief
# moment to recompile -- calling it every 30s regardless of whether
# anything changed created a small, constantly-recurring window where
# two unrelated live tests (Crunchyroll, Webtoons) both showed a
# correctly-denied device getting through anyway.
# ============================================================

def test_sync_once_skips_the_write_when_nothing_changed(conn, monkeypatch):
    _insert_domain(conn, "crunchyroll\\.com", mode="bump")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})

    # First cycle computes the real managed block -- capture exactly
    # what it would push, then have get_custom_rules report THAT as
    # AdGuard's current state on the second cycle, simulating "the
    # previous cycle's write already landed, nothing has changed since."
    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    first_push = {}
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: first_push.setdefault("rules", rules),
    )
    adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")
    assert "rules" in first_push, "expected the first cycle (empty -> real rules) to actually write"

    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: list(first_push["rules"]))
    write_calls = []
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: write_calls.append(rules),
    )

    adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    assert write_calls == [], "expected the second, unchanged cycle to skip set_custom_rules entirely"


def test_sync_once_still_writes_when_something_actually_changed(conn, monkeypatch):
    """The diff-and-skip fix must not turn into diff-and-NEVER-write --
    a real, detectable change still has to go through."""
    _insert_domain(conn, "crunchyroll\\.com", mode="bump")
    device_id = _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})

    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    first_push = {}
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: first_push.setdefault("rules", rules),
    )
    adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    # A real change: a second device now also needs denying.
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:02", "192.168.1.20", bump_enabled=False)
    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: list(first_push["rules"]))
    write_calls = []
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: write_calls.append(rules),
    )

    adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    assert len(write_calls) == 1, "expected the cycle with a real change to actually write"
    assert any("192.168.1.20" in r for r in write_calls[0])


def test_sync_once_skip_does_not_affect_the_other_independent_sync_calls(conn, monkeypatch):
    """sync_category_subscriptions()/sync_safesearch()/
    sync_optigate_rewrite() are separate mechanisms with their own
    success/failure shape -- skipping the custom-rules write must not
    accidentally skip these too."""
    _insert_domain(conn, "crunchyroll\\.com", mode="bump")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    first_push = {}
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: first_push.setdefault("rules", rules),
    )
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})
    adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: list(first_push["rules"]))
    monkeypatch.setattr(adguard_sync.adguard_client, "set_custom_rules", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("set_custom_rules must not be called on an unchanged cycle")
    ))
    safesearch_calls = []
    monkeypatch.setattr(adguard_sync, "sync_safesearch", lambda *a, **k: safesearch_calls.append(1))
    rewrite_calls = []
    monkeypatch.setattr(adguard_sync, "sync_optigate_rewrite", lambda *a, **k: rewrite_calls.append(1))
    subs_calls = []
    monkeypatch.setattr(adguard_sync, "sync_category_subscriptions", lambda *a, **k: subs_calls.append(1))

    adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    assert safesearch_calls == [1]
    assert rewrite_calls == [1]
    assert subs_calls == [1]


# ============================================================
# run_loop -- wiring sync_once() into a background PeriodicTask
# ============================================================
#
# Same reasoning/pattern as test_controller_discovery.py's run_loop
# tests: run_loop() opens its OWN connection lazily on its background
# thread, so the `conn` fixture's monkeypatched db.DB_PATH is what lets
# that internal db.get_conn() call land on the same on-disk test DB
# these tests read back from.

def test_run_loop_calls_sync_repeatedly(conn, monkeypatch):
    _insert_domain(conn, "crunchyroll\\.com")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.10", bump_enabled=False)

    calls = []
    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: calls.append(rules),
    )

    task = adguard_sync.run_loop(interval=0.02, base_url="http://x", username="a", password="b")
    try:
        time.sleep(0.15)
    finally:
        task.stop()

    assert len(calls) >= 2, "expected sync_once to run repeatedly on the interval"
    assert any("192.168.1.10" in r for r in calls[0])


def test_run_loop_stops_promptly(conn, monkeypatch):
    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})
    monkeypatch.setattr(adguard_sync.adguard_client, "set_custom_rules", lambda *a, **k: None)

    task = adguard_sync.run_loop(interval=0.05, base_url="http://x", username="a", password="b")
    time.sleep(0.02)
    started_stop = time.monotonic()
    task.stop()
    elapsed = time.monotonic() - started_stop
    assert elapsed < 0.5, f"stop() took {elapsed:.3f}s, expected it to return promptly"


def test_run_loop_reports_sync_errors_via_on_error_without_dying(conn, monkeypatch):
    def _boom(*a, **k):
        raise adguard_sync.adguard_client.AdGuardError("adguard unreachable")

    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", _boom)

    errors = []
    lock = threading.Lock()

    def on_error(exc):
        with lock:
            errors.append(exc)

    task = adguard_sync.run_loop(
        interval=0.02, base_url="http://x", username="a", password="b", on_error=on_error
    )
    try:
        time.sleep(0.1)
    finally:
        task.stop()

    with lock:
        got = len(errors)
    assert got >= 2, f"expected the loop to keep retrying (and reporting) after failures, got {got}"


# ============================================================
# Phase 8: build_category_deny_rules
# ============================================================

def test_build_category_deny_rules_global_category_produces_unscoped_rules(conn):
    category = _insert_category(conn, "Gambling", is_global=True)
    _insert_category_domains(conn, category, [r"bet\.example\.com"])
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:01", "192.168.1.11")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:02", "192.168.1.12")

    rules = adguard_sync.build_category_deny_rules(conn)

    assert rules == ["/(?i)(?:^|\\.)(?:bet\\.example\\.com)$/"]


def test_build_category_deny_rules_scoped_to_one_user_only_denies_their_devices(conn):
    category = _insert_category(conn, "Social Media")
    _insert_category_domains(conn, category, [r"social\.example\.com"])
    conn.execute(
        "INSERT INTO users (username, display_name, password_hash, created_at) "
        "VALUES ('kid1', 'Kid One', 'x', datetime('now'))"
    )
    conn.commit()
    user_id = conn.execute("SELECT id FROM users WHERE username = 'kid1'").fetchone()["id"]
    kid_device = _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:03", "192.168.1.13", user_id=user_id)
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:04", "192.168.1.14")
    conn.execute("INSERT INTO category_users (category_id, user_id) VALUES (?, ?)", (category, user_id))
    conn.commit()

    rules = adguard_sync.build_category_deny_rules(conn)

    assert rules == ["/(?i)(?:^|\\.)(?:social\\.example\\.com)$/$client=192.168.1.13"]
    assert "192.168.1.14" not in rules[0]


def test_build_category_deny_rules_override_excludes_that_domain(conn):
    category = _insert_category(conn, "Gambling", is_global=True)
    _insert_category_domains(conn, category, [r"bet\.example\.com", r"casino\.example\.com"])
    conn.execute(
        "INSERT INTO category_overrides (category_id, pattern, created_at) VALUES (?, ?, datetime('now'))",
        (category, r"casino\.example\.com"),
    )
    conn.commit()
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:05", "192.168.1.15")

    rules = adguard_sync.build_category_deny_rules(conn)

    assert rules == ["/(?i)(?:^|\\.)(?:bet\\.example\\.com)$/"]


def test_build_category_deny_rules_excludes_an_ignored_device_from_a_global_category(conn):
    category = _insert_category(conn, "Gambling", is_global=True)
    _insert_category_domains(conn, category, [r"bet\.example\.com"])
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:06", "192.168.1.16")
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:07", "192.168.1.17", ignored=True)

    rules = adguard_sync.build_category_deny_rules(conn)

    # Still unscoped -- the ignored device was never "eligible" to begin
    # with, so the remaining one eligible device is still "everyone".
    assert rules == ["/(?i)(?:^|\\.)(?:bet\\.example\\.com)$/"]


def test_build_category_deny_rules_skips_a_category_over_the_scoping_threshold(conn, monkeypatch):
    monkeypatch.setattr(adguard_sync, "MAX_SCOPED_CATEGORY_DOMAINS", 1)
    category = _insert_category(conn, "Porn", is_global=True)
    _insert_category_domains(conn, category, [r"a\.example\.com", r"b\.example\.com"])
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:08", "192.168.1.18")

    rules = adguard_sync.build_category_deny_rules(conn)

    assert rules == []


def test_build_category_deny_rules_schedule_gated_category_only_active_in_window(conn):
    category = _insert_category(conn, "Gaming")
    _insert_category_domains(conn, category, [r"games\.example\.com"])
    device = _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:09", "192.168.1.19")
    schedule = _insert_schedule(conn, "School hours", is_global=True, days="mon", start="08:00", end="15:00")
    conn.execute(
        "INSERT INTO schedule_categories (schedule_id, category_id) VALUES (?, ?)", (schedule, category)
    )
    conn.commit()

    during = datetime(2026, 8, 31, 10, 0, tzinfo=timezone.utc)  # Monday 10:00 -- in window
    outside = datetime(2026, 8, 31, 20, 0, tzinfo=timezone.utc)  # Monday 20:00 -- outside window

    assert adguard_sync.build_category_deny_rules(conn, now=during) == [
        "/(?i)(?:^|\\.)(?:games\\.example\\.com)$/"
    ]
    assert adguard_sync.build_category_deny_rules(conn, now=outside) == []


def test_build_category_deny_rules_override_suppresses_a_mode_gating_schedule(conn):
    # School's window is active by the clock, but an override forcing
    # Free Time (a different is_mode schedule targeting the same device)
    # should suppress School's category gate for the duration -- the
    # same "instead of" semantics common/schedule_eval.py's
    # is_full_lockout_active() tests already cover for the nftables side.
    category = _insert_category(conn, "Gaming")
    _insert_category_domains(conn, category, [r"games\.example\.com"])
    device = _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:20", "192.168.1.30")
    school = _insert_schedule(conn, "School hours", is_global=True, is_mode=True,
                               days="mon", start="08:00", end="15:00")
    free_time = _insert_schedule(conn, "Free Time", is_global=True, is_mode=True,
                                  days="mon,tue,wed,thu,fri,sat,sun", start="00:00", end="23:59")
    conn.execute("INSERT INTO schedule_categories (schedule_id, category_id) VALUES (?, ?)", (school, category))
    conn.commit()
    _insert_override(conn, free_time, device_id=device)

    during_school = datetime(2026, 8, 31, 10, 0, tzinfo=timezone.utc)  # Monday 10:00 -- School's window
    assert adguard_sync.build_category_deny_rules(conn, now=during_school) == []


def test_build_category_deny_rules_no_applicable_devices_contributes_nothing(conn):
    category = _insert_category(conn, "Vaping")  # no is_global, no assignment at all
    _insert_category_domains(conn, category, [r"vape\.example\.com"])
    _insert_device_with_binding(conn, "aa:bb:cc:dd:ee:10", "192.168.1.20")

    assert adguard_sync.build_category_deny_rules(conn) == []


# ============================================================
# build_anti_doh_rules -- 2026-09-02, closing the DNS-over-HTTPS
# bypass found during the brute-force/injection audit
# ============================================================

def test_build_anti_doh_rules_is_never_empty():
    # Unlike every other builder in this module, there's no DB state
    # that could ever make this return nothing -- it's a fixed,
    # unconditional baseline.
    assert adguard_sync.build_anti_doh_rules() != []


def test_build_anti_doh_rules_covers_the_firefox_canary_domain():
    rules = adguard_sync.build_anti_doh_rules()
    assert any("use-application-dns.net" in r for r in rules)


def test_build_anti_doh_rules_covers_known_public_doh_providers():
    rules = adguard_sync.build_anti_doh_rules()
    joined = " ".join(rules)
    for provider in ("cloudflare-dns.com", "dns.google", "dns.quad9.net"):
        assert provider in joined


def test_build_anti_doh_rules_produces_unscoped_rules_not_client_scoped():
    # Deliberately not device-scoped -- see the function's own docstring
    # for why this isn't a per-device or per-household decision. A
    # $client= modifier would mean this file's helper functions somehow
    # decided who it applies to; it must apply to everyone.
    for rule in adguard_sync.build_anti_doh_rules():
        assert "$client=" not in rule


def test_build_anti_doh_rules_needs_no_db_connection():
    # No `conn` parameter at all -- confirms this reads no per-household
    # state (see the function's own docstring's last paragraph).
    import inspect
    assert list(inspect.signature(adguard_sync.build_anti_doh_rules).parameters) == []


def test_sync_once_always_includes_the_anti_doh_baseline_even_with_nothing_else_configured(conn, monkeypatch):
    """No domains, no categories, no devices at all -- every OTHER
    builder in sync_once() returns [], but the anti-DoH baseline must
    still be pushed."""
    monkeypatch.setattr(adguard_sync.adguard_client, "get_custom_rules", lambda *a, **k: [])
    monkeypatch.setattr(adguard_sync.adguard_client, "get_safesearch_status", lambda *a, **k: {"enabled": False})
    pushed = {}
    monkeypatch.setattr(
        adguard_sync.adguard_client, "set_custom_rules",
        lambda base_url, u, p, rules: pushed.setdefault("rules", rules),
    )

    count = adguard_sync.sync_once(conn, "http://127.0.0.1:3000", "admin", "x")

    anti_doh = adguard_sync.build_anti_doh_rules()
    assert count == len(anti_doh)
    assert pushed["rules"][1:-1] == anti_doh


# ============================================================
# Phase 8: sync_category_subscriptions
# ============================================================

class _FakeAdGuardClient:
    """Records calls instead of hitting the network -- swapped in via
    monkeypatch.setattr(adguard_sync, "adguard_client", ...)."""

    DEFAULT_TIMEOUT = 5.0

    def __init__(self, existing_filters=None, safesearch=None, rewrites=None):
        self.filters = list(existing_filters or [])
        self.calls = []
        self.safesearch = dict(safesearch) if safesearch is not None else {
            "enabled": False, "bing": True, "duckduckgo": True, "ecosia": True,
            "google": True, "pixabay": True, "yandex": True, "youtube": True,
        }
        self.rewrites = [dict(r) for r in (rewrites or [])]

    def get_filters_status(self, base_url, username, password, timeout=None):
        return self.filters

    def add_filter_url(self, base_url, username, password, name, url, timeout=None):
        self.calls.append(("add", name, url))
        self.filters.append({"id": len(self.filters) + 1, "enabled": True, "name": name, "url": url})

    def set_filter_url_enabled(self, base_url, username, password, url, name, enabled, timeout=None):
        self.calls.append(("set_enabled", url, enabled))
        for f in self.filters:
            if f["url"] == url:
                f["enabled"] = enabled

    def get_safesearch_status(self, base_url, username, password, timeout=None):
        return dict(self.safesearch)

    def set_safesearch_settings(self, base_url, username, password, config, timeout=None):
        self.calls.append(("safesearch", dict(config)))
        self.safesearch = dict(config)

    def get_rewrites(self, base_url, username, password, timeout=None):
        return [dict(r) for r in self.rewrites]

    def add_rewrite(self, base_url, username, password, domain, answer, timeout=None):
        self.calls.append(("add_rewrite", domain, answer))
        self.rewrites.append({"domain": domain, "answer": answer, "enabled": True})

    def delete_rewrite(self, base_url, username, password, domain, answer, timeout=None):
        self.calls.append(("delete_rewrite", domain, answer))
        self.rewrites = [r for r in self.rewrites if not (r["domain"] == domain and r["answer"] == answer)]


def test_sync_category_subscriptions_skips_categories_at_or_under_threshold(conn, monkeypatch):
    category = _insert_category(conn, "Small", is_global=True, subscription_url="https://example.invalid/small.txt")
    _insert_category_domains(conn, category, [r"a\.example\.com"])
    fake = _FakeAdGuardClient()
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    adguard_sync.sync_category_subscriptions(conn, "http://x", "admin", "pw")

    assert fake.calls == []


def test_sync_category_subscriptions_adds_a_new_global_category_enabled(conn, monkeypatch):
    monkeypatch.setattr(adguard_sync, "MAX_SCOPED_CATEGORY_DOMAINS", 0)
    category = _insert_category(conn, "Porn", is_global=True, subscription_url="https://example.invalid/porn.txt")
    _insert_category_domains(conn, category, [r"a\.example\.com"])
    fake = _FakeAdGuardClient()
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    adguard_sync.sync_category_subscriptions(conn, "http://x", "admin", "pw")

    assert fake.calls == [("add", "Porn", "https://example.invalid/porn.txt")]
    assert fake.filters[0]["enabled"] is True


def test_sync_category_subscriptions_enables_only_during_an_active_gating_schedule(conn, monkeypatch):
    monkeypatch.setattr(adguard_sync, "MAX_SCOPED_CATEGORY_DOMAINS", 0)
    category = _insert_category(conn, "Gaming", is_global=False, subscription_url="https://example.invalid/gaming.txt")
    _insert_category_domains(conn, category, [r"a\.example\.com"])
    schedule = _insert_schedule(conn, "School hours", is_global=True, days="mon", start="08:00", end="15:00")
    conn.execute("INSERT INTO schedule_categories (schedule_id, category_id) VALUES (?, ?)", (schedule, category))
    conn.commit()
    fake = _FakeAdGuardClient()
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    outside = datetime(2026, 8, 31, 20, 0, tzinfo=timezone.utc)
    adguard_sync.sync_category_subscriptions(conn, "http://x", "admin", "pw", now=outside)
    assert fake.calls == [
        ("add", "Gaming", "https://example.invalid/gaming.txt"),
        ("set_enabled", "https://example.invalid/gaming.txt", False),
    ]

    fake.calls.clear()
    during = datetime(2026, 8, 31, 10, 0, tzinfo=timezone.utc)
    adguard_sync.sync_category_subscriptions(conn, "http://x", "admin", "pw", now=during)
    assert fake.calls == [("set_enabled", "https://example.invalid/gaming.txt", True)]


def test_sync_category_subscriptions_never_removes_an_existing_filter(conn, monkeypatch):
    monkeypatch.setattr(adguard_sync, "MAX_SCOPED_CATEGORY_DOMAINS", 0)
    category = _insert_category(conn, "Porn", is_global=False, subscription_url="https://example.invalid/porn.txt")
    _insert_category_domains(conn, category, [r"a\.example\.com"])
    fake = _FakeAdGuardClient(
        existing_filters=[{"id": 1, "enabled": True, "name": "Porn", "url": "https://example.invalid/porn.txt"}]
    )
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    adguard_sync.sync_category_subscriptions(conn, "http://x", "admin", "pw")

    # is_global=False and no gating schedule -- should be disabled, not removed.
    assert fake.calls == [("set_enabled", "https://example.invalid/porn.txt", False)]
    assert len(fake.filters) == 1


# ============================================================
# G3: sync_safesearch
# ============================================================

def test_sync_safesearch_enables_when_setting_on_and_adguard_currently_off(conn, monkeypatch):
    db.set_setting(conn, "safesearch_enabled", "1")
    conn.commit()
    fake = _FakeAdGuardClient(safesearch={
        "enabled": False, "bing": True, "duckduckgo": True, "ecosia": True,
        "google": True, "pixabay": True, "yandex": True, "youtube": True,
    })
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    adguard_sync.sync_safesearch(conn, "http://x", "admin", "pw")

    assert len(fake.calls) == 1
    assert fake.calls[0][0] == "safesearch"
    assert fake.calls[0][1]["enabled"] is True


def test_sync_safesearch_disables_when_setting_off_and_adguard_currently_on(conn, monkeypatch):
    db.set_setting(conn, "safesearch_enabled", "0")
    conn.commit()
    fake = _FakeAdGuardClient(safesearch={
        "enabled": True, "bing": True, "duckduckgo": True, "ecosia": True,
        "google": True, "pixabay": True, "yandex": True, "youtube": True,
    })
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    adguard_sync.sync_safesearch(conn, "http://x", "admin", "pw")

    assert fake.calls[0][1]["enabled"] is False


def test_sync_safesearch_is_a_noop_when_already_matching(conn, monkeypatch):
    db.set_setting(conn, "safesearch_enabled", "1")
    conn.commit()
    fake = _FakeAdGuardClient(safesearch={
        "enabled": True, "bing": True, "duckduckgo": True, "ecosia": True,
        "google": True, "pixabay": True, "yandex": True, "youtube": True,
    })
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    adguard_sync.sync_safesearch(conn, "http://x", "admin", "pw")

    assert fake.calls == []


def test_sync_safesearch_defaults_off_when_setting_never_configured(conn, monkeypatch):
    # No settings row at all -- must default to "off", never silently on.
    fake = _FakeAdGuardClient(safesearch={
        "enabled": False, "bing": True, "duckduckgo": True, "ecosia": True,
        "google": True, "pixabay": True, "yandex": True, "youtube": True,
    })
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    adguard_sync.sync_safesearch(conn, "http://x", "admin", "pw")

    assert fake.calls == []


def test_sync_safesearch_never_touches_per_service_booleans(conn, monkeypatch):
    """An admin's own AdGuard-UI customization (duckduckgo/pixabay off,
    say) must survive this project's own reconciliation untouched --
    only the master 'enabled' flag is this project's business."""
    db.set_setting(conn, "safesearch_enabled", "1")
    conn.commit()
    fake = _FakeAdGuardClient(safesearch={
        "enabled": False, "bing": True, "duckduckgo": False, "ecosia": True,
        "google": True, "pixabay": False, "yandex": True, "youtube": True,
    })
    monkeypatch.setattr(adguard_sync, "adguard_client", fake)

    adguard_sync.sync_safesearch(conn, "http://x", "admin", "pw")

    pushed = fake.calls[0][1]
    assert pushed["duckduckgo"] is False
    assert pushed["pixabay"] is False
    assert pushed["bing"] is True
    assert pushed["enabled"] is True


# ============================================================
# sync_optigate_rewrite (optigate.home memorable-URL feature, RoadMap.md's
# dated 2026-09-07 entry)
# ============================================================

def test_sync_optigate_rewrite_skipped_entirely_without_a_block_page_ip(conn, monkeypatch):
    fake = _FakeAdGuardClient()
    monkeypatch.setattr(optigate_rewrite, "adguard_client", fake)

    adguard_sync.sync_optigate_rewrite(conn, "http://x", "admin", "pw", None)

    assert fake.calls == []


def test_sync_optigate_rewrite_adds_the_default_hostname_on_a_fresh_instance(conn, monkeypatch):
    fake = _FakeAdGuardClient()
    monkeypatch.setattr(optigate_rewrite, "adguard_client", fake)

    adguard_sync.sync_optigate_rewrite(conn, "http://x", "admin", "pw", "192.168.1.250")

    assert fake.calls == [("add_rewrite", "optigate.home", "192.168.1.250")]


def test_sync_optigate_rewrite_is_a_noop_when_already_correct(conn, monkeypatch):
    fake = _FakeAdGuardClient(rewrites=[{"domain": "optigate.home", "answer": "192.168.1.250", "enabled": True}])
    monkeypatch.setattr(optigate_rewrite, "adguard_client", fake)

    adguard_sync.sync_optigate_rewrite(conn, "http://x", "admin", "pw", "192.168.1.250")

    assert fake.calls == []


def test_sync_optigate_rewrite_replaces_a_stale_ip_when_dashboard_url_changed(conn, monkeypatch):
    fake = _FakeAdGuardClient(rewrites=[{"domain": "optigate.home", "answer": "192.168.1.99", "enabled": True}])
    monkeypatch.setattr(optigate_rewrite, "adguard_client", fake)

    adguard_sync.sync_optigate_rewrite(conn, "http://x", "admin", "pw", "192.168.1.250")

    assert fake.calls == [
        ("delete_rewrite", "optigate.home", "192.168.1.99"),
        ("add_rewrite", "optigate.home", "192.168.1.250"),
    ]
    assert fake.rewrites == [{"domain": "optigate.home", "answer": "192.168.1.250", "enabled": True}]


def test_sync_optigate_rewrite_replaces_a_stale_domain_when_prefix_renamed(conn, monkeypatch):
    db.set_setting(conn, "optigate_hostname_prefix", "mynetwork")
    conn.commit()
    fake = _FakeAdGuardClient(rewrites=[{"domain": "optigate.home", "answer": "192.168.1.250", "enabled": True}])
    monkeypatch.setattr(optigate_rewrite, "adguard_client", fake)

    adguard_sync.sync_optigate_rewrite(conn, "http://x", "admin", "pw", "192.168.1.250")

    assert fake.calls == [
        ("delete_rewrite", "optigate.home", "192.168.1.250"),
        ("add_rewrite", "mynetwork.home", "192.168.1.250"),
    ]


def test_sync_optigate_rewrite_never_touches_an_unrelated_rewrite(conn, monkeypatch):
    """Only entries ending in .home are this project's business -- an
    admin's own unrelated AdGuard rewrite (a general-purpose AdGuard
    feature this project doesn't otherwise manage) must survive
    untouched."""
    fake = _FakeAdGuardClient(rewrites=[{"domain": "printer.lan", "answer": "192.168.1.5", "enabled": True}])
    monkeypatch.setattr(optigate_rewrite, "adguard_client", fake)

    adguard_sync.sync_optigate_rewrite(conn, "http://x", "admin", "pw", "192.168.1.250")

    assert ("delete_rewrite", "printer.lan", "192.168.1.5") not in fake.calls
    assert {"domain": "printer.lan", "answer": "192.168.1.5", "enabled": True} in fake.rewrites
    assert ("add_rewrite", "optigate.home", "192.168.1.250") in fake.calls
