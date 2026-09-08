"""common/policy_class.py: PolicyClass classification precedence."""
from __future__ import annotations

import pytest

from policy_class import PolicyClass, bump_eligible, classify_device, to_set_name


def _row(ignored=0, quarantined_at=None, is_authenticated=1, bump_enabled=0, bypass_login=0):
    return {
        "ignored": ignored,
        "quarantined_at": quarantined_at,
        "is_authenticated": is_authenticated,
        "bump_enabled": bump_enabled,
        "bypass_login": bypass_login,
    }


def test_ignored_device_is_bypass_regardless_of_other_flags():
    row = _row(ignored=1, quarantined_at="2026-08-29T00:00:00Z", is_authenticated=0)
    assert classify_device(row) == PolicyClass.BYPASS


def test_quarantined_device_is_quarantine():
    row = _row(quarantined_at="2026-08-29T00:00:00Z", is_authenticated=1)
    assert classify_device(row) == PolicyClass.QUARANTINE


def test_authenticated_device_with_no_overrides():
    assert classify_device(_row(is_authenticated=1)) == PolicyClass.AUTHENTICATED


def test_unauthenticated_device_is_preauth():
    assert classify_device(_row(is_authenticated=0)) == PolicyClass.PREAUTH


def test_bypass_login_device_is_authenticated_even_when_not_logged_in():
    """Regression test for a real bug found 2026-08-31: classify_device()
    never consulted bypass_login at all, so a device an admin marked
    bypass_login stayed stuck in PREAUTH forever -- still redirected to
    the captive portal on every request -- contradicting both the
    dashboard's own hint text and RoadMap.md's design sketch, both of
    which describe bypass_login as exempting a device from the gate."""
    row = _row(is_authenticated=0, bypass_login=1)
    assert classify_device(row) == PolicyClass.AUTHENTICATED


def test_bypass_login_is_not_the_same_as_ignored():
    """bypass_login only skips the LOGIN requirement -- it must not
    also short-circuit quarantine the way `ignored` (BYPASS) does."""
    row = _row(quarantined_at="2026-08-29T00:00:00Z", is_authenticated=0, bypass_login=1)
    assert classify_device(row) == PolicyClass.QUARANTINE


def test_bypass_beats_quarantine():
    row = _row(ignored=1, quarantined_at="2026-08-29T00:00:00Z")
    assert classify_device(row) == PolicyClass.BYPASS


def test_quarantine_beats_authentication_state():
    row = _row(quarantined_at="2026-08-29T00:00:00Z", is_authenticated=1)
    assert classify_device(row) == PolicyClass.QUARANTINE


# ============================================================
# group_ignored (added 2026-09-07, project owner's explicit request for
# a group-level "ignore mode" -- db.py's schema comment on
# groups.ignored)
# ============================================================

def test_group_ignored_is_bypass_even_when_devices_ignored_is_0():
    row = _row(ignored=0, quarantined_at="2026-08-29T00:00:00Z", is_authenticated=0)
    assert classify_device(row, group_ignored=True) == PolicyClass.BYPASS


def test_group_ignored_false_is_the_default_and_changes_nothing():
    row = _row(quarantined_at="2026-08-29T00:00:00Z")
    assert classify_device(row) == classify_device(row, group_ignored=False) == PolicyClass.QUARANTINE


def test_group_ignored_beats_quarantine_same_as_devices_own_ignored():
    row = _row(quarantined_at="2026-08-29T00:00:00Z")
    assert classify_device(row, group_ignored=True) == PolicyClass.BYPASS


def test_bump_eligible_false_when_group_ignored_even_with_flag_set():
    row = _row(is_authenticated=1, bump_enabled=1)
    assert bump_eligible(row) is True  # sanity check: true without group_ignored
    assert bump_eligible(row, group_ignored=True) is False
    row2 = _row(quarantined_at="2026-08-29T00:00:00Z", is_authenticated=0)
    assert classify_device(row2) == PolicyClass.QUARANTINE


@pytest.mark.parametrize(
    "policy_class,expected",
    [
        (PolicyClass.AUTHENTICATED, "authenticated"),
        (PolicyClass.PREAUTH, "unauthenticated"),
        (PolicyClass.BYPASS, "bypass"),
        (PolicyClass.QUARANTINE, "quarantine"),
    ],
)
def test_to_set_name(policy_class, expected):
    assert to_set_name(policy_class) == expected


def test_bump_eligible_true_for_authenticated_device_with_flag_set():
    assert bump_eligible(_row(is_authenticated=1, bump_enabled=1)) is True


def test_bump_eligible_false_when_flag_not_set():
    assert bump_eligible(_row(is_authenticated=1, bump_enabled=0)) is False


def test_bump_eligible_false_for_preauth_device_even_with_flag_set():
    # A device that hasn't logged in yet has no DNS-tier access at all --
    # it can't be bump-eligible before that, per RoadMap.md's Phase 4 flow.
    assert bump_eligible(_row(is_authenticated=0, bump_enabled=1)) is False


def test_bump_eligible_false_for_bypass_device_even_with_flag_set():
    # An ignored device's traffic must never be forced through Squid --
    # bypass means "outside the whole system, for good."
    assert bump_eligible(_row(ignored=1, bump_enabled=1)) is False


def test_bump_eligible_false_for_quarantined_device_even_with_flag_set():
    row = _row(quarantined_at="2026-08-29T00:00:00Z", bump_enabled=1)
    assert bump_eligible(row) is False
