"""common/oui_lookup.py: pure, offline MAC-prefix -> vendor lookup for
the "Devices awaiting login" card's Manufacturer column (RoadMap.md,
2026-09-11). Matching logic is tested against a small injected table
(no dependency on the real bundled data); a couple of sanity checks at
the bottom confirm the real data/oui_prefixes.tsv file actually loads
and resolves a few well-known real vendors.
"""
from __future__ import annotations

import oui_lookup

_TABLE = {
    "AABBCC": "Generic MA-L Vendor",
    "AABBCC1": "Narrower MA-M Vendor",
    "AABBCC1EE": "Narrowest MA-S Vendor",
}


def test_matches_a_plain_ma_l_prefix():
    assert oui_lookup.vendor_for_mac("aa:bb:cc:99:88:77", table=_TABLE) == "Generic MA-L Vendor"


def test_normalizes_colons_dashes_dots_and_case():
    assert oui_lookup.vendor_for_mac("AA-BB-CC-99-88-77", table=_TABLE) == "Generic MA-L Vendor"
    assert oui_lookup.vendor_for_mac("aabb.cc99.8877", table=_TABLE) == "Generic MA-L Vendor"
    assert oui_lookup.vendor_for_mac("AABBCC998877", table=_TABLE) == "Generic MA-L Vendor"


def test_longest_prefix_wins_ma_s_over_ma_m_over_ma_l():
    # aa:bb:cc:22:33:44 -- doesn't match either narrower carve-out
    # (AABBCC1... vs AABBCC22...), only the broad 6-char MA-L block.
    assert oui_lookup.vendor_for_mac("aa:bb:cc:22:33:44", table=_TABLE) == "Generic MA-L Vendor"
    # aa:bb:cc:1f:33:44 -- 7-char prefix AABBCC1 matches, but the 9-char
    # prefix (AABBCC1F3) doesn't -- the MA-M carve-out wins over its
    # parent MA-L block.
    assert oui_lookup.vendor_for_mac("aa:bb:cc:1f:33:44", table=_TABLE) == "Narrower MA-M Vendor"
    # aa:bb:cc:1e:e3:44 -- matches the 9-char MA-S carve-out (AABBCC1EE)
    # directly -- beats both broader entries.
    assert oui_lookup.vendor_for_mac("aa:bb:cc:1e:e3:44", table=_TABLE) == "Narrowest MA-S Vendor"


def test_unknown_prefix_returns_none():
    assert oui_lookup.vendor_for_mac("00:11:22:33:44:55", table=_TABLE) is None


def test_malformed_mac_returns_none_instead_of_raising():
    assert oui_lookup.vendor_for_mac("not-a-mac", table=_TABLE) is None
    assert oui_lookup.vendor_for_mac("", table=_TABLE) is None
    assert oui_lookup.vendor_for_mac("aa:bb", table=_TABLE) is None


# ============================================================
# Real bundled data -- sanity checks only, not exhaustive
# ============================================================

def test_real_data_file_resolves_amazon():
    assert oui_lookup.vendor_for_mac("84:28:59:00:00:00") == "Amazon Technologies Inc."


def test_real_data_file_resolves_apple():
    assert oui_lookup.vendor_for_mac("f0:ee:7a:00:00:00") == "Apple, Inc."


def test_real_data_file_resolves_espressif():
    assert oui_lookup.vendor_for_mac("d4:8a:fc:00:00:00") == "Espressif Inc."


def test_real_data_file_returns_none_for_a_locally_administered_test_mac():
    # 02:00:00:... is the classic "locally administered, unicast" test
    # MAC -- guaranteed never a real IEEE-assigned OUI.
    assert oui_lookup.vendor_for_mac("02:00:00:00:00:00") is None
