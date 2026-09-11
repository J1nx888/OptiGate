#!/usr/bin/env python3
"""MAC-address-prefix -> vendor name lookup, for the "Devices awaiting
login" card's "Manufacturer" column (RoadMap.md, 2026-09-11: project
owner's own words -- "I need to see the device type that is trying to
connect... to distinguish between an Amazon Echo and an actual
laptop/phone").

Deliberately a pure, static, offline lookup against
data/oui_prefixes.tsv (a bundled snapshot of the IEEE's public MA-L/
MA-M/MA-S registries -- see that file's own header for provenance and
how to refresh it) -- no network call, no third-party dependency,
matching common/'s stdlib-only discipline.

This is a DISPLAY AID ONLY. It must never be used to auto-associate a
device_bindings row with a `devices` row, or to auto-fill/override a
device's label -- common/db.py's own device_bindings schema comment is
explicit that "hostname/vendor guessing is exactly the auto-merge the
v2 roadmap rules out." A vendor name shown next to a MAC address is
just a hint for the human looking at the "Devices awaiting login"
card to make their own decision; it never feeds back into any
`devices` row or policy decision.
"""
from __future__ import annotations

from pathlib import Path

_DATA_PATH = Path(__file__).resolve().parent / "data" / "oui_prefixes.tsv"

# Longest match wins: MA-S (/36, 9 hex chars) is a carve-out within a
# larger MA-L block, MA-M (/28, 7 hex chars) likewise -- checking the
# most specific prefix length first is what makes an MA-S/MA-M
# assignment correctly override its parent MA-L entry rather than the
# reverse.
_PREFIX_LENGTHS = (9, 7, 6)

_table: dict[str, str] | None = None


def _load_table() -> dict[str, str]:
    global _table
    if _table is not None:
        return _table
    table: dict[str, str] = {}
    try:
        with _DATA_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                prefix, _, vendor = line.partition("\t")
                if prefix and vendor:
                    table[prefix] = vendor
    except OSError:
        # Missing/unreadable data file: fail soft into "no vendor info
        # available" rather than crashing whatever page or loop called
        # in here -- same fail-open spirit as every other best-effort
        # enrichment in this project.
        pass
    _table = table
    return table


def _normalize_mac(mac_address: str) -> str:
    return mac_address.upper().replace(":", "").replace("-", "").replace(".", "")


def vendor_for_mac(mac_address: str, table: dict[str, str] | None = None) -> str | None:
    """The registered vendor name for `mac_address`'s OUI, or None if
    it's malformed or not found in the bundled snapshot. `table` is
    injectable for tests; production callers always omit it and get
    the lazily-loaded real data."""
    if table is None:
        table = _load_table()
    normalized = _normalize_mac(mac_address)
    if len(normalized) < 6 or any(c not in "0123456789ABCDEF" for c in normalized):
        return None
    for length in _PREFIX_LENGTHS:
        if len(normalized) >= length:
            vendor = table.get(normalized[:length])
            if vendor is not None:
                return vendor
    return None
