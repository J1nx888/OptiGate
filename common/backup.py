#!/usr/bin/env python3
"""Configuration export/import (backup/restore) -- tracked as a deferred
item in RoadMap.md since before 2026-09-07 ("no way currently to export
the whole household's configuration... useful before a risky change, or
when moving to new hardware"), built 2026-09-08 as the actual mechanism
for that: wipe the production box and redeploy clean (e.g. once the
Phase C infrastructure rename happens) without losing anything or
needing to re-trust a new CA certificate on every device.

Lives in common/ (not dashboard/) on the same reasoning
category_fetch.py's own docstring already gives for its module -- purely
a lower-level data concern, kept separate from the HTTP/file-upload
handling in dashboard.py.

**What "configuration" means here, deliberately**: every table (or
column) a human actually decided, not runtime/observational state that
either doesn't matter after a restore or actively shouldn't survive one:

- INCLUDED: settings (an explicit allowlist, see SETTINGS_ALLOWLIST --
  not the whole table, see its own comment), users, domains,
  user_domains, domain_paths, user_shows, groups, group_domains,
  devices, device_domains, categories, category_domains (source='manual'
  only -- see below), category_overrides, category_users,
  category_groups, category_devices, schedules, schedule_categories,
  schedule_users, schedule_groups, schedule_devices, schedule_overrides.
- EXCLUDED: `category_domains` where source='subscription' -- these are
  mechanically re-fetched from the category's own `subscription_url`
  (category_fetch.py), not admin-authored; a real subscription category
  can hold 900,000+ rows (the Adult category alone, see
  idx_category_domains_pattern's own comment in db.py), so including
  them would make an ordinary backup file enormous for zero benefit --
  the categories row itself (with its subscription_url intact) is all a
  restore needs; the next sync (scheduled, or a manual "Sync now" click)
  repopulates the rest. Also excluded entirely: `series_cache` (a
  resolution cache, rebuilds itself), `device_bindings`/
  `interception_runtime`/`network_events` (network-observed/runtime
  state, self-healing via discovery), `system_events`/`access_log`
  (historical/audit records, not configuration, and access_log
  specifically can be large).

**Restore is a full replace, not a merge**: every included table is
cleared and reinserted from the backup, WITH THE ORIGINAL ROW IDS
preserved. This is deliberate, not an oversight -- every join table
above (user_domains, category_users, etc.) references its parent by
that same original id, so preserving ids means every foreign key just
lines up naturally with zero remapping logic, at the cost of restore
being a genuine "return to exactly this snapshot" operation rather than
an incremental import. `PRAGMA foreign_keys=ON` (common/db.py's own
get_conn()) is what makes deleting the six root tables below
(users/groups/devices/domains/categories/schedules) enough to clear
every dependent join-table row too -- every child table above uses `ON
DELETE CASCADE` on its parent references (device_bindings/
network_events use `ON DELETE SET NULL` instead, deliberately, so a
restore doesn't destroy real network-observation history sitting in
those excluded-from-backup tables, just orphans it back to "pending"
until discovery re-associates it -- self-healing, not a bug). access_log
and system_events have no REFERENCES clause at all on purpose (see their
own schema comments), so a restore never touches Report-page history or
the audit log either way.

The CA certificate/private key files are NOT part of this module's own
job (they're not database rows) -- dashboard.py's backup/restore routes
handle those directly, reusing `_validate_ca_cert_pair()`/
`_replace_ca_cert_pair()`, the same functions the existing CA-upload
feature already uses.
"""
from __future__ import annotations

import sqlite3
from typing import Any

FORMAT_VERSION = 1

# Deliberately an ALLOWLIST, not "the whole settings table" -- a few keys
# are internal/generated, not something a human configured, and must
# never round-trip through a backup:
#   secret_key             Flask's session-cookie signing key. Regenerating
#                           it is harmless (invalidates any in-flight flash
#                           message, nothing more) -- a restore should let a
#                           fresh install keep its own, not overwrite it with
#                           an old one from a different install.
#   cr_resolver_last_error Diagnostic-only (Crunchyroll resolver's own last
#                           failure), not configuration.
#   network_sweep_last_run_at / _last_host_count
#                           Diagnostic-only (controller/network_sweep.py's
#                           own status, for the Settings page's live
#                           display), same reasoning as cr_resolver_last_error
#                           above -- restoring a "last ran" timestamp from a
#                           different box onto a fresh install would just be
#                           misleading, not useful. network_sweep_enabled/
#                           _interval_minutes (the actual admin configuration)
#                           ARE included, below.
# A NEW setting added later defaults to EXCLUDED unless deliberately added
# here -- safer than a denylist, which would silently include a future
# secret nobody thought to exclude.
SETTINGS_ALLOWLIST = (
    "admin_username",
    "admin_password_hash",
    "adguard_username",
    "adguard_password",
    "adguard_url",
    "local_network",
    "block_page_mode",
    "safesearch_enabled",
    "household_time_zone",
    "optigate_hostname_prefix",
    "device_stale_days",
    "cert_banner_dismissed",
    "network_sweep_enabled",
    "network_sweep_interval_minutes",
)

# Ordered so every table is inserted only after whatever it references by
# foreign key -- the six "root" tables first (users/groups/devices/
# domains/categories/schedules, none of which reference each other via a
# blocking constraint -- devices.user_id/group_id are ON DELETE SET NULL,
# not a same-tier dependency), then every join/child table, in no
# particular order relative to each other since they only ever reference
# an already-inserted root.
_ROOT_TABLES = ("users", "groups", "devices", "domains", "categories", "schedules")
_CHILD_TABLES = (
    "user_domains", "domain_paths", "user_shows",
    "group_domains", "device_domains",
    "category_overrides", "category_users", "category_groups", "category_devices",
    "schedule_categories", "schedule_users", "schedule_groups", "schedule_devices",
    "schedule_overrides",
)
# Every table above, in the exact order export walks them and restore
# re-inserts them -- category_domains is handled separately (see
# export_config/restore_config) since it needs the source='manual' filter.
_ALL_TABLES = _ROOT_TABLES + _CHILD_TABLES + ("category_domains",)


def export_config(conn: sqlite3.Connection) -> dict[str, Any]:
    """Builds the JSON-serializable snapshot. Column names are read from
    each table via `SELECT *` (not hardcoded here) so a future schema
    change (a new column) is picked up automatically without editing this
    module -- restore_config() below inserts by column name for the same
    reason, so the two never need to be kept in sync by hand."""
    data: dict[str, Any] = {"format_version": FORMAT_VERSION}

    settings: dict[str, str] = {}
    for key in SETTINGS_ALLOWLIST:
        value = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if value is not None:
            settings[key] = value["value"]
    data["settings"] = settings

    for table in _ROOT_TABLES + _CHILD_TABLES:
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
        data[table] = [dict(row) for row in rows]

    # source='manual' only -- see this module's own docstring for why
    # subscription-sourced rows (potentially 900,000+ for one category)
    # are deliberately left out.
    data["category_domains"] = [
        dict(row) for row in conn.execute(
            "SELECT * FROM category_domains WHERE source = 'manual'"
        ).fetchall()
    ]
    return data


class RestoreError(Exception):
    """A backup file that's structurally invalid or from an
    incompatible/future format -- never a partial-application state,
    since restore_config() only starts writing after this would have
    already been raised."""


def _validate(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise RestoreError("Not a valid backup file (expected a JSON object).")
    version = data.get("format_version")
    if version != FORMAT_VERSION:
        raise RestoreError(
            f"This backup is format version {version!r}, but this install expects "
            f"version {FORMAT_VERSION}. Restore it on a matching OptiGate version instead."
        )
    for table in _ALL_TABLES:
        if table not in data or not isinstance(data[table], list):
            raise RestoreError(f"Backup is missing or has a malformed '{table}' section.")
    if not isinstance(data.get("settings"), dict):
        raise RestoreError("Backup is missing or has a malformed 'settings' section.")


def restore_config(conn: sqlite3.Connection, data: dict[str, Any]) -> None:
    """Full replace, in one transaction (see this module's own docstring
    for why preserving original row ids makes this safe under
    PRAGMA foreign_keys=ON). Raises RestoreError -- and leaves the
    database completely untouched -- if `data` fails validation; nothing
    is deleted until validation has already passed."""
    _validate(data)

    conn.execute("BEGIN IMMEDIATE")
    try:
        # Deleting the six root tables cascades to every child table
        # (including category_domains, both sources) via their own
        # ON DELETE CASCADE -- see this module's docstring.
        for table in _ROOT_TABLES:
            conn.execute(f"DELETE FROM {table}")

        for table in _ROOT_TABLES + _CHILD_TABLES + ("category_domains",):
            rows = data[table]
            if not rows:
                continue
            columns = list(rows[0].keys())
            placeholders = ", ".join("?" for _ in columns)
            column_list = ", ".join(columns)
            conn.executemany(
                f"INSERT INTO {table} ({column_list}) VALUES ({placeholders})",
                [tuple(row[c] for c in columns) for row in rows],
            )

        for key, value in data["settings"].items():
            if key in SETTINGS_ALLOWLIST:
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.commit()
