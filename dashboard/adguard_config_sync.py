#!/usr/bin/env python3
"""Writes AdGuard Home's OWN admin credential directly into its
AdGuardHome.yaml config file -- the only way to actually change it.

**Why this exists, and why the REST API can't do this**: confirmed live
2026-09-07 against a real production AdGuard Home v0.107.79 instance,
after the project owner correctly flagged the previous approach (showing
the plaintext `adguard_password` setting back to the admin on the
Settings page) as insecure and asked for real integration instead of a
workaround. Fetched AdGuard's own OpenAPI spec for that exact version:
`PUT /control/profile/update`'s `ProfileInfo` request schema has only
`name`/`language`/`theme` -- there is no password field anywhere in
AdGuard Home's REST API. The only way to actually change AdGuard's own
stored credential is to edit its config file directly (the same
conclusion `adguard/entrypoint.sh`'s own first-boot-only bootstrap
already reflects) and restart the container so it re-reads the file --
AdGuard never hot-reloads its config, confirmed by this project's own
prior `ADGUARD_WEB_BIND` fix.

**Bcrypt cross-compatibility, also confirmed live, not assumed**: AdGuard
stores `users[].password` as a bcrypt hash (`$2a$10$...` in the real
config). Generated a hash with THIS module's own `bcrypt` library,
injected it as a temporary second user into the real production
AdGuardHome.yaml, restarted the container, and successfully authenticated
against it via HTTP Basic Auth -- then removed the test user and restored
the original file, restarting again to confirm the real admin credential
was untouched throughout. Go's `golang.org/x/crypto/bcrypt` (what AdGuard
Home uses) and Python's `bcrypt` package both implement the same
standardized algorithm; the `$2a$`/`$2b$` prefix difference (Python's
default) is a historical null-termination detail that doesn't affect
verification in either library.

**What this does NOT do**: restart the `adguard` container itself. Doing
that safely from inside the dashboard container would need Docker socket
access -- a far larger privilege grant (host-root-equivalent) than the
scoped, data-only volume mount this module actually needs, and a worse
trade than the problem it would solve. Callers must tell the admin to
run `docker compose restart adguard` themselves after a successful sync
(see `dashboard.py`'s `update_admin()`) -- same "config change takes
effect on next restart" limitation this project already accepts for
`ADGUARD_WEB_BIND`.

**Single-admin-user assumption**: this project only ever creates ONE
AdGuard user (`adguard/entrypoint.sh`'s first-boot bootstrap). If
`users` has more than one entry (an admin added extras by hand, directly
in AdGuard's own UI), only the FIRST is updated -- documented, not
silently guessed at.
"""
from __future__ import annotations

import logging
from pathlib import Path

import bcrypt
import yaml

log = logging.getLogger("dashboard.adguard_config_sync")

DEFAULT_CONF_PATH = Path("/opt/adguardhome/conf/AdGuardHome.yaml")


class AdGuardConfigSyncError(RuntimeError):
    """Raised for a failure reading/writing AdGuardHome.yaml -- callers
    (update_admin()) must treat this as best-effort and never let it
    block the dashboard's own password change from saving; see that
    route's own try/except."""


def sync_adguard_credentials(username: str, password: str, conf_path: Path = DEFAULT_CONF_PATH) -> None:
    """Rewrites AdGuardHome.yaml's first `users[]` entry to `username`/
    a fresh bcrypt hash of `password`. Raises AdGuardConfigSyncError
    (never a bare exception type) on any failure -- file not found (the
    volume isn't mounted yet on an existing install that hasn't
    recreated its dashboard container since this feature shipped, or
    adguard has never booted/configured itself yet), malformed YAML, or
    no `users` list to update. Silent on success -- the change is on
    disk, not yet live; the caller is responsible for telling the admin
    to restart the `adguard` container.
    """
    try:
        raw = conf_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AdGuardConfigSyncError(
            f"{conf_path} doesn't exist yet -- adguard hasn't booted/configured itself, "
            "or this dashboard container doesn't have the config volume mounted"
        ) from exc
    except OSError as exc:
        raise AdGuardConfigSyncError(f"couldn't read {conf_path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise AdGuardConfigSyncError(f"{conf_path} isn't valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise AdGuardConfigSyncError(f"{conf_path} didn't parse to a YAML mapping")
    users = data.get("users")
    if not isinstance(users, list) or not users:
        raise AdGuardConfigSyncError(f"{conf_path} has no users list to update")

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("ascii")
    users[0] = {**users[0], "name": username, "password": password_hash}

    try:
        conf_path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
    except OSError as exc:
        raise AdGuardConfigSyncError(f"couldn't write {conf_path}: {exc}") from exc
