"""controller/main.py: _resolve_adguard_credentials() and main()'s
credential-requirement check.

Background (RoadMap.md, 2026-09-10): the controller used to take its
AdGuard admin credentials as --adguard-username/--adguard-password,
filled from .env by docker-compose.yml. The dashboard, meanwhile, stores
them in the `adguard_username`/`adguard_password` settings rows and keeps
AdGuardHome.yaml's own hash in sync with those. The two drifted the first
time an admin changed the password from the dashboard -- the controller
kept sending the old one, 401ing on every cycle, which tripped AdGuard's
brute-force lockout and locked the dashboard out too. The fix makes the
DB settings the single source of truth for the controller as well.
"""
from __future__ import annotations

import pytest

import db
from main import _resolve_adguard_credentials, main


def _seed(conn, **settings):
    for key, value in settings.items():
        db.set_setting(conn, key, value)
    conn.commit()


def test_reads_password_from_db_setting_when_no_cli_flag(conn):
    _seed(conn, adguard_username="admin", adguard_password="from-the-db")
    assert _resolve_adguard_credentials(conn, None, None) == ("admin", "from-the-db")


def test_reads_both_username_and_password_from_db_settings(conn):
    _seed(conn, adguard_username="household", adguard_password="s3kret")
    assert _resolve_adguard_credentials(conn, None, None) == ("household", "s3kret")


def test_cli_flags_override_db_settings(conn):
    _seed(conn, adguard_username="household", adguard_password="s3kret")
    assert _resolve_adguard_credentials(conn, "cliuser", "clipass") == ("cliuser", "clipass")


def test_cli_password_only_still_takes_username_from_db(conn):
    _seed(conn, adguard_username="household", adguard_password="s3kret")
    assert _resolve_adguard_credentials(conn, None, "clipass") == ("household", "clipass")


def test_no_cli_and_no_db_password_yields_none_password(conn):
    # username still resolves to a sane default; password None is the
    # caller's signal to skip the AdGuard loops rather than send nothing.
    assert _resolve_adguard_credentials(conn, None, None) == ("admin", None)


def test_empty_string_db_password_is_treated_as_absent(conn):
    _seed(conn, adguard_username="admin", adguard_password="")
    assert _resolve_adguard_credentials(conn, None, None) == ("admin", None)


def test_empty_string_db_username_falls_back_to_admin(conn):
    _seed(conn, adguard_username="", adguard_password="s3kret")
    assert _resolve_adguard_credentials(conn, None, None) == ("admin", "s3kret")


def test_main_still_requires_cli_creds_when_there_is_no_db_to_read_from():
    # --adguard-url but no --db-path: nowhere to read the settings from,
    # so the flags are mandatory and argparse must reject their absence.
    with pytest.raises(SystemExit) as excinfo:
        main(["--socket=/tmp/nope.sock", "--adguard-url=http://127.0.0.1:3000"])
    assert excinfo.value.code == 2
