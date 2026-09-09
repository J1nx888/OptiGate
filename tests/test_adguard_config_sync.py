"""dashboard/adguard_config_sync.py: writes AdGuard Home's real
AdGuardHome.yaml credential directly, since its REST API has no
password-change endpoint at all (see that module's own docstring for the
live verification against a real instance -- confirmed a hash generated
by THIS module's bcrypt library authenticates against AdGuard's real Go
bcrypt validator).
"""
from __future__ import annotations

from pathlib import Path

import bcrypt
import pytest
import yaml

import adguard_config_sync as sync


def _write_conf(path, users=None, **extra):
    data = {"users": users if users is not None else [{"name": "admin", "password": "$2a$10$oldhash"}]}
    data.update(extra)
    path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
    return path


def test_sync_writes_a_bcrypt_hash_the_python_library_itself_can_verify(tmp_path):
    conf = _write_conf(tmp_path / "AdGuardHome.yaml")

    sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)

    data = yaml.safe_load(conf.read_text())
    user = data["users"][0]
    assert user["name"] == "newadmin"
    assert bcrypt.checkpw(b"newpass123", user["password"].encode())


def test_sync_only_touches_the_first_user_when_multiple_exist(tmp_path):
    conf = _write_conf(
        tmp_path / "AdGuardHome.yaml",
        users=[{"name": "admin", "password": "$2a$10$one"}, {"name": "extra", "password": "$2a$10$two"}],
    )

    sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)

    data = yaml.safe_load(conf.read_text())
    assert data["users"][0]["name"] == "newadmin"
    assert data["users"][1] == {"name": "extra", "password": "$2a$10$two"}, "must not touch a second user"


def test_sync_preserves_every_other_top_level_config_key(tmp_path):
    """A real AdGuardHome.yaml has dozens of unrelated keys (DNS
    upstreams, filtering rules, DHCP, TLS...) -- this must round-trip
    every one of them untouched, not just the users list."""
    conf = _write_conf(
        tmp_path / "AdGuardHome.yaml",
        dns={"bind_hosts": ["0.0.0.0"], "port": 53},
        filtering={"protection_enabled": True},
        auth_attempts=5,
    )

    sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)

    data = yaml.safe_load(conf.read_text())
    assert data["dns"] == {"bind_hosts": ["0.0.0.0"], "port": 53}
    assert data["filtering"] == {"protection_enabled": True}
    assert data["auth_attempts"] == 5


def test_sync_preserves_other_fields_on_the_updated_user_entry(tmp_path):
    """A real user entry can carry more than name/password (AdGuard adds
    fields over versions) -- only name/password should change."""
    conf = _write_conf(
        tmp_path / "AdGuardHome.yaml",
        users=[{"name": "admin", "password": "$2a$10$oldhash", "language": "en"}],
    )

    sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)

    data = yaml.safe_load(conf.read_text())
    assert data["users"][0]["language"] == "en"


def test_sync_raises_when_config_file_does_not_exist(tmp_path):
    with pytest.raises(sync.AdGuardConfigSyncError):
        sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=tmp_path / "does-not-exist.yaml")


def test_sync_raises_on_malformed_yaml(tmp_path):
    conf = tmp_path / "AdGuardHome.yaml"
    conf.write_text("users: [unterminated", encoding="utf-8")
    with pytest.raises(sync.AdGuardConfigSyncError):
        sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)


def test_sync_raises_when_no_users_list_exists(tmp_path):
    conf = _write_conf(tmp_path / "AdGuardHome.yaml", users=[])
    with pytest.raises(sync.AdGuardConfigSyncError):
        sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)

    conf2 = tmp_path / "AdGuardHome2.yaml"
    conf2.write_text(yaml.safe_dump({"dns": {}}), encoding="utf-8")
    with pytest.raises(sync.AdGuardConfigSyncError):
        sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf2)


def test_sync_raises_when_yaml_is_not_a_mapping(tmp_path):
    conf = tmp_path / "AdGuardHome.yaml"
    conf.write_text(yaml.safe_dump(["not", "a", "mapping"]), encoding="utf-8")
    with pytest.raises(sync.AdGuardConfigSyncError):
        sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)


def test_sync_retries_a_transient_permission_error_on_read(tmp_path, monkeypatch):
    """Real gap found live 2026-09-09: adguard/entrypoint.sh's own repair
    loop re-grants the dashboard access every few seconds, but a write
    attempted in the narrow window right after AdGuard resets the
    file's permissions and right before the next repair tick would
    otherwise still fail outright. sync_adguard_credentials() must
    survive a PermissionError that clears up within a couple of
    retries, not fail on the very first attempt."""
    monkeypatch.setattr(sync, "_PERMISSION_RETRY_DELAY_SECONDS", 0)
    conf = _write_conf(tmp_path / "AdGuardHome.yaml")

    real_read_text = Path.read_text
    calls = {"n": 0}

    def flaky_read_text(self, *a, **kw):
        calls["n"] += 1
        if calls["n"] < 3 and self == conf:
            raise PermissionError("simulated transient permission error")
        return real_read_text(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", flaky_read_text)

    sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)

    assert calls["n"] == 3
    data = yaml.safe_load(conf.read_text())
    assert data["users"][0]["name"] == "newadmin"


def test_sync_gives_up_after_repeated_permission_errors_on_read(tmp_path, monkeypatch):
    monkeypatch.setattr(sync, "_PERMISSION_RETRY_DELAY_SECONDS", 0)
    conf = _write_conf(tmp_path / "AdGuardHome.yaml")

    def always_denied(self, *a, **kw):
        raise PermissionError("simulated permanent permission error")

    monkeypatch.setattr(Path, "read_text", always_denied)

    with pytest.raises(sync.AdGuardConfigSyncError, match="couldn't read"):
        sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)


def test_sync_retries_a_transient_permission_error_on_write(tmp_path, monkeypatch):
    monkeypatch.setattr(sync, "_PERMISSION_RETRY_DELAY_SECONDS", 0)
    conf = _write_conf(tmp_path / "AdGuardHome.yaml")

    real_write_text = Path.write_text
    calls = {"n": 0}

    def flaky_write_text(self, *a, **kw):
        if self == conf:
            calls["n"] += 1
            if calls["n"] < 2:
                raise PermissionError("simulated transient permission error")
        return real_write_text(self, *a, **kw)

    monkeypatch.setattr(Path, "write_text", flaky_write_text)

    sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=conf)

    assert calls["n"] == 2
    data = yaml.safe_load(conf.read_text())
    assert data["users"][0]["name"] == "newadmin"


def test_sync_does_not_retry_a_missing_file(tmp_path, monkeypatch):
    """FileNotFoundError is a different OSError subclass than
    PermissionError -- retrying on a timer would never fix a genuinely
    missing file, so this must fail immediately, not after 3 attempts'
    worth of delay."""
    monkeypatch.setattr(sync, "_PERMISSION_RETRY_DELAY_SECONDS", 999)  # would time out the test if ever slept

    with pytest.raises(sync.AdGuardConfigSyncError, match="doesn't exist yet"):
        sync.sync_adguard_credentials("newadmin", "newpass123", conf_path=tmp_path / "does-not-exist.yaml")


def test_each_call_generates_a_fresh_salt(tmp_path):
    """Two syncs of the same password must not produce identical hashes
    -- a fresh bcrypt salt every time, same discipline as password
    hashing anywhere else in this project."""
    conf = _write_conf(tmp_path / "AdGuardHome.yaml")
    sync.sync_adguard_credentials("admin", "samepassword", conf_path=conf)
    first_hash = yaml.safe_load(conf.read_text())["users"][0]["password"]

    sync.sync_adguard_credentials("admin", "samepassword", conf_path=conf)
    second_hash = yaml.safe_load(conf.read_text())["users"][0]["password"]

    assert first_hash != second_hash
    assert bcrypt.checkpw(b"samepassword", second_hash.encode())
