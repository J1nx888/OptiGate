"""controller/network_sweep.py: the active whole-subnet discovery sweep
that closes the "silent device is invisible forever" gap (RoadMap.md's
2026-09-08 dated entry). Reuses active_scan.nudge() directly rather
than re-implementing the UDP-nudge trick, so these tests fake the
network the exact same way tests/test_controller_active_scan.py
already does: monkeypatching active_scan.socket.socket with a fake
that records what it was asked to send, never touching a real network.
The UDP-nudge technique itself was separately confirmed live against a
real kernel (see active_scan.py's own module docstring) -- not
re-verified here.
"""
from __future__ import annotations

import threading
import time

import active_scan
import db
import network_sweep


class _FakeSocket:
    instances: list["_FakeSocket"] = []

    def __init__(self, *a, **k):
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        _FakeSocket.instances.append(self)

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def close(self):
        pass


def _reset_fake_socket(monkeypatch):
    _FakeSocket.instances = []
    monkeypatch.setattr(active_scan.socket, "socket", lambda *a, **k: _FakeSocket())


# ============================================================
# _configured_hosts
# ============================================================

def test_configured_hosts_expands_a_slash_24(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/24")
    conn.commit()

    hosts = network_sweep._configured_hosts(conn)

    assert len(hosts) == 254, "a /24 has 254 usable host addresses (network+broadcast excluded)"
    assert "192.168.1.1" in hosts
    assert "192.168.1.254" in hosts
    assert "192.168.1.0" not in hosts, "network address must be excluded"
    assert "192.168.1.255" not in hosts, "broadcast address must be excluded"


def test_configured_hosts_combines_multiple_cidrs(conn):
    db.set_setting(conn, "local_network", "192.168.1.0/29 10.0.0.0/29")
    conn.commit()

    hosts = network_sweep._configured_hosts(conn)

    assert len(hosts) == 12, "two /29s = 6 usable hosts each"
    assert any(h.startswith("192.168.1.") for h in hosts)
    assert any(h.startswith("10.0.0.") for h in hosts)


def test_configured_hosts_empty_when_local_network_unset(conn):
    assert network_sweep._configured_hosts(conn) == []


def test_configured_hosts_skips_unparseable_entries_without_crashing(conn):
    db.set_setting(conn, "local_network", "not-a-cidr 192.168.1.0/30")
    conn.commit()

    hosts = network_sweep._configured_hosts(conn)

    assert len(hosts) == 2, "the one valid CIDR still expands; the bad one is skipped, not fatal"


def test_configured_hosts_caps_an_unreasonably_large_range(conn, monkeypatch):
    monkeypatch.setattr(network_sweep, "_MAX_HOSTS_PER_SWEEP", 10)
    db.set_setting(conn, "local_network", "10.0.0.0/16")  # 65534 real hosts
    conn.commit()

    hosts = network_sweep._configured_hosts(conn)

    assert len(hosts) == 10, "must stop at the cap, not silently sweep a huge range"


# ============================================================
# sweep_once
# ============================================================

def test_sweep_once_nudges_every_configured_host(conn, monkeypatch):
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")  # 2 usable hosts
    conn.commit()

    swept = network_sweep.sweep_once(conn)

    assert swept == 2
    all_sent = [addr for sock in _FakeSocket.instances for _, addr in sock.sent]
    assert ("192.168.1.1", active_scan._NUDGE_PORT) in all_sent
    assert ("192.168.1.2", active_scan._NUDGE_PORT) in all_sent


def test_sweep_once_returns_zero_and_never_nudges_when_unconfigured(conn, monkeypatch):
    _reset_fake_socket(monkeypatch)

    assert network_sweep.sweep_once(conn) == 0
    assert _FakeSocket.instances == []


def test_sweep_once_never_writes_device_bindings(conn, monkeypatch):
    """Same design as active_scan.py -- this module only ever nudges;
    controller/discovery.py's own snapshot loop is what actually
    observes and records any resulting resolution."""
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    conn.commit()

    network_sweep.sweep_once(conn)

    assert conn.execute("SELECT COUNT(*) AS c FROM device_bindings").fetchone()["c"] == 0


def test_sweep_once_records_status_settings_for_the_dashboard(conn, monkeypatch):
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    conn.commit()

    network_sweep.sweep_once(conn)

    assert db.get_setting(conn, "network_sweep_last_run_at", "") != ""
    assert db.get_setting(conn, "network_sweep_last_host_count", "") == "2"


# ============================================================
# _interval_seconds / _enabled
# ============================================================

def test_interval_seconds_reads_the_configured_minutes(conn):
    db.set_setting(conn, "network_sweep_interval_minutes", "15")
    conn.commit()
    assert network_sweep._interval_seconds(conn) == 15 * 60.0


def test_interval_seconds_defaults_when_unset(conn):
    assert network_sweep._interval_seconds(conn) == network_sweep.DEFAULT_INTERVAL_MINUTES * 60.0


def test_interval_seconds_falls_back_on_a_corrupted_value(conn):
    """Defense-in-depth for a value that reached the DB some way other
    than the dashboard's own validated route (a stale row, a direct DB
    edit) -- must never produce a zero/negative interval, which would
    make every single check tick re-sweep the whole LAN."""
    db.set_setting(conn, "network_sweep_interval_minutes", "-5")
    conn.commit()
    assert network_sweep._interval_seconds(conn) == network_sweep.DEFAULT_INTERVAL_MINUTES * 60.0


def test_enabled_defaults_to_true(conn):
    assert network_sweep._enabled(conn) is True


def test_enabled_respects_explicit_disable(conn):
    db.set_setting(conn, "network_sweep_enabled", "0")
    conn.commit()
    assert network_sweep._enabled(conn) is False


# ============================================================
# run_loop -- wiring sweep_once() into a background PeriodicTask with
# its own live-settings-driven due-check, not a fixed PeriodicTask
# interval (see the module's own docstring for why)
# ============================================================

def test_run_loop_sweeps_immediately_then_repeats_when_due(conn, monkeypatch):
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    conn.commit()
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(network_sweep, "_interval_seconds", lambda conn: 0.03)

    task = network_sweep.run_loop()
    try:
        time.sleep(0.2)
    finally:
        task.stop()

    assert len(_FakeSocket.instances) >= 4, "expected multiple sweep cycles, not just the startup one"


def test_run_loop_never_sweeps_while_disabled(conn, monkeypatch):
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    db.set_setting(conn, "network_sweep_enabled", "0")
    conn.commit()
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)

    task = network_sweep.run_loop()
    try:
        time.sleep(0.1)
    finally:
        task.stop()

    assert _FakeSocket.instances == [], "disabled must mean disabled, even at the immediate startup tick"


def test_run_loop_picks_up_a_live_disable_without_restarting(conn, monkeypatch):
    """The whole point of checking settings fresh every tick instead of
    a fixed PeriodicTask interval: an admin's change takes effect on
    the next check, not only after a controller restart."""
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    conn.commit()
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(network_sweep, "_interval_seconds", lambda conn: 0.01)

    task = network_sweep.run_loop()
    try:
        time.sleep(0.1)
        assert len(_FakeSocket.instances) >= 1, "should have swept at least once by now"
        swept_before_disable = len(_FakeSocket.instances)
        db.set_setting(conn, "network_sweep_enabled", "0")
        conn.commit()
        time.sleep(0.1)
    finally:
        task.stop()

    assert len(_FakeSocket.instances) == swept_before_disable, "must stop sweeping once disabled, without a restart"


def test_run_loop_stops_promptly(conn, monkeypatch):
    _reset_fake_socket(monkeypatch)
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.05)

    task = network_sweep.run_loop()
    time.sleep(0.02)
    started_stop = time.monotonic()
    task.stop()
    elapsed = time.monotonic() - started_stop
    assert elapsed < 0.5, f"stop() took {elapsed:.3f}s, expected it to return promptly"


def test_run_loop_run_now_bypasses_disabled_and_interval(conn, monkeypatch):
    """"Run now" (dashboard Settings page button) is an explicit one-off
    admin action -- must fire even when the automatic schedule is off
    and even if a normal sweep isn't due yet."""
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    db.set_setting(conn, "network_sweep_enabled", "0")
    conn.commit()
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(network_sweep, "_interval_seconds", lambda conn: 9999)

    task = network_sweep.run_loop()
    try:
        time.sleep(0.06)
        assert _FakeSocket.instances == [], "must not have swept yet -- disabled and nothing requested"
        db.set_setting(conn, "network_sweep_run_now_requested_at", db.now_iso())
        conn.commit()
        time.sleep(0.06)
    finally:
        task.stop()

    assert len(_FakeSocket.instances) == 2, "exactly one sweep (2 hosts in a /30) for the one run-now request"


def test_run_loop_run_now_logs_a_system_events_info_row(conn, monkeypatch):
    """Fixed 2026-09-09, real gap found live: clicking "Run now" visibly
    did something, but nothing showed up on the Events page at all."""
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    conn.commit()
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(network_sweep, "_interval_seconds", lambda conn: 9999)

    task = network_sweep.run_loop()
    try:
        db.set_setting(conn, "network_sweep_run_now_requested_at", db.now_iso())
        conn.commit()
        time.sleep(0.06)
    finally:
        task.stop()

    rows = conn.execute("SELECT * FROM system_events").fetchall()
    assert len(rows) == 1
    assert rows[0]["severity"] == "info"
    assert rows[0]["source"] == "network_sweep"
    assert "2" in rows[0]["message"]
    assert "192.168.1.0/30" in rows[0]["message"]


def test_run_loop_automatic_sweep_does_not_log_a_system_event(conn, monkeypatch):
    """The 'info' severity is deliberately scoped to an explicit admin
    action, not the automatic schedule -- an automatic sweep completing
    must stay just as silent on the Events page as it always has been,
    matching the "not a firehose" principle this table was built on."""
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    conn.commit()
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(network_sweep, "_interval_seconds", lambda conn: 0.01)

    task = network_sweep.run_loop()
    try:
        time.sleep(0.1)
    finally:
        task.stop()

    assert len(_FakeSocket.instances) > 0, "sanity check: the automatic sweep actually ran"
    assert conn.execute("SELECT COUNT(*) c FROM system_events").fetchone()["c"] == 0


def test_run_loop_run_now_fires_only_once_per_request(conn, monkeypatch):
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    db.set_setting(conn, "network_sweep_enabled", "0")
    db.set_setting(conn, "network_sweep_run_now_requested_at", "2026-09-09T00:00:00Z")
    conn.commit()
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)

    task = network_sweep.run_loop()
    try:
        time.sleep(0.1)
    finally:
        task.stop()

    assert len(_FakeSocket.instances) == 2, "one pre-existing request must trigger exactly one sweep (2 hosts), not one per tick"


def test_run_loop_run_now_fires_again_for_a_second_request(conn, monkeypatch):
    _reset_fake_socket(monkeypatch)
    db.set_setting(conn, "local_network", "192.168.1.0/30")
    db.set_setting(conn, "network_sweep_enabled", "0")
    conn.commit()
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)

    task = network_sweep.run_loop()
    try:
        db.set_setting(conn, "network_sweep_run_now_requested_at", "2026-09-09T00:00:00Z")
        conn.commit()
        time.sleep(0.06)
        assert len(_FakeSocket.instances) == 2, "first request: one sweep of the 2-host /30"

        db.set_setting(conn, "network_sweep_run_now_requested_at", "2026-09-09T00:01:00Z")
        conn.commit()
        time.sleep(0.06)
    finally:
        task.stop()

    assert len(_FakeSocket.instances) == 4, "a genuinely new request must trigger a second sweep (2 more hosts)"


def test_run_loop_reports_errors_via_on_error_without_dying(conn, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(network_sweep, "sweep_once", _boom)
    monkeypatch.setattr(network_sweep, "_CHECK_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(network_sweep, "_interval_seconds", lambda conn: 0.01)

    errors = []
    lock = threading.Lock()

    def on_error(exc):
        with lock:
            errors.append(exc)

    task = network_sweep.run_loop(on_error=on_error)
    try:
        time.sleep(0.1)
    finally:
        task.stop()

    with lock:
        got = len(errors)
    assert got >= 2, "expected repeated errors, not a dead loop"
