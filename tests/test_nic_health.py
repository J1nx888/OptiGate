"""common/nic_health.py: the dashboard Health page's "NIC load balancing"
card (2026-09-12, RoadMap.md's "Item 3 revisited" -- a real production
sustained-upload failure traced to a single-queue NIC with RPS disabled
and every interrupt pinned to one core). All functions read plain files
by path, so these tests build a fake sysfs/procfs tree under tmp_path
rather than depending on the real host's actual network interfaces.
"""
from __future__ import annotations

import nic_health


def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def test_detect_primary_interface_finds_the_default_route(tmp_path, monkeypatch):
    route_file = tmp_path / "route"
    _write(
        route_file,
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n"
        "enp1s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n",
    )
    monkeypatch.setattr(nic_health, "PROC_NET_ROUTE", route_file)
    assert nic_health.detect_primary_interface() == "enp1s0"


def test_detect_primary_interface_returns_none_without_a_default_route(tmp_path, monkeypatch):
    route_file = tmp_path / "route"
    _write(
        route_file,
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n",
    )
    monkeypatch.setattr(nic_health, "PROC_NET_ROUTE", route_file)
    assert nic_health.detect_primary_interface() is None


def test_detect_primary_interface_returns_none_when_unreadable(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "PROC_NET_ROUTE", tmp_path / "does-not-exist")
    assert nic_health.detect_primary_interface() is None


def test_rps_enabled_true_when_any_rx_queue_has_a_nonzero_mask(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    _write(tmp_path / "enp1s0" / "queues" / "rx-0" / "rps_cpus", "f")
    assert nic_health.rps_enabled("enp1s0") is True


def test_rps_enabled_false_when_every_rx_queue_is_all_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    _write(tmp_path / "enp1s0" / "queues" / "rx-0" / "rps_cpus", "0")
    _write(tmp_path / "enp1s0" / "queues" / "rx-1" / "rps_cpus", "0,00000000")
    assert nic_health.rps_enabled("enp1s0") is False


def test_rps_enabled_true_for_a_wide_comma_separated_mask(tmp_path, monkeypatch):
    """A machine with >32 CPUs formats rps_cpus as comma-separated 32-bit
    hex groups -- confirm the "any character outside 0,\" check handles
    that shape too, not just the single-hex-string case a small box
    like the real production Beelink actually has."""
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    _write(tmp_path / "enp1s0" / "queues" / "rx-0" / "rps_cpus", "1,00000000")
    assert nic_health.rps_enabled("enp1s0") is True


def test_rps_enabled_none_when_interface_has_no_queues_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    assert nic_health.rps_enabled("does-not-exist") is None


def test_nic_drop_counters_reads_the_real_sysfs_statistics_files(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    _write(tmp_path / "enp1s0" / "statistics" / "rx_missed_errors", "833\n")
    _write(tmp_path / "enp1s0" / "statistics" / "rx_dropped", "30\n")
    assert nic_health.nic_drop_counters("enp1s0") == {"rx_missed_errors": 833, "rx_dropped": 30}


def test_nic_drop_counters_none_when_statistics_dir_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    assert nic_health.nic_drop_counters("does-not-exist") is None


def test_nic_load_status_reports_unavailable_when_no_interface_is_given_or_detected(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "PROC_NET_ROUTE", tmp_path / "does-not-exist")
    assert nic_health.nic_load_status() == {"available": False, "interface": None}


def test_nic_load_status_reports_unavailable_when_interface_has_no_queues_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    status = nic_health.nic_load_status(iface="ghost0")
    assert status == {"available": False, "interface": "ghost0"}


def test_nic_load_status_full_shape_when_everything_is_present(tmp_path, monkeypatch):
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    _write(tmp_path / "enp1s0" / "queues" / "rx-0" / "rps_cpus", "f")
    _write(tmp_path / "enp1s0" / "statistics" / "rx_missed_errors", "833")
    _write(tmp_path / "enp1s0" / "statistics" / "rx_dropped", "30")
    status = nic_health.nic_load_status(iface="enp1s0")
    assert status == {
        "available": True,
        "interface": "enp1s0",
        "rps_enabled": True,
        "rx_missed_errors": 833,
        "rx_dropped": 30,
    }


def test_with_baseline_none_leaves_status_untouched_but_flagged(tmp_path):
    status = {"available": True, "interface": "enp1s0", "rx_missed_errors": 5, "rx_dropped": 1}
    result = nic_health.with_baseline(status, None)
    assert result["baseline_set_at"] is None
    assert result["interface"] == "enp1s0"
    assert result["rx_missed_errors"] == 5
    assert "rx_missed_errors_since_baseline" not in result


def test_with_baseline_unavailable_status_short_circuits(tmp_path):
    status = {"available": False, "interface": None}
    baseline = {"interface": None, "rx_missed_errors": 0, "rx_dropped": 0, "set_at": "2026-09-12T00:00:00Z"}
    result = nic_health.with_baseline(status, baseline)
    assert result["baseline_set_at"] is None


def test_with_baseline_computes_the_delta_for_a_matching_interface():
    status = {"available": True, "interface": "enp1s0", "rx_missed_errors": 900, "rx_dropped": 40}
    baseline = {"interface": "enp1s0", "rx_missed_errors": 833, "rx_dropped": 30, "set_at": "2026-09-12T18:00:00Z"}
    result = nic_health.with_baseline(status, baseline)
    assert result["baseline_set_at"] == "2026-09-12T18:00:00Z"
    assert result["rx_missed_errors_since_baseline"] == 67
    assert result["rx_dropped_since_baseline"] == 10
    assert result["counters_reset_since_baseline"] is False
    assert result["interface_changed_since_baseline"] is False


def test_with_baseline_flags_a_different_interface_instead_of_computing_a_meaningless_delta():
    status = {"available": True, "interface": "enp2s0", "rx_missed_errors": 5, "rx_dropped": 1}
    baseline = {"interface": "enp1s0", "rx_missed_errors": 833, "rx_dropped": 30, "set_at": "2026-09-12T18:00:00Z"}
    result = nic_health.with_baseline(status, baseline)
    assert result["baseline_set_at"] is None
    assert result["interface_changed_since_baseline"] is True
    assert "rx_missed_errors_since_baseline" not in result


def test_with_baseline_clamps_a_negative_delta_and_flags_a_real_counter_reset():
    """The interface itself got reset since the baseline was taken (a
    reboot, an interface bounce) -- the live counter is genuinely lower
    than the stored baseline now. Must clamp to 0, not show a negative
    "since" count, and flag it so the admin knows to re-baseline."""
    status = {"available": True, "interface": "enp1s0", "rx_missed_errors": 2, "rx_dropped": 0}
    baseline = {"interface": "enp1s0", "rx_missed_errors": 833, "rx_dropped": 30, "set_at": "2026-09-12T18:00:00Z"}
    result = nic_health.with_baseline(status, baseline)
    assert result["counters_reset_since_baseline"] is True
    assert result["rx_missed_errors_since_baseline"] == 0
    assert result["rx_dropped_since_baseline"] == 0


def test_nic_load_status_defaults_counters_to_zero_when_statistics_dir_is_missing(tmp_path, monkeypatch):
    """rps_enabled() only needs queues/, so a queues-only fake tree (no
    statistics/ dir) must still report available=True with zeroed
    counters, not fall over or report unavailable."""
    monkeypatch.setattr(nic_health, "SYS_CLASS_NET", tmp_path)
    _write(tmp_path / "enp1s0" / "queues" / "rx-0" / "rps_cpus", "0")
    status = nic_health.nic_load_status(iface="enp1s0")
    assert status == {
        "available": True,
        "interface": "enp1s0",
        "rps_enabled": False,
        "rx_missed_errors": 0,
        "rx_dropped": 0,
    }
