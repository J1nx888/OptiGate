#!/usr/bin/env python3
"""Entrypoint for the interception-controller (Milestones 3/4/6/7
scaffold).

Wires a WorkerClient, a desired-state source, reconcile(), and the
heartbeat pacer together into the control loop RoadMap.md's Milestone 3
describes: versioned Unix-socket IPC, generations, leases, idempotent
reconciliation. Milestone 6 adds systemd sd_notify/watchdog integration
and interception_runtime health reporting; Milestone 7 adds computing
and publishing the DesiredPolicy blob phase3/nftables-manager reads.

NOT a real deployable yet: --db-path wires in the real Milestone 4
desired-state source (controller/desired_state.py, devices +
device_bindings), but there's still no Dockerfile/systemd unit for this
component, and the gateway is passed in on the command line rather than
resolved live (that's the ARP worker's own job at startup -- see
phase3/arp-worker/internal/worker/safety.go's ResolveGateway -- not
something the controller should do a second time). See
docs/design/phase3-technical-design.md and RoadMap.md's milestone list.

**Discovery is now wired in (2026-08-30)**: when --db-path is given,
run() also starts controller/discovery.py's snapshot loop on its own
background thread and its own DB connection (see discovery.run_loop's
own docstring for why a separate connection is required). This is still
only the periodic ip-neigh-show snapshot -- the higher-precedence live
rtnetlink-event listener remains unbuilt (see discovery.py's module
docstring).
"""
from __future__ import annotations

import argparse
import logging
import signal
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Callable

# common/*.py lives in ../common relative to this file when run from a
# repo checkout. controller/Dockerfile (added 2026-08-30) instead
# flat-copies common/*.py alongside controller/*.py into one directory,
# matching proxy/Dockerfile and dashboard/Dockerfile's own pattern --
# in that layout ../common doesn't exist, but it doesn't need to:
# Python already puts this script's own directory (where the flat-
# copied common/*.py sit) on sys.path[0] by default. Only insert the
# repo-checkout path when it's actually there, so both layouts work.
_common_dir = Path(__file__).resolve().parent.parent / "common"
if _common_dir.is_dir():
    sys.path.insert(0, str(_common_dir))

import active_scan
import adguard_discovery
import adguard_sync
import category_fetch
import discovery
import readiness
import rtnetlink_listener
import health
import sdnotify
import system_events
from ipc_client import Target, WorkerClient, WorkerConnectionError, WorkerError
from lease import HeartbeatPacer
from reconcile import AppliedState, DesiredState, reconcile

log = logging.getLogger("controller")

# How many consecutive ARP send failures (worker.Worker.
# ConsecutiveSendFailures, reported via heartbeat_ack -- see
# run()'s arp_send_health) before run_cycle treats the pipeline as
# fail_open rather than running, even though the controller<->worker
# socket itself is perfectly healthy. The worker attempts a send for
# every active target on every poison tick (Config.Interval, 2s
# default) -- 3 needs no more than a couple of ticks' worth of genuine,
# sustained failure (the realistic case is the whole bound interface
# going down, which fails every send at once) to trip, while still
# tolerating one merely-transient dropped frame without flapping
# fail_open on every send.
ARP_SEND_FAILURE_THRESHOLD = 3


def placeholder_desired_state() -> DesiredState:
    """The default when --db-path isn't given. See
    controller/desired_state.py's db_backed_desired_state for the real
    Milestone 4 source (devices + device_bindings) -- this placeholder
    still exists for running against a worker with no real device data
    behind it yet. Deliberately raises rather than guessing at a
    "safe-looking" empty target list -- an empty DesiredState would
    still be a real generation applied to the worker (see reconcile()),
    which isn't something to do silently by default.
    """
    raise NotImplementedError(
        "no desired-state source configured -- pass --db-path (and "
        "--gateway-ip/--gateway-mac) to use the real devices/"
        "device_bindings source, or pass a different "
        "`desired_state_provider` to run() directly for manual testing."
    )


def run(
    socket_path: str,
    desired_state_provider: Callable[[], DesiredState],
    heartbeat_interval: float = 2.0,
    poll_interval: float = 5.0,
    health_conn: sqlite3.Connection | None = None,
    policy_conn: sqlite3.Connection | None = None,
    discovery_interval: float | None = None,
    enable_rtnetlink: bool = False,
    adguard_interval: float | None = None,
    adguard_discovery_interval: float | None = None,
    adguard_url: str | None = None,
    adguard_username: str | None = None,
    adguard_password: str | None = None,
    block_page_ip: str | None = None,
    worker_ready_timeout: float = 30.0,
    adguard_ready_timeout: float = 30.0,
    active_scan_interval: float | None = None,
    active_scan_stale_after: float = 300.0,
    active_scan_limit: int = 5,
    category_fetch_interval: float | None = None,
) -> None:
    """The main control loop. Runs until SIGTERM/SIGINT.

    Registering the signal handlers here (rather than in main()) is
    deliberate: run() is also what a future integration test would call
    directly against a real worker socket, and it should be
    self-contained regardless of caller.

    health_conn/policy_conn are separate parameters (even though
    they're typically the same connection in practice -- see
    _build_db_backed_provider) because they're conceptually independent:
    a caller could report health without computing policy, or vice
    versa, and keeping them distinct avoids run() assuming its caller's
    wiring. Either or both may be None.

    discovery_interval, if given (not None), starts discovery.py's
    periodic `ip neigh show` snapshot on its own background thread and
    its own DB connection (see discovery.run_loop's own docstring for
    why it must open that connection itself rather than being handed
    health_conn/policy_conn) for the duration of this call, stopped in
    the `finally` block below alongside the heartbeat pacer. None (the
    default) means no discovery loop runs, matching this parameter's
    absence before 2026-08-30 -- existing callers that don't pass it see
    no behavior change.

    enable_rtnetlink, if True, starts
    controller/rtnetlink_listener.py's live RTM_NEWNEIGH listener
    alongside the discovery snapshot loop above -- the higher-precedence
    source discovery.py's own docstring flagged as still unbuilt until
    2026-08-30. Also stopped in the `finally` block below. Independent
    of discovery_interval -- both can run together (the snapshot catches
    anything the live listener missed, e.g. a device already-idle before
    this process started), matching the design doc's own layered
    precedence order rather than one replacing the other.

    adguard_interval, if given (not None), starts
    controller/adguard_sync.py's periodic hard-deny sync on its own
    background thread and its own DB connection (same reasoning as
    discovery_interval above) for the duration of this call, stopped in
    the `finally` block alongside the heartbeat pacer and discovery
    task. adguard_url/adguard_username/adguard_password are required
    together with it -- see main()'s own argument validation.
    adguard_discovery_interval, if given (not None), starts
    controller/adguard_discovery.py's periodic querylog correlation on
    its own background thread and its own DB connection (same reasoning
    as discovery_interval above) -- Milestone 4's "AdGuard query-log
    observations (confirms active IP usage)" discovery source. Only
    refreshes last_seen_at for bindings another source already created;
    never creates one on its own (AdGuard's query log has no MAC).
    Independent of adguard_interval -- one pushes hard-deny rules TO
    AdGuard, the other only reads FROM it -- both require adguard_url/
    adguard_username/adguard_password when set.

    active_scan_interval, if given (not None), starts
    controller/active_scan.py's periodic rate-limited ARP-nudge loop on
    its own background thread and its own DB connection (same reasoning
    as discovery_interval above) -- Milestone 4's final discovery
    source, "active, rate-limited ARP scanning (only when stale or
    onboarding a new device)." Requires no adguard_url/credentials
    (unlike adguard_interval/adguard_discovery_interval above) since it
    never touches AdGuard at all -- it only nudges the kernel's own
    neighbor-resolution state for stale device_bindings rows;
    controller/discovery.py's own already-running snapshot loop is what
    actually observes and records any resulting resolution (see
    active_scan.py's module docstring). active_scan_stale_after/
    active_scan_limit control, respectively, how old last_seen_at must
    be before a binding is nudged and how many bindings get nudged per
    cycle -- the rate limit that keeps this from becoming a scan storm
    on a large household LAN.
    category_fetch_interval, if given (not None), starts
    common/category_fetch.py's periodic subscription-blocklist refresh
    (Phase 8) on its own background thread and its own DB connection
    (same reasoning as discovery_interval above) -- requires no
    adguard_url/credentials (same as active_scan_interval above) since it
    only fetches each category's OWN subscription_url and writes
    category_domains; it never talks to AdGuard itself (that's
    adguard_sync.py's build_category_deny_rules()/
    sync_category_subscriptions(), already running whenever
    adguard_interval is set).

    block_page_ip, if given, is threaded through to
    adguard_sync.build_rules() so hard-deny rules also carry a
    $dnsrewrite pointing at that IP's port 80 (see
    dashboard/block_page_server.py) instead of a bare deny -- optional
    even when adguard_interval is set, and silently ignored (see
    main()'s own _parse_block_page_ip) if not a plain IPv4 address.

    A single failed reconcile cycle (a worker fault, a transient DB
    error) is logged and reported via health_conn rather than crashing
    the process -- matching the fail-open design's "controller drives
    repair, not a crash" intent (RoadMap.md's Milestone 9 fault-
    campaign). If the underlying socket itself dies (WorkerConnectionError
    -- a broken pipe, connection reset, or EOF, as opposed to a healthy
    connection carrying an application-level fault), run() closes the
    dead client and tries exactly one fresh connection per loop
    iteration -- naturally rate-limited to poll_interval without needing
    explicit backoff, and still responsive to a stop request every
    iteration. `applied` is reset to None on reconnect: a freshly
    (re)connected worker process may be a brand-new process (systemd
    restarted it) with no memory of any prior generation, so the next
    cycle must treat this as a first application again rather than
    possibly skipping a resend because desired state happens not to
    have changed since the connection dropped.

    **This reconnect path is also triggered by a failed heartbeat, not
    just a failed run_cycle() (added 2026-08-30, a real gap found during
    this project's first live-container verification pass)**: if
    desired state never changes across a worker restart, run_cycle()'s
    own reconcile() correctly returns None every time (nothing new to
    send) and never touches the connection at all -- with an unchanging
    desired state, a dead worker could previously go undetected
    indefinitely, since the heartbeat pacer's own failures were only
    ever logged, never acted on. The heartbeat pacer is the one thing
    that touches the connection every single cycle regardless of
    desired state, which is what makes it the thing that actually
    notices. `heartbeat_worker_dead` (a threading.Event set by the
    pacer's on_error callback, checked at the top of the main loop)
    routes a heartbeat-detected failure through the exact same
    `_reconnect()` codepath run_cycle()'s own WorkerConnectionError
    uses, rather than duplicating the reconnect logic.

    Known race, accepted rather than fixed here given the scope of this
    pass: the heartbeat pacer runs on its own thread and reads `client`
    from this closure at call time. If it fires in the narrow window
    between closing a dead client and a fresh one being assigned, its
    heartbeat call raises AttributeError on None -- HeartbeatPacer's own
    broad exception handling logs it via on_error rather than crashing,
    so this is a harmless, if noisy, cosmetic race, not a correctness
    bug. A future pass could add a lock around client reads/writes if
    the noise proves annoying in practice.

    worker_ready_timeout/adguard_ready_timeout (Milestone 6's readiness
    gates, added 2026-08-31 -- see controller/readiness.py) bound how
    long this call blocks waiting for each real dependency to actually
    answer, rather than just having started: the initial worker connect
    below retries for up to worker_ready_timeout seconds instead of
    failing on the very first attempt (closing the ordinary "arp-worker
    hasn't created its socket file yet" startup race docker-compose.yml's
    own comment already documented as an accepted one-restart-cycle gap
    -- this makes that restart far less often necessary, it doesn't
    remove Docker's restart policy as the fallback if the worker is
    genuinely never going to come up). adguard_ready_timeout similarly
    bounds a best-effort wait for AdGuard before starting the periodic
    sync loop and calling sdnotify.ready() -- but, unlike the worker
    socket, never raises: AdGuard isn't required for the rest of this
    function, and adguard_sync.py's own run_loop() already retries
    forever on its own schedule regardless of this gate's outcome.
    """
    client = readiness.wait_for_worker(socket_path, timeout=worker_ready_timeout)
    applied: AppliedState | None = None
    sequence = 0
    stop = False

    def _request_stop(signum, frame):  # noqa: ARG001 -- required signal handler signature
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)

    # Written by _send_heartbeat below (heartbeat-pacer thread), read by
    # run_cycle (main thread) once per reconcile cycle -- a plain dict
    # rather than a lock is enough here since CPython's GIL makes a
    # single dict-item assignment/read atomic, matching this file's own
    # heartbeat_worker_dead precedent for cross-thread signaling without
    # a full lock. Added 2026-08-31 to close a real, confirmed gap: a
    # NIC-down test against a properly-isolated veth harness showed
    # interception_runtime staying "running" throughout a sustained real
    # ARP-send-failure window, because nothing upstream of
    # worker.Worker.ConsecutiveSendFailures (added the same day) existed
    # to carry that signal from the worker to here. See run_cycle's own
    # docstring for how this gets turned into a fail_open report.
    arp_send_health = {"consecutive_failures": 0}

    def _send_heartbeat() -> None:
        nonlocal sequence
        sequence += 1
        ack = client.heartbeat(sequence)
        arp_send_health["consecutive_failures"] = ack.consecutive_send_failures
        sdnotify.watchdog()  # a successful heartbeat round-trip IS this process's own liveness signal

    # Set by the heartbeat pacer's own error callback below when a
    # heartbeat fails with WorkerConnectionError -- checked at the top
    # of the main loop to trigger the exact same reconnect path
    # run_cycle()'s own WorkerConnectionError handling uses. Added
    # 2026-08-30 after a real gap found during this project's first
    # live-container verification pass: if desired state never changes
    # across a worker restart, run_cycle() never touches the connection
    # at all (by design -- reconcile() returns None, nothing to send),
    # so a dead worker was previously only ever noticed by whichever
    # thread happened to actually try using the socket next -- which,
    # with an unchanging desired state, could be never. The heartbeat
    # pacer is the one thing that ALWAYS touches the connection every
    # cycle regardless of desired state, making it the right place to
    # actually detect this.
    heartbeat_worker_dead = threading.Event()

    # Added 2026-09-02, same cross-thread-signaling shape as
    # heartbeat_worker_dead above: the worker's own unsolicited
    # lease-expiry fault (see phase3/arp-worker's ipc.Server.Notify) is
    # asynchronous, so it can arrive as the "reply" to whichever request
    # this connection happens to send next -- which, in practice, is
    # often a routine heartbeat rather than run_cycle()'s own
    # replace_targets/reconcile call. run_cycle()'s docstring documents
    # it as the sole writer of health_conn's mode column specifically to
    # avoid two threads racing on that write, so this thread must NOT
    # call health.report_repair_only() directly -- it only records the
    # reason here; the main loop below performs the actual write.
    heartbeat_repair_only = {"reason": None}

    def _on_heartbeat_error(exc: Exception) -> None:
        log.warning("heartbeat failed: %s", exc)
        if isinstance(exc, WorkerConnectionError):
            heartbeat_worker_dead.set()
        elif isinstance(exc, WorkerError) and exc.action == "entering_repair_only_mode":
            heartbeat_repair_only["reason"] = str(exc)
        # No system_events recovery-transition tracking here (unlike the
        # loops below) -- a dead worker already surfaces via the Health
        # page's own fail_open state, and reconnect logic already lives
        # in this function's own _reconnect() path, not in a PeriodicTask
        # on_success hook. Still worth a row so an admin can see WHEN and
        # HOW OFTEN this happened, even without a matching recovery row.
        conn = None
        try:
            import db as _db

            conn = _db.get_conn()
            system_events.log_event(conn, "controller_heartbeat", "error", f"heartbeat failed: {exc}")
        finally:
            if conn is not None:
                conn.close()

    def _events(source: str, log_message: str):
        """Combines this function's existing log.warning(...) reporting
        with system_events' own failure/recovery tracking for one named
        periodic loop -- see system_events.failure_recovery_callbacks()'s
        docstring for why recoveries are tracked via an in-process
        closure rather than state persisted across a restart."""
        event_error, event_success = system_events.failure_recovery_callbacks(source)

        def on_error(exc: Exception) -> None:
            log.warning(log_message, exc)
            event_error(exc)

        return on_error, event_success

    pacer = HeartbeatPacer(heartbeat_interval, _send_heartbeat, on_error=_on_heartbeat_error)
    pacer.start()

    discovery_task = None
    if discovery_interval is not None:
        _on_error, _on_success = _events("discovery", "discovery snapshot failed: %s")
        discovery_task = discovery.run_loop(discovery_interval, on_error=_on_error, on_success=_on_success)

    rtnetlink_task = None
    if enable_rtnetlink:
        # No on_success/recovery tracking here -- unlike the fixed-
        # interval loops below, this is a continuous event listener with
        # no discrete per-cycle "did this succeed" concept to hook a
        # recovery transition onto; on_error still gets a system_events
        # row per occurrence via _events(), the recovery half of the
        # pair is just never called.
        _on_error, _ = _events("rtnetlink_listener", "rtnetlink listener failed: %s")
        rtnetlink_task = rtnetlink_listener.run_loop(on_error=_on_error)

    adguard_task = None
    if adguard_interval is not None:
        readiness.wait_for_adguard(
            adguard_url, adguard_username, adguard_password, timeout=adguard_ready_timeout
        )
        _on_error, _on_success = _events("adguard_sync", "adguard sync failed: %s")
        adguard_task = adguard_sync.run_loop(
            adguard_interval,
            adguard_url,
            adguard_username,
            adguard_password,
            block_page_ip=block_page_ip,
            on_error=_on_error,
            on_success=_on_success,
        )

    adguard_discovery_task = None
    if adguard_discovery_interval is not None:
        _on_error, _on_success = _events("adguard_discovery", "adguard discovery correlation failed: %s")
        adguard_discovery_task = adguard_discovery.run_loop(
            adguard_discovery_interval,
            adguard_url,
            adguard_username,
            adguard_password,
            on_error=_on_error,
            on_success=_on_success,
        )

    active_scan_task = None
    if active_scan_interval is not None:
        _on_error, _on_success = _events("active_scan", "active ARP scan failed: %s")
        active_scan_task = active_scan.run_loop(
            active_scan_interval,
            active_scan_stale_after,
            active_scan_limit,
            on_error=_on_error,
            on_success=_on_success,
        )

    category_fetch_task = None
    if category_fetch_interval is not None:
        _on_error, _on_success = _events("category_fetch", "category subscription fetch failed: %s")
        category_fetch_task = category_fetch.run_loop(
            category_fetch_interval, on_error=_on_error, on_success=_on_success
        )

    sdnotify.ready()

    def _reconnect(reason: str) -> None:
        nonlocal client, applied
        log.warning("worker connection lost (%s) -- attempting to reconnect", reason)
        if health_conn is not None:
            health.report_fail_open(health_conn, f"worker connection lost: {reason}")
        client.close()
        try:
            client = WorkerClient.connect(socket_path)
            applied = None
            log.info("reconnected to worker")
        except OSError as reconnect_exc:
            log.warning("reconnect attempt failed, will retry next cycle: %s", reconnect_exc)

    try:
        while not stop:
            if heartbeat_worker_dead.is_set():
                heartbeat_worker_dead.clear()
                _reconnect("detected via a failed heartbeat")
            else:
                try:
                    applied = run_cycle(
                        client, desired_state_provider, applied, health_conn, policy_conn,
                        arp_send_health["consecutive_failures"],
                    )
                except WorkerConnectionError as exc:
                    _reconnect(str(exc))
                # Checked AFTER run_cycle(), on the main thread, same
                # single-writer discipline as every other health_conn
                # write here -- see heartbeat_repair_only's own comment
                # above for why the heartbeat thread itself never calls
                # health.report_repair_only() directly.
                repair_reason = heartbeat_repair_only["reason"]
                if repair_reason is not None:
                    heartbeat_repair_only["reason"] = None
                    if health_conn is not None:
                        health.report_repair_only(health_conn, repair_reason)
            time.sleep(poll_interval)
    finally:
        pacer.stop()
        if discovery_task is not None:
            discovery_task.stop()
        if rtnetlink_task is not None:
            rtnetlink_task.stop()
        if adguard_task is not None:
            adguard_task.stop()
        if adguard_discovery_task is not None:
            adguard_discovery_task.stop()
        if active_scan_task is not None:
            active_scan_task.stop()
        if category_fetch_task is not None:
            category_fetch_task.stop()
        try:
            client.shutdown("controller_requested")
        except WorkerConnectionError:
            pass  # already dead -- nothing to tell it
        client.close()


def run_cycle(
    client: WorkerClient,
    desired_state_provider: Callable[[], DesiredState],
    applied: AppliedState | None,
    health_conn: sqlite3.Connection | None,
    policy_conn: sqlite3.Connection | None,
    consecutive_send_failures: int = 0,
) -> AppliedState | None:
    """One reconcile+health+policy cycle, pulled out of run()'s loop
    specifically so it's independently testable against a fake worker
    socket without needing to fight Python's main-thread-only
    signal.signal() restriction that run() itself is subject to.

    A failure anywhere in this cycle is caught and reported via
    health_conn rather than propagating -- see run()'s own docstring
    for why a single bad cycle shouldn't crash the process -- with ONE
    deliberate exception: WorkerConnectionError propagates to the
    caller uncaught, since only run() (which owns the WorkerClient
    variable) can actually reconnect; this function has no way to hand
    its caller a replacement client. Returns the (possibly unchanged)
    AppliedState for the caller to pass back in next cycle.

    consecutive_send_failures (added 2026-08-31) is the most recent
    value of worker.Worker.ConsecutiveSendFailures, read from run()'s
    own arp_send_health (populated by the heartbeat pacer, which runs
    independently of this cycle) -- NOT re-fetched here, so this
    function stays the single writer of health_conn's mode/
    fail_open_reason columns rather than racing the heartbeat thread
    for that write. A reconcile cycle can succeed completely (the
    controller<->worker socket is fine, desired state was computed and
    sent) while the worker's actual packet transmission is failing --
    the whole point of this parameter is making that distinction
    visible instead of unconditionally reporting healthy whenever the
    socket itself is fine. See ARP_SEND_FAILURE_THRESHOLD's own comment
    for why 3.
    """
    try:
        desired = desired_state_provider()
        next_gen = reconcile(applied, desired)
        if next_gen is not None:
            result = client.replace_targets(
                next_gen, desired.gateway, list(desired.targets), desired.full_duplex
            )
            if result.resolution_failures:
                log.warning("worker rejected some targets: %s", result.resolution_failures)
            applied = AppliedState(generation=next_gen, desired=desired)
            log.info("applied generation %d (%d targets)", next_gen, result.target_count)

        if policy_conn is not None:
            # Milestone 7: recompute and publish DesiredPolicy every
            # cycle -- phase3/nftables-manager reads this directly from
            # the DB (see policy_state.py's own module doc), so this is
            # the only "push" step needed on this side.
            from policy_state import compute_desired_policy, write_desired_policy

            write_desired_policy(policy_conn, compute_desired_policy(policy_conn))

        if health_conn is not None:
            if consecutive_send_failures >= ARP_SEND_FAILURE_THRESHOLD:
                health.report_fail_open(
                    health_conn,
                    f"arp-worker: {consecutive_send_failures} consecutive ARP send "
                    "failures (the bound network interface is likely down)",
                    applied_generation=applied.generation if applied else 0,
                )
            else:
                health.report_healthy(health_conn, applied.generation if applied else 0)
    except WorkerConnectionError:
        raise  # let run() handle reconnection -- see this function's own docstring
    except WorkerError as exc:
        # A real reply from a live worker, just an unhappy one -- most
        # commonly the worker's own unsolicited lease-expiry fault
        # (added 2026-09-02: the worker now actually sends this instead
        # of silently self-correcting with zero signal, see
        # phase3/arp-worker's ipc.Server.Notify). Distinguish that
        # specific, self-limiting case (repair_only -- the worker
        # already restored real MACs and stopped poisoning on its own)
        # from every other WorkerError (fail_open), so the dashboard's
        # amber vs. red badge actually means something -- see
        # health.report_repair_only()'s own docstring for why this was
        # previously unreachable.
        log.warning("reconcile cycle failed: %s", exc)
        if health_conn is not None:
            if exc.action == "entering_repair_only_mode":
                health.report_repair_only(health_conn, str(exc))
            else:
                health.report_fail_open(health_conn, str(exc))
    except Exception as exc:  # noqa: BLE001 -- deliberately broad, see run()'s own docstring
        log.warning("reconcile cycle failed: %s", exc)
        if health_conn is not None:
            health.report_fail_open(health_conn, str(exc))

    return applied


def _build_db_backed_provider(
    db_path: str, gateway_ip: str, gateway_mac: str, full_duplex: bool
) -> tuple[Callable[[], DesiredState], sqlite3.Connection]:
    import db
    from desired_state import db_backed_desired_state

    db.DB_PATH = Path(db_path)
    conn = db.get_conn()
    db.init_db(conn)
    gateway = Target(ip=gateway_ip, mac=gateway_mac)

    provider = lambda: db_backed_desired_state(conn, gateway, full_duplex=full_duplex)  # noqa: E731
    return provider, conn


def _parse_block_page_ip(dashboard_url: str | None) -> str | None:
    """Extracts a plain IPv4 host from a DASHBOARD_URL-shaped value
    (e.g. "http://192.168.1.50:8787" -> "192.168.1.50") for
    adguard_sync.py's $dnsrewrite target -- which needs a literal IP,
    not a hostname (a hostname would itself need DNS resolution,
    circular for a rule that exists to REPLACE DNS resolution). Returns
    None for anything that isn't a plain IPv4 address (including a
    genuine hostname, or an unset/malformed URL) -- this is a cosmetic
    enhancement (see dashboard/block_page_server.py's own docstring),
    not something worth failing loudly over if misconfigured; a device
    just keeps getting the plain default deny instead of a friendly page.
    """
    if not dashboard_url:
        return None
    import ipaddress
    from urllib.parse import urlparse

    host = urlparse(dashboard_url).hostname
    if not host:
        return None
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        return None
    return host


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default="/run/optigate/arp-worker.sock")
    parser.add_argument("--heartbeat-interval", type=float, default=2.0)
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument(
        "--worker-ready-timeout", type=float, default=30.0,
        help="Seconds to retry connecting to --socket before giving up "
        "(controller/readiness.py, Milestone 6) -- turns the ordinary "
        "arp-worker-hasn't-created-its-socket-yet startup race into a fast "
        "in-process retry instead of a full container restart cycle.",
    )
    parser.add_argument(
        "--adguard-ready-timeout", type=float, default=30.0,
        help="Seconds to wait for AdGuard's API to answer before starting the "
        "periodic sync loop anyway (controller/readiness.py, Milestone 6). "
        "Only relevant when --adguard-url is set; never blocks startup "
        "indefinitely or fails hard -- the periodic sync keeps retrying on "
        "its own schedule regardless of this timeout's outcome.",
    )
    parser.add_argument(
        "--db-path",
        help="Use the real devices/device_bindings tables (Milestone 4) as the "
        "desired-state source instead of the placeholder, and enable health/"
        "policy reporting into the same database (Milestones 6/7). Requires "
        "--gateway-ip and --gateway-mac.",
    )
    parser.add_argument("--gateway-ip", help="Required if --db-path is set.")
    parser.add_argument("--gateway-mac", help="Required if --db-path is set.")
    parser.add_argument("--full-duplex", action="store_true")
    parser.add_argument(
        "--discovery-interval", type=float, default=30.0,
        help="Seconds between discovery.py periodic ip-neigh-show snapshots "
        "(only runs at all if --db-path is set). See controller/discovery.py's "
        "module docstring for what this does and doesn't catch.",
    )
    parser.add_argument(
        "--no-discovery", action="store_true",
        help="Disable the discovery snapshot loop even when --db-path is set "
        "-- e.g. for a deployment that already runs the snapshot externally "
        "(cron, a separate process) and doesn't want it duplicated here.",
    )
    parser.add_argument(
        "--no-rtnetlink", action="store_true",
        help="Disable the live rtnetlink RTM_NEWNEIGH listener "
        "(controller/rtnetlink_listener.py) even when --db-path is set. "
        "Requires the pyroute2 package (controller/requirements.txt) and a "
        "Linux host -- enabled by default alongside --db-path since it has "
        "no interval of its own to tune, only a way to turn it off.",
    )
    parser.add_argument(
        "--adguard-url",
        help="Base URL of AdGuard Home's control API, e.g. http://127.0.0.1:3000 "
        "(or http://adguard:3000 once this process runs in the same compose "
        "network as the adguard service). Enables the hard-deny sync loop "
        "(controller/adguard_sync.py) when set, together with "
        "--adguard-username/--adguard-password. Only runs at all if --db-path "
        "is also set.",
    )
    parser.add_argument("--adguard-username", help="Required if --adguard-url is set.")
    parser.add_argument("--adguard-password", help="Required if --adguard-url is set.")
    parser.add_argument(
        "--adguard-interval", type=float, default=30.0,
        help="Seconds between adguard_sync.py hard-deny rule pushes (only runs "
        "at all if --adguard-url is set).",
    )
    parser.add_argument(
        "--adguard-discovery-interval", type=float, default=60.0,
        help="Seconds between controller/adguard_discovery.py querylog "
        "correlation cycles -- Milestone 4's 'confirms active IP usage' "
        "discovery source (only runs at all if --adguard-url is set). Longer "
        "than --adguard-interval by default since this is a soft freshness "
        "signal, not enforcement.",
    )
    parser.add_argument(
        "--no-adguard-discovery", action="store_true",
        help="Disable the querylog correlation loop even when --adguard-url is "
        "set -- e.g. if AdGuard's query log is disabled/rotated too fast to be "
        "useful in a given deployment.",
    )
    parser.add_argument(
        "--active-scan-interval", type=float, default=60.0,
        help="Seconds between controller/active_scan.py rate-limited ARP-nudge "
        "cycles -- Milestone 4's 'active, rate-limited ARP scanning (only when "
        "stale or onboarding a new device)' source (only runs at all if "
        "--db-path is set). Requires no AdGuard config -- see --no-active-scan "
        "to disable it independently.",
    )
    parser.add_argument(
        "--category-fetch-interval", type=float, default=86400.0,
        help="Seconds between common/category_fetch.py subscription-blocklist "
        "refreshes (Phase 8) -- only runs at all if --db-path is set. Requires "
        "no AdGuard config, same as --active-scan-interval, since this only "
        "fetches each category's own subscription_url and writes "
        "category_domains; see --no-category-fetch to disable it "
        "independently. Defaults to once a day -- category lists change far "
        "less often than AdGuard's own bundled ad/tracker lists.",
    )
    parser.add_argument(
        "--no-category-fetch", action="store_true",
        help="Disable the subscription-blocklist refresh loop even when "
        "--db-path is set -- categories stay whatever was last fetched (or "
        "manual-only, for a category with no subscription_url).",
    )
    parser.add_argument(
        "--active-scan-stale-after", type=float, default=300.0,
        help="Seconds a device_bindings row's last_seen_at must be older than "
        "before controller/active_scan.py nudges it -- distinct from "
        "dashboard.py's own HEALTH_STALE_AFTER_SECONDS (that's about "
        "interception-runtime health, this is about device freshness).",
    )
    parser.add_argument(
        "--active-scan-limit", type=int, default=5,
        help="Maximum number of stale bindings controller/active_scan.py nudges "
        "per cycle -- the rate limit that keeps this from becoming a scan storm "
        "on a large household LAN.",
    )
    parser.add_argument(
        "--no-active-scan", action="store_true",
        help="Disable the active ARP-nudge loop even when --db-path is set.",
    )
    parser.add_argument(
        "--dashboard-url",
        help="Same value as the dashboard's own DASHBOARD_URL env var, e.g. "
        "http://192.168.1.50:8787 -- if set (and its host is a plain IPv4 "
        "address), adguard_sync.py points hard-denied domains' DNS answers at "
        "that IP's port 80 (dashboard/block_page_server.py) instead of the "
        "bare default deny, showing a friendly page for plain-HTTP requests. "
        "Silently has no effect if unset or if the host isn't a plain IPv4 "
        "address (AdGuard's $dnsrewrite modifier needs a literal IP, not a "
        "hostname) -- this is a cosmetic enhancement, not something worth "
        "failing loudly over.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO)

    if args.adguard_url and not (args.adguard_username and args.adguard_password):
        parser.error("--adguard-url requires --adguard-username and --adguard-password")

    conn: sqlite3.Connection | None = None
    discovery_interval: float | None = None
    enable_rtnetlink = False
    adguard_interval: float | None = None
    adguard_discovery_interval: float | None = None
    active_scan_interval: float | None = None
    category_fetch_interval: float | None = None
    if args.db_path:
        if not args.gateway_ip or not args.gateway_mac:
            parser.error("--db-path requires --gateway-ip and --gateway-mac")
        provider, conn = _build_db_backed_provider(
            args.db_path, args.gateway_ip, args.gateway_mac, args.full_duplex
        )
        if not args.no_discovery:
            # discovery.run_loop() opens its own connection internally
            # (see its docstring for why) -- db.DB_PATH is already set to
            # args.db_path by _build_db_backed_provider above, so it just
            # needs to be told to run at all, and at what interval.
            discovery_interval = args.discovery_interval
        if not args.no_rtnetlink:
            # rtnetlink_listener.run_loop() opens its own connection
            # internally too, same reasoning -- see its own module
            # docstring for why pyroute2 (Linux-only) is imported lazily
            # rather than at this file's top level.
            enable_rtnetlink = True
        if args.adguard_url:
            # Same reasoning as discovery_interval above -- adguard_sync
            # opens its own connection internally, reading the DB
            # policy-state discovery already keeps current.
            adguard_interval = args.adguard_interval
            if not args.no_adguard_discovery:
                # adguard_discovery.run_loop() opens its own connection
                # internally too, same reasoning as discovery_interval
                # above -- only meaningful alongside adguard_interval
                # since both require the same adguard_url/credentials.
                adguard_discovery_interval = args.adguard_discovery_interval
        if not args.no_active_scan:
            # active_scan.run_loop() opens its own connection internally
            # too, same reasoning as discovery_interval above -- unlike
            # adguard_discovery above, this needs no adguard_url/
            # credentials gate since it never touches AdGuard at all.
            active_scan_interval = args.active_scan_interval
        if not args.no_category_fetch:
            # category_fetch.run_loop() opens its own connection
            # internally too, same reasoning as active_scan above -- this
            # also never touches AdGuard at all, only the category's own
            # subscription_url and the shared DB.
            category_fetch_interval = args.category_fetch_interval
    else:
        provider = placeholder_desired_state

    run(
        args.socket,
        provider,
        args.heartbeat_interval,
        args.poll_interval,
        health_conn=conn,
        policy_conn=conn,
        discovery_interval=discovery_interval,
        enable_rtnetlink=enable_rtnetlink,
        adguard_interval=adguard_interval,
        adguard_discovery_interval=adguard_discovery_interval,
        adguard_url=args.adguard_url,
        adguard_username=args.adguard_username,
        adguard_password=args.adguard_password,
        block_page_ip=_parse_block_page_ip(args.dashboard_url),
        worker_ready_timeout=args.worker_ready_timeout,
        adguard_ready_timeout=args.adguard_ready_timeout,
        active_scan_interval=active_scan_interval,
        active_scan_stale_after=args.active_scan_stale_after,
        active_scan_limit=args.active_scan_limit,
        category_fetch_interval=category_fetch_interval,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
