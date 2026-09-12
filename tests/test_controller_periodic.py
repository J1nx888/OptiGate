"""controller/periodic.py: the generic background-interval-task
primitive shared by lease.HeartbeatPacer and discovery.run_loop.
lease.HeartbeatPacer's own tests (test_controller_lease.py) already
cover the thread-lifecycle behavior this class provides -- it's now a
thin, same-interface subclass -- so these tests focus on what's
specific to using PeriodicTask directly (a custom thread_name, no
on_error given at all) rather than re-proving the same timing behavior
a second time under a different class name."""
from __future__ import annotations

import threading
import time

from periodic import PeriodicTask


def test_task_runs_on_the_given_thread_name():
    seen_name = {}

    def task():
        seen_name["name"] = threading.current_thread().name

    pt = PeriodicTask(0.02, task, thread_name="my-custom-task")
    pt.start()
    time.sleep(0.05)
    pt.stop()

    assert seen_name.get("name") == "my-custom-task"


def test_task_runs_immediately_not_after_waiting_a_full_interval():
    """Regression for a real bug (RoadMap.md, "categories not
    pre-seeded"): every PeriodicTask consumer used to wait a full
    `interval` before its very first cycle -- harmless at a 5s
    reconciliation interval, but common/category_fetch.py's own 86400s
    default meant category subscriptions could never populate until
    controller had run continuously for a full day, which had never
    actually happened. A long interval proves this isn't just "the
    first tick happened to land inside the sleep window" -- it can only
    pass if the first call happens near-instantly."""
    calls = []
    lock = threading.Lock()

    def task():
        with lock:
            calls.append(time.monotonic())

    started_at = time.monotonic()
    pt = PeriodicTask(3600.0, task)
    pt.start()
    time.sleep(0.05)
    pt.stop()

    with lock:
        count = len(calls)
        first_call_at = calls[0] if calls else None
    assert count == 1, f"expected exactly one immediate call within 50ms, got {count}"
    assert first_call_at is not None and (first_call_at - started_at) < 1.0, (
        "expected the first call within ~1s of start(), not after waiting the full 3600s interval"
    )


def test_stop_before_start_never_runs_the_task_at_all():
    """The _stop.is_set() guard on the immediate call: calling stop()
    before start() (already-covered as "safe" by lease.py's own tests,
    for the no-thread-to-join case) sets the same Event a later start()
    would otherwise race against -- without the guard, the new
    immediate-first-tick behavior would run the task once anyway,
    despite being told to stop first."""
    calls = []

    def task():
        calls.append(1)

    pt = PeriodicTask(0.02, task)
    pt.stop()  # before start() -- see lease.py's own "stop before start is safe" coverage
    pt.start()
    time.sleep(0.05)
    pt.stop()

    assert calls == [], f"expected the task to never run at all, got {len(calls)} call(s)"


def test_task_calls_repeatedly_until_stopped():
    calls = []
    lock = threading.Lock()

    def task():
        with lock:
            calls.append(time.monotonic())

    pt = PeriodicTask(0.02, task)
    pt.start()
    time.sleep(0.15)
    pt.stop()

    with lock:
        count = len(calls)
    assert count >= 4, f"expected several calls in 150ms at a 20ms interval, got {count}"


def test_task_with_no_on_error_swallows_exceptions_without_dying():
    calls = []
    lock = threading.Lock()

    def task():
        with lock:
            calls.append(1)
        raise RuntimeError("boom")

    # No on_error given at all -- must not raise out of the background
    # thread (which would be silently lost anyway) or stop the loop.
    pt = PeriodicTask(0.02, task)
    pt.start()
    time.sleep(0.1)
    pt.stop()

    with lock:
        count = len(calls)
    assert count >= 2, f"expected the loop to keep calling task() despite errors, got {count}"


def test_on_success_fires_after_every_non_raising_cycle():
    successes = []
    lock = threading.Lock()

    def task():
        pass

    def on_success():
        with lock:
            successes.append(1)

    pt = PeriodicTask(0.02, task, on_success=on_success)
    pt.start()
    time.sleep(0.1)
    pt.stop()

    with lock:
        count = len(successes)
    assert count >= 2, f"expected on_success to fire on repeated successful cycles, got {count}"


def test_on_success_is_not_called_when_task_raises():
    successes = []
    lock = threading.Lock()

    def task():
        raise RuntimeError("boom")

    def on_success():
        with lock:
            successes.append(1)

    pt = PeriodicTask(0.02, task, on_success=on_success)
    pt.start()
    time.sleep(0.06)
    pt.stop()

    with lock:
        count = len(successes)
    assert count == 0, "on_success must never fire for a cycle that raised"


def test_on_error_itself_raising_does_not_kill_the_loop(caplog):
    """Real production incident, 2026-09-11 (see this module's own
    dated docstring): a real caller's on_error writes to the shared DB
    (common/system_events.py's failure_recovery_callbacks()), and that
    write can itself raise (sqlite3.OperationalError: database is
    locked, on a real box with several containers hitting the DB at
    once). That second exception used to have nowhere to go -- it
    escaped uncaught and killed the whole background thread outright,
    which is exactly what silently froze a real reconcile loop in
    production. The loop must survive an on_error that itself raises."""
    task_calls = []
    lock = threading.Lock()

    def task():
        with lock:
            task_calls.append(1)
        raise RuntimeError("original failure")

    def bad_on_error(exc):
        raise RuntimeError("on_error itself blew up")

    pt = PeriodicTask(0.02, task, on_error=bad_on_error)
    pt.start()
    time.sleep(0.1)
    pt.stop()

    with lock:
        count = len(task_calls)
    assert count >= 2, f"expected the loop to keep ticking despite on_error raising, got {count}"
    assert "on_error/on_success callback itself raised" in caplog.text


def test_on_success_itself_raising_does_not_kill_the_loop(caplog):
    """Same guard as the on_error case above, for symmetry -- on_success
    is called via the exact same _safe_report() path."""
    task_calls = []
    lock = threading.Lock()

    def task():
        with lock:
            task_calls.append(1)

    def bad_on_success():
        raise RuntimeError("on_success itself blew up")

    pt = PeriodicTask(0.02, task, on_success=bad_on_success)
    pt.start()
    time.sleep(0.1)
    pt.stop()

    with lock:
        count = len(task_calls)
    assert count >= 2, f"expected the loop to keep ticking despite on_success raising, got {count}"
    assert "on_error/on_success callback itself raised" in caplog.text


def test_on_stop_fires_exactly_once_after_the_loop_exits():
    """Added 2026-09-12 alongside `stop_requested` so
    controller/rtnetlink_listener.py could delegate its own
    thread/stop-Event bookkeeping to this class -- on_stop is that
    listener's one guaranteed place to close its thread-affine sqlite
    connection."""
    events = []
    lock = threading.Lock()

    def task():
        with lock:
            events.append("tick")

    def on_stop():
        with lock:
            events.append("stop")

    pt = PeriodicTask(0.02, task, on_stop=on_stop)
    pt.start()
    time.sleep(0.06)
    pt.stop()

    with lock:
        snapshot = list(events)
    assert snapshot.count("stop") == 1, f"expected on_stop exactly once, got {snapshot.count('stop')}"
    assert snapshot[-1] == "stop", "on_stop must fire after the last tick, not before"


def test_on_stop_fires_even_when_the_final_tick_raised():
    """The whole reason on_stop exists rather than callers wrapping their
    own task in try/finally: stop() can race in during the post-error
    backoff wait, so the very last cycle to actually run may have been a
    raising one. on_stop must still fire so a resource opened by task()
    is never leaked."""
    events = []
    lock = threading.Lock()

    def task():
        with lock:
            events.append("tick")
        raise RuntimeError("boom")

    def on_stop():
        with lock:
            events.append("stop")

    pt = PeriodicTask(0.02, task, on_stop=on_stop)
    pt.start()
    time.sleep(0.05)
    pt.stop()

    with lock:
        snapshot = list(events)
    assert snapshot.count("stop") == 1, f"expected on_stop exactly once even after a raising tick, got {snapshot}"


def test_on_stop_itself_raising_does_not_propagate(caplog):
    """Same guard as on_error/on_success -- on_stop is reported via the
    same _safe_report() path, so a bad on_stop must not raise out of
    stop()."""

    def task():
        pass

    def bad_on_stop():
        raise RuntimeError("on_stop itself blew up")

    pt = PeriodicTask(0.02, task, on_stop=bad_on_stop)
    pt.start()
    time.sleep(0.03)
    pt.stop()  # must not raise

    assert "on_error/on_success callback itself raised" in caplog.text


def test_stop_requested_reflects_whether_stop_has_been_called():
    pt = PeriodicTask(3600.0, lambda: None)
    assert pt.stop_requested is False
    pt.stop()
    assert pt.stop_requested is True


def test_on_success_and_on_error_alternate_correctly_across_a_transition():
    """A real regression class: on_success firing for a FAILED cycle (or
    vice versa) would silently corrupt system_events.py's own
    failure/recovery transition tracking."""
    events = []
    lock = threading.Lock()
    should_fail = {"value": True}

    def task():
        if should_fail["value"]:
            raise RuntimeError("boom")

    def on_error(exc):
        with lock:
            events.append(("error", str(exc)))

    def on_success():
        with lock:
            events.append(("success",))

    pt = PeriodicTask(0.02, task, on_error=on_error, on_success=on_success)
    pt.start()
    time.sleep(0.06)
    should_fail["value"] = False
    time.sleep(0.06)
    pt.stop()

    with lock:
        snapshot = list(events)
    assert any(e[0] == "error" for e in snapshot), "expected at least one error while should_fail was True"
    assert any(e[0] == "success" for e in snapshot), "expected at least one success after should_fail flipped"
    # Every entry logged before the flip must be an error, every entry
    # after must be a success -- no interleaving/misattribution.
    first_success_index = next(i for i, e in enumerate(snapshot) if e[0] == "success")
    assert all(e[0] == "error" for e in snapshot[:first_success_index])
    assert all(e[0] == "success" for e in snapshot[first_success_index:])
