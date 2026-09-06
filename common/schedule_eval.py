#!/usr/bin/env python3
"""Phase 8: time-window evaluation for `schedules` rows.

`schedule_is_active()` is pure (no DB access) and does the actual
day-of-week/time-of-day/time-zone arithmetic -- kept separate from
`is_full_lockout_active()` (which does need the DB, to enumerate
`lockout_all` schedules and check who they target) so the tricky part is
independently unit-testable without a database at all.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo

# Index matches Python's datetime.weekday() (Monday=0 .. Sunday=6) --
# see schedule_is_active()'s use of this below.
_DAY_CODES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _parse_hhmm(value: str) -> tuple[int, int]:
    """Parses a `schedules.start_time`/`end_time` value ("HH:MM"). Assumes
    well-formed input -- the dashboard's add/update routes are responsible
    for rejecting a malformed value before it ever reaches the database,
    same boundary-validation discipline as add_domain()'s regex check."""
    hour_str, _, minute_str = value.partition(":")
    return int(hour_str), int(minute_str)


def schedule_is_active(schedule_row: sqlite3.Row, now_utc: datetime) -> bool:
    """True if `now_utc` falls within `schedule_row`'s
    days_of_week/start_time/end_time window, evaluated in the schedule's
    OWN `time_zone` (never the server's local time, never bare UTC --
    "bedtime 21:00" means 21:00 in the household's zone). `now_utc` may be
    naive (assumed UTC, matching this project's own now_iso() convention)
    or tz-aware.

    Handles the overnight-wraparound case (`end_time < start_time`, e.g.
    bedtime "21:00" to "06:00") explicitly: such a window is active either
    during today's evening leg (today is a scheduled day, now is at or
    after start_time) OR during today's early-morning leg carried over
    from LAST night (yesterday was a scheduled day, now is still before
    end_time) -- so a Monday-night bedtime scheduled for "mon" alone still
    covers the Tuesday-morning hours before it ends, without needing "tue"
    listed too.
    """
    if now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=ZoneInfo("UTC"))
    local = now_utc.astimezone(ZoneInfo(schedule_row["time_zone"]))

    days = {d.strip().lower() for d in schedule_row["days_of_week"].split(",") if d.strip()}
    start_h, start_m = _parse_hhmm(schedule_row["start_time"])
    end_h, end_m = _parse_hhmm(schedule_row["end_time"])
    start_minutes = start_h * 60 + start_m
    end_minutes = end_h * 60 + end_m
    now_minutes = local.hour * 60 + local.minute
    today_code = _DAY_CODES[local.weekday()]

    if start_minutes == end_minutes:
        # Fixed 2026-09-02, a real bug found by code review: equal
        # start/end times (e.g. "00:00" to "00:00") is the natural way
        # an admin would type "block all day" -- but the same-day
        # branch below evaluates `start_minutes <= now_minutes <
        # end_minutes`, which is X <= now < X for any X, a range no
        # integer ever satisfies. That silently made a full-day
        # lockout schedule NEVER activate, on any day, with no error
        # anywhere to reveal why. Treated as "active all day on a
        # scheduled day" instead, matching what an admin who typed this
        # almost certainly meant.
        return today_code in days

    if start_minutes < end_minutes:
        # Same-day window: active only on a scheduled day, only inside
        # [start, end).
        return today_code in days and start_minutes <= now_minutes < end_minutes

    # Overnight window -- see docstring above for the two-leg logic.
    yesterday_code = _DAY_CODES[(local.weekday() - 1) % 7]
    evening_leg = today_code in days and now_minutes >= start_minutes
    morning_leg = yesterday_code in days and now_minutes < end_minutes
    return evening_leg or morning_leg


def active_override_for_device(
    conn: sqlite3.Connection, device: sqlite3.Row, now_utc: datetime
) -> sqlite3.Row | None:
    """The currently-unexpired `schedule_overrides` row targeting `device`
    -- directly, or via its `user_id`/`group_id` -- or None if no override
    is in effect right now. Device-level match wins over user-level, which
    wins over group-level, on the rare chance more than one somehow
    targets this device at once (dashboard.add_schedule_override() already
    clears any existing override for the exact target it's about to
    write, so this is a defensive tie-break, not the normal case).

    `now_utc` follows schedule_is_active()'s own naive-treated-as-UTC
    convention. `expires_at` is stored the same ISO-8601-UTC way every
    other timestamp column in this project is (see db.now_iso()), so a
    plain string comparison against a same-format value is correct and
    avoids parsing the stored value back into a datetime.
    """
    if now_utc.tzinfo is None:
        now_utc = now_utc.replace(tzinfo=ZoneInfo("UTC"))
    now_iso = now_utc.astimezone(ZoneInfo("UTC")).strftime("%Y-%m-%dT%H:%M:%S") + "Z"

    if device["id"] is not None:
        row = conn.execute(
            "SELECT * FROM schedule_overrides WHERE device_id = ? AND expires_at > ? "
            "ORDER BY created_at DESC LIMIT 1",
            (device["id"], now_iso),
        ).fetchone()
        if row is not None:
            return row
    if device["user_id"] is not None:
        row = conn.execute(
            "SELECT * FROM schedule_overrides WHERE user_id = ? AND expires_at > ? "
            "ORDER BY created_at DESC LIMIT 1",
            (device["user_id"], now_iso),
        ).fetchone()
        if row is not None:
            return row
    if device["group_id"] is not None:
        row = conn.execute(
            "SELECT * FROM schedule_overrides WHERE group_id = ? AND expires_at > ? "
            "ORDER BY created_at DESC LIMIT 1",
            (device["group_id"], now_iso),
        ).fetchone()
        if row is not None:
            return row
    return None


def schedule_is_active_for_device(
    conn: sqlite3.Connection, schedule_row: sqlite3.Row, device: sqlite3.Row, now_utc: datetime
) -> bool:
    """Device-aware wrapper around schedule_is_active() -- the one choke
    point both controller/policy_state.py (via is_full_lockout_active()
    below) and controller/adguard_sync.py's build_category_deny_rules()
    call instead of the bare clock check, so a Phase 12 override affects
    both enforcement paths (nftables lockout AND DNS-tier category
    blocks) without either module needing its own special case.

    Only a schedule with `is_mode = 1` is ever affected by an override --
    see schedules.is_mode's own comment in common/db.py for why this is
    opt-in rather than "an override suspends every schedule for this
    target": a standing safety-net category block (not one of a kid's
    swappable daily modes) must never be silently lifted by someone
    shifting that kid into Free Time.

    For an is_mode schedule: an active override for `device` means this
    schedule is active only if the override names IT specifically --
    every other is_mode schedule targeting the same device is forced
    INACTIVE for the override's duration, regardless of what the clock
    says (that's the "instead of", not "in addition to", semantics the
    feature exists for). No override at all falls through to the normal
    schedule_is_active() clock check, unchanged.
    """
    if not schedule_row["is_mode"]:
        return schedule_is_active(schedule_row, now_utc)
    override = active_override_for_device(conn, device, now_utc)
    if override is not None:
        return override["schedule_id"] == schedule_row["id"]
    return schedule_is_active(schedule_row, now_utc)


def is_full_lockout_active(conn: sqlite3.Connection, device: sqlite3.Row, now_utc: datetime) -> bool:
    """True if any `lockout_all=1` schedule is both currently active and
    targets `device` right now. Used by controller/policy_state.py's
    compute_desired_policy() as a pure computed overlay onto the nftables
    QUARANTINE set -- see that module's own comment on why this
    deliberately never writes devices.quarantined_at (a manual operator
    quarantine and a scheduled bedtime lockout stay on independent axes,
    the same separation `bump_eligible()` already established for bump vs.
    base classification).

    "Currently active" is schedule_is_active_for_device(), not the bare
    clock check -- so a mode-flagged Bedtime schedule can be manually
    suppressed (shifted into Free Time instead) exactly like a mode-
    flagged category-block schedule can, via the same schedule_overrides
    mechanism. A non-mode lockout_all schedule is unaffected either way.
    """
    import matching  # local import: keeps schedule_is_active() usable with zero DB dependency

    for row in conn.execute("SELECT * FROM schedules WHERE lockout_all = 1"):
        if schedule_is_active_for_device(conn, row, device, now_utc) and matching.schedule_applies_to_device(
            conn, device, row
        ):
            return True
    return False
