#!/usr/bin/env python3
"""Minimal systemd sd_notify protocol client -- stdlib only, no
third-party dependency. Mirrors the ARP worker's use of
github.com/coreos/go-systemd/v22/daemon on the Go side.

Implements exactly the two messages this project needs (READY=1,
WATCHDOG=1), not the full sd_notify protocol -- see
https://www.freedesktop.org/software/systemd/man/sd_notify.html for
the complete spec if more is ever needed.
"""
from __future__ import annotations

import os
import socket


def _notify_socket_path() -> str | None:
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        return None
    if path.startswith("@"):
        path = "\0" + path[1:]  # Linux abstract socket namespace
    return path


def notify(message: str) -> bool:
    """Sends one sd_notify datagram. Returns False (not an error) when
    NOTIFY_SOCKET isn't set -- the normal case when not running under
    systemd (local dev, a plain `python3 main.py` invocation, or the
    test suite)."""
    path = _notify_socket_path()
    if path is None:
        return False
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(path)
        sock.sendall(message.encode("utf-8"))
    finally:
        sock.close()
    return True


def ready() -> bool:
    return notify("READY=1")


def watchdog() -> bool:
    return notify("WATCHDOG=1")


def watchdog_usec() -> int | None:
    """The WatchdogSec= interval systemd configured, in microseconds, or
    None if no watchdog is configured (WATCHDOG_USEC unset or
    unparseable) -- mirrors coreos/go-systemd's SdWatchdogEnabled."""
    raw = os.environ.get("WATCHDOG_USEC")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None
