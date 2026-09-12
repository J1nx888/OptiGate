#!/usr/bin/env python3
"""Best-effort device hostname discovery via mDNS reverse-PTR queries --
RoadMap.md, 2026-09-11: the project owner's own request, after being
asked to scope "pre-authentication" down to just "let me see the
device type that's trying to connect" -- the "Devices awaiting login"
card gets a Manufacturer column (common/oui_lookup.py, a pure offline
MAC-prefix lookup, no networking involved) and a Hostname column, which
this module feeds.

Distinct from every other controller/*.py discovery source: none of
them can produce a human-readable device name at all (rtnetlink/
discovery.py only ever see a MAC<->IP pairing; AdGuard's query log has
no MAC). A hostname has to come from the device itself, and mDNS
(Bonjour/Avahi -- most phones, laptops, smart-TVs, and many IoT
gadgets run an mDNS responder) is the standard, unauthenticated way to
ask a LAN device "what do you call yourself" without installing
anything on it. Not every device answers (most smart speakers,
including Echoes, don't respond to a bare reverse-PTR query) -- that's
fine, this is a hint for the "Manufacturer" column to lean on, not a
load-bearing identification mechanism. Same "display only, never
auto-associated" rule as oui_lookup.py -- see device_bindings.hostname's
own schema comment in common/db.py.

**Design decision: hand-rolled DNS wire format instead of a
third-party mDNS library.** A reverse-PTR query is one fixed-shape
question and (at most) one PTR answer to extract -- small enough to
implement and unit-test directly against crafted byte strings (see
tests/test_controller_mdns_lookup.py), and keeps this project's
dependency footprint exactly where it already was (stdlib only, same
discipline as common/, plus controller's one pre-existing pyroute2
exception). All response parsing is wrapped and bounds-checked (see
_decode_name's _MAX_NAME_JUMPS guard) because it handles untrusted
network input -- any malformed/hostile packet just yields "no hostname
this cycle," the same fail-soft outcome as an honest non-response.

**No CAP_NET_RAW, no multicast group join needed.** Sets the "QU" bit
(RFC 6762 SS5.4, the top bit of the question's class field) on the
query sent to 224.0.0.251:5353, which asks a compliant responder to
reply by ordinary unicast UDP straight back to this socket's own
ephemeral port -- so an ordinary UDP socket sending to that multicast
address is enough, the same "no special privilege needed" shape as
active_scan.py's own UDP-nudge trick, just for a different protocol.
"""
from __future__ import annotations

import logging
import random
import socket
import sqlite3
import struct
import time

import db
from periodic import PeriodicTask

log = logging.getLogger("controller.mdns_lookup")

_MDNS_ADDR = "224.0.0.251"
_MDNS_PORT = 5353
_TYPE_PTR = 12
_CLASS_IN = 1
_QU_BIT = 0x8000  # "unicast response requested", RFC 6762 SS5.4
_MAX_MESSAGE_BYTES = 4096
# Bounds a hostile/malformed response's compression-pointer chain --
# RFC 1035 names are never legitimately this deep; without this a
# crafted pointer loop would spin _decode_name forever.
_MAX_NAME_JUMPS = 128


def _reverse_arpa_name(ipv4_address: str) -> str:
    octets = ipv4_address.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        raise ValueError(f"not a dotted-quad IPv4 address: {ipv4_address!r}")
    return ".".join(reversed(octets)) + ".in-addr.arpa"


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out.append(len(encoded))
        out += encoded
    out.append(0)
    return bytes(out)


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    """Decodes a (possibly compressed) DNS name starting at `offset`.
    Returns (name, resume_offset) -- resume_offset is where the
    ENCLOSING record's own fields continue, i.e. right after this
    name's own length-byte/pointer bytes as they originally appeared at
    `offset` (correct whether or not a compression pointer was
    followed partway through)."""
    labels: list[str] = []
    jumps = 0
    pos = offset
    resume_at: int | None = None
    while True:
        if pos >= len(message):
            raise ValueError("name extends past end of message")
        length = message[pos]
        if length == 0:
            pos += 1
            if resume_at is None:
                resume_at = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(message):
                raise ValueError("truncated compression pointer")
            jumps += 1
            if jumps > _MAX_NAME_JUMPS:
                raise ValueError("too many compression pointer jumps")
            if resume_at is None:
                resume_at = pos + 2
            pos = ((length & 0x3F) << 8) | message[pos + 1]
            continue
        if length & 0xC0 != 0:
            raise ValueError("invalid DNS label length byte")
        pos += 1
        labels.append(message[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(labels), resume_at  # type: ignore[return-value]


def _strip_local_suffix(name: str) -> str | None:
    name = name.rstrip(".")
    if name.lower() == "local":
        # A bare "local." target (no actual hostname label in front of
        # it) is a degenerate/meaningless response -- treat it the same
        # as no answer at all rather than showing "local" as if it were
        # a real device name.
        return None
    if name.lower().endswith(".local"):
        name = name[: -len(".local")]
    return name or None


def _build_query(ipv4_address: str) -> tuple[bytes, str]:
    expected_name = _reverse_arpa_name(ipv4_address)
    transaction_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", transaction_id, 0, 1, 0, 0, 0)
    question = _encode_name(expected_name) + struct.pack(">HH", _TYPE_PTR, _CLASS_IN | _QU_BIT)
    return header + question, expected_name


def _parse_ptr_response(message: bytes, expected_name: str) -> str | None:
    """Returns the (`.local`-stripped) PTR target if `message` is a DNS
    response containing a PTR answer for `expected_name`, else None.
    Any malformed input raises ValueError/struct.error -- callers treat
    that identically to "no answer", see reverse_lookup()."""
    if len(message) < 12:
        return None
    _txid, _flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", message[0:12])
    pos = 12
    for _ in range(qdcount):
        _name, pos = _decode_name(message, pos)
        pos += 4  # QTYPE + QCLASS
    expected = expected_name.lower().rstrip(".")
    for _ in range(ancount):
        name, pos = _decode_name(message, pos)
        if pos + 10 > len(message):
            return None
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", message[pos:pos + 10])
        pos += 10
        rdata_start = pos
        pos += rdlength
        if rtype == _TYPE_PTR and name.lower().rstrip(".") == expected:
            target, _ = _decode_name(message, rdata_start)
            return _strip_local_suffix(target)
    return None


def reverse_lookup(ipv4_address: str, timeout: float = 1.0) -> str | None:
    """Best-effort mDNS reverse-PTR hostname lookup for `ipv4_address`.
    Returns the resolved hostname, or None on any failure, timeout, or
    malformed/irrelevant response -- a missed lookup just leaves that
    device's hostname unknown until the next cycle, never a reason to
    fail a caller's loop (same fail-soft shape as active_scan.py's own
    nudge())."""
    try:
        query, expected_name = _build_query(ipv4_address)
    except ValueError as exc:
        log.debug("skipping mDNS lookup for %r: %s", ipv4_address, exc)
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query, (_MDNS_ADDR, _MDNS_PORT))
    except OSError as exc:
        log.debug("mDNS query send to %s failed synchronously (ignored): %s", ipv4_address, exc)
        sock.close()
        return None
    try:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(_MAX_MESSAGE_BYTES)
            except (socket.timeout, OSError):
                return None
            if addr[0] != ipv4_address:
                # Fixed 2026-09-11, found by code review: mDNS is a
                # shared multicast channel, and this query's QU bit (see
                # module docstring) asks the real responder to reply by
                # unicast straight back to this socket -- so a legitimate
                # answer always arrives FROM ipv4_address itself. Without
                # this check, any other host on the segment answering
                # with a PTR record matching the expected reverse-arpa
                # name (a forged reply racing the real device, or just an
                # unrelated bystander packet) was trusted and written
                # into device_bindings.hostname as if it came from the
                # device we actually asked.
                continue
            try:
                hostname = _parse_ptr_response(data, expected_name)
            except (ValueError, struct.error):
                # Malformed/irrelevant packet (mDNS is a shared multicast
                # channel -- plenty of unrelated traffic arrives on it) --
                # keep listening until the deadline, don't give up on the
                # first bystander packet.
                continue
            if hostname:
                return hostname
    finally:
        sock.close()


def select_pending_targets(conn: sqlite3.Connection, limit: int) -> list[tuple[str, str]]:
    """Up to `limit` (mac_address, ipv4_address) pairs for devices
    currently on the "Devices awaiting login" card (same
    ignored/bypass_login/is_authenticated filter as dashboard.py's own
    pending_sql) whose CURRENT binding -- the same "most recent
    device_bindings row for this MAC, regardless of active" the
    dashboard's own current_ip column already uses -- has no hostname
    yet. Ordered oldest-current-sighting-first, same fairness reasoning
    as active_scan.py's select_stale_bindings()."""
    rows = conn.execute(
        """
        SELECT d.mac_address AS mac_address,
               (SELECT b.ipv4_address FROM device_bindings b
                WHERE b.mac_address = d.mac_address
                ORDER BY b.last_seen_at DESC LIMIT 1) AS ipv4_address,
               (SELECT b.hostname FROM device_bindings b
                WHERE b.mac_address = d.mac_address
                ORDER BY b.last_seen_at DESC LIMIT 1) AS hostname,
               (SELECT b.last_seen_at FROM device_bindings b
                WHERE b.mac_address = d.mac_address
                ORDER BY b.last_seen_at DESC LIMIT 1) AS last_seen_at
        FROM devices d
        WHERE d.ignored = 0 AND d.bypass_login = 0 AND d.is_authenticated = 0
        """
    ).fetchall()
    targets = [
        (row["mac_address"], row["ipv4_address"], row["last_seen_at"])
        for row in rows
        if row["ipv4_address"] and not row["hostname"]
    ]
    targets.sort(key=lambda t: t[2] or "")
    return [(mac, ip) for mac, ip, _ in targets[:limit]]


def lookup_once(conn: sqlite3.Connection, limit: int, timeout: float = 1.0) -> int:
    """One rate-limited lookup cycle. Returns how many hostnames were
    resolved and written (0 is a normal, healthy result -- every
    pending device either already has a hostname or didn't answer)."""
    targets = select_pending_targets(conn, limit)
    resolved = 0
    for mac_address, ipv4_address in targets:
        hostname = reverse_lookup(ipv4_address, timeout=timeout)
        if not hostname:
            continue
        conn.execute(
            "UPDATE device_bindings SET hostname = ? WHERE mac_address = ? AND ipv4_address = ?",
            (hostname, mac_address, ipv4_address),
        )
        resolved += 1
    if resolved:
        conn.commit()
    return resolved


def run_loop(
    interval: float,
    limit: int,
    timeout: float = 1.0,
    on_error=None,
    on_success=None,
) -> PeriodicTask:
    """Starts `lookup_once()` running on a fixed interval, on its own
    background thread, until the returned `PeriodicTask.stop()` is
    called -- same shape as active_scan.py's own run_loop, including
    opening its own DB connection lazily on the background thread
    (sqlite3.Connection objects are only usable from the thread that
    created them)."""
    state: dict[str, sqlite3.Connection] = {}

    def task() -> None:
        conn = state.get("conn")
        if conn is None:
            conn = db.get_conn()
            db.init_db(conn)
            state["conn"] = conn
        lookup_once(conn, limit, timeout=timeout)

    pt = PeriodicTask(interval, task, on_error=on_error, on_success=on_success, thread_name="mdns-lookup")
    pt.start()
    return pt
