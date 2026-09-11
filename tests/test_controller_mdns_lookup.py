"""controller/mdns_lookup.py: best-effort mDNS reverse-PTR hostname
lookup for devices on the "Devices awaiting login" card (RoadMap.md,
2026-09-11). The hand-rolled DNS wire-format encode/decode is tested
directly against crafted byte strings -- see this module's own
docstring for why hand-rolling this (rather than a third-party mDNS
library) was the chosen design. All real network I/O (`socket.socket`)
is monkeypatched via `_FakeSocket`, same pattern as
test_controller_active_scan.py -- these tests never touch a real
network. The UDP "QU bit" technique itself is standard RFC 6762 SS5.4
behavior, not separately live-verified here.
"""
from __future__ import annotations

import socket as real_socket
import struct
import threading
import time

import pytest

import identity
import mdns_lookup

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"
IP_1 = "192.168.1.10"
IP_2 = "192.168.1.11"


# ============================================================
# _reverse_arpa_name
# ============================================================

def test_reverse_arpa_name_reverses_octets():
    assert mdns_lookup._reverse_arpa_name("192.168.1.10") == "10.1.168.192.in-addr.arpa"


def test_reverse_arpa_name_rejects_malformed_ip():
    with pytest.raises(ValueError):
        mdns_lookup._reverse_arpa_name("not-an-ip")
    with pytest.raises(ValueError):
        mdns_lookup._reverse_arpa_name("1.2.3")


# ============================================================
# _encode_name / _decode_name round trip
# ============================================================

def test_encode_decode_round_trip_plain_name():
    encoded = mdns_lookup._encode_name("10.1.168.192.in-addr.arpa")
    name, resume = mdns_lookup._decode_name(encoded, 0)
    assert name == "10.1.168.192.in-addr.arpa"
    assert resume == len(encoded)


def test_encode_rejects_an_oversized_label():
    with pytest.raises(ValueError):
        mdns_lookup._encode_name("a" * 64 + ".local")


def test_decode_name_follows_a_compression_pointer():
    # First name stored literally at offset 0; second "name" is just a
    # 2-byte pointer back to it.
    first = mdns_lookup._encode_name("my-laptop.local")
    pointer = struct.pack(">H", 0xC000 | 0)
    message = first + pointer
    name, resume = mdns_lookup._decode_name(message, len(first))
    assert name == "my-laptop.local"
    # resume must be right after the 2-byte pointer itself, not wherever
    # the jump landed -- that's what lets the caller correctly resume
    # parsing the enclosing record.
    assert resume == len(first) + 2


def test_decode_name_rejects_a_self_referential_pointer_loop():
    # A pointer at offset 0 that points back to offset 0 -- a malicious/
    # corrupt packet, must not hang forever.
    message = struct.pack(">H", 0xC000 | 0)
    with pytest.raises(ValueError):
        mdns_lookup._decode_name(message, 0)


def test_decode_name_rejects_truncated_message():
    with pytest.raises(ValueError):
        mdns_lookup._decode_name(b"\x05short", 0)


# ============================================================
# _strip_local_suffix
# ============================================================

def test_strip_local_suffix_removes_trailing_local():
    assert mdns_lookup._strip_local_suffix("My-Laptop.local.") == "My-Laptop"
    assert mdns_lookup._strip_local_suffix("My-Laptop.local") == "My-Laptop"


def test_strip_local_suffix_is_case_insensitive():
    assert mdns_lookup._strip_local_suffix("My-Laptop.LOCAL.") == "My-Laptop"


def test_strip_local_suffix_leaves_a_non_local_name_untouched():
    assert mdns_lookup._strip_local_suffix("something.else.") == "something.else"


def test_strip_local_suffix_of_bare_local_is_none():
    assert mdns_lookup._strip_local_suffix("local.") is None


# ============================================================
# _build_query
# ============================================================

def test_build_query_sets_the_qu_bit_and_ptr_type():
    query, expected_name = mdns_lookup._build_query(IP_1)
    assert expected_name == "10.1.168.192.in-addr.arpa"
    _txid, flags, qdcount, ancount, ns, ar = struct.unpack(">HHHHHH", query[0:12])
    assert flags == 0
    assert qdcount == 1 and ancount == 0 and ns == 0 and ar == 0
    name, pos = mdns_lookup._decode_name(query, 12)
    assert name == expected_name
    qtype, qclass = struct.unpack(">HH", query[pos:pos + 4])
    assert qtype == mdns_lookup._TYPE_PTR
    assert qclass & 0x8000, "QU bit (unicast-response-requested) must be set"
    assert qclass & 0x7FFF == mdns_lookup._CLASS_IN


# ============================================================
# _parse_ptr_response
# ============================================================

def _build_response(owner_name: str, rtype: int, target_name: str | None, rdata: bytes | None = None) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x8400, 0, 1, 0, 0)
    if rdata is None:
        assert target_name is not None
        rdata = mdns_lookup._encode_name(target_name)
    answer = (
        mdns_lookup._encode_name(owner_name)
        + struct.pack(">HHIH", rtype, mdns_lookup._CLASS_IN, 120, len(rdata))
        + rdata
    )
    return header + answer


def test_parse_ptr_response_extracts_the_hostname():
    expected_name = "10.1.168.192.in-addr.arpa"
    response = _build_response(expected_name, mdns_lookup._TYPE_PTR, "My-Laptop.local")
    assert mdns_lookup._parse_ptr_response(response, expected_name) == "My-Laptop"


def test_parse_ptr_response_ignores_an_answer_for_a_different_name():
    expected_name = "10.1.168.192.in-addr.arpa"
    response = _build_response("11.1.168.192.in-addr.arpa", mdns_lookup._TYPE_PTR, "Someone-Elses-Phone.local")
    assert mdns_lookup._parse_ptr_response(response, expected_name) is None


def test_parse_ptr_response_ignores_a_non_ptr_answer():
    expected_name = "10.1.168.192.in-addr.arpa"
    # A record: 4-byte rdata, not a name -- must not be mistaken for PTR.
    response = _build_response(expected_name, 1, None, rdata=b"\x01\x02\x03\x04")
    assert mdns_lookup._parse_ptr_response(response, expected_name) is None


def test_parse_ptr_response_returns_none_for_a_message_shorter_than_a_dns_header():
    assert mdns_lookup._parse_ptr_response(b"\x00" * 5, "anything") is None


def test_parse_ptr_response_raises_for_a_header_claiming_data_that_is_not_there():
    # Valid-looking 12-byte header claiming one question, but the
    # message ends right there -- reverse_lookup() treats this the same
    # as any other malformed packet (caught, ignored, keep listening).
    header = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0)
    with pytest.raises((ValueError, struct.error)):
        mdns_lookup._parse_ptr_response(header, "anything")


# ============================================================
# reverse_lookup -- fakes the socket module entirely
# ============================================================

class _FakeSocket:
    instances: list["_FakeSocket"] = []

    def __init__(self, *a, **k):
        self.sent: list[tuple[bytes, tuple[str, int]]] = []
        self.closed = False
        self.raise_on_sendto: Exception | None = None
        self.recv_queue: list[bytes] = []
        self.timeout_after_queue_empty = True
        _FakeSocket.instances.append(self)

    def sendto(self, data, addr):
        if self.raise_on_sendto is not None:
            raise self.raise_on_sendto
        self.sent.append((data, addr))

    def settimeout(self, value):
        pass

    def recvfrom(self, bufsize):
        if self.recv_queue:
            return self.recv_queue.pop(0), ("192.168.1.1", mdns_lookup._MDNS_PORT)
        raise real_socket.timeout()

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _reset_fake_socket_instances():
    _FakeSocket.instances = []
    yield
    _FakeSocket.instances = []


def test_reverse_lookup_returns_hostname_on_a_valid_reply(monkeypatch):
    # Build the reply using the SAME expected_name reverse_lookup() will
    # compute internally for IP_1, so parsing actually matches.
    expected_name = mdns_lookup._reverse_arpa_name(IP_1)
    response = _build_response(expected_name, mdns_lookup._TYPE_PTR, "Kids-Tablet.local")

    def _make_socket(*a, **k):
        sock = _FakeSocket()
        sock.recv_queue = [response]
        return sock

    monkeypatch.setattr(mdns_lookup.socket, "socket", _make_socket)

    hostname = mdns_lookup.reverse_lookup(IP_1, timeout=0.2)

    assert hostname == "Kids-Tablet"
    assert _FakeSocket.instances[0].closed


def test_reverse_lookup_returns_none_on_timeout(monkeypatch):
    monkeypatch.setattr(mdns_lookup.socket, "socket", lambda *a, **k: _FakeSocket())

    hostname = mdns_lookup.reverse_lookup(IP_1, timeout=0.05)

    assert hostname is None
    assert _FakeSocket.instances[0].closed


def test_reverse_lookup_ignores_a_bystander_packet_then_times_out(monkeypatch):
    # mDNS is a shared multicast channel -- an unrelated packet must not
    # crash the lookup, just be skipped.
    def _make_socket(*a, **k):
        sock = _FakeSocket()
        sock.recv_queue = [b"garbage-not-dns"]
        return sock

    monkeypatch.setattr(mdns_lookup.socket, "socket", _make_socket)

    hostname = mdns_lookup.reverse_lookup(IP_1, timeout=0.05)

    assert hostname is None


def test_reverse_lookup_swallows_a_synchronous_send_oserror(monkeypatch):
    def _make_socket(*a, **k):
        sock = _FakeSocket()
        sock.raise_on_sendto = OSError("network unreachable")
        return sock

    monkeypatch.setattr(mdns_lookup.socket, "socket", _make_socket)

    assert mdns_lookup.reverse_lookup(IP_1, timeout=0.05) is None
    assert _FakeSocket.instances[0].closed


def test_reverse_lookup_returns_none_for_a_malformed_ip():
    assert mdns_lookup.reverse_lookup("not-an-ip", timeout=0.05) is None
    assert _FakeSocket.instances == []


# ============================================================
# select_pending_targets
# ============================================================

def _mark_pending(conn, mac_address):
    conn.execute(
        "UPDATE devices SET ignored = 0, bypass_login = 0, is_authenticated = 0 WHERE mac_address = ?",
        (mac_address,),
    )
    conn.commit()


def test_select_pending_targets_only_returns_devices_awaiting_login(conn):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(60))
    identity.record_binding(conn, MAC_B, IP_2, source="rtnetlink", seen_at=db.iso_secs_ago(60))
    _mark_pending(conn, MAC_A)
    conn.execute("UPDATE devices SET is_authenticated = 1 WHERE mac_address = ?", (MAC_B,))
    conn.commit()

    targets = mdns_lookup.select_pending_targets(conn, limit=10)

    assert targets == [(MAC_A, IP_1)]


def test_select_pending_targets_skips_a_binding_that_already_has_a_hostname(conn):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(60))
    _mark_pending(conn, MAC_A)
    conn.execute("UPDATE device_bindings SET hostname = 'Already-Known' WHERE mac_address = ?", (MAC_A,))
    conn.commit()

    assert mdns_lookup.select_pending_targets(conn, limit=10) == []


def test_select_pending_targets_respects_limit_oldest_first(conn):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(3000))
    identity.record_binding(conn, MAC_B, IP_2, source="rtnetlink", seen_at=db.iso_secs_ago(1000))
    _mark_pending(conn, MAC_A)
    _mark_pending(conn, MAC_B)

    targets = mdns_lookup.select_pending_targets(conn, limit=1)

    assert targets == [(MAC_A, IP_1)], "expected the older binding first"


def test_select_pending_targets_excludes_ignored_and_bypass_devices(conn):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(60))
    conn.execute(
        "UPDATE devices SET ignored = 1, is_authenticated = 0 WHERE mac_address = ?", (MAC_A,)
    )
    conn.commit()

    assert mdns_lookup.select_pending_targets(conn, limit=10) == []


# ============================================================
# lookup_once
# ============================================================

def test_lookup_once_writes_resolved_hostnames(conn, monkeypatch):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(60))
    _mark_pending(conn, MAC_A)
    monkeypatch.setattr(mdns_lookup, "reverse_lookup", lambda ip, timeout=1.0: "Resolved-Name")

    resolved = mdns_lookup.lookup_once(conn, limit=10)

    assert resolved == 1
    row = conn.execute("SELECT hostname FROM device_bindings WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["hostname"] == "Resolved-Name"


def test_lookup_once_leaves_hostname_null_when_nothing_answers(conn, monkeypatch):
    import db

    identity.record_binding(conn, MAC_A, IP_1, source="rtnetlink", seen_at=db.iso_secs_ago(60))
    _mark_pending(conn, MAC_A)
    monkeypatch.setattr(mdns_lookup, "reverse_lookup", lambda ip, timeout=1.0: None)

    resolved = mdns_lookup.lookup_once(conn, limit=10)

    assert resolved == 0
    row = conn.execute("SELECT hostname FROM device_bindings WHERE mac_address = ?", (MAC_A,)).fetchone()
    assert row["hostname"] is None


def test_lookup_once_returns_zero_when_nothing_is_pending(conn, monkeypatch):
    monkeypatch.setattr(mdns_lookup, "reverse_lookup", lambda ip, timeout=1.0: "should-not-be-called")

    assert mdns_lookup.lookup_once(conn, limit=10) == 0


# ============================================================
# run_loop -- wiring lookup_once() into a background PeriodicTask
# ============================================================

def test_run_loop_calls_lookup_repeatedly(conn, monkeypatch):
    calls = []
    monkeypatch.setattr(mdns_lookup, "lookup_once", lambda conn, limit, timeout=1.0: calls.append(1))

    task = mdns_lookup.run_loop(interval=0.02, limit=5)
    try:
        time.sleep(0.15)
    finally:
        task.stop()

    assert len(calls) >= 2, "expected lookup_once to run repeatedly on the interval"


def test_run_loop_stops_promptly(monkeypatch):
    monkeypatch.setattr(mdns_lookup, "lookup_once", lambda conn, limit, timeout=1.0: None)

    task = mdns_lookup.run_loop(interval=0.05, limit=5)
    time.sleep(0.02)
    started_stop = time.monotonic()
    task.stop()
    elapsed = time.monotonic() - started_stop
    assert elapsed < 0.5, f"stop() took {elapsed:.3f}s, expected it to return promptly"


def test_run_loop_reports_errors_via_on_error_without_dying(monkeypatch):
    def _boom(conn, limit, timeout=1.0):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(mdns_lookup, "lookup_once", _boom)

    errors = []
    lock = threading.Lock()

    def on_error(exc):
        with lock:
            errors.append(exc)

    task = mdns_lookup.run_loop(interval=0.02, limit=5, on_error=on_error)
    try:
        time.sleep(0.1)
    finally:
        task.stop()

    with lock:
        got = len(errors)
    assert got >= 2, "expected repeated errors, not a dead loop"
