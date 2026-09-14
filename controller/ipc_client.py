#!/usr/bin/env python3
"""Controller-side client for the ARP worker's IPC protocol.

Wire format matches phase3/arp-worker/internal/ipc/protocol.go exactly:
versioned JSON over a Unix domain socket, one newline-delimited frame per
message. Keep the two in sync if either changes.
"""
from __future__ import annotations

import dataclasses
import json
import socket
import threading
from typing import Any

PROTOCOL_VERSION = 1


class WorkerError(RuntimeError):
    """Raised when the worker replies with a "fault" message, an
    unsupported protocol version, or an unexpected op.

    `reason`/`action` are populated only for a real "fault" reply --
    the worker's own structured explanation of what went wrong (e.g.
    reason="lease_expired", action="entering_repair_only_mode") -- and
    stay None for every other kind of WorkerError (a malformed frame,
    an unexpected op, a version mismatch), none of which carry that
    shape. A caller that
    needs to react differently to a specific fault (see
    controller/main.py's run_cycle()) should check these attributes
    rather than parsing the exception's own message string."""

    def __init__(self, message: str, *, reason: str | None = None, action: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.action = action


class WorkerConnectionError(WorkerError):
    """Raised specifically when the underlying socket itself is the
    problem (EOF before a full frame, a broken pipe, connection reset)
    -- as opposed to a healthy connection carrying an application-level
    problem (a fault reply, a version mismatch). This distinction is
    what lets controller/main.py's run() decide when a fresh
    WorkerClient needs to be established versus just logging and
    retrying the next cycle on the same connection."""


@dataclasses.dataclass(frozen=True)
class Target:
    ip: str
    mac: str

    def to_wire(self) -> dict[str, str]:
        return {"ip": self.ip, "mac": self.mac}


@dataclasses.dataclass(frozen=True)
class GenerationApplied:
    generation: int
    target_count: int
    resolution_failures: list[str]


@dataclasses.dataclass(frozen=True)
class HeartbeatAck:
    sequence: int
    sent_counters: dict[str, int]
    consecutive_send_failures: int = 0


class WorkerClient:
    """One connection to the arp-worker's Unix socket.

    Every public method that talks on the wire holds an internal lock
    for the full duration of its own send-then-await-reply exchange,
    which is what makes it safe to call heartbeat() from a background
    pacer thread (see controller/lease.py) at the same time
    controller/main.py's reconciliation loop calls replace_targets()/
    shutdown() from the main thread: without it, two threads calling
    _send()/_read_frame() concurrently could interleave their writes on
    the shared socket or race on the shared read buffer, corrupting the
    JSON stream. This still matches the worker's own "single connection
    at a time" design (phase3/arp-worker/internal/ipc/server.go's doc
    comment) -- only one LOGICAL request is ever in flight on the wire
    at once, the lock just makes that true under real concurrency
    instead of by unenforced convention.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = b""
        self._lock = threading.Lock()

    @classmethod
    def connect(cls, path: str, timeout: float = 5.0) -> "WorkerClient":
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(path)
        return cls(sock)

    def close(self) -> None:
        # Holds the same lock every other method uses: without it, a
        # caller's close() (e.g. run()'s _reconnect() replacing a dead
        # client) could run concurrently with the heartbeat pacer's own
        # thread still blocked mid-request inside _read_frame()'s
        # socket.recv() on this exact object. Closing the fd out from
        # under a thread blocked in recv() can, on POSIX, let that fd
        # number get reused by a different socket opened moments later
        # -- so the still-blocked recv() could, in the worst case, read
        # bytes belonging to an unrelated connection instead of failing
        # cleanly. The tradeoff is that close() can now itself block on
        # a concurrent in-flight request, but connect()'s own
        # socket.settimeout() (default 5s) already bounds how long any
        # single recv() can actually block for, so this is a bounded
        # wait, not a risk of hanging forever.
        with self._lock:
            self._sock.close()

    def replace_targets(
        self,
        generation: int,
        gateway: Target,
        targets: list[Target],
        full_duplex: bool = False,
    ) -> GenerationApplied:
        reply = self._request(
            {
                "v": PROTOCOL_VERSION,
                "op": "replace_targets",
                "generation": generation,
                "gateway": gateway.to_wire(),
                "targets": [t.to_wire() for t in targets],
                "full_duplex": full_duplex,
            }
        )
        self._expect_op(reply, "generation_applied")
        return GenerationApplied(
            generation=reply["generation"],
            target_count=reply["target_count"],
            resolution_failures=reply.get("resolution_failures") or [],
        )

    def heartbeat(self, sequence: int) -> HeartbeatAck:
        reply = self._request({"v": PROTOCOL_VERSION, "op": "heartbeat", "sequence": sequence})
        self._expect_op(reply, "heartbeat_ack")
        return HeartbeatAck(
            sequence=reply["sequence"],
            sent_counters=reply.get("sent_counters") or {},
            consecutive_send_failures=reply.get("consecutive_send_failures") or 0,
        )

    def shutdown(self, reason: str) -> None:
        """Sends "shutdown" and does not wait for a reply -- per
        phase3/arp-worker/internal/ipc/dispatch.go, "shutdown" always
        terminates the connection on the worker's side without a reply
        of its own, so waiting here would just block until the worker
        closes the socket anyway.
        """
        with self._lock:
            self._send({"v": PROTOCOL_VERSION, "op": "shutdown", "reason": reason})

    def _request(self, msg: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._send(msg)
            reply = self._read_frame()
        if reply.get("v") != PROTOCOL_VERSION:
            raise WorkerError(f"worker replied with unsupported protocol version: {reply!r}")
        if reply.get("op") == "fault":
            raise WorkerError(
                f"worker fault: reason={reply.get('reason')!r} action={reply.get('action')!r}",
                reason=reply.get("reason"),
                action=reply.get("action"),
            )
        return reply

    def _expect_op(self, reply: dict[str, Any], op: str) -> None:
        if reply.get("op") != op:
            raise WorkerError(f"expected op={op!r} in reply, got {reply!r}")

    def _send(self, msg: dict[str, Any]) -> None:
        line = json.dumps(msg, separators=(",", ":")) + "\n"
        try:
            self._sock.sendall(line.encode("utf-8"))
        except OSError as exc:
            # Broken pipe, connection reset, etc. -- the socket itself
            # is dead, not just this one request.
            raise WorkerConnectionError(f"send failed: {exc}") from exc

    def _read_frame(self) -> dict[str, Any]:
        while b"\n" not in self._buf:
            try:
                chunk = self._sock.recv(4096)
            except OSError as exc:
                raise WorkerConnectionError(f"recv failed: {exc}") from exc
            if not chunk:
                raise WorkerConnectionError("worker closed the connection before sending a reply")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            raise WorkerError(f"malformed JSON frame from worker: {line!r}") from exc
