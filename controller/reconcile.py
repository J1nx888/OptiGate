#!/usr/bin/env python3
"""Reconciliation logic: decide whether the worker's currently-applied
generation already matches desired state, and if not, what the next
generation number should be. Pure functions, no I/O -- see
controller/main.py for the loop that drives this against a real
WorkerClient.
"""
from __future__ import annotations

import dataclasses

from ipc_client import Target


@dataclasses.dataclass(frozen=True)
class DesiredState:
    """What the controller wants poisoned right now.

    Built from device_bindings + devices.is_authenticated / bypass_v4
    rules -- see controller/desired_state.py's db_backed_desired_state.
    """

    gateway: Target
    targets: tuple[Target, ...]
    full_duplex: bool = False

    def target_key(self) -> frozenset[tuple[str, str]]:
        """A comparison key that's insensitive to target ORDER but
        sensitive to which (ip, mac) pairs are present, so a DB read
        that happens to return the same devices in a different row
        order doesn't spuriously trigger a new generation."""
        return frozenset((t.ip, t.mac) for t in self.targets)


@dataclasses.dataclass(frozen=True)
class AppliedState:
    """What the controller last successfully told the worker."""

    generation: int
    desired: DesiredState


def reconcile(current: AppliedState | None, desired: DesiredState) -> int | None:
    """Returns the next generation number to send to the worker, or None
    if current already matches desired and nothing needs to be sent.

    Re-running this against unchanged desired state must be a no-op, not
    a needless generation bump -- an unnecessary generation switch on the
    worker interrupts its corrective-restoration bookkeeping for no
    reason (see phase3/arp-worker/internal/worker/worker.go's
    ApplyGeneration doc comment on why generation switches are handled
    carefully there).
    """
    if current is None:
        return 1
    if (
        current.desired.gateway == desired.gateway
        and current.desired.target_key() == desired.target_key()
        and current.desired.full_duplex == desired.full_duplex
    ):
        return None
    return current.generation + 1
