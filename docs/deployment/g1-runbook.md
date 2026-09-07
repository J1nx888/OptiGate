# G1 runbook — real-network ARP interception validation

> **Result: GO, as of 2026-09-02.** Run against the real Netgear Orbi
> RBR850 mesh this household actually runs, with real household devices
> — not just the Docker-bridge/veth harnesses everything was previously
> verified in. Every applicable matrix row (this mesh has one satellite,
> so rows 5/6/8 don't apply) was confirmed directly or soundly inferred,
> no no-go condition triggered on the highest-risk row or anywhere else.
> Full detailed writeup, including two real incidents hit and fixed
> along the way (both setup mistakes, not the ARP mechanism itself), is
> in [RoadMap.md's dated G1 result](../../RoadMap.md#g1-result-go-2026-09-02-real-orbi-mesh-real-household-devices).
> **Update, 2026-09-07**: the discovery + arp-worker composition
> disabled during the pass above (after it caused one of the two
> incidents) has now been separately verified GO, with a review-buffer
> safety mechanism (a 3-minute reconciliation interval instead of
> arp-worker staying idle) rather than a code change — see RoadMap.md's
> dated result. **Not yet done**: one full back-to-back pass through the
> matrix without stopping between rows, and the soak test (Milestone 10).
> This runbook's procedure below is kept as-is for that follow-up work
> and for anyone re-deriving the plan later — it's what was actually
> followed.

## Why this gates everything

The whole architecture depends on one unproven claim: that ARP-spoofing
a client on this specific mesh router reliably redirects its traffic to
the interception box (the Beelink), on every attachment path a real
household device might use — main router, either satellite, wireless
backhaul, roaming mid-session. No public documentation says whether the
RBR850 filters unsolicited ARP replies or how it handles MAC learning
across its wireless backhaul. If it doesn't work on some real path (most
plausibly: a satellite-attached client's actual unicast traffic switches
on a path that never reaches the Beelink even though its ARP cache
looks poisoned), the whole ARP-based approach needs to be rethought
before another line of feature code matters. This is exactly the kind of
irreversible, real-world, household-network-affecting step this project
has deliberately never attempted without you directly involved and
watching.

## Where things stand

| Gap | Status |
|---|---|
| **G1** — no real-network evidence for the ARP mechanism | ✅ **GO (2026-09-02)** — see RoadMap.md's dated result |
| G2 — YouTube channel/creator filtering | ⬜ Not built (0%), not required for baseline Bark Home parity |
| G3 — SafeSearch / YouTube Restricted Mode | ✅ Done (Phase 9) |
| G4 — show approvals are user-only, not user-or-device | ⏸ Explicitly deferred by you to a later phase, not a G1 blocker |
| G5 — captive-portal session model (DHCP window, MAC-rotation friction) | ✅ Resolved by policy decision (accepted as-is) |
| G6 — no ad-hoc "pause the internet" control | ✅ Done (Phase 10) |
| G7 — cutover data step for existing household devices | ✅ Resolved by policy: start with zero pre-added devices, use the new CSV bulk-import feature once real MACs are known |
| G8 — Bark's on-device ML content-scanning | Out of scope — an app/device feature, not achievable from a network box |

**G1 itself is done**, and the discovery + arp-worker composition is
now also verified (2026-09-07, see RoadMap.md). What's left before a
real deployment decision: one full back-to-back matrix pass and the
soak test (Milestone 10).

## Before you start

- [ ] `main` is up to date locally (the `fix/cross-tier-domain-enforcement`
      branch has been merged in — confirm with `git log --oneline -3`
      showing `6dcf1d2` or later).
- [ ] Full test suite green on Linux (last confirmed: 722 passed, 0
      skipped on the smoke-test VM).
- [ ] The Beelink (real production box, `192.168.1.250`) is reachable and
      has the current `main` branch checked out — this is a **different**
      box from the disposable smoke-test VM; nothing done there so far has
      touched the real box's interception path.
- [ ] You (the project owner) are physically available for the whole test
      window — this is not something to run and walk away from. If a test
      goes wrong, someone needs to be there to notice a device lost
      connectivity and decide whether to abort.
- [ ] A **kill switch is rehearsed, not just documented**, before the
      first packet goes on the wire (see below).
- [ ] Bark Home can actually be paused for the test window (confirmed
      feasible by you already) — schedule the window for a genuinely
      low-stakes time (not while anyone's on a video call, gaming online,
      or otherwise latency/uptime-sensitive).
- [ ] Pick one real, low-value test client device you don't mind losing
      connectivity on for a few minutes — a spare phone/laptop, not
      someone's primary work machine — for the first pass at each new
      attachment point.

## The kill switch

Two independent ways to stop everything, both faster than waiting for
graceful shutdown to matter:

1. **Software stop**: `docker compose --profile interception stop` on the
   Beelink. This sends the worker a real shutdown IPC message, which
   triggers corrective ARP replies restoring every poisoned client's
   cache to the real gateway MAC — this exact path is already unit- and
   integration-tested (Milestone 3/9 in RoadMap.md).
2. **Physical fallback, if the software path is unresponsive**: unplug
   the Beelink's Ethernet connection from the router/switch, or power it
   off. The mesh has no dependency on this box for actual routing — it's
   a bystander performing ARP spoofing, not the gateway — so removing it
   from the network restores normal operation without anything else
   needing to change. This is the whole point of the "no router
   replacement" design principle in RoadMap.md's opening section.

**Rehearse #1 for real before the first real test** — start the
interception profile against a throwaway/low-value target, confirm you
know exactly which command stops it and what "back to normal" looks like
on that device (its ARP cache, its actual connectivity), before ever
pointing it at anything that matters.

## Step-by-step procedure

Poisoning starts **half-duplex** (only the test client's own ARP cache is
poisoned, not the gateway's) for every step below — this avoids fighting
Orbi's own ARP table for its downstream client entries. Only escalate to
full-duplex for a specific attachment point if half-duplex testing shows
the reverse path bypasses the interception box there.

For **each** row of the matrix, do the same four checks and record the
result before moving to the next row:

1. **Forged ARP visibility** — confirm the worker's spoofed replies are
   actually reaching the client (packet capture on the client, or its own
   `arp -a`/`ip neigh` showing the Beelink's MAC for the gateway IP).
2. **Client's resolved gateway MAC** — confirm it now points at the
   Beelink, not the real Orbi node.
3. **Traffic traversal, both directions** — a real request from the
   client (e.g. `curl` to a known site) actually reaches the Beelink
   first (visible in its logs/capture) before going out; the response
   path back to the client works too. No packet duplication or loops.
4. **Clean recovery** — stop the worker (graceful `stop`, then separately
   a hard `kill -9` / container removal, then separately a simulated
   NIC-down) and confirm the client's connectivity and ARP table return
   to normal each time, without manual intervention on the client.

### Test matrix

| # | Attachment | Link | Notes |
|---|---|---|---|
| 1 | Main router (RBR850) | Wired | Baseline — the simplest case, do this first |
| 2 | Main router (RBR850) | Wireless | |
| 3 | Satellite 1 | Wired (if applicable) | |
| 4 | Satellite 1 | Wireless | **Highest-risk row — see no-go condition** |
| 5 | Satellite 2 | Wired (if applicable) | |
| 6 | Satellite 2 | Wireless | **Highest-risk row — see no-go condition** |
| 7 | Roaming: router → satellite mid-session | Wireless | Start a long-lived connection (e.g. a video stream), physically walk the client from router range to satellite range |
| 8 | Roaming: satellite → satellite mid-session | Wireless | Same, between the two satellites |
| 9 | DHCP renewal | Either | Force a renewal (or wait one out) while poisoned; confirm the binding/reconciliation cycle notices the IP change (this is exactly what `device_bindings`/`controller/discovery.py` already exist to catch) |
| 10 | Satellite reboot while poisoned | Either | Power-cycle the satellite the test client is attached to; confirm recovery once it's back |
| 11 | Beelink/worker process crash | Either | `kill -9` the worker mid-test on a poisoned client; confirm the client doesn't get stuck in a broken half-state |

### No-go condition

If, for **any** satellite-attached row (3–6 especially), the client's ARP
cache shows the forged entry but its actual unicast traffic is switched
on a path that bypasses the Beelink — or the Orbi mesh rapidly overwrites
the poisoned entry on its own — **stop and do not continue down the
matrix**. This means the architecture doesn't work as-is against this
specific router, and the fix is a design conversation (see "If this comes
back a no-go" below), not a persistence-tuning tweak.

### If a row fails but isn't the no-go condition

Some individual-row failures are recoverable without abandoning the
approach — e.g. a slow reconciliation after DHCP renewal, or a rough edge
in the hard-kill recovery path. Note exactly what failed and how, stop
for the day, and bring it back for a code fix + re-test rather than
pushing through the rest of the matrix on a known-shaky foundation.

## If this comes back a go

1. Run the full matrix end-to-end at least once more, back-to-back,
   without stopping between rows — the individual-row passes above prove
   the mechanism works; this pass proves it holds up under realistic
   back-to-back use.
2. Decide the soak-test window (Milestone 10 in RoadMap.md) — a longer
   real-world period (days, not minutes) with the actual household
   running on it, before fully decommissioning Bark Home. Bark Home stays
   installed and re-enabled between test windows until this soak period
   also passes.
3. Cutover (G7, already resolved by policy): start the real deployment
   with **zero** devices pre-added. As real household devices are
   identified, bulk-import them via the dashboard's CSV import
   (Settings → Bulk import devices) rather than trying to guess/migrate
   Bark Home's own device list.
4. Only after the soak period passes: decommission Bark Home for real.

## If this comes back a no-go

Do not attempt a quick patch. Bring the exact failure mode (which row,
what the packet capture showed, whether it's a switching-layer issue
like the one already documented in RoadMap.md's ARP-worker section —
switches relearning MAC-forwarding-table entries, a different and lower
layer than a client's ARP cache) back for a real design conversation.
Rethinking the interception mechanism for a mesh router that doesn't
cooperate with ARP spoofing is a project-shape decision, not a bug fix.

## What this runbook does not cover

- **G2 (YouTube filtering)** and **G4 (device/group show approvals)** are
  deliberately out of scope for G1 — neither blocks a real deployment
  decision, per your own explicit sequencing.
- This is a **validation** runbook, not the full deployment runbook.
  Once G1 passes and the soak period completes, the actual cutover steps
  (final `.env` values for `ARP_WORKER_IFACE`/`GATEWAY_IP`/`GATEWAY_MAC`,
  bringing up `docker compose --profile interception up -d` for real
  against the household LAN, disabling Bark Home permanently) deserve
  their own short runbook written after G1's results are known — writing
  it now would mean guessing at details G1 itself is meant to surface.
