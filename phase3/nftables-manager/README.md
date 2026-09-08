# pp-nftables-manager (Milestones 5 & 7)

Status: **builds, vets, passes its unit tests, AND verified against a
real kernel nftables instance multiple times** — the strongest
verification any Phase 3 component has gotten, since this is the one
piece testable without any special hardware: a plain Docker container
with `--cap-add=NET_ADMIN` (no host root, no sudo) gets its own
nftables state in its own network namespace, so the actual kernel
behavior can be exercised safely.

See [`../../docs/design/phase3-technical-design.md`](../../docs/design/phase3-technical-design.md)
section 5 for the design this implements, and
[`../../RoadMap.md`](../../RoadMap.md) for how Milestones 5/7 fit the
overall plan.

## Layout

```
internal/policy/  Pure logic, no nftables dependency at all:
                   DesiredPolicy/ActualPolicy types, ResolveConflicts
                   (an IP requested in more than one of the four policy
                   sets keeps only its highest-priority one --
                   bypass > authenticated > unauthenticated >
                   quarantine, matching the prerouting chain's own
                   evaluation order), and Reconcile (per-set add/remove
                   diff, only sets that actually changed appear in the
                   output). Fully unit tested.
internal/nft/     Adapter wiring sigs.k8s.io/knftables to internal/policy
                   -- the one piece that needs CAP_NET_ADMIN.
                   EnsureBaseline creates the table/sets/chain from the
                   design skeleton (idempotent across repeated calls,
                   e.g. a systemd restart -- see its own doc comment);
                   ReadActual reads live set membership; ApplyDiffs
                   applies every set's changes in ONE atomic knftables
                   transaction. Fault-injection tests use knftables' own
                   Fake test double, not a hand-rolled one -- see
                   fault_test.go's comments for why a bare fake panics.
internal/dbsource/  Reads the DesiredPolicy JSON blob
                   controller/policy_state.py (Python) computes and
                   writes into the shared SQLite database's
                   interception_runtime table -- pure Go, no cgo
                   (modernc.org/sqlite), since the sandboxed test
                   accounts this was verified on have no C compiler.
                   Also writes this process's own nft_mode/
                   nft_last_healthy_at/nft_fail_reason health columns.
cmd/pp-nftables-manager/  Real reconciliation loop: read desired policy
                   from the DB -> ResolveConflicts -> ReadActual ->
                   Reconcile -> ApplyDiffs, on an interval, with
                   sd_notify/watchdog. `-bootstrap-only` skips the loop
                   for just creating the baseline table/sets/chain.
```

## Verifying it yourself

```bash
cd phase3/nftables-manager
go build ./... && go vet ./... && go test ./...   # no CAP_NET_ADMIN needed for any of this

# Real functional check against actual nftables, no host root required:
go build -o /tmp/pp-nftables-manager ./cmd/pp-nftables-manager
docker run --rm --cap-add=NET_ADMIN \
  -v /tmp/pp-nftables-manager:/pp-nftables-manager:ro ubuntu:24.04 \
  bash -c 'apt-get update -qq && apt-get install -y -qq nftables >/dev/null 2>&1 &&
           /pp-nftables-manager -bootstrap-only=true && nft list table inet optigate'
```

What's actually been verified this way, on 2026-08-29 (Ubuntu 24.04
container, real `nft` binary, no mocking):
- Bootstrap produces the exact skeleton ruleset: four sets, the
  `bypass_v4` short-circuit `return`, every redirect rule with the
  right ports.
- `ApplyDiffs`/`ReadActual` end to end: adding elements, an idempotent
  re-reconcile against unchanged desired state producing a genuinely
  empty diff, and an incremental add+remove in one atomic transaction.
- Running `-bootstrap-only` twice in a row (simulating a process
  restart) leaves exactly the baseline rule count in the chain, not
  double — the `EnsureBaseline` idempotency fix, verified live.
- The full Milestone 7 loop, end to end: a real DB with three devices
  in three policy states, the real binary running in a background
  `--cap-add=NET_ADMIN` container, then — **without restarting the
  container** (confirmed via `docker inspect StartedAt` staying
  constant) — toggling one device's `is_authenticated` from the host
  and watching the same running process move that device's IP between
  `authenticated_v4`/`unauthenticated_v4` in the real kernel ruleset on
  its next poll cycle.

## What's deliberately NOT here yet

- No systemd unit file (just the sketch in the design doc) or
  Dockerfile for this component.
- Real interval/threshold constants — the poll interval is a CLI flag
  with a guessed default, not a soak-tested number (RoadMap.md section
  8's "not decided here" applies on this side too).
- Whether this ships as its own binary/systemd unit or gets folded into
  the Python controller process is still open (see the design doc's
  closing section) — this scaffold assumes "own binary" since Go is
  what `knftables` is written for, and coordinates with the controller
  purely through the shared database rather than a new IPC protocol
  between them (an autonomous engineering call, not fully locked — see
  the design doc's note on it).
