# Phase 3 Technical Design: ARP Worker, Controller, nftables-manager

Status: **design only, nothing in this document is built yet.** This is
the concrete follow-on to the architecture decision recorded in
[`RoadMap.md`](../../RoadMap.md) — that file has the "what and why," this
file has the "with which libraries and roughly what code." Nothing here
has been compiled or tested (this dev environment has no Go or Rust
toolchain installed), so treat every code sketch below as illustrative,
not verified.

---

## 1. Language decision: Go

`RoadMap.md` calls for "a memory-safe compiled language" for the
privileged ARP worker, without picking one. Recommendation: **Go**, for
three concrete reasons found while researching this:

1. **`mdlayher/arp`** is a small, purpose-built Go package implementing
   RFC 826 ARP directly — send/receive ARP requests and replies over a
   raw socket. This is exactly the worker's core job, already solved by
   a well-regarded low-level-networking Go author (mdlayher also
   maintains `mdlayher/ethernet`, `mdlayher/netlink`, `mdlayher/raw` —
   the whole stack this worker needs is one author's coherent
   ecosystem, not stitched-together miscellany).
2. **`knftables`** (`github.com/kubernetes-sigs/knftables`) is a
   Kubernetes SIG Network-maintained Go library, **Apache-2.0**,
   explicitly built so Kubernetes's own network components can drive
   nftables correctly — i.e. already trusted in production for exactly
   the kind of "a privileged daemon manages firewall state
   programmatically" job this project needs from its nftables-manager.
   It supports named sets and atomic transactions natively (an
   operation that would fail rolls back the whole transaction). By
   contrast, **`google/nftables`** (pure Go, no `nft` shell-out,
   Apache-2.0) explicitly documents itself as early-stage/experimental
   and "not recommended for production" with expected breaking changes
   — a worse fit despite the appeal of avoiding a subprocess. `knftables`
   shells out to the `nft` CLI internally, which is fine: the CLI is
   nftables' own most stable, well-documented interface, and this is a
   local subprocess call, not a network dependency.
3. Go's garbage-collected, bounds-checked memory model already satisfies
   "memory-safe" for a `CAP_NET_RAW`-only worker doing small, periodic
   packet sends — this isn't a workload where Rust's stronger
   compile-time ownership guarantees buy much, and Go gets there with a
   shallower learning curve and less code.

**Update 2026-08-29**: an initial Go scaffold implementing the design
below now exists in [`phase3/arp-worker/`](../../phase3/arp-worker/) —
the generation scheduler, corrective-restoration-on-switch logic, lease/
heartbeat state machine, safety checks, and IPC protocol from sections
3–4 below, each with unit tests. **Builds, vets, and passes its full
test suite on the smoke-test VM** (Go 1.26.7, `go build`/`go vet`/`go test -count=10`
all clean); see that directory's `README.md` for exact status. The
sketches below remain the reference design; the scaffold follows them
but sharpens one detail not spelled out here — a direct generation
switch only sends corrective ARPs to targets *leaving* scope, never to
targets present in both the old and new generation, to avoid a race
between a stale corrective pass and the new generation's own poisoning
ticks. One real API mismatch surfaced on first build:
`github.com/mdlayher/arp` uses `netip.Addr`, not `net.IP` — fixed in
`internal/arpio/mdlayher_adapter.go` with a conversion at that one
boundary.

Rust remains a legitimate alternative (`pnet` for packet crafting,
`netlink-packet-route`/`rtnetlink` crates for neighbor monitoring, both
actively maintained) if there's a reason to prefer it later, but nothing
found in this research makes Rust materially better-suited here, and
Go's library fit — especially `knftables` — is the deciding factor.

**Concrete package list, if Go is confirmed:**

| Concern | Package |
|---|---|
| ARP send/receive | `github.com/mdlayher/arp` |
| Ethernet framing | `github.com/mdlayher/ethernet` |
| Raw sockets | `github.com/mdlayher/raw` or `golang.org/x/net/bpf` |
| rtnetlink neighbor events | `github.com/vishvananda/netlink` (`NeighSubscribe`) or `github.com/jsimonetti/rtnetlink` |
| nftables (controller/nftables-manager side) | `github.com/kubernetes-sigs/knftables` |
| Unix socket IPC + peer-credential check | stdlib `net` (`net.UnixConn`) + `golang.org/x/sys/unix` (`SO_PEERCRED`) |
| systemd watchdog/notify | `github.com/coreos/go-systemd/v22/daemon` |

---

## 2. Licensing facts, verified for this document (updates/sharpens `RoadMap.md`)

- **bettercap**: confirmed `GPL-3.0` (its own `LICENSE.md`). Matches
  what's already in `RoadMap.md`.
- **Scapy**: confirmed `GPL-2.0-only` per its PyPI listing and license
  file — but worth knowing the project's own GitHub issues show some
  internal inconsistency/ambiguity about this (at least one contrib
  file under GPL-3.0 instead), which if anything is a reason for *more*
  caution, not less, about importing it as a library into a public
  repo's main process. Reinforces the existing decision to keep Scapy
  (if used at all, e.g. for a throwaway diagnostic script) out of the
  shipped worker entirely.
- **`knftables`**: `Apache-2.0` — no copyleft concerns at all, cleanest
  possible license for this specific piece.
- **`google/nftables`**: also `Apache-2.0`, but rejected above on
  maturity grounds, not licensing.
- **eBlocker**: `EUPL-1.2`, as already recorded in `RoadMap.md` — no new
  findings here, still "reference only."

---

## 3. ARP worker: packet-level design sketch

Core loop, one goroutine, operating on an immutable per-generation
target snapshot (per `RoadMap.md`'s "one scheduler, not a thread per
host" requirement):

```go
type Target struct {
    IP  net.IP
    MAC net.HardwareAddr // resolved once, refreshed on rebind
}

type Generation struct {
    ID       uint64
    Gateway  Target
    Targets  []Target // clients to poison
    FullDuplex bool
}

func (w *Worker) runGeneration(ctx context.Context, gen Generation) {
    ticker := time.NewTicker(w.interval)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return // caller sends corrective ARPs on the way out
        case <-ticker.C:
            for _, t := range gen.Targets {
                w.sendGratuitousReply(t.IP, gen.Gateway.IP, w.selfMAC) // "gateway is at my MAC" -> client
                if gen.FullDuplex {
                    w.sendGratuitousReply(gen.Gateway.IP, t.IP, w.selfMAC) // "client is at my MAC" -> gateway
                }
                atomic.AddUint64(&w.sentCounter, 1)
            }
        }
    }
}
```

`sendGratuitousReply` is a thin wrapper around `mdlayher/arp`'s
reply-construction: an ARP reply (opcode 2) with the spoofed
sender IP/MAC pair, sent to the target's real MAC over a raw socket
bound to the LAN interface.

**Corrective restoration** (the fail-open requirement from
`RoadMap.md`) is the same primitive with the *real* MAC addresses
substituted back in, sent several times with short spacing on the way
out:

```go
func (w *Worker) sendCorrective(gen Generation) {
    for i := 0; i < correctiveRepeats; i++ {
        for _, t := range gen.Targets {
            w.sendGratuitousReply(t.IP, gen.Gateway.IP, gen.Gateway.MAC) // real gateway MAC, not ours
        }
        time.Sleep(correctiveSpacing)
    }
}
```

**Startup safety checks**, before poisoning anyone:
- Resolve and validate the gateway's real MAC via a genuine ARP request
  (not from a possibly-already-poisoned cache).
- Reject as targets: the gateway itself, the worker's own interface
  IP/MAC, the subnet broadcast address, any multicast address, and
  every `bypass_v4` entry from the controller's target list.

---

## 4. Controller ↔ worker IPC: message schema (fleshes out the sketch in the engineering report)

Versioned JSON over a Unix domain socket, one connection, newline-delimited
frames. Peer credentials checked via `SO_PEERCRED` so only the controller
process (verified by UID, not just socket path) can drive the worker.

**Controller → worker:**
```json
{"v": 1, "op": "replace_targets", "generation": 43,
 "gateway": {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01"},
 "targets": [
   {"ip": "192.168.1.21", "mac": "aa:bb:cc:dd:ee:22"},
   {"ip": "192.168.1.35", "mac": "aa:bb:cc:dd:ee:36"}
 ],
 "full_duplex": false}
```
```json
{"v": 1, "op": "heartbeat", "sequence": 8842}
```
```json
{"v": 1, "op": "shutdown", "reason": "controller_requested"}
```

**Worker → controller (replies + unsolicited events):**
```json
{"v": 1, "op": "generation_applied", "generation": 43, "target_count": 2, "resolution_failures": []}
```
```json
{"v": 1, "op": "heartbeat_ack", "sequence": 8842, "sent_counters": {"192.168.1.21": 118}}
```
```json
{"v": 1, "op": "fault", "reason": "lease_expired", "action": "entering_repair_only_mode"}
```

**Lease rule**: if the worker receives no `heartbeat` within
`N × interval` (N configurable, start conservative — e.g. 5 cycles), it
stops sending forged replies, sends one round of corrective ARPs for its
current generation, and enters a passive "repair-only" state, waiting for
a fresh `replace_targets` rather than resuming the stale one. This is the
concrete mechanism behind `RoadMap.md`'s "must not auto-resume an old
target generation after restart" requirement.

**Update 2026-08-29**: the controller side of this schema is now
implemented in [`controller/ipc_client.py`](../../controller/ipc_client.py)
(Python, per the architecture decision that the controller fits the
existing Python stack) — `WorkerClient.replace_targets`/`.heartbeat`/
`.shutdown()` speak exactly the JSON shape above. `controller/reconcile.py`
implements the idempotent-reconciliation half (generation only bumps
when desired state actually changes, order-insensitively on the target
list), and `controller/lease.py` drives the heartbeat on an interval.
Verified against real `AF_UNIX` sockets on the smoke-test VM — see
`RoadMap.md`'s Milestone 3 entry for status. `main.py`'s desired-state
source is still a placeholder pending Milestone 4.

---

## 5. nftables skeleton (four auth-state policy classes + one orthogonal bump flag)

Illustrative `nft` syntax for what the nftables-manager (via `knftables`)
would maintain — a dedicated table, so nothing here interferes with any
other firewall rules on the box.

**Update 2026-08-30 — corrected, replaces the original skeleton below**:
the original version redirected *every* `authenticated_v4` device's
HTTP/HTTPS to Squid, which turned out to be wrong — most devices (a
Smart TV, a kid's everyday device) should get DNS-tier protection only,
never Squid. Squid access is a separate, admin-chosen, per-device
opt-in (`devices.bump_enabled`), independent of authentication state —
a device can be simultaneously `authenticated_v4` (for DNS) and
`bump_v4` (for Squid), or `authenticated_v4` alone. `bump_v4` is a
**fifth, orthogonal set**, not a fifth mutually-exclusive policy class
— nftables can't be selective by domain within it (no SNI visibility
below TLS), so a `bump_v4` device gets *all* its port 80/443 traffic
redirected, with Squid's own SNI-based logic (unchanged) narrowing that
down to only the domains that actually need refinement. See
`RoadMap.md`'s "Authentication and bump-tier" section for the full
reasoning and the "Squid: explicit-proxy-with-login → transparent
intercept" section for why Squid's own config needs to change to
receive this traffic without a login at all.

```
table inet parental_proxy {
    set authenticated_v4   { type ipv4_addr; flags interval; }
    set unauthenticated_v4 { type ipv4_addr; flags interval; }
    set bypass_v4          { type ipv4_addr; flags interval; }
    set quarantine_v4      { type ipv4_addr; flags interval; }
    set bump_v4            { type ipv4_addr; flags interval; }  # orthogonal -- overlaps authenticated_v4

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        ip saddr @bypass_v4 ct mark set 0x1 return

        ip saddr @authenticated_v4 udp dport 53  redirect to :5353   # -> AdGuard Home
        ip saddr @authenticated_v4 tcp dport 53  redirect to :5353

        # Independent of the auth-state rules above -- a device only
        # reaches here if bump_enabled=1 (computed alongside, not
        # instead of, its authenticated_v4 membership).
        ip saddr @bump_v4 tcp dport 80  redirect to :3129   # -> Squid, HTTP (intercept mode)
        ip saddr @bump_v4 tcp dport 443 redirect to :3130   # -> Squid, HTTPS (intercept + ssl-bump)

        ip saddr @authenticated_v4 ct mark set 0x1   # see the FORWARD-chain note below

        ip saddr @unauthenticated_v4 udp dport 53 redirect to :5353  # still gets DNS
        ip saddr @unauthenticated_v4 tcp dport 80 redirect to :3131  # -> future portal
        # unauthenticated_v4 HTTPS: deliberately not redirected yet --
        # this is the "deliberate pre-auth policy" RoadMap.md flags as
        # still an open call for Phase 4, not decided here.

        ip saddr @quarantine_v4 counter drop
    }
}
```

**`ct mark set 0x1` addition, 2026-09-07**: a real bug (see RoadMap.md's
dated section, "Soak test paused after ~15 minutes") -- Docker's own
`ip filter` table sets its `FORWARD` chain's policy to `drop` by
default, and since every service in this project runs with
`network_mode: host`, nothing here ever needed Docker's own
bridge-network firewalling, but its drop policy was still silently
dropping every `bypass_v4`/`authenticated_v4` device's real (non-
redirected) traffic -- no device had ever actually gotten real
end-to-end internet access through this mechanism before that fix.
Sets are table-scoped, so a permit rule elsewhere can't reference
`@bypass_v4`/`@authenticated_v4` directly; `ct mark` bridges the two
tables instead -- see `phase3/nftables-manager/internal/nft/
knftables_adapter.go`'s `ensureDockerUserException` for the permit rule
this mark feeds and the full reasoning for why that (not a documented
manual host prerequisite) is the fix.

The hard-deny invariant for `mode='bump'` domains on a device that
*isn't* in `bump_v4` (e.g. a kid trying Crunchyroll on a DNS-only
device) can't be enforced here — nftables has no domain visibility.
That has to happen at AdGuard (block the domain outright for that
device) or, as a backstop, Squid itself if the connection somehow still
arrives there. See RoadMap.md's changes-needed checklist.

**Below is the original (2026-08-29) skeleton, before the above
correction — kept for history, not current:**

```
table inet parental_proxy {
    set authenticated_v4   { type ipv4_addr; flags interval; }
    set unauthenticated_v4 { type ipv4_addr; flags interval; }
    set bypass_v4          { type ipv4_addr; flags interval; }
    set quarantine_v4      { type ipv4_addr; flags interval; }

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        ip saddr @bypass_v4 return

        ip saddr @authenticated_v4 udp dport 53  redirect to :5353   # -> AdGuard Home
        ip saddr @authenticated_v4 tcp dport 53  redirect to :5353
        ip saddr @authenticated_v4 tcp dport 80  redirect to :3129   # -> Squid, HTTP
        ip saddr @authenticated_v4 tcp dport 443 redirect to :3130   # -> Squid, HTTPS/bump

        ip saddr @unauthenticated_v4 udp dport 53 redirect to :5353  # still gets DNS
        ip saddr @unauthenticated_v4 tcp dport 80 redirect to :3131  # -> future portal
        # unauthenticated_v4 HTTPS: deliberately not redirected yet --
        # this is the "deliberate pre-auth policy" RoadMap.md flags as
        # still an open call for Phase 4, not decided here.

        ip saddr @quarantine_v4 counter drop
    }
}
```

**Update 2026-08-29**: this skeleton is now implemented and
functionally verified in
[`phase3/nftables-manager/`](../../phase3/nftables-manager/) — a real
`docker run --cap-add=NET_ADMIN` container's `nft list table` output
matched this skeleton exactly (four sets, the `bypass_v4` short-circuit,
every redirect rule), and a follow-up check confirmed atomic
add/remove and idempotent re-reconciliation against the real kernel
ruleset, not just an in-memory model. `internal/policy` adds one thing
this skeleton doesn't spell out: `ResolveConflicts`, which keeps an IP
that's (incorrectly) requested in more than one set only in its
highest-priority one, using this chain's own evaluation order as the
priority (`bypass > authenticated > unauthenticated > quarantine`).
See `phase3/nftables-manager/README.md` for exact status — the
reconciliation loop and a real desired-state input aren't wired up yet.

Membership in these sets is exactly what `AUTH_CHANGED` events (from
`RoadMap.md`'s outbox-event design) update — the controller reconciles
`devices.is_authenticated` into set membership, `knftables` applies it
as one atomic transaction, and the worker's target list is **not**
affected by any of this (every enrolled device stays in the worker's
target list regardless of which set it's in — spoofing scope and policy
scope are different axes, per `RoadMap.md`).

**Note on the live end-to-end tests already run (2026-08-30)**: both
the Milestone 7 live auth-toggle proof and the full three-component
pipeline test (RoadMap.md's "core architectural claim" section) were
run against the **original, now-superseded** skeleton above (blanket
`authenticated_v4` → Squid redirect), before the `bump_v4` correction
existed. The underlying mechanisms those tests proved — real ARP
poisoning, real atomic nftables reconciliation, real live policy
toggling reaching real traffic — all still hold; what changes is only
*which* set the HTTP/HTTPS redirect rules attach to.

**Update (2026-08-30, later same day): the `bump_v4` Go logic itself is
now implemented and verified** — see RoadMap.md's changes-needed
checklist. `go build`/`go vet`/`gofmt`/`go test -count=5` all pass
clean on the smoke-test VM, including an end-to-end case (knftables'
real in-memory `Fake`) proving an IP lands in both `authenticated_v4`
and `bump_v4` at once, and that `ResolveConflicts` correctly drops a
bump IP that isn't also authenticated. What this does **not** yet
cover: a live `--cap-add=NET_ADMIN` container test against a real
kernel (the way the original blanket-redirect skeleton was verified
live, per the ARP worker's own README) — the `Fake`-based test proves
the Go logic is correct, not that the real kernel's `nft` ruleset
behaves identically. Worth doing once Squid's own side (intercept mode)
is also in place, so the two can be verified together rather than
separately.

---

## 6. systemd units (sketch)

```ini
# arp-worker.service
[Service]
Type=notify
WatchdogSec=15
ExecStart=/usr/local/bin/pp-arp-worker
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=true
Restart=on-failure
RestartSec=2
```

```ini
# interception-controller.service
[Service]
Type=notify
WatchdogSec=15
ExecStart=/usr/local/bin/pp-interception-controller
User=pp-controller
Restart=on-failure
RestartSec=2
```

`Type=notify` + `WatchdogSec` means the process must call `sd_notify`
with `WATCHDOG=1` on a schedule or systemd kills and restarts it — this
is the "watchdog notifications let systemd terminate a hung service"
mechanism `RoadMap.md`'s fail-open section calls for, not just
`Restart=on-failure` on its own (which only helps once a process has
actually exited, not when it's hung but still alive).

**Update 2026-08-29 (Milestone 6)**: both halves of this now exist —
the Go worker already used `coreos/go-systemd/v22/daemon`; the
Python controller side is `common/sdnotify.py` (stdlib-only, no new
dependency), sending a real `WATCHDOG=1` datagram on every successful
heartbeat round-trip. `phase3/nftables-manager`'s own
`cmd/pp-nftables-manager` does the same on the Go side. Not yet
written: the actual `.service` unit files above (still just this
sketch) and Squid/AdGuard readiness *gates* specifically — the health
tables those gates would feed (see the Milestone 7 update below) exist
and are tested, but nothing blocks startup on them yet.

---

## 7. Database migration draft (for Milestone 4, not applied yet)

Following this project's own established migration discipline
(`common/db.py`'s `_migrate()`, real `ALTER TABLE`/`CREATE TABLE`
statements, idempotent):

```sql
CREATE TABLE IF NOT EXISTS device_bindings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    mac_address   TEXT NOT NULL,
    ipv4_address  TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    source        TEXT NOT NULL, -- 'rtnetlink' | 'snapshot' | 'adguard' | 'bettercap' | 'active_scan'
    confidence    REAL NOT NULL DEFAULT 1.0,
    active        INTEGER NOT NULL DEFAULT 1,
    UNIQUE(mac_address, ipv4_address)
);

CREATE TABLE IF NOT EXISTS interception_runtime (
    singleton_id       INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    desired_generation INTEGER NOT NULL DEFAULT 0,
    applied_generation INTEGER NOT NULL DEFAULT 0,
    mode               TEXT NOT NULL DEFAULT 'stopped', -- 'stopped'|'running'|'repair_only'|'fail_open'
    last_healthy_at    TEXT,
    fail_open_reason   TEXT
);

CREATE TABLE IF NOT EXISTS network_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type   TEXT NOT NULL,
    device_id    INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    mac_address  TEXT,
    ipv4_address TEXT,
    source       TEXT NOT NULL,
    observed_at  TEXT NOT NULL,
    payload_json TEXT
);
```

**Update 2026-08-29**: wired into `common/db.py` now, close to this
draft with a few real refinements found along the way: `device_id` is
nullable (a MAC seen for the first time gets a pending binding rather
than being dropped — see `common/identity.py`), `INTEGER PRIMARY KEY`
without `AUTOINCREMENT` (matching every other table in this schema,
not a deliberate deviation from this draft, just consistency), and
`interception_runtime` grew four more columns beyond this draft:
`desired_policy_json` (the Milestone 7 `PolicyClass` output,
`controller/policy_state.py` writes it, `phase3/nftables-manager`
reads it directly — see section 5's own update) and `nft_mode`/
`nft_last_healthy_at`/`nft_fail_reason` (nftables-manager's own health,
deliberately separate columns from `mode`/`last_healthy_at`/
`fail_open_reason` above so the ARP-worker pipeline and the
nftables-manager never clobber each other's status in this shared
singleton row). `devices` also gained `quarantined_at` (nullable,
backing the `QUARANTINE` `PolicyClass` — nothing sets it yet, no
dashboard control exists to trigger it).

---

## 8. What this document does not decide

- Exact `unauthenticated_v4` HTTPS handling pre-login (flagged above as
  still open, belongs to Phase 4 design).
- ~~Whether the controller and nftables-manager are one binary or two~~
  — **built as two separate binaries, coordinating through the shared
  SQLite database rather than a new IPC protocol between them**
  (`controller/policy_state.py` writes `desired_policy_json`;
  `phase3/nftables-manager/internal/dbsource` reads it directly, pure
  Go via `modernc.org/sqlite`, no cgo). This follows the project's own
  already-stated "one shared database, live reads, no separate sync"
  principle (`docs/project.md`'s Key technical decisions) rather than
  inventing something new, and was verified working end-to-end (see
  `RoadMap.md`'s Milestone 7 entry). Made autonomously, then reviewed
  and confirmed by the project owner on 2026-08-30 — locked.
- Final interval/threshold constants (spoof interval, lease cycle count,
  corrective repeat count/spacing) — these need real numbers from the
  soak-test milestone, not guessed up front.
