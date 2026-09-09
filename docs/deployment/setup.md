# Deployment

Reference for deploying, redeploying, or modifying the deployment of Parental
Proxy v2. Covers local setup, the two-container architecture, environment
variables, the CA certificate, networking caveats, port mappings, CI, and
common operational commands.

## Prerequisites

- Docker with the `docker compose` plugin (Docker Desktop on Windows/Mac, or
  Docker Engine + compose plugin on Linux).
- A LAN CIDR for the network client devices connect from (optional — see
  [Networking notes](#networking-notes)).

## Step-by-step local setup

### Option A: `./setup.sh` (recommended)

`setup.sh` lives at the project root and is the one-command path: it writes
`.env` (if one doesn't already exist) by asking a handful of questions, then
builds and starts both containers. Walking through exactly what it does:

1. **Checks prerequisites.** Exits with an install link if `docker` isn't on
   `PATH`, or if `docker compose version` fails (the compose plugin is
   missing).
2. **Guesses this machine's LAN IP** to prefill the CIDR prompt: tries
   `ip route get 1.1.1.1` (Linux/native), then falls back to parsing
   `ipconfig` output (Git Bash on Windows). The first IPv4 address found is
   turned into a `/24` guess, e.g. `192.168.1.0/24`.
3. **If `.env` already exists, it is left untouched** — the script prints a
   note that you'd need to delete it first to redo the questions. This makes
   `./setup.sh` safe to re-run (e.g. to rebuild) without clobbering config.
4. **If `.env` does not exist, prompts for:**
   - **LAN CIDR** — defaults to the guessed value or `192.168.1.0/24`.
     Typing `none`/`NONE`/`off`/`disabled` writes an empty `LOCAL_NETWORK`
     (disables the LAN check — see the networking caveat below).
   - **Dashboard admin username** — defaults to `admin`.
   - **Dashboard admin password** — if left blank, generates one with
     `openssl rand -base64 12` (or reads `/dev/urandom` if `openssl` isn't
     available) and prints it once to the terminal, noting it won't be shown
     again by the script (though it's still recoverable — see
     [Viewing the auto-generated dashboard password](#viewing-the-auto-generated-dashboard-password)).
   - **Whether to expose the dashboard on the LAN** (y/N) — sets
     `DASHBOARD_BIND` to `0.0.0.0` if yes, otherwise `127.0.0.1`.
   - **Whether to show a friendly blocked-site page** (Y/n) — if yes, asks
     for this machine's LAN IP (prefilled from the earlier guess) and writes
     `DASHBOARD_URL=http://<ip>:8787`; if no, or no IP is available,
     `DASHBOARD_URL` is left blank.
   - Writes all of the above to `.env` in the project root.
5. **Runs `docker compose up -d --build`.**
6. **Prints next steps**: the dashboard URL to open, and a reminder to create
   a user per person, and — for each device that needs SSL-Bump refinement
   (e.g. Crunchyroll) — add it under **Devices**, assign it to that person,
   and install the CA cert on that one device. There is no proxy
   address/port/password to configure on any device; Phase 3's interception
   layer (see RoadMap.md) routes matching traffic to Squid transparently
   once it's deployed.

Run it from the project root:

```
./setup.sh
```

### Option B: manual `docker-compose` (no wizard)

Equivalent to Option A without the interactive prompts — useful for scripted
or non-interactive deploys:

1. Copy the template and edit it:
   ```
   cp .env.example .env
   ```
   Edit `.env` to set `LOCAL_NETWORK`, `DASHBOARD_USER`, `DASHBOARD_PASSWORD`,
   `DASHBOARD_BIND`, and `DASHBOARD_URL` as desired (every value is optional —
   see [Environment variables](#environment-variables) for defaults).
2. Build and start both containers:
   ```
   docker compose up -d --build
   ```
3. Open the dashboard (`http://127.0.0.1:8787/` by default, or
   `http://<host-ip>:8787/` if `DASHBOARD_BIND=0.0.0.0`) and log in with the
   admin credentials from `.env` (or the auto-generated password from the
   dashboard container's logs if `DASHBOARD_PASSWORD` was left blank).
4. Create a user per person under **Users**. For any device that needs
   SSL-Bump refinement, add it under **Devices**, assign it to that person
   (and check "SSL-Bump enabled"), download the CA certificate from the
   Users page, and install it as a trusted root on that device — no proxy
   host/port/credential to configure anywhere; identity is resolved from
   the device itself once Phase 3's interception layer is deployed (see
   RoadMap.md).
5. Approve shows/sites per user ahead of time, or reactively from the
   **Report** page as blocks show up.

**Before enabling the captive portal (Phase 4) for real: start with zero
devices pre-added.** (Decided 2026-09-01, resolving G7's "gate existing
devices" cutover question with a policy instead of a code change.) The
schema defaults a hand-added device's `is_authenticated` to `1`
(trusted) while a device the interception layer *discovers* on its own
gets created at `0` (gated, per `common/identity.py`'s `record_binding()`)
-- if any devices already exist in the table with the trusted default
before the portal goes live, they'll never be forced to log in. Adding
devices manually under **Devices** (step 4 above) is still exactly right
for setting up SSL-Bump ahead of time; just don't do it for devices you
intend the portal to actually gate. Already have a list of known MACs
(e.g. exported from the router's client list)? Settings' **Bulk import
devices** card accepts a CSV (`mac_address,label` per row) and adds them
all as plain Unassigned devices in one step, rather than needing them
added one at a time.

## Six-service architecture

Six services, defined in `docker-compose.yml` at the project root.
Three run by default; three more (the Phase 3 interception layer,
added 2026-08-30) are gated behind the `interception` compose profile
and never start unless explicitly asked for -- see the second list
below.

**Default (`docker compose up`):**

- **`proxy`** (container name `optigate-proxy`, built from
  `proxy/Dockerfile`) — the SSL-bumping Squid proxy, running in native
  intercept mode since 2026-08-30 (`http_port 3129 intercept` /
  `https_port 3130 intercept ssl-bump`; see RoadMap.md's Squid
  intercept-mode section). Runs `proxy/entrypoint.sh` as its `ENTRYPOINT`,
  and (since 2026-08-30) `network_mode: host` -- see
  [Networking notes](#networking-notes).
- **`adguard`** (container name `optigate-adguard`, built from
  `adguard/Dockerfile`, added 2026-08-30) — a thin wrapper around the
  official `adguard/adguardhome:v0.107.79` image, adding only an
  automated first-run bootstrap (`adguard/entrypoint.sh`, via AdGuard's
  own `/control/install/configure` API — no manual setup wizard). This is
  what enforces the hard-deny invariant for `mode='bump'` domains on
  non-`bump_enabled` devices (see `docs/security/overview.md` §3 and
  `controller/adguard_sync.py`). Also `network_mode: host`. Has its own
  two volumes (`optigate_adguard_conf`, `optigate_adguard_work`) — separate from
  proxy/dashboard's shared one, since it isn't part of this project's own
  application data.
- **`dashboard`** (container name `optigate-dashboard`, built from
  `dashboard/Dockerfile`) — the Flask web UI (`dashboard/dashboard.py`).
  Listens on port `8787`, run as the `proxy` user (Debian uid 13). Also
  `network_mode: host` since 2026-08-30 — not for traffic interception
  (it doesn't do any), but because its Settings page needs to reach
  AdGuard's admin API at `127.0.0.1:3000`, which a loopback-bound socket
  only accepts from within the same network namespace (see
  [Networking notes](#networking-notes)). `DASHBOARD_BIND` now feeds
  directly into `DASHBOARD_HOST`, the app's own listen address, instead
  of a Docker port-publish mapping.

`proxy` and `dashboard` mount the same named volume, **`optigate_config`**, at
**`/config`** in each container. That's where the shared SQLite database
(`/config/optigate.db`) and the generated CA cert/key
(`/config/ssl_cert/`) live — there's no other IPC between them; they
coordinate purely through files on this shared volume. `adguard` is
otherwise fully independent — it currently has no coded integration with
the shared database at all except through `controller/adguard_sync.py`,
which talks to it purely over its own HTTP API, not the shared volume.

**Behind the `interception` profile (`docker compose --profile
interception up -d`):**

- **`arp-worker`** (built from `phase3/arp-worker/Dockerfile`) — the
  privileged ARP poisoning/corrective-restore process (Go). Needs
  `cap_add: [NET_RAW]` and `network_mode: host` to see the real LAN
  interface. Refuses to start without `-iface`/`-controller-uid`
  (`ARP_WORKER_IFACE`/`CONTROLLER_UID` in `.env`) — no default.
- **`nftables-manager`** (built from
  `phase3/nftables-manager/Dockerfile`) — reconciles the real kernel's
  `optigate` nftables table against the DB-computed
  `DesiredPolicy` blob. Needs `cap_add: [NET_ADMIN]` and
  `network_mode: host`; the image also installs the real `nft` CLI,
  since `knftables` shells out to it.
- **`controller`** (built from `controller/Dockerfile`) — Milestone 3's
  control loop: talks to `arp-worker` over a Unix socket on the shared
  `optigate_run` volume, reads/writes the shared `optigate_config` database, and
  calls AdGuard's admin API (`network_mode: host`, same reachability
  reason as `dashboard`). Refuses to start without `--gateway-ip`/
  `--gateway-mac` (`GATEWAY_IP`/`GATEWAY_MAC` in `.env`) — no default.

None of `ARP_WORKER_IFACE`/`GATEWAY_IP`/`GATEWAY_MAC`/`CONTROLLER_UID`
have a sensible default on purpose — each binary's own argument
validation refuses to start without them, so an unconfigured attempt to
enable this profile fails loudly and immediately rather than guessing.
Actually enabling the `interception` profile is the real "start
intercepting this LAN" decision; see RoadMap.md's live-verification
section for how this was proven end-to-end on a disposable Docker-bridge
test network, never the real production box. **Before enabling it
against a real household LAN for the first time**, run
[`docs/deployment/g1-runbook.md`](g1-runbook.md) — real-network
validation of the ARP interception mechanism against the actual mesh
router is the one remaining gate before that decision, per
RoadMap.md's "Path to deployment" section.

### Startup order dependency

`docker-compose.yml` declares:

```yaml
dashboard:
  depends_on:
    - proxy
```

This is load-bearing, not incidental. `proxy`'s `entrypoint.sh` is what:

- `chown -R proxy:proxy /config` — fixes ownership on the shared volume
  (needed because a fresh named volume can be first-initialized by whichever
  container mounts it first, and would otherwise leave it root-owned for the
  other container to trip over — "attempt to write a readonly database").
- Generates the CA certificate/key pair under `/config/ssl_cert/` if absent.
- Initializes the SQLite database and Squid's own on-disk cert cache
  (`/var/lib/squid/ssl_db`).

The dashboard container runs as the same `proxy` user and opens the same
SQLite file, so it needs `/config` to already be correctly owned and
initialized before it starts — hence `depends_on: [proxy]`. Both Dockerfiles
also pre-chown `/config` at build time (`proxy/Dockerfile` line ~22,
`dashboard/Dockerfile` line ~15) as a first line of defense for a
freshly-created volume, and `entrypoint.sh` re-chowns on every start to
repair a volume left root-owned by an older build.

Note `depends_on` here only waits for the `proxy` container to *start*, not
for its entrypoint work to fully finish — in practice this has been fine
because the dashboard's own DB open/init is tolerant of the brief startup
window, per the ownership-repair logic on both sides.

## Environment variables

All variables are optional; defaults apply if a line is missing. Source:
`.env.example` (LOCAL_NETWORK, DASHBOARD_USER, DASHBOARD_PASSWORD,
DASHBOARD_BIND, DASHBOARD_URL, ADGUARD_USERNAME, ADGUARD_PASSWORD,
ADGUARD_WEB_BIND) and `docker-compose.yml`'s `environment:`
blocks (which also inject DASHBOARD_HOST, OG_DB_PATH, OG_CA_CERT_PATH into
the dashboard container).

| Variable | Consumed by | Purpose | Default |
|---|---|---|---|
| `LOCAL_NETWORK` | proxy + dashboard | LAN CIDR(s) allowed to use the proxy, space-separated if more than one. Seeded into the DB once on first run (`db.set_setting_if_absent`); editable afterward from the dashboard's Settings page without restarting. | `192.168.1.0/24` |
| `DASHBOARD_USER` | dashboard | Admin login username. Only read on first run to seed the account; editable from Settings afterward. | `admin` |
| `DASHBOARD_PASSWORD` | dashboard | Admin login password. Only read on first run. If left blank, the dashboard generates a random password on first start and prints it to its own container logs. | (blank → auto-generated) |
| `DASHBOARD_BIND` | `docker-compose.yml`, feeds directly into `DASHBOARD_HOST` below | Which address the dashboard's own Flask app listens on. `127.0.0.1` = this machine only (use SSH port-forwarding for remote access); `0.0.0.0` = reachable from any device on the LAN. Since 2026-08-30 (`dashboard` runs `network_mode: host`, see [Two/Three-container architecture](#three-container-architecture)) this is the app's own bind address, not a Docker port-publish mapping. | `127.0.0.1` |
| `DASHBOARD_URL` | proxy (`entrypoint.sh` appends a `deny_info` line to `squid.conf` when set), dashboard (starts `block_page_server.py` on port 80 when set, added 2026-08-30), controller (`--dashboard-url`, `interception` profile only), nftables-manager (`--dashboard-url`, `interception` profile only, added 2026-09-09) | If set (e.g. `http://192.168.1.50:8787`), blocked bump-mode Squid requests redirect to a friendly page (`${DASHBOARD_URL}/blocked`); separately, `adguard_sync.py` points hard-denied domains' plain-HTTP DNS answers at this same IP's port 80 for a friendly AdGuard-side page too (HTTPS deliberately excluded -- see `dashboard/block_page_server.py`'s own docstring). Also required for the memorable troubleshooting address (`optigate.home` by default, Settings page, added 2026-09-07) -- same port-80 server, same IP, a different Host header. `nftables-manager` reuses this same value purely to learn the box's own LAN IP (`internal/nft.SelfIPFromDashboardURL`), so `bump_v4`'s Squid redirect can exclude traffic addressed to the box itself (RoadMap.md items 7/18/20) -- deliberately not a separate setting of its own. Leave blank to skip all of the above. | (blank) |
| `DASHBOARD_HOST` | dashboard | Bind address the dashboard container's Flask app actually listens on. Set in `docker-compose.yml` to `${DASHBOARD_BIND:-127.0.0.1}` (see that row above) -- prior to 2026-08-30 this was hardcoded to `0.0.0.0` and a separate port-publish mapping controlled reachability instead. | `${DASHBOARD_BIND:-127.0.0.1}` |
| `OG_DB_PATH` | dashboard (and set internally by `proxy/entrypoint.sh` for its own process) | Path to the shared SQLite database file inside the container. Hardcoded in `docker-compose.yml`'s dashboard environment block to the shared-volume path. | `/config/optigate.db` |
| `OG_CA_CERT_PATH` | dashboard | Path to the generated CA certificate, used by the dashboard's CA-download endpoint (Users page download link). Hardcoded in `docker-compose.yml`. | `/config/ssl_cert/ca_cert.pem` |
| `CA_ORG` | proxy (`entrypoint.sh`) | Organization name (`/O=`) baked into the generated CA certificate's subject. Not present in `.env.example`; set it directly in `docker-compose.yml`'s proxy environment block or as a shell-exported var if you want to override it. | `OptiGate` |
| `CA_COMMON_NAME` | proxy (`entrypoint.sh`) | Common name (`/CN=`) baked into the generated CA certificate's subject. Same override mechanism as `CA_ORG`. | `OptiGate CA` |
| `ADGUARD_USERNAME` | adguard (first-run bootstrap) + dashboard (seeds a matching DB setting, only consumed once) | AdGuard Home's own admin login username -- a separate account from this project's dashboard. | `admin` |
| `ADGUARD_PASSWORD` | adguard (first-run bootstrap), dashboard (seeds a matching DB setting, only consumed once), and controller (`interception` profile -- calls AdGuard's own API) | AdGuard Home's own admin login password. `./setup.sh` generates a real value here before anything ever starts (also self-heals an existing `.env` with this left blank -- see RoadMap.md's 2026-09-07 entry for the real bug this fixes). If you're filling in `.env` by hand instead of using `./setup.sh`, set a real value yourself -- leaving it blank still lets `adguard` boot (it self-generates one), but `controller` will then refuse to start once the interception profile is enabled, since it has no way to learn that generated value. | (blank → `./setup.sh` fills it in; genuinely blank otherwise) |
| `ADGUARD_WEB_BIND` | adguard (`adguard/entrypoint.sh`, first run only) | Which address AdGuard Home's own admin UI binds to. `127.0.0.1` = this machine only; `0.0.0.0` = reachable from any device on the LAN. Independent of `DASHBOARD_BIND` -- this gates a second, separate admin login surface. | `127.0.0.1` |
| `ADGUARD_SKIP_EXTRA_BLOCKLISTS` | adguard (`adguard/entrypoint.sh`, first run only) | Set to `1` to skip subscribing to the curated uBlockOrigin/uAssets domain-blocking lists (added 2026-08-30) and keep only AdGuard Home's own default filter (enabled automatically, no action needed for that part). See RoadMap.md's live-verification section for exactly which lists and why. | (blank -> lists added) |
| `ADGUARD_FILTERS_UPDATE_INTERVAL_HOURS` | adguard (`adguard/entrypoint.sh`, first run only) | How often AdGuard itself re-checks every subscribed filter list, in hours -- `168` = once a week (AdGuard's own "Once a week" UI preset). Independent of the dashboard's "Check for filter updates now" button, which works on demand regardless. | `168` |
| `ADGUARD_DNS_PORT` | adguard (`adguard/entrypoint.sh`, first run only) | Local port AdGuard's own DNS listener binds. Not `5353` (mDNS's well-known port -- `avahi-daemon`, a common default service on many Linux distributions, already binds it; a real deployment hit this exact conflict). Must be kept in sync with `phase3/nftables-manager`'s own `-dns-redirect-port` flag if you ever enable the `interception` profile (`docker-compose.yml` passes the same value to both). | `5354` |
| `ARP_WORKER_IFACE` | arp-worker (`interception` profile only) | The real LAN-facing network interface name (e.g. `eth0`) to send/receive ARP packets on. No default -- `pp-arp-worker` refuses to start without it. | (none -- required to enable the profile) |
| `GATEWAY_IP` / `GATEWAY_MAC` | controller (`interception` profile only) | The real router's IP and MAC address on this LAN. No default -- `controller/main.py` refuses `--db-path` without both. | (none -- required to enable the profile) |
| `CONTROLLER_UID` | arp-worker (`interception` profile only) | The UID the `controller` container's process runs as, checked by `arp-worker` via `SO_PEERCRED` before accepting IPC commands. `controller/Dockerfile` doesn't set a `USER`, so this is `0` (root) by default, matching the container's actual default UID. | `0` |
| `ADGUARD_URL` | dashboard, only consumed once to seed the same-named DB setting | Where the dashboard reaches AdGuard Home's control API for its "Check for filter updates now" button. Both run `network_mode: host`, so this is just the loopback address unless AdGuard is ever moved elsewhere. Editable afterward from the dashboard's own Settings page. | `http://127.0.0.1:3000` |
| `CAPTIVE_PORTAL_DISABLED` | dashboard | Set to any non-empty value to skip starting `dashboard/captive_portal_server.py` on port 3131 (Phase 4 milestone 3, added 2026-08-31) -- an operator kill switch if the captive-portal login flow needs to be turned off in a hurry without a redeploy. `phase3/nftables-manager`'s own baseline rules keep redirecting `unauthenticated_v4`'s port-80 traffic to `:3131` either way; with this set, nothing is listening there, so those devices' plain-HTTP requests just fail to connect instead of showing a login page. | (blank -> enabled) |
| `HOUSEHOLD_TIME_ZONE` | dashboard, only consumed once to seed the same-named DB setting | Default IANA time zone new Schedules (Phase 8, `/schedules`) are created with. Editable afterward from the dashboard's own Settings page; each schedule stores its own time zone once created, so changing this later never moves an already-created schedule's meaning. | `UTC` |

Notes:
- `DASHBOARD_HOST`, `OG_DB_PATH`, and `OG_CA_CERT_PATH` are not meant to be
  set by the user in `.env` — they're fixed values wired directly into
  `docker-compose.yml`'s `dashboard.environment` block, listed here because
  they're part of the deployment's environment surface and a future change
  to the compose file might need to know what they're for.
- `CA_ORG` / `CA_COMMON_NAME` are read by `entrypoint.sh` via shell parameter
  expansion (`${CA_ORG:-OptiGate}`) but are not passed through by
  `docker-compose.yml`'s current `proxy.environment` block — to override
  them you'd need to add entries there.

## CA certificate

Generated by `proxy/entrypoint.sh` on the proxy container's first start (only
if `/config/ssl_cert/ca_cert.pem` or `/config/ssl_cert/ca_key.pem` is
missing — otherwise it's left alone on every subsequent start, so it's stable
across restarts and rebuilds as long as the `optigate_config` volume persists):

```
openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
  -keyout "$SSL_DIR/ca_key.pem" \
  -out "$SSL_DIR/ca_cert.pem" \
  -subj "/O=${CA_ORG:-OptiGate}/CN=${CA_COMMON_NAME:-OptiGate CA}" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```

A 2048-bit RSA key, self-signed, valid 10 years (3650 days), with
`basicConstraints=CA:TRUE` and `keyCertSign`/`cRLSign` usage explicitly set
so Squid's `security_file_certgen` can mint per-site leaf certificates from
it at request time (SSL-bump). Both files land in `/config/ssl_cert/` on the
shared `optigate_config` volume — same path as `OG_CA_CERT_PATH` used by the
dashboard container.

**What a client device needs to do:** install `ca_cert.pem` (not the key —
the private key never leaves the proxy container) as a trusted root
certificate. That's the only per-device step since 2026-08-30 — there is no
proxy host/port/username/password to configure on the device at all; the
device just needs to be added under the dashboard's **Devices** page and
assigned to a user, and its traffic reaches Squid transparently once
Phase 3's interception layer (NAT redirection, see RoadMap.md) is deployed.
The dashboard's **Users** page has a direct download link for the
certificate — same file for every device, no per-device cert. Per-OS install
steps (Windows/macOS/iOS/Android/Chromebook) aren't duplicated here; see the
README's "Setting up a person" section and the "Setting up a device"
reference it points to.

Caveat directly from the README: a native app doing certificate pinning will
simply fail to connect through this proxy rather than being filtered —
SSL-bump can't defeat pinning without modifying the app.

## Networking notes

**As of 2026-08-30, `docker-compose.yml` runs both `proxy` and `adguard`
with `network_mode: host`** — a change from this project's earlier
bridge-networked setup, made after a live verification pass found that
bridge networking doesn't just affect the LAN-IP check below, it
actually breaks Squid's `SO_ORIGINAL_DST` destination recovery and
AdGuard's per-client rule matching entirely, since `phase3/nftables-
manager`'s redirect rules fire in the host's own network namespace and
a bridge-networked container is a different namespace (see RoadMap.md's
live-verification section for the full writeup). This is Linux-only —
Docker Desktop (Windows/Mac) doesn't support `network_mode: host` the
same way, so local development/testing there still needs the
`LOCAL_NETWORK`-blank workaround below. `dashboard` also runs
`network_mode: host` as of 2026-08-30 -- not for traffic interception
(it does none), but because its Settings page needs to reach AdGuard's
admin API at `127.0.0.1:3000`, and a loopback-bound socket only accepts
connections from within the exact same network namespace (confirmed
live: `host.docker.internal`/`extra_hosts` doesn't work around this --
that arrives via a bridge-facing address, a genuinely different source
than `127.0.0.1`).

`LOCAL_NETWORK` (the LAN CIDR check) has a platform-dependent caveat,
documented in `.env.example`:

- **Linux (the supported deployment target, host networking)**: the
  proxy container sees clients' real LAN IPs, so `LOCAL_NETWORK`
  correctly restricts proxy use to that CIDR. Since 2026-08-30, there is
  no per-request login behind it at all (see `docs/security/overview.md`
  §3/§7) — this CIDR check, alongside nftables only ever redirecting a
  bump-enabled device's own IP to Squid in the first place (Phase 3,
  once deployed), is what stands between arbitrary LAN traffic and being
  treated as a specific user.
- **Docker Desktop (Windows/Mac), or if `network_mode: host` is ever
  reverted to bridge networking**: the proxy only sees an internal
  Docker gateway address for every connection, regardless of the real
  client, and Squid's own destination recovery breaks too. Leaving
  `LOCAL_NETWORK` set in this environment would reject *every* request.
  Set it to blank (via `.env`, or `none`/`off`/`disabled` at the
  `setup.sh` prompt, or later from the dashboard's Settings page) to
  disable the CIDR check entirely — at which point nftables' `bump_v4`
  set membership (Phase 3) is the only thing left gating which traffic
  reaches Squid at all, and Squid itself won't work correctly regardless
  (see the security doc's networking caveat).
- This setting is editable at runtime from the dashboard (Settings page)
  without restarting either container — the `.env` value only seeds it on
  first run (`db.set_setting_if_absent` in `entrypoint.sh`).

## Build-time note: apt sources are forced to HTTPS

`controller/Dockerfile`, `dashboard/Dockerfile`, `proxy/Dockerfile`, and
`phase3/nftables-manager/Dockerfile` all `sed` the base image's
`/etc/apt/sources.list.d/debian.sources` from `http://deb.debian.org` to
`https://deb.debian.org` before running `apt-get update`. This exists
because of a real failure confirmed live on the smoke-test VM (2026-09-01):
plain-HTTP apt fetches of `deb.debian.org`'s `InRelease` files consistently
failed apt's clearsign parser (`Clearsigned file isn't valid, got
'NOSPLIT'`), while a byte-for-byte-identical `curl` fetch of the exact same
URL over plain HTTP from the VM's own host network succeeded every time —
something in that environment's path between the Docker container network
and the mirror mangles the plain-HTTP response specifically for apt's
fetcher. HTTPS is unaffected, hence the switch. If a future rebuild
environment hits the same symptom, this is already handled; if a
*different* symptom shows up building on a new environment, don't assume
it's the same root cause without checking (this one was never fully root-
caused, just routed around).

One follow-on wrinkle: `debian:bookworm-slim` (the base for `proxy` and
`phase3/nftables-manager`) ships with **no `ca-certificates` package at
all**, so switching it straight to HTTPS hit a chicken-and-egg problem —
apt can't TLS-verify the mirror to fetch the very package that would let it
verify anything. Both Dockerfiles bootstrap around this with a plain
`COPY --from=python:3.12-slim /etc/ssl/certs/ca-certificates.crt ...`
(that image already carries a real, current CA bundle) — a plain file copy
of a standard root bundle, not a relaxation of TLS verification. The real
`ca-certificates` package is still installed via apt right after, which
reconciles/manages that file properly from then on.

## Port mappings

With `network_mode: host`, all three services' ports bind directly to
the host's own interfaces — there's no compose-level port mapping to look
at for any of them, only what each service's own config asks for.

| Port | Service | Reachable from | Notes |
|---|---|---|---|
| `3128` | proxy | loopback only (`127.0.0.1`) | Plain, non-intercept `http_port` — exists purely so Squid has a "normal" address to build its own internal URLs from (built-in icons); never carries real traffic. Added 2026-08-30 after a live boot found intercept-only Squid FATALs without it. |
| `3129` | proxy | all host interfaces | Squid's intercept-mode HTTP port (`http_port 3129 intercept`). No device configures a proxy setting for this -- it's a NAT-redirect target for Phase 3's interception layer once deployed. |
| `3130` | proxy | all host interfaces | Squid's intercept-mode HTTPS/SSL-Bump port (`https_port 3130 intercept ssl-bump ...`). Same NAT-redirect model as 3129. |
| `3000` | adguard | `ADGUARD_WEB_BIND` (default `127.0.0.1`) | AdGuard Home's own admin UI — a separate login from this project's dashboard. Defaults to loopback-only for the same reason `DASHBOARD_BIND` does; set `ADGUARD_WEB_BIND=0.0.0.0` to expose it on the LAN. |
| `5354` (`ADGUARD_DNS_PORT`) | adguard | all host interfaces | AdGuard Home's DNS listener — the redirect target for `phase3/nftables-manager`'s `authenticated_v4`/`unauthenticated_v4` DNS rules once deployed (its own `-dns-redirect-port` flag must be kept in sync, see `docker-compose.yml`). Genuinely configurable, not just a default: `5354`, not the more obvious `5353`, specifically because `avahi-daemon` (mDNS), a common default service on many Linux distributions, already binds `5353` — a real deployment hit this exact conflict (2026-09-07, then again 2026-09-08 once `avahi-daemon` came back after apparently surviving a `systemctl disable`, likely via `avahi-daemon.socket`'s own socket activation). If `5354` also collides with something on your box, override `ADGUARD_DNS_PORT` in `.env`. |
| `8787` | dashboard | `DASHBOARD_BIND` (default `127.0.0.1`) | Flask dashboard. Bound only to `127.0.0.1` on the host by default — **not LAN-reachable** unless `DASHBOARD_BIND=0.0.0.0` is set (see the `DASHBOARD_BIND` row above). Remote access to a `127.0.0.1`-bound dashboard requires SSH port-forwarding. |

## CI

`.github/workflows/tests.yml` defines a single job, `pytest`, run on
`ubuntu-latest`:

- **Triggers:** `push` to `main`, and every `pull_request` (any branch).
- **Steps:** checkout, set up Python 3.12, `pip install -r
  requirements-dev.txt` and `pip install -r dashboard/requirements.txt`, then
  `pytest -v`.
- **Scope:** this is explicitly the "Tier-1 (no-Docker)" suite only — no
  Squid, no real Docker networking, no real device involved. Per the
  workflow's own comment and the README's "Testing notes" section, Phase
  2/3 verification (real Squid SSL-bump, real Docker networking, a real
  client device) is not covered by CI and has to be run manually against an
  actual deployment (this project keeps a disposable VM for that — see the
  `parental_proxy_smoketest_vm` memory note if using this repo's usual
  workflow).

Nothing in this workflow builds or runs the Docker images — it only
exercises the pure-Python test suite under `tests/`.

## Common commands

```
# Start (build if needed) both containers in the background
docker compose up -d --build

# Stop and remove both containers (the optigate_config volume, and its
# database/CA cert, is preserved)
docker compose down

# Follow logs for both services
docker compose logs -f

# Follow logs for just the dashboard (e.g. to read the auto-generated
# admin password)
docker compose logs dashboard
```

### Viewing the auto-generated dashboard password

If `DASHBOARD_PASSWORD` was left blank in `.env`, the dashboard generates a
random password on its first start and prints it to its own container's
logs — per the comment in `.env.example`:

```
docker compose logs dashboard
```

Look for the generated-password line near the top of the dashboard
container's startup output (i.e. from its first-ever start — if you've
restarted the container many times since, you may need `docker compose
logs dashboard --since <time>` or scroll further back to find the original
first-run output).

The same applies to `docker compose logs adguard` for AdGuard Home's own
admin login if you used Option B (manual `docker-compose`, no `./setup.sh`)
and left `ADGUARD_PASSWORD` blank — but note that leaving it blank there
also means `controller` will refuse to start once you enable the
`interception` profile (see `ADGUARD_PASSWORD`'s own row in
[Environment variables](#environment-variables)); `./setup.sh` avoids this
scenario entirely by generating a real value up front.

### Full backup / moving to another machine

The `optigate_config` volume holds everything stateful: the CA private key (so
restored devices don't need to re-trust a new cert) and the full SQLite
database (users, permissions, log entries). Per the README:

```
docker run --rm -v <project-dir-name>_optigate_config:/config -v "$PWD":/backup \
  alpine tar czf /backup/pp-config-backup.tar.gz -C /config .
```

Replace `<project-dir-name>` with the actual Compose project name (by
default, the project directory's basename) since Compose prefixes volume
names with it.
