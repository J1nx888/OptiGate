#!/bin/sh
set -eu

# Wraps the official adguard/adguardhome image's own entrypoint
# (/opt/adguardhome/AdGuardHome) so this container comes up fully
# configured on first boot -- no manual setup-wizard step, matching
# proxy/entrypoint.sh's own idempotent-bootstrap pattern for the CA
# cert. AdGuardHome.yaml (on the persisted /opt/adguardhome/conf
# volume) existing at all is what AdGuard itself uses to decide whether
# it's already configured -- once it exists, every later start is a
# plain, unmodified launch.

CONF=/opt/adguardhome/conf/AdGuardHome.yaml
BIN=/opt/adguardhome/AdGuardHome
WORK=/opt/adguardhome/work

# 2026-09-07 (RoadMap.md's dated entry): grants the dashboard container's
# own `proxy` user (uid/gid 13 -- see dashboard/Dockerfile's `USER proxy`)
# read/write access to this file, so dashboard/adguard_config_sync.py can
# write a real password change into it directly (AdGuard Home's REST API
# has no password-change endpoint at all). This image runs AdGuard as
# root (the upstream image's own default -- confirmed live, the file is
# created `root:root` mode 600), so dashboard's non-root process would
# otherwise have zero access to it at all. Numeric gid, not a name --
# this image's own /etc/group has no "proxy" entry, but chown/chmod don't
# need one. Run on EVERY start (not just first boot), same "re-fix
# ownership every time, don't just hope it stays" discipline
# proxy/entrypoint.sh already uses for the shared /config volume -- if
# AdGuard's own live process ever rewrites this file in a way that resets
# its permissions (unconfirmed either way), the next restart repairs it,
# and a restart is already required for any credential sync to actually
# take effect anyway.
_grant_dashboard_access() {
  chown root:13 "$CONF" 2>/dev/null || true
  chmod 660 "$CONF" 2>/dev/null || true
}

if [ -f "$CONF" ]; then
  # Already configured from a previous run (persisted volume) --
  # nothing to bootstrap. exec so this process IS pid 1 and receives
  # signals directly, same as the unwrapped image would.
  _grant_dashboard_access
  exec "$BIN" --no-check-update -c "$CONF" -w "$WORK"
fi

if [ -z "${ADGUARD_PASSWORD:-}" ]; then
  # Mirrors dashboard/dashboard.py's bootstrap_admin() exactly -- same
  # message shape, same "generate and print once, editable afterward"
  # behavior -- for the same reason: no default admin password should
  # ever ship, but failing to boot at all over a missing one would be
  # worse than a random one the operator can rotate right after.
  ADGUARD_PASSWORD=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)
  SEP=$(printf '=%.0s' $(seq 1 64))
  {
    echo ""
    echo "$SEP"
    echo "  No ADGUARD_PASSWORD was set. Generated an admin login:"
    echo "    username: ${ADGUARD_USERNAME:-admin}"
    echo "    password: $ADGUARD_PASSWORD"
    echo "  Change it from the Settings page after logging in."
    echo "$SEP"
    echo ""
  } >&2
fi

echo "First run: bootstrapping AdGuard Home via its own install API (no manual wizard)..." >&2

# Backgrounded (not exec'd) only for this first-run path, specifically
# so this script can poll it and complete setup via its own real HTTP
# API before handing off control -- confirmed live 2026-08-30 against a
# real v0.107.79 instance that /control/install/configure (NOT the bare
# /install/configure some of AdGuard's own generated OpenAPI-doc
# tooling implies -- every route lives under /control, even before the
# instance is configured at all) writes a complete, correctly-versioned
# AdGuardHome.yaml itself. Hand-authoring that file from the wiki's
# documented fields was tried first and found missing several fields
# the real binary always writes (session_ttl's duration format,
# upstream_mode, cache_optimistic_*, the doh.routes block) -- letting
# AdGuard build its own config is both simpler and impossible to drift
# out of sync with whatever version is actually running.
"$BIN" --no-check-update -c "$CONF" -w "$WORK" &
PID=$!
trap 'kill -TERM "$PID" 2>/dev/null; wait "$PID" 2>/dev/null' TERM INT

i=0
while ! wget -q -O /dev/null http://127.0.0.1:3000/control/install/get_addresses 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then
    echo "AdGuard Home did not come up for setup within 30s" >&2
    kill -TERM "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
    exit 1
  fi
  sleep 1
done

# Minimal JSON-string escaping (backslash, then double-quote -- the two
# characters that matter for a plain JSON string value) so an
# operator-supplied ADGUARD_USERNAME/ADGUARD_PASSWORD containing either
# doesn't break the request body. Web port is always left at the
# image's own default (3000) -- only DNS gets a non-default port
# (5353, matching phase3/nftables-manager's baselineRules redirect
# target) -- so this script never has to guess which port to poll
# above, and there's no live web-port change to verify (DNS's port DID
# need confirming: the running process picks up the new DNS port
# immediately after configure, live, with no restart -- confirmed
# 2026-08-30, real dig queries succeeded against :5353 within the same
# process that was still only listening on :3000/HTTP moments earlier).
_json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}
USERNAME_JSON=$(_json_escape "${ADGUARD_USERNAME:-admin}")
PASSWORD_JSON=$(_json_escape "$ADGUARD_PASSWORD")

# Web is ALWAYS configured onto the wildcard address here, regardless
# of ADGUARD_WEB_BIND -- confirmed live 2026-08-30 that
# /control/install/configure validates the NEW address by test-binding
# it before releasing the current pre-configure listener, and asking
# for exactly the same specific address that listener already holds
# (e.g. 127.0.0.1:3000) fails with "address already in use" against
# itself; the wildcard doesn't conflict the same way (standard Linux
# bind() behavior: a wildcard bind coexists with an already-bound
# specific address, where repeating that exact specific address does
# not). ADGUARD_WEB_BIND is applied as a second step below instead.
wget -q -O /dev/null \
  --header 'Content-Type: application/json' \
  --post-data "{\"web\":{\"ip\":\"0.0.0.0\",\"port\":3000},\"dns\":{\"ip\":\"0.0.0.0\",\"port\":${ADGUARD_DNS_PORT:-5353}},\"username\":\"$USERNAME_JSON\",\"password\":\"$PASSWORD_JSON\"}" \
  http://127.0.0.1:3000/control/install/configure

if [ ! -f "$CONF" ]; then
  echo "AdGuard Home install/configure did not produce $CONF -- aborting" >&2
  kill -TERM "$PID" 2>/dev/null
  wait "$PID" 2>/dev/null
  exit 1
fi
_grant_dashboard_access

# Ad/tracker blocking, layered on top of AdGuard's own default filter --
# confirmed live 2026-08-30 that install/configure itself already
# registers and enables "AdGuard DNS filter" with real rules moments
# after configuring (checking the raw AdGuardHome.yaml file too early
# makes it look empty; the live /control/filtering/status API is the
# one that's actually accurate). These additional lists are pulled from
# uBlockOrigin/uAssets, at the user's own request -- but NOT the whole
# repo blindly: uBO's lists are written for a browser extension
# (cosmetic element-hiding, JS scriptlet injection) that a DNS server
# fundamentally cannot apply -- only each list's DOMAIN-blocking subset
# is usable here. Every URL below was confirmed live to parse with a
# meaningful nonzero count of exactly that subset (not picked from the
# repo's file listing blindly): filters.txt (uBO's main list, ~6k usable
# domain rules despite being mostly cosmetic), badware.txt, privacy.txt,
# resource-abuse.txt. unbreak.txt is included specifically to counteract
# the others' false positives (uAssets ships it as the matching
# exception list for exactly this purpose) -- never subscribe to one of
# these without its companion exceptions list. Explicitly left out:
# annoyances*.txt (cookie-banner/cosmetic-heavy, low DNS-blocking value,
# real over-blocking risk), experimental.txt (opt-in even within uBO
# itself), the per-year filters-20XX.txt archives and ubol-filters.txt/
# lan-block.txt/ubo-link-shorteners.txt (niche, not obviously a sane
# default for a household). Set ADGUARD_SKIP_EXTRA_BLOCKLISTS=1 to skip
# this step entirely and keep only AdGuard's own default filter.
if [ "${ADGUARD_SKIP_EXTRA_BLOCKLISTS:-}" != "1" ]; then
  echo "Adding uBlock Origin (uAssets) filter lists..." >&2
  AUTH_B64=$(printf '%s:%s' "${ADGUARD_USERNAME:-admin}" "$ADGUARD_PASSWORD" | base64 -w0)
  UASSETS_BASE="https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters"
  for entry in \
    "uBO - filters|$UASSETS_BASE/filters.txt" \
    "uBO - Badware|$UASSETS_BASE/badware.txt" \
    "uBO - Privacy|$UASSETS_BASE/privacy.txt" \
    "uBO - Resource abuse|$UASSETS_BASE/resource-abuse.txt" \
    "uBO - Unbreak (exceptions)|$UASSETS_BASE/unbreak.txt"
  do
    list_name=$(_json_escape "${entry%%|*}")
    list_url=$(_json_escape "${entry#*|}")
    wget -q -O /dev/null \
      --header "Authorization: Basic $AUTH_B64" \
      --header 'Content-Type: application/json' \
      --post-data "{\"name\":\"$list_name\",\"url\":\"$list_url\",\"whitelist\":false}" \
      http://127.0.0.1:3000/control/filtering/add_url \
      || echo "  warning: failed to add blocklist '$list_name' -- continuing anyway" >&2
  done

  # AdGuard already re-checks every subscribed list on its own --
  # ADGUARD_FILTERS_UPDATE_INTERVAL_HOURS just tells it how often
  # (confirmed live 2026-08-30: 168 = one week is accepted and echoed
  # back exactly, matching AdGuard's own "Once a week" UI preset). The
  # dashboard's "Check for filter updates now" button
  # (common/adguard_client.refresh_filters) covers the "whenever the
  # admin wants" half of this independently of whatever interval is set
  # here -- it doesn't wait for this schedule.
  wget -q -O /dev/null \
    --header "Authorization: Basic $AUTH_B64" \
    --header 'Content-Type: application/json' \
    --post-data "{\"enabled\":true,\"interval\":${ADGUARD_FILTERS_UPDATE_INTERVAL_HOURS:-168}}" \
    http://127.0.0.1:3000/control/filtering/config \
    || echo "  warning: failed to set the filter update interval -- continuing anyway" >&2
fi

# Same reasoning as dashboard/dashboard.py's DASHBOARD_BIND default:
# with `network_mode: host` (required for DNS interception, see
# docker-compose.yml's own comment), the wildcard bind above would put
# AdGuard Home's own admin UI -- a second login surface this project
# didn't build, separate from our dashboard -- directly on the LAN. If
# a non-wildcard bind was actually requested, rewrite the now-written
# config's http.address directly and restart onto it: AdGuardHome.yaml
# only takes effect while the process isn't running (AdGuard's own
# documented behavior), which this restart satisfies, and there's no
# more self-conflict once the wildcard listener above is torn down
# first. Set ADGUARD_WEB_BIND=0.0.0.0 to skip this step and deliberately
# expose it on the LAN instead.
WEB_BIND="${ADGUARD_WEB_BIND:-127.0.0.1}"
if [ "$WEB_BIND" != "0.0.0.0" ]; then
  kill -TERM "$PID" 2>/dev/null
  wait "$PID" 2>/dev/null
  trap - TERM INT
  sed -i "s/^  address: 0\.0\.0\.0:3000\$/  address: ${WEB_BIND}:3000/" "$CONF"
  exec "$BIN" --no-check-update -c "$CONF" -w "$WORK"
fi

echo "AdGuard Home configured (DNS on :${ADGUARD_DNS_PORT:-5353}, admin UI on 0.0.0.0:3000)." >&2
wait "$PID"
