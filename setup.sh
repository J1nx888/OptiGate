#!/usr/bin/env bash
# One-command setup: writes .env if needed, then builds and starts the containers.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== OptiGate setup ==="
echo

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required but wasn't found."
  echo "Install Docker Desktop (Mac/Windows) or Docker Engine (Linux):"
  echo "  https://docs.docker.com/get-docker/"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "This needs the 'docker compose' plugin (bundled with recent"
  echo "Docker Desktop / Docker Engine installs)."
  exit 1
fi

guess=""
host_ip_guess=""
if command -v ip >/dev/null 2>&1; then
  host_ip_guess="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
fi
if [ -z "${host_ip_guess:-}" ] && command -v ipconfig >/dev/null 2>&1; then
  # Git Bash on Windows: pull the first IPv4 address out of ipconfig.
  host_ip_guess="$(ipconfig 2>/dev/null | sed -n 's/.*IPv4 Address[^:]*: *\([0-9.]*\).*/\1/p' | head -n1 | tr -d '\r')"
fi
if [ -n "${host_ip_guess:-}" ]; then
  guess="$(printf '%s' "$host_ip_guess" | awk -F. '{print $1"."$2"."$3".0/24"}')"
fi

if [ -f .env ]; then
  echo ".env already exists -- leaving it as-is."
  echo "(Delete .env first if you want to redo the questions below.)"
else
  echo "A few questions, then this will build and start everything."
  echo
  echo "LAN CIDR: the network your kids' devices connect from. This is a"
  echo "belt-and-suspenders check on top of each device's own assignment."
  echo "It only works with host networking (Linux); under Docker Desktop the"
  echo "proxy can't see real client IPs, so enter 'none' to disable it there."
  read -rp "LAN CIDR devices will connect from [${guess:-192.168.1.0/24}]: " local_network
  local_network="${local_network:-${guess:-192.168.1.0/24}}"
  case "$local_network" in
    none|NONE|off|disabled) local_network="" ;;
  esac

  read -rp "Dashboard admin username [admin]: " dash_user
  dash_user="${dash_user:-admin}"

  read -rsp "Dashboard admin password (leave blank to generate one): " dash_pass
  echo
  if [ -z "$dash_pass" ]; then
    if command -v openssl >/dev/null 2>&1; then
      dash_pass="$(openssl rand -base64 12)"
    else
      dash_pass="$(head -c 12 /dev/urandom | base64)"
    fi
    echo "Generated password: $dash_pass"
    echo "(Save this now -- it's written to .env but not shown again by this script.)"
  fi

  read -rp "Allow the dashboard from other devices on your LAN (not just this machine)? [y/N]: " lan_dash
  dash_bind="127.0.0.1"
  case "${lan_dash:-N}" in
    y|Y) dash_bind="0.0.0.0" ;;
  esac

  read -rp "Show a friendly 'blocked' page for blocked sites (recommended)? [Y/n]: " want_blocked
  dashboard_url=""
  case "${want_blocked:-Y}" in
    n|N) dashboard_url="" ;;
    *)
      read -rp "  This machine's LAN IP, for the block-page link [${host_ip_guess:-<enter manually>}]: " dash_ip
      dash_ip="${dash_ip:-${host_ip_guess:-}}"
      if [ -n "$dash_ip" ]; then
        dashboard_url="http://${dash_ip}:8787"
      fi
      ;;
  esac

  # Generated silently, not asked about: this is AdGuard Home's OWN admin
  # account (separate login surface from the dashboard above), not
  # something used day-to-day. Real bug found live 2026-09-07 (RoadMap.md,
  # "Soak test paused after ~15 minutes"): leaving this blank is
  # documented as "safe, a random one gets generated" -- true for
  # adguard/entrypoint.sh's own first-run bootstrap, but that generated
  # value only ever lands in the adguard container's own logs, never in
  # .env, so controller has no way to know it once the interception
  # profile starts (its argparse just refuses to start:
  # "--adguard-url requires --adguard-username and --adguard-password").
  # Generating it here instead, before any container ever exists, means
  # every service reads the exact same value from .env from the very
  # first `docker compose up` -- no propagation gap, nothing to grep out
  # of a log and paste back in by hand later.
  if command -v openssl >/dev/null 2>&1; then
    adguard_pass="$(openssl rand -base64 15)"
  else
    adguard_pass="$(head -c 15 /dev/urandom | base64)"
  fi

  cat > .env << EOF
LOCAL_NETWORK=${local_network}
DASHBOARD_USER=${dash_user}
DASHBOARD_PASSWORD=${dash_pass}
DASHBOARD_BIND=${dash_bind}
DASHBOARD_URL=${dashboard_url}
ADGUARD_USERNAME=admin
ADGUARD_PASSWORD=${adguard_pass}
EOF
  echo
  echo "Wrote .env"
fi

# Runs regardless of whether .env was just created above or already
# existed -- covers an existing install made before this check existed
# (like the real production box that surfaced this bug), not just a
# brand new one. Idempotent: only ever fills in a value that's
# currently blank, never touches one you've since set or changed
# (including from the dashboard's own Settings page -- this only ever
# looks at .env, never the database).
if grep -qE '^ADGUARD_PASSWORD=\s*$' .env 2>/dev/null; then
  if command -v openssl >/dev/null 2>&1; then
    adguard_pass="$(openssl rand -base64 15)"
  else
    adguard_pass="$(head -c 15 /dev/urandom | base64)"
  fi
  tmp_env="$(mktemp)"
  sed "s|^ADGUARD_PASSWORD=.*|ADGUARD_PASSWORD=${adguard_pass}|" .env > "$tmp_env"
  mv "$tmp_env" .env
  if ! grep -qE '^ADGUARD_USERNAME=' .env; then
    echo "ADGUARD_USERNAME=admin" >> .env
  fi
  echo "Generated a random ADGUARD_PASSWORD in .env (was blank) -- fixes a real"
  echo "bug where controller couldn't authenticate to AdGuard once the"
  echo "interception profile starts. See RoadMap.md's 2026-09-07 entry."
fi

if [ "$(uname -s 2>/dev/null)" = "Linux" ]; then
  echo
  echo "OptiGate's interception mode does real kernel packet forwarding for"
  echo "every intercepted device's traffic -- a real production box hit a"
  echo "sustained-upload bottleneck on a cheap single-queue NIC with all"
  echo "interrupts pinned to one CPU core (see RoadMap.md, \"Item 3"
  echo "revisited\"). Installing a small, reversible boot-time tuning step"
  echo "(RPS + interrupt coalescing) to reduce that risk on similar hardware..."
  if [ "$(id -u)" = "0" ]; then
    install -m 755 nic-tuning/optigate-nic-tuning.sh /usr/local/bin/optigate-nic-tuning.sh
    install -m 644 nic-tuning/optigate-nic-tuning.service /etc/systemd/system/optigate-nic-tuning.service
    systemctl daemon-reload
    systemctl enable --now optigate-nic-tuning.service
    echo "Installed optigate-nic-tuning.service (re-applies at every boot)."
  else
    echo "Skipped -- needs root. To install it later:"
    echo "  sudo install -m 755 nic-tuning/optigate-nic-tuning.sh /usr/local/bin/optigate-nic-tuning.sh"
    echo "  sudo install -m 644 nic-tuning/optigate-nic-tuning.service /etc/systemd/system/optigate-nic-tuning.service"
    echo "  sudo systemctl daemon-reload && sudo systemctl enable --now optigate-nic-tuning.service"
  fi
fi

echo
echo "Building and starting containers (this can take a minute the first time)..."
docker compose up -d --build

host_ip=""
if command -v ip >/dev/null 2>&1; then
  host_ip="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
fi
if [ -z "$host_ip" ] && command -v hostname >/dev/null 2>&1; then
  host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
host_ip="${host_ip:-<this-machine-ip>}"

echo
echo "=== Done ==="
echo
echo "1. Open http://${host_ip}:8787/ (or http://127.0.0.1:8787/ if you kept"
echo "   the dashboard local-only) and log in with your admin credentials."
echo "2. Create a user for each person, under Users."
echo "3. On each device that needs SSL-Bump refinement (e.g. Crunchyroll):"
echo "   under Devices, add its MAC address and assign it to that person,"
echo "   then just install the CA certificate on that one device (Users"
echo "   page has a download link) -- no proxy address, port, or password"
echo "   to configure anywhere; Phase 3's interception layer (see"
echo "   RoadMap.md) routes matching traffic to Squid transparently once"
echo "   it's deployed."
echo "4. Approve shows/sites per user, or just let them try and approve from"
echo "   the Report page as blocks show up."
echo
echo "Full instructions: see README.md"
