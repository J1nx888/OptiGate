#!/bin/sh
set -eu

CONFIG_DIR=/config
SSL_DIR="$CONFIG_DIR/ssl_cert"
mkdir -p "$CONFIG_DIR" "$SSL_DIR"

# Make the shared volume writable by the `proxy` user before anything opens
# the database. The dashboard container also runs as `proxy` and both
# processes read/write the same SQLite file (+ its -wal/-shm sidecars); a
# root-owned file here means one side gets "attempt to write a readonly
# database". This also repairs a volume left root-owned by an older build.
chown -R proxy:proxy "$CONFIG_DIR" 2>/dev/null || true

export OG_DB_PATH="$CONFIG_DIR/optigate.db"

# Seed defaults (idempotent -- safe every start, changes nothing on an
# already-configured database) and bootstrap the env-seeded settings. Run as
# `proxy` (via runuser, util-linux) so the DB and WAL sidecars are created
# with the right owner. If runuser somehow isn't present, fall back to root
# -- the chown above and below still leaves the volume proxy-owned before
# squid starts.
if command -v runuser >/dev/null 2>&1; then
  AS_PROXY="runuser -u proxy --"
else
  AS_PROXY=""
fi

$AS_PROXY python3 /opt/optigate/defaults/seed_defaults.py
$AS_PROXY python3 - << PYEOF
import sys
sys.path.insert(0, "/opt/optigate")
import db
conn = db.get_conn()
db.init_db(conn)
db.set_setting_if_absent(conn, "local_network", "${LOCAL_NETWORK:-192.168.1.0/24}")
db.set_setting_if_absent(conn, "block_page_mode", "terminate")
conn.commit()
PYEOF

# Generate the SSL-bump CA certificate on first run. This is what gets
# installed as a trusted root on client devices -- the private key never
# leaves this container.
if [ ! -f "$SSL_DIR/ca_cert.pem" ] || [ ! -f "$SSL_DIR/ca_key.pem" ]; then
  echo "Generating a new SSL-bump CA certificate..."
  # basicConstraints=CA:TRUE and keyCertSign are required for Squid to mint
  # per-site leaf certs from this key. openssl 3 (bookworm) usually adds them
  # for -x509 via the default config, but make it explicit so cert generation
  # doesn't silently depend on the base image's openssl.cnf.
  openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
    -keyout "$SSL_DIR/ca_key.pem" \
    -out "$SSL_DIR/ca_cert.pem" \
    -subj "/O=${CA_ORG:-OptiGate}/CN=${CA_COMMON_NAME:-OptiGate CA}" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

# Initialize Squid's SSL certificate cache database if this is the first run.
# Unlike /var/spool/squid and /var/log/squid, the squid-openssl package does
# not pre-create /var/lib/squid itself -- security_file_certgen -c creates
# ssl_db but not a missing parent, so it fails with "Cannot create
# /var/lib/squid/ssl_db" on a fresh container without this.
mkdir -p /var/lib/squid
if [ ! -d /var/lib/squid/ssl_db ]; then
  /usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 4MB
fi
chown -R proxy:proxy /var/lib/squid "$SSL_DIR" "$CONFIG_DIR" 2>/dev/null || true

# Render squid.conf, then conditionally append the friendly-block-page
# redirect if DASHBOARD_URL is configured.
cp /etc/squid/squid.conf.template /etc/squid/squid.conf
if [ -n "${DASHBOARD_URL:-}" ]; then
  echo "deny_info ${DASHBOARD_URL}/blocked authz_allowed" >> /etc/squid/squid.conf
fi

exec squid -N -f /etc/squid/squid.conf
