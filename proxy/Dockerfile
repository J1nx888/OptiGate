FROM debian:bookworm-slim

# squid-openssl, not squid: Debian's default `squid` package is built
# --with-gnutls, which does not support SSL-Bump at all (on-the-fly leaf
# certificate signing needs OpenSSL) -- `squid -k parse` fails with "Unknown
# http_port option 'ssl-bump'" on the plain package. squid-openssl is the
# same version, built --with-openssl instead, and is what this project's
# entire ssl_bump config depends on.
# The sed below forces the base image's apt sources to HTTPS -- see
# controller/Dockerfile's own comment on this same fix for the full
# story (a live-confirmed plain-HTTP apt fetch corruption against
# deb.debian.org, HTTPS unaffected). debian:bookworm-slim ships with NO
# ca-certificates package at all (confirmed live: zero files under
# /etc/ssl/certs, dpkg has no ca-certificates entry) -- switching it
# straight to HTTPS is a chicken-and-egg problem, since apt can't
# TLS-verify the mirror to fetch the very package that would let it
# verify anything. Bootstrapped by copying the CA bundle from
# python:3.12-slim (already used elsewhere in this repo's own images,
# confirmed to already carry a real, current `ca-certificates` package)
# -- a plain file copy of a standard root bundle, not a relaxation of
# TLS verification. The real `ca-certificates` package below then
# installs/reconciles it properly via apt for everything after this.
COPY --from=python:3.12-slim /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
        squid-openssl \
        openssl \
        python3 \
        ca-certificates \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Intercept mode's IP_TRANSPARENT bind + SO_ORIGINAL_DST lookup need
# CAP_NET_ADMIN -- but this Debian build of Squid is compiled
# --with-default-user=proxy, so it always calls setuid() down to the
# unprivileged `proxy` user during startup (see tools.cc's leave_suid,
# visible in a `squid -X` trace as "giving up root, becoming 'proxy'")
# *before* it gets to opening those listener sockets. Linux drops a
# process's capabilities on setuid() unless they're preserved another
# way, so cap_add: NET_ADMIN on the container alone isn't enough --
# confirmed live 2026-08-30, where this crashed Squid silently
# (RegisteredRunner::finalizeConfig never completing, no message at
# the default log level) despite the container capability being
# present the whole time. A file capability survives setuid() because
# it's granted to the binary itself, not the process's inherited set --
# this is Squid's own documented fix for TPROXY/intercept deployments
# that don't run as root.
RUN setcap 'cap_net_admin=+ep' /usr/sbin/squid

# Pre-create /config owned by the `proxy` user (uid 13 on Debian). If a fresh
# named volume is first initialised by this container, Docker seeds it with
# this ownership so the squid helper processes (which run as `proxy`) can
# write the SQLite database. entrypoint.sh also re-chowns it on every start
# to cover volumes created by the dashboard container.
RUN mkdir -p /opt/optigate/defaults /config \
    && chown -R proxy:proxy /config

COPY common/*.py /opt/optigate/
COPY proxy/sni_helper.py proxy/authz_helper.py /opt/optigate/
COPY defaults/seed_defaults.py defaults/ai_sites_seed.py /opt/optigate/defaults/
COPY proxy/squid.conf.template /etc/squid/squid.conf.template
COPY proxy/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh /opt/optigate/*.py /opt/optigate/defaults/*.py

# Intercept-mode ports (RoadMap.md's Squid intercept-mode section, locked
# 2026-08-30) -- nftables NAT-redirects a bump_v4 device's own port 80/443
# traffic here, replacing the old explicit-proxy 3128.
EXPOSE 3129 3130

ENTRYPOINT ["/entrypoint.sh"]
