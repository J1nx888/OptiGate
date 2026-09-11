FROM python:3.12-slim

WORKDIR /app

COPY dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/*.py /app/
COPY common/data /app/data
COPY dashboard/dashboard.py dashboard/block_page_server.py dashboard/captive_portal_server.py dashboard/adguard_config_sync.py dashboard/adguard_report_sync.py /app/
COPY dashboard/static /app/static

# Port 80 (block_page_server.py, started only when DASHBOARD_URL is set)
# needs CAP_NET_BIND_SERVICE -- but docker-compose.yml's own `cap_add`
# alone isn't enough for the non-root `proxy` user below to actually use
# it: confirmed live 2026-08-30 ("PermissionError: [Errno 13] Permission
# denied" on bind(), despite the container capability being present)
# that a container-level capability only reaches a non-root EXECVE if
# the exec'd BINARY also carries a matching file capability -- the exact
# same lesson as proxy/Dockerfile's own `setcap` for Squid, hit again
# here for a completely different process. Granting this to the whole
# `python3.12` binary (not just this one script) is broad in general,
# but this image only ever runs `python3 dashboard.py`, so it's
# equivalent in practice and is the standard fix for a non-root
# interpreter needing a privileged port (the same pattern node/python
# images needing port 80/443 commonly use).
#
# The sed below forces the base image's apt sources to HTTPS -- see
# controller/Dockerfile's own comment on this same fix for the full
# story (a live-confirmed plain-HTTP apt fetch corruption against
# deb.debian.org, HTTPS unaffected).
#
# `openssl` (added 2026-09-06, alongside libcap2-bin above): the Settings
# page's SSL-Bump CA cert management (regenerate / validate-and-replace an
# uploaded cert+key pair, dashboard.py's _validate_ca_cert_pair()/
# regenerate_ca_cert()) shells out to it rather than adding a Python
# crypto library dependency for one admin action -- same tool
# proxy/entrypoint.sh already uses to generate the default CA pair.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends libcap2-bin openssl \
    && rm -rf /var/lib/apt/lists/* \
    && setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(which python3)")"

# Run as the same user the squid helpers use (Debian's `proxy`, uid 13) so the
# SQLite database and its -wal/-shm files on the shared /config volume stay
# writable by both containers. A fresh named volume first mounted here is
# seeded with this ownership.
RUN mkdir -p /config && chown -R proxy:proxy /config /app
USER proxy

EXPOSE 8787 80 3131

CMD ["python3", "dashboard.py"]
