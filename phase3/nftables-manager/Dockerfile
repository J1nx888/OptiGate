# Multi-stage: compile the static Go binary, then run it in a minimal
# image that ALSO has the real `nft` CLI installed -- knftables
# (sigs.k8s.io/knftables) shells out to it rather than talking netlink
# directly, confirmed live 2026-08-30 ("could not find nftables binary:
# exec: \"nft\": executable file not found in $PATH") while first
# verifying this binary against a real kernel.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /pp-nftables-manager ./cmd/pp-nftables-manager

FROM debian:bookworm-slim
# The sed below forces the base image's apt sources to HTTPS -- see
# controller/Dockerfile's own comment on this same fix for the full
# story (a live-confirmed plain-HTTP apt fetch corruption against
# deb.debian.org, HTTPS unaffected). debian:bookworm-slim ships with no
# ca-certificates at all, a chicken-and-egg problem for switching it to
# HTTPS -- bootstrapped by copying the CA bundle from python:3.12-slim
# (see proxy/Dockerfile's own copy of this comment for the full
# reasoning: a plain file copy of a standard root bundle, not a
# relaxation of TLS verification).
COPY --from=python:3.12-slim /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# conntrack-tools (added 2026-09-09, RoadMap.md item 21): provides the
# `conntrack` CLI internal/nft/conntrack.go shells out to -- a
# DIFFERENT tool than `nft` above, managing a different kernel
# subsystem (the connection-tracking table, not the nftables ruleset
# itself). nftables has no equivalent "delete an already-tracked
# connection" primitive of its own; see that file's own doc comment for
# why this exists at all.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends ca-certificates nftables conntrack \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /pp-nftables-manager /usr/local/bin/pp-nftables-manager

# Runs as root deliberately -- CAP_NET_ADMIN alone isn't enough to
# create/manage the "optigate" nftables table's rules the way
# this process needs (confirmed live this session for the analogous
# Squid case: a non-root effective user loses a capability granted at
# the container level unless the binary itself carries a matching file
# capability -- simplest correct answer here, since this process's
# whole purpose IS privileged nftables management with nothing else
# running alongside it in this container, is to just run it as root).
ENTRYPOINT ["/usr/local/bin/pp-nftables-manager"]
