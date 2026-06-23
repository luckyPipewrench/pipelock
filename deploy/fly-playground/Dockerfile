# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0
#
# Pipelock playground — per-visitor Fly.io microVM image.
#
# Bundles the playground server + model agent + probe/web-tool binaries, creates
# the contained agent user (fixed uid 10001, matching the nft rule), and the boot
# entrypoint loads the proven kernel owner-match egress rule so the agent uid can
# reach ONLY the in-process Pipelock proxy. The microVM is the filesystem /
# visitor-vs-visitor isolation; Pipelock + the nft rule are the egress firewall
# inside it.
#
# Build from the REPO ROOT (the build stage needs the whole module):
#   docker build -f deploy/fly-playground/Dockerfile -t pipelock-playground .
#
# Run requires NET_ADMIN to load the nft rule (Fly microVMs allow this; for a
# local smoke test: docker run --cap-add NET_ADMIN ...).

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w" -o /out/pipelock-playground-live      ./cmd/pipelock-playground-live \
 && go build -trimpath -ldflags "-s -w" -o /out/pipelock-playground-llm-agent ./cmd/pipelock-playground-llm-agent \
 && go build -trimpath -ldflags "-s -w" -o /out/pipelock-playground-toyagent  ./cmd/pipelock-playground-toyagent \
 && go build -trimpath -ldflags "-s -w" -o /out/pipelock-playground-webtool   ./cmd/pipelock-playground-webtool

FROM debian:bookworm-slim
# nftables: load the owner-match egress rule. ca-certificates: TLS to the model
# API through the proxy. tini: clean PID 1 signal handling. iproute2: diagnostics.
#
# The rest (curl, wget, python3, netcat, dnsutils, openssl) ARM the agent on
# purpose: this is a disposable per-visitor microVM, and the demo is only
# credible if the agent is fully equipped and STILL cannot get a secret out. A
# crippled box ("it had no curl") proves nothing; an armed agent blocked at the
# proxy (signed receipt) and kernel-dropped on any direct egress (containment
# witness) proves everything. Every tool here egresses only through Pipelock or
# is dropped by the owner-match rule.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nftables ca-certificates tini iproute2 \
      curl wget python3 netcat-openbsd dnsutils openssl \
 && rm -rf /var/lib/apt/lists/*
# Contained agent user. Fixed uid 10001 MUST match the nft rule (--agent-uid) and
# the server's contained-agent user. No login shell, no preseeded home: the
# server creates + chowns a per-session scratch dir at session start.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin pipelock-agent
COPY --from=build /out/pipelock-playground-live      /usr/local/bin/pipelock-playground-live
COPY --from=build /out/pipelock-playground-llm-agent /usr/local/bin/pipelock-playground-llm-agent
COPY --from=build /out/pipelock-playground-toyagent  /usr/local/bin/pipelock-playground-toyagent
COPY --from=build /out/pipelock-playground-webtool   /usr/local/bin/pipelock-playground-webtool
COPY deploy/fly-playground/entrypoint.sh /usr/local/bin/playground-entrypoint
RUN chmod 0755 /usr/local/bin/playground-entrypoint /usr/local/bin/pipelock-playground-*
ENV PLAYGROUND_AGENT_USER=pipelock-agent \
    PLAYGROUND_AGENT_UID=10001 \
    PLAYGROUND_PROXY_PORT=8888 \
    PLAYGROUND_LISTEN=0.0.0.0:8080
EXPOSE 8080
# The server runs as root in the disposable single-tenant VM (hardened-root
# posture): it hosts the in-process proxy (full egress) and drops the agent
# subprocess to uid 10001, which the nft rule confines to the proxy.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/playground-entrypoint"]
