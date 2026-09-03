# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Multi-stage build for minimal image size
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder

# The image builds the binary that ships in the container, so its toolchain is
# a security input rather than a build detail: govulncheck analyses the active
# toolchain's stdlib, and a base image that drifts behind the pinned release
# reintroduces the stdlib advisories that release pins away from. The tag above
# and this expectation are updated together, and a mismatch stops the build here
# instead of producing an image whose Go version nothing states.
# The expected version is written literally rather than taken from an ARG. A
# build argument can be overridden on the command line, so an assertion that
# reads one can be satisfied by whoever is building instead of by the toolchain,
# which is the opposite of what this check is for. Change the tag, the digest
# and this literal together.
RUN got="$(go env GOVERSION)"; \
    if [ "$got" != "go1.26.6" ]; then \
      echo "toolchain mismatch: base image reports $got, expected go1.26.6" >&2; \
      echo "update the golang base image tag and digest together with this expectation" >&2; \
      exit 1; \
    fi; \
    echo "toolchain verified: $got"

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=0.0.0-dev.unknown
ARG BUILD_DATE=unknown
ARG GIT_COMMIT=unknown
ARG LICENSE_PUBLIC_KEY=""
ARG RULES_KEYRING_HEX=""
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN apk add --no-cache tini-static=0.19.0-r3 && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -tags enterprise \
    -ldflags "-s -w \
      -X github.com/luckyPipewrench/pipelock/internal/cliutil.Version=${VERSION} \
      -X github.com/luckyPipewrench/pipelock/internal/cliutil.BuildDate=${BUILD_DATE} \
      -X github.com/luckyPipewrench/pipelock/internal/cliutil.GitCommit=${GIT_COMMIT} \
      -X github.com/luckyPipewrench/pipelock/internal/cliutil.GoVersion=$(go version | awk '{print $3}') \
      -X github.com/luckyPipewrench/pipelock/internal/proxy.Version=${VERSION} \
      -X github.com/luckyPipewrench/pipelock/internal/license.PublicKeyHex=${LICENSE_PUBLIC_KEY} \
      -X github.com/luckyPipewrench/pipelock/internal/rules.KeyringHex=${RULES_KEYRING_HEX}" \
    -o /pipelock ./cmd/pipelock

# Scratch-based final image (~15MB)
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /sbin/tini-static /sbin/tini-static
COPY --from=builder /pipelock /pipelock

EXPOSE 8888

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/pipelock", "healthcheck"]

ENTRYPOINT ["/sbin/tini-static", "--", "/pipelock"]
CMD ["run", "--listen", "0.0.0.0:8888"]
