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
ARG EXPECTED_GO_VERSION=go1.26.6
RUN got="$(go env GOVERSION)"; \
    if [ "$got" != "$EXPECTED_GO_VERSION" ]; then \
      echo "toolchain mismatch: base image reports $got, expected $EXPECTED_GO_VERSION" >&2; \
      echo "update the golang base image tag and digest together with EXPECTED_GO_VERSION" >&2; \
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
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -tags enterprise \
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
COPY --from=builder /pipelock /pipelock

EXPOSE 8888

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/pipelock", "healthcheck"]

ENTRYPOINT ["/pipelock"]
CMD ["run", "--listen", "0.0.0.0:8888"]
