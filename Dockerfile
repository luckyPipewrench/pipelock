# Multi-stage build for minimal image size
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=0.1.0-dev
ARG BUILD_DATE=unknown
ARG GIT_COMMIT=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X github.com/luckyPipewrench/pipelock/internal/cli.Version=${VERSION} \
      -X github.com/luckyPipewrench/pipelock/internal/cli.BuildDate=${BUILD_DATE} \
      -X github.com/luckyPipewrench/pipelock/internal/cli.GitCommit=${GIT_COMMIT} \
      -X github.com/luckyPipewrench/pipelock/internal/cli.GoVersion=$(go version | awk '{print $3}') \
      -X github.com/luckyPipewrench/pipelock/internal/proxy.Version=${VERSION}" \
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
