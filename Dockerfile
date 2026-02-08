# Multi-stage build for minimal image size
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/luckyPipewrench/pipelock/internal/cli.Version=${VERSION} \
              -X github.com/luckyPipewrench/pipelock/internal/proxy.Version=${VERSION}" \
    -o /pipelock ./cmd/pipelock

# Scratch-based final image (~15MB)
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /pipelock /pipelock

EXPOSE 8888

ENTRYPOINT ["/pipelock"]
CMD ["run"]
