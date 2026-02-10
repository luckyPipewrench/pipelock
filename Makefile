BINARY := pipelock
MODULE := github.com/luckyPipewrench/pipelock
VERSION    ?= $(shell (git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev") | sed 's/^v//')
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | awk '{print $$3}')
LDFLAGS := -ldflags "-s -w \
	-X $(MODULE)/internal/cli.Version=$(VERSION) \
	-X $(MODULE)/internal/cli.BuildDate=$(BUILD_DATE) \
	-X $(MODULE)/internal/cli.GitCommit=$(GIT_COMMIT) \
	-X $(MODULE)/internal/cli.GoVersion=$(GO_VERSION) \
	-X $(MODULE)/internal/proxy.Version=$(VERSION)"

.PHONY: build test bench lint clean docker install fmt vet tidy-check

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/pipelock

install:
	go install $(LDFLAGS) ./cmd/pipelock

test:
	go test -race -count=1 ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

bench:
	go test -bench=. -benchmem -count=3 -run=^$$ ./internal/scanner/ ./internal/mcp/

fmt:
	gofmt -s -w .

vet:
	go vet ./...

lint: vet
	@which golangci-lint > /dev/null 2>&1 || echo "golangci-lint not installed, skipping"
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run || true

tidy-check:
	go mod tidy
	git diff --exit-code go.mod go.sum

clean:
	rm -f $(BINARY) coverage.out coverage.html

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(BINARY):$(VERSION) -t $(BINARY):latest .
