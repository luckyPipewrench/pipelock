BINARY := pipelock
MODULE := github.com/luckyPipewrench/pipelock
VERSION    ?= $(shell (git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev") | sed 's/^v//')
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | awk '{print $$3}')
LICENSE_PUBLIC_KEY ?=
LDFLAGS := -ldflags "-s -w \
	-X $(MODULE)/internal/cliutil.Version=$(VERSION) \
	-X $(MODULE)/internal/cliutil.BuildDate=$(BUILD_DATE) \
	-X $(MODULE)/internal/cliutil.GitCommit=$(GIT_COMMIT) \
	-X $(MODULE)/internal/cliutil.GoVersion=$(GO_VERSION) \
	-X $(MODULE)/internal/proxy.Version=$(VERSION) \
	-X $(MODULE)/internal/license.PublicKeyHex=$(LICENSE_PUBLIC_KEY) \
	-X $(MODULE)/internal/rules.KeyringHex=$(LICENSE_PUBLIC_KEY)"

.PHONY: build test bench lint clean docker install fmt vet tidy-check fuzz

build:
	go build -trimpath $(LDFLAGS) -o $(BINARY) ./cmd/pipelock

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
	gofumpt -w .

vet:
	go vet ./...

lint: vet
	golangci-lint run ./...

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
		--build-arg LICENSE_PUBLIC_KEY=$(LICENSE_PUBLIC_KEY) \
		-t $(BINARY):$(VERSION) -t $(BINARY):latest .

fuzz:
	@echo "Running all fuzz targets (30s each)..."
	@go test -run=^$$ -fuzz=FuzzScanURL -fuzztime=30s ./internal/scanner/
	@go test -run=^$$ -fuzz=FuzzMatchDomain -fuzztime=30s ./internal/scanner/
	@go test -run=^$$ -fuzz=FuzzShannonEntropy -fuzztime=30s ./internal/scanner/
	@go test -run=^$$ -fuzz=FuzzScanResponseContent -fuzztime=30s ./internal/scanner/
	@go test -run=^$$ -fuzz=FuzzSanitizeString -fuzztime=30s ./internal/audit/
	@go test -run=^$$ -fuzz=FuzzParseDiff -fuzztime=30s ./internal/gitprotect/
	@go test -run=^$$ -fuzz=FuzzScanDiff -fuzztime=30s ./internal/gitprotect/
	@go test -run=^$$ -fuzz=FuzzScanResponse -fuzztime=30s ./internal/mcp/
	@go test -run=^$$ -fuzz=FuzzDetect -fuzztime=30s ./internal/seedprotect/
	@echo "All fuzz targets complete."
