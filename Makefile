BINARY := pipelock
MODULE := github.com/luckyPipewrench/pipelock
VERSION    ?= $(shell ./scripts/git-version.sh 2>/dev/null || echo "0.0.0-dev.unknown")
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION := $(shell go version | awk '{print $$3}')
LICENSE_PUBLIC_KEY ?=
RULES_KEYRING_HEX ?=
LDFLAGS := -ldflags "-s -w \
	-X $(MODULE)/internal/cliutil.Version=$(VERSION) \
	-X $(MODULE)/internal/cliutil.BuildDate=$(BUILD_DATE) \
	-X $(MODULE)/internal/cliutil.GitCommit=$(GIT_COMMIT) \
	-X $(MODULE)/internal/cliutil.GoVersion=$(GO_VERSION) \
	-X $(MODULE)/internal/proxy.Version=$(VERSION) \
	-X $(MODULE)/internal/license.PublicKeyHex=$(LICENSE_PUBLIC_KEY) \
	-X $(MODULE)/internal/rules.KeyringHex=$(RULES_KEYRING_HEX)"

.PHONY: all build build-verifier verify-examples test test-wasm-verifier bench bench-baseline bench-regression bench-egress bench-egress-long bench-egress-release lint test-stability-check clean docker install fmt vet tidy-check fuzz stats docs-check brand-assets brand-check source-header-check reproducible-build-check \
	test-runtime-critical test-replay-harness test-sharded test-sharded-enterprise release-audit runtime-policy-audit debt-check release-check hermes-e2e test-liveproof

all: build

build:
	go build -trimpath $(LDFLAGS) -o $(BINARY) ./cmd/pipelock

verify-examples: build
	python3 -m unittest scripts.test_e2e_hermetic scripts.test_example_verification_workflow
	PIPELOCK_BIN="$(CURDIR)/$(BINARY)" ./scripts/verify-examples.sh

VERIFIER_BINARY := pipelock-verifier
LDFLAGS_VERIFIER := -ldflags "-s -w \
	-X $(MODULE)/internal/cliutil.Version=$(VERSION) \
	-X $(MODULE)/internal/cliutil.BuildDate=$(BUILD_DATE) \
	-X $(MODULE)/internal/cliutil.GitCommit=$(GIT_COMMIT) \
	-X $(MODULE)/internal/cliutil.GoVersion=$(GO_VERSION)"

build-verifier:
	go build -trimpath $(LDFLAGS_VERIFIER) -o $(VERIFIER_BINARY) ./cmd/pipelock-verifier

install:
	go install $(LDFLAGS) ./cmd/pipelock

test:
	$(MAKE) --no-print-directory test-sharded

test-wasm-verifier:
	node --test deploy/wasm-verify/chain-parity.test.js

test-runtime-critical:
	scripts/run-race-test.sh --packages "./internal/config ./internal/cli ./internal/mcp ./internal/proxy"

# Test shards mirror CI (scripts/ci_test_packages.py): the three heavy packages
# (proxy, scanner, mcp) plus three balanced rest shards. Their union is the same
# package set as `make test`. The proxy shard runs its two packages sequentially
# to match CI's peak-memory cap. Use these to reproduce one CI shard locally, or
# to run the full suite in scoped chunks instead of the single monolithic
# `go test ./...` invocation that becomes a long pole if reused in one CI step.
# `make test` stays the canonical full local run.
TEST_SHARDS := proxy scanner mcp rest-0 rest-1 rest-2
.PHONY: FORCE
FORCE:

# Run one CI-equivalent OSS shard, e.g. `make test-shard-proxy`.
test-shard-%: FORCE
	scripts/run-race-test.sh --shard $*

# Run one CI-equivalent enterprise shard, e.g. `make test-shard-enterprise-mcp`.
test-shard-enterprise-%: FORCE
	scripts/run-race-test.sh --tags enterprise --shard $*

# Run every OSS shard sequentially: same coverage as `make test`, sharded and
# labelled (serial to respect the local single-race-at-a-time constraint).
test-sharded:
	@for shard in $(TEST_SHARDS); do \
		echo "=== OSS test shard: $$shard ==="; \
		scripts/run-race-test.sh --shard $$shard || exit $$?; \
	done

# Run every enterprise shard sequentially (mirrors both CI enterprise matrices).
test-sharded-enterprise:
	@for shard in $(TEST_SHARDS); do \
		echo "=== enterprise test shard: $$shard ==="; \
		scripts/run-race-test.sh --tags enterprise --shard $$shard || exit $$?; \
	done

# test-replay-harness exercises the synthetic replay regression suite:
# deterministic compile + per-session replay + golden snapshot comparison.
# Refresh goldens after intentional logic changes:
#   go test ./internal/capture -run TestReplayHarness -update
test-replay-harness:
	scripts/run-race-test.sh --packages ./internal/capture --run TestReplayHarness

test-cover:
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# hermes-e2e runs the live-Hermes integration proof: it installs a pinned
# hermes-agent into a throwaway venv, does a real `pipelock hermes install
# --mode full`, and drives Hermes' own plugin machinery to confirm the plugin
# loads, enables, and blocks an adversarial tool call. Requires python3 +
# network (pip). Behind the hermes_e2e build tag so it never runs in `make test`.
hermes-e2e:
	go test -tags hermes_e2e -run TestHermesLiveE2E -count=1 -v ./internal/cli/hermes/...

# test-liveproof runs the shipped-binary live-proof harness. It is build-tagged
# because it builds a real pipelock binary, writes real configs, binds real
# ephemeral ports, and is slower/portful enough to keep out of default CI.
test-liveproof:
	go test -tags liveproof -run TestLiveProof -count=1 -v ./internal/liveproof/...

bench:
	go test -bench=. -benchmem -count=3 -run=^$$ ./internal/scanner/ ./internal/mcp/

bench-baseline:
	bash scripts/check-bench-regression.sh --update-baseline

bench-regression:
	bash scripts/check-bench-regression.sh

bench-egress:
	bash bench/egress/run-all.sh

bench-egress-long:
	bash bench/egress/run-all.sh --long

bench-egress-release:
	bash bench/egress/run-all.sh --release

fmt:
	# Format with the gofumpt that golangci-lint bundles, not whatever
	# gofumpt happens to be on PATH. A standalone binary drifts from the
	# pinned one and then disagrees with CI in both directions: a newer
	# local gofumpt reports files CI accepts, and an older one accepts
	# files CI rejects.
	golangci-lint fmt ./...

vet:
	go vet ./...

lint: vet
	golangci-lint run ./...
	./scripts/check-test-stability.sh

test-stability-check:
	./scripts/check-test-stability.sh

release-audit:
	./scripts/release-audit.sh

runtime-policy-audit:
	./scripts/runtime-policy-audit.sh

debt-check:
	golangci-lint run --enable-only dupl,gocyclo,gocognit,maintidx ./...

release-check: test lint release-audit runtime-policy-audit

tidy-check:
	go mod tidy
	git diff --exit-code go.mod go.sum

clean:
	rm -f $(BINARY) $(VERIFIER_BINARY) coverage.out coverage.html

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg LICENSE_PUBLIC_KEY=$(LICENSE_PUBLIC_KEY) \
		--build-arg RULES_KEYRING_HEX=$(RULES_KEYRING_HEX) \
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

stats: ## Print canonical stats
	@go test -race -count=1 -run TestCanonicalStats -v ./internal/config/ 2>&1 | grep -E 'DLP patterns|Response patterns|Chain patterns|Preset files|Direct deps|PASS|FAIL|---'

docs-check: ## Check public docs for known stale claims and print canonical stats
	@./scripts/docs-check.sh

brand-assets: ## Regenerate canonical SVG brand assets
	@python3 scripts/render_brand.py

brand-check: ## Verify SVG masters and raster provenance
	@python3 scripts/render_brand.py --check

source-header-check: ## Verify source files carry the required copyright and license notices
	@./scripts/check-source-headers.sh

reproducible-build-check: ## Build the OSS binary twice and require identical bytes
	@./scripts/check-reproducible-build.sh
