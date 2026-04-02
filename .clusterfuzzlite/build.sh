#!/bin/bash -eu

# Register the go-118-fuzz-build/testing dependency required by
# compile_native_go_fuzzer. Build-time-only, not in go.mod.
printf "package scanner\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > "$SRC/pipelock/internal/scanner/fuzz_dep.go"

# The scanner fuzz functions call testConfig() which lives in
# scanner_test.go. compile_native_go_fuzzer excludes _test.go files
# from the build, so generate a non-test copy of testConfig.
cat > "$SRC/pipelock/internal/scanner/fuzz_helpers.go" << 'GOEOF'
package scanner

import "github.com/luckyPipewrench/pipelock/internal/config"

func testConfig() *config.Config {
	cfg := config.Defaults()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.5
	cfg.FetchProxy.Monitoring.MaxURLLength = 200
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	return cfg
}
GOEOF

export GOFLAGS="-mod=mod"
go mod tidy

# Compile each native Go fuzz target into a libFuzzer binary.
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/scanner FuzzScanURL fuzz_scan_url
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/scanner FuzzMatchDomain fuzz_match_domain
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/scanner FuzzShannonEntropy fuzz_shannon_entropy
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/scanner FuzzScanResponseContent fuzz_scan_response_content
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/audit FuzzSanitizeString fuzz_sanitize_string
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/gitprotect FuzzParseDiff fuzz_parse_diff
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/gitprotect FuzzScanDiff fuzz_scan_diff
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/mcp FuzzScanResponse fuzz_scan_response
compile_native_go_fuzzer github.com/luckyPipewrench/pipelock/internal/seedprotect FuzzDetect fuzz_detect
