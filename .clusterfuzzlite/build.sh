#!/bin/bash -eu

# Register the go-118-fuzz-build/testing dependency required by
# compile_native_go_fuzzer. This is a build-time-only dependency
# that does not belong in go.mod permanently.
printf "package scanner\nimport _ \"github.com/AdamKorcz/go-118-fuzz-build/testing\"\n" > "$SRC/pipelock/internal/scanner/fuzz_dep.go"
export GOFLAGS="-mod=mod"
go mod tidy

# Fuzz functions live in _test.go files which go build excludes.
# Symlink them to _fuzz.go so compile_native_go_fuzzer can find them.
ln -sf "$SRC/pipelock/internal/scanner/scanner_fuzz_test.go" "$SRC/pipelock/internal/scanner/scanner_fuzz_fuzz.go"
ln -sf "$SRC/pipelock/internal/scanner/response_fuzz_test.go" "$SRC/pipelock/internal/scanner/response_fuzz_fuzz.go"
ln -sf "$SRC/pipelock/internal/audit/sanitize_fuzz_test.go" "$SRC/pipelock/internal/audit/sanitize_fuzz_fuzz.go"
ln -sf "$SRC/pipelock/internal/gitprotect/diffscan_fuzz_test.go" "$SRC/pipelock/internal/gitprotect/diffscan_fuzz_fuzz.go"
ln -sf "$SRC/pipelock/internal/mcp/scan_fuzz_test.go" "$SRC/pipelock/internal/mcp/scan_fuzz_fuzz.go"
ln -sf "$SRC/pipelock/internal/seedprotect/detector_fuzz_test.go" "$SRC/pipelock/internal/seedprotect/detector_fuzz_fuzz.go"

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
