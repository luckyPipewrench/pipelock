#!/usr/bin/env bash
# coverage-with-subprocess.sh — Collects coverage from both the test process
# and any child processes (sandbox init, standalone init, etc.) using GOCOVERDIR.
#
# Usage: bash scripts/coverage-with-subprocess.sh [package-pattern]
# Default pattern: ./internal/sandbox/...
#
# Requires Go 1.20+ for GOCOVERDIR support.

set -euo pipefail

PKG="${1:-./internal/sandbox/...}"
COVERDIR=$(mktemp -d /tmp/pipelock-covdata-XXXXXX)
MERGED_DIR=$(mktemp -d /tmp/pipelock-covmerge-XXXXXX)

cleanup() {
    rm -rf "$COVERDIR" "$MERGED_DIR"
}
trap cleanup EXIT

echo "=== Coverage with subprocess merging ==="
echo "Package: $PKG"
echo "GOCOVERDIR: $COVERDIR"
echo ""

# Run tests with GOCOVERDIR set. The test binary and any re-exec'd children
# will write raw coverage data to this directory.
GOCOVERDIR="$COVERDIR" go test -race -count=1 -cover "$PKG" 2>&1 | tail -5

echo ""
echo "=== Raw coverage files ==="
ls -la "$COVERDIR"/ 2>/dev/null | head -20

# Merge all coverage data into a single profile.
if [ "$(ls -A "$COVERDIR" 2>/dev/null)" ]; then
    go tool covdata textfmt -i="$COVERDIR" -o="$MERGED_DIR/merged.out"
    echo ""
    echo "=== Merged coverage ==="
    go tool cover -func="$MERGED_DIR/merged.out" | tail -1

    echo ""
    echo "=== Uncovered functions ==="
    go tool cover -func="$MERGED_DIR/merged.out" | grep -v "100.0%" | sort -t'%' -k3 -n | head -20 || echo "(all functions at 100%)"
else
    echo "No subprocess coverage data collected."
    echo "This may mean the test binary was not built with -cover,"
    echo "or child processes did not write to GOCOVERDIR."
fi
