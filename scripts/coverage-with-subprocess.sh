#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# coverage-with-subprocess.sh — Builds an instrumented Pipelock binary and
# collects coverage from its parent and sandbox child processes via GOCOVERDIR.
#
# Usage: bash scripts/coverage-with-subprocess.sh [output-profile]
# Default output: coverage-subprocess.out

set -euo pipefail

OUTPUT="${1:-coverage-subprocess.out}"
COVERDIR=$(mktemp -d /tmp/pipelock-covdata-XXXXXX)
RAW_PROFILE=$(mktemp /tmp/pipelock-subprocess-raw-XXXXXX.out)
UNIT_PROFILE=$(mktemp /tmp/pipelock-subprocess-unit-XXXXXX.out)

cleanup() {
    rm -rf "$COVERDIR" "$RAW_PROFILE" "$UNIT_PROFILE"
}
trap cleanup EXIT

echo "=== Coverage with subprocess merging ==="
echo "GOCOVERDIR: $COVERDIR"
echo ""

go test -count=1 -covermode=set -coverprofile="$UNIT_PROFILE" \
    -tags subprocess_coverage ./internal/sandbox \
    -run '^Test(Prepare|Validated)SubprocessCoverage'

PIPELOCK_SUBPROCESS_COVERAGE=1 GOCOVERDIR="$COVERDIR" \
    go test -count=1 -timeout=5m ./internal/sandbox -run '^TestIntegration_'

# Guard's enforcement can only be observed from a process that has actually been
# restricted, and Landlock is irreversible, so those assertions run in a
# re-executed child. The child ends with os.Exit, which skips the coverage
# writer, so the subprocess_coverage build tag compiles in an explicit flush and
# GOCOVERDIR tells it where to write. Without this the enforcement path measures
# around half covered while being the most thoroughly exercised code in the
# package, which is a false signal in the dangerous direction: it invites
# someone to "fix" it with weaker in-process tests.
#
# -cover is required, not optional: the child inherits coverage instrumentation
# from the test binary, and runtime/coverage has nothing to write from a binary
# that was not built with it. Omitting it produces a run that passes, writes no
# counters, and reports zero coverage for the code it just exercised.
PIPELOCK_GUARD_COVERDIR="$COVERDIR" \
    go test -count=1 -timeout=5m -cover -covermode=atomic \
    ./internal/guard \
    -run '^TestEnforcement_(RealBoundary/(granted-write|ungranted-read|socket-connect|other-thread)|DetectsPolicyNarrowedByOuterDomain)$'

# Merge all coverage data into a single profile.
counter_count=$(find "$COVERDIR" -maxdepth 1 -type f -name 'covcounters.*' | wc -l)
echo "subprocess counter files: $counter_count"
if [ "$counter_count" -lt 2 ]; then
    echo "No subprocess coverage data collected."
    echo "Expected counters from at least two Pipelock processes; found $counter_count."
    exit 1
fi

go tool covdata textfmt -i="$COVERDIR" -o="$RAW_PROFILE"
awk '
    FNR == 1 { next }
    {
        key = $1 " " $2
        if (!(key in count) || $3 > count[key]) {
            count[key] = $3
        }
    }
    END {
        print "mode: set"
        for (key in count) {
            print key, count[key]
        }
    }
' "$RAW_PROFILE" "$UNIT_PROFILE" > "$OUTPUT"

covered_statements() {
    local source_file="$1"
    awk -v source_file="$source_file" '
        index($1, source_file ":") > 0 && $3 > 0 { covered += $2 }
        END { print covered + 0 }
    ' "$OUTPUT"
}

child_init_covered=$(covered_statements "internal/sandbox/child_init.go")
standalone_init_covered=$(covered_statements "internal/sandbox/child_standalone_init.go")
if [ "$child_init_covered" -eq 0 ] || [ "$standalone_init_covered" -eq 0 ]; then
    echo "Merged profile is missing sandbox child execution."
    echo "child_init.go covered statements: $child_init_covered"
    echo "child_standalone_init.go covered statements: $standalone_init_covered"
    exit 1
fi

# The same assertion for Guard. This is the check that keeps the mechanism
# honest: if the flush silently stops working, the merged profile still parses
# and the script still exits zero, so only naming the file that MUST appear
# turns a broken collection into a failure instead of a quiet coverage drop.
guard_apply_covered=$(covered_statements "internal/guard/apply_linux.go")
if [ "$guard_apply_covered" -eq 0 ]; then
    echo "Merged profile is missing guard enforcement execution."
    echo "apply_linux.go covered statements: $guard_apply_covered"
    exit 1
fi

echo ""
echo "=== Merged coverage ==="
go tool cover -func="$OUTPUT" | tail -1
echo "child_init.go covered statements: $child_init_covered"
echo "child_standalone_init.go covered statements: $standalone_init_covered"
echo "guard apply_linux.go covered statements: $guard_apply_covered"
