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

GUARD_LOG=""
cleanup() {
    rm -rf "$COVERDIR" "$RAW_PROFILE" "$UNIT_PROFILE"
    [ -n "$GUARD_LOG" ] && rm -f "$GUARD_LOG"
    return 0
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
# re-executed child. The child now runs as an ordinary test, which lets the
# testing framework write its own counters on normal exit. The go tool does not
# pass GOCOVERDIR through to a re-executed test binary, so the parent translates
# this dedicated variable into -test.gocoverdir for the child. Without that
# hand-off the enforcement path measures as uncovered while being the most
# thoroughly exercised code in this package, inviting weaker in-process tests
# solely to satisfy coverage.
#
# Run every enforcement scenario once without subprocess coverage first. The
# empty and zero-manifest cases must grant nothing, so giving them the coverage
# directory would change the policy they prove. Running the parent test keeps
# those cases honest and automatically includes any future boundary scenario.
go test -count=1 -timeout=5m ./internal/guard -run '^TestEnforcement_RealBoundary$'

# -cover is required, not optional: the child inherits coverage instrumentation
# from the test binary, and runtime/coverage has nothing to write from a binary
# that was not built with it. Omitting it produces a run that passes, writes no
# counters, and reports zero coverage for the code it just exercised.
# TWO invocations, and the split is required rather than cosmetic.
#
# `go test -run` splits its pattern on `/` into one regex per test-name level,
# but testing.splitRegexp deliberately ignores a `/` inside parentheses. A single
# combined pattern with the subtests in an alternation therefore never splits,
# so it is matched whole against the top-level name and selects NONE of the
# boundary subtests. They silently did not run, and the collected coverage came
# only from the narrowed-policy tests, which was not visible because those tests
# exercise the same file.
GUARD_LOG=$(mktemp /tmp/pipelock-guard-cover-XXXXXX.log)
PIPELOCK_GUARD_COVERDIR="$COVERDIR" \
    go test -count=1 -timeout=5m -cover -covermode=atomic -v \
    ./internal/guard \
    -run '^TestEnforcement_RealBoundary$/^(granted-write|ungranted-read|socket-connect|other-thread)$' \
    | tee "$GUARD_LOG"

PIPELOCK_GUARD_COVERDIR="$COVERDIR" \
    go test -count=1 -timeout=5m -cover -covermode=atomic -v \
    ./internal/guard \
    -run '^TestEnforcement_Detects(Policy|WritePolicy|DirectoryWrite)NarrowedByOuterDomain$' \
    | tee -a "$GUARD_LOG"

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

# The same assertion for Guard. This is the check that keeps the hand-off
# honest: if child collection silently stops working, the merged profile still
# parses and the script still exits zero, so only naming the file that MUST
# appear turns a broken collection into a failure instead of a quiet drop.
# Guard's enforcement tests need a kernel above the in-process Landlock floor
# and skip below it. A host that skipped them has collected nothing to assert
# on, and failing there would red the job for a kernel version rather than for a
# defect. The distinction is made from the test log, not from the coverage
# number, because "skipped" and "ran but collected nothing" both produce zero
# and only the second is a broken mechanism.
guard_apply_covered=$(covered_statements "internal/guard/apply_linux.go")
if grep -q -- '--- SKIP: TestEnforcement_' "$GUARD_LOG"; then
    echo "Guard enforcement tests SKIPPED on this host (landlock ABI below the in-process floor)."
    echo "Guard subprocess coverage was not collected; skipping the guard assertion."
    echo "apply_linux.go covered statements: $guard_apply_covered"
elif [ "$guard_apply_covered" -eq 0 ]; then
    echo "Merged profile is missing guard enforcement execution."
    echo "The enforcement tests ran but produced no counters, so collection is broken."
    echo "apply_linux.go covered statements: $guard_apply_covered"
    exit 1
fi
echo ""
echo "=== Merged coverage ==="
go tool cover -func="$OUTPUT" | tail -1
echo "child_init.go covered statements: $child_init_covered"
echo "child_standalone_init.go covered statements: $standalone_init_covered"
echo "guard apply_linux.go covered statements: $guard_apply_covered"
