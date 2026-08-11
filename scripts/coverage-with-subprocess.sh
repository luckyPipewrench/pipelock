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
GUARD_UNIT_PROFILE=$(mktemp /tmp/pipelock-guard-unit-XXXXXX.out)
CONFIG_UNIT_PROFILE=$(mktemp /tmp/pipelock-guard-config-unit-XXXXXX.out)
SCANNER_UNIT_PROFILE=$(mktemp /tmp/pipelock-guard-scanner-unit-XXXXXX.out)
PROXY_UNIT_PROFILE=$(mktemp /tmp/pipelock-guard-proxy-unit-XXXXXX.out)

GUARD_LOG=""
cleanup() {
    rm -rf "$COVERDIR" "$RAW_PROFILE" "$UNIT_PROFILE" "$GUARD_UNIT_PROFILE" \
        "$CONFIG_UNIT_PROFILE" "$SCANNER_UNIT_PROFILE" "$PROXY_UNIT_PROFILE"
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

# The pre-exec ruleset operations are injectable. This runs the complete
# create/add/restrict/close sequence at the base ABI without changing the test
# process, so hosted runners cover the path even when their kernel is below the
# in-process thread-sync floor.
run_targeted_coverage() {
    local profile="$1" package="$2" pattern="$3"
    local output
    output=$(go test -count=1 -covermode=set -coverprofile="$profile" "$package" -run "$pattern" 2>&1) || {
        echo "$output"
        return 1
    }
    echo "$output"
    if grep -q 'no tests to run' <<<"$output"; then
        echo "Targeted coverage pattern '$pattern' matched no test in $package."
        return 1
    fi
}

run_targeted_coverage "$GUARD_UNIT_PROFILE" ./internal/guard \
    '^TestApplyForExec_CompleteSequenceUsesBaseABIAndNoThreadSync$'

# The scoped PR gate defers the high-fan-in scanner and proxy race suites to CI.
# Collect the narrow Guard tests here so their changed lines are measured
# alongside the child paths that consume the same exact destination grants.
run_targeted_coverage "$CONFIG_UNIT_PROFILE" ./internal/config \
    '^TestCanonicalPolicyHash_GuardIncludedAndOrderIndependent$'
run_targeted_coverage "$SCANNER_UNIT_PROFILE" ./internal/scanner '^TestGuard'
run_targeted_coverage "$PROXY_UNIT_PROFILE" ./internal/proxy '^TestGuard'

PIPELOCK_SUBPROCESS_COVERAGE=1 GOCOVERDIR="$COVERDIR" \
    go test -count=1 -timeout=5m ./internal/sandbox \
    -run '^Test(Integration_|LaunchStandaloneDeveloperEnvironmentReachesOnlyFinalCommand$|LaunchStandaloneGuardAppliesOnlyToFinalCommand$)'

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
' "$RAW_PROFILE" "$UNIT_PROFILE" "$GUARD_UNIT_PROFILE" "$CONFIG_UNIT_PROFILE" \
    "$SCANNER_UNIT_PROFILE" "$PROXY_UNIT_PROFILE" > "$OUTPUT"

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
guard_apply_covered=$(covered_statements "internal/guard/apply_linux.go")
if [ "$guard_apply_covered" -eq 0 ]; then
    echo "Merged profile is missing guard enforcement execution."
    echo "The injectable pre-exec sequence ran but produced no counters, so collection is broken."
    echo "apply_linux.go covered statements: $guard_apply_covered"
    exit 1
fi
echo ""
echo "=== Merged coverage ==="
go tool cover -func="$OUTPUT" | tail -1
echo "child_init.go covered statements: $child_init_covered"
echo "child_standalone_init.go covered statements: $standalone_init_covered"
echo "guard apply_linux.go covered statements: $guard_apply_covered"
