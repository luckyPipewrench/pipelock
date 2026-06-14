#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0
#
# Containment direct-egress conformance gate.
#
# Packages pipelock's `contain verify` direct-egress probes (probe 8:
# pipelock-agent must NOT reach the internet directly; probe 9: the operator
# must still reach the internet) as a publishable conformance artifact and
# proves the egress-denied test is REAL.
#
# It does three things, all offline (no real network, sudo, curl, or nft):
#
#   1. Runs the Go conformance test over every fixture pair under
#      testdata/containment/ (clean baseline + the must-fail leaky fixture).
#   2. Asserts the MUST-FAIL property directly: it makes a temp copy of the
#      corpus where leaky-egress.expect.json is rewritten to expect a PASS, and
#      confirms the conformance test then FAILS. If a leaked agent egress could
#      ever be marked pass, the gate itself is worthless — so the gate fails if
#      that mutation does NOT trip the test.
#   3. Confirms the clean baseline fixture is present and asserted.
#
# Exit codes:
#   0  the gate held: clean fixture passes, leaky fixture is detected-as-fail,
#      and the must-fail mutation correctly trips the test.
#   1  a conformance failure: a fixture diverged from its .expect.json, or the
#      must-fail mutation did NOT trip the test (the gate is not real).
#   2  fatal config: fixtures or the Go toolchain are missing/unusable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
FIXTURE_DIR="$ROOT/testdata/containment"
TEST_PKG="./sdk/conformance/"
TEST_RUN="TestContainmentConformance"

fatal() {
  echo "FATAL: $*" >&2
  exit 2
}

command -v go >/dev/null 2>&1 || fatal "go toolchain not found on PATH"
[ -d "$FIXTURE_DIR" ] || fatal "fixture directory missing: $FIXTURE_DIR"

LEAKY_PROBE="$FIXTURE_DIR/leaky-egress.probe.json"
LEAKY_EXPECT="$FIXTURE_DIR/leaky-egress.expect.json"
CLEAN_PROBE="$FIXTURE_DIR/pass-all.probe.json"
CLEAN_EXPECT="$FIXTURE_DIR/pass-all.expect.json"
for f in "$LEAKY_PROBE" "$LEAKY_EXPECT" "$CLEAN_PROBE" "$CLEAN_EXPECT"; do
  [ -f "$f" ] || fatal "required fixture missing: $f"
done

echo "==> [1/2] Running containment conformance test over the real corpus"
if ! ( cd "$REPO_ROOT" && go test -race -count=1 -run "$TEST_RUN" "$TEST_PKG" ); then
  echo "FAIL: containment conformance test failed against the real corpus" >&2
  exit 1
fi
echo "    clean baseline passes; leaky-egress is detected-as-fail (as expected)"

echo "==> [2/2] Proving the must-fail property: a leaked egress marked 'pass' MUST trip the gate"
# The conformance test reads testdata/containment relative to its package dir,
# so we temporarily swap leaky-egress.expect.json in place to wrongly expect a
# PASS, re-run the corpus-walking test, and confirm it FAILS. The original is
# always restored via the EXIT trap, even on interrupt. A clean test exit
# against the mutated corpus means a leaked egress could be marked pass -> the
# gate is not real -> we fail loud.
BACKUP="$(mktemp)"
MUT_OUT="$(mktemp)"
RESTORED=0
restore_expect() {
  # Only restore from a NON-EMPTY backup. mktemp creates an empty file; if the
  # backup cp below never succeeded, $BACKUP is still empty and restoring from it
  # would clobber the real fixture with nothing. An empty backup also means the
  # in-place mutation never happened (we fatal before mutating), so the fixture
  # on disk is already the untouched original — skipping restore is correct.
  if [ "$RESTORED" -eq 0 ]; then
    if [ -s "$BACKUP" ]; then
      cp "$BACKUP" "$LEAKY_EXPECT" 2>/dev/null || true
    fi
    rm -f "$BACKUP" 2>/dev/null || true
    rm -f "$MUT_OUT" 2>/dev/null || true
    RESTORED=1
  fi
}
trap restore_expect EXIT INT TERM

cp "$LEAKY_EXPECT" "$BACKUP" || fatal "could not back up $LEAKY_EXPECT"

cat > "$LEAKY_EXPECT" <<'JSON'
{
  "description": "MUTATED by containment-gate.sh: wrongly expects the leaked egress to pass. The conformance test MUST fail against this. This file is restored automatically.",
  "exit_code": 0,
  "probes": [
    { "probe": 8, "name": "cc_agent_egress_denied", "status": "pass" },
    { "probe": 9, "name": "operator_egress_reachable", "status": "pass" }
  ]
}
JSON

# Run only the corpus-walking test (the one that reads .expect.json) against the
# mutated corpus. The regex is anchored so it does NOT also pull in the dedicated
# TestContainmentConformance_* helpers (which assert the must-fail property
# independently of .expect.json); this mutation step must isolate the corpus
# walker's expect-comparison logic. Restore immediately after, regardless of outcome.
set +e
( cd "$REPO_ROOT" && go test -race -count=1 -run '^TestContainmentConformance$' "$TEST_PKG" >"$MUT_OUT" 2>&1 )
MUT_RC=$?
set -e

if [ "$MUT_RC" -eq 0 ]; then
  restore_expect
  echo "FAIL: mutating leaky-egress to expect 'pass' did NOT trip the conformance test." >&2
  echo "      The must-fail property is broken — the egress-denied gate is not real." >&2
  exit 1
fi

if ! grep -Eq 'leaky-egress: (exit code = 1, want 0|probe 8 status = "fail", want "pass")' "$MUT_OUT"; then
  echo "FAIL: mutated conformance test failed, but not for the expected leaky-egress mismatch." >&2
  echo "      Refusing to treat an unrelated compile/tooling failure as proof of the must-fail property." >&2
  echo "---- mutated test output ----" >&2
  cat "$MUT_OUT" >&2
  restore_expect
  exit 1
fi

restore_expect
echo "    mutation correctly tripped the test: the must-fail property holds"

echo "----"
echo "PASS: containment direct-egress conformance gate held"
