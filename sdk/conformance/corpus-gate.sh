#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Cross-language receipt-verifier conformance gate.
#
# Runs the four reference verifiers (Go, TypeScript, Rust, Python) over every
# single-receipt fixture in the vendored conformance corpus and FAILS if:
#
#   1. the four verifiers disagree with each other on accept/reject (a
#      cross-language differential — the exact bug class this gate exists to
#      prevent), or
#   2. the unanimous verdict disagrees with the fixture's .expect.json, except
#      for the documented policy fixtures the reference verifiers do not yet
#      implement (max_age expiry, control-byte/header-injection rejection).
#
# The receipt-v1 lane remains single-receipt compatibility coverage. The
# provenance lane below includes signed multi-entry chains in its fixture
# envelope, compares the exact staged JSON, and checks committed expectations.
#
# The verifier invocations are parameterized so this runs locally and in CI.
# Each must accept `<command...> <fixture-path> --key <hex>` and exit 0 for
# accept, non-zero for reject.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="${CORPUS:-$ROOT/testdata/corpus}"
KEY="${KEY:-}"

GO_VERIFY="${GO_VERIFY:-}"      # e.g. "pipelock verify-receipt"
TS_VERIFY="${TS_VERIFY:-}"      # e.g. "node sdk/verifiers/ts/dist/src/cli.js receipt"
RUST_VERIFY="${RUST_VERIFY:-}"  # e.g. "sdk/verifiers/rust/target/release/pipelock-verifier-rs receipt"
PY_VERIFY="${PY_VERIFY:-}"      # e.g. "python -m pipelock_verify"

PROVENANCE_CORPUS="${PROVENANCE_CORPUS:-$ROOT/testdata/provenance}"
GO_PROVENANCE="${GO_PROVENANCE:-}"
TS_PROVENANCE="${TS_PROVENANCE:-}"
RUST_PROVENANCE="${RUST_PROVENANCE:-}"
PY_PROVENANCE="${PY_PROVENANCE:-}"

# Policy fixtures: all four verifiers UNANIMOUSLY accept these because none yet
# implement the verifier-policy check they exercise. They are not a
# differential. Keep this list in sync with sdk/conformance/corpus_test.go.
POLICY_FIXTURES=" m03-expired-timestamp m12-header-injection-null-byte "

if [ "${PROVENANCE_ONLY:-0}" != "1" ] && [ -z "$KEY" ]; then
  KEY="$(grep -o '"public_key_hex": *"[0-9a-f]*"' "$CORPUS/test-key.json" | sed 's/.*"\([0-9a-f]*\)"$/\1/')"
fi
if [ "${PROVENANCE_ONLY:-0}" != "1" ] && [ -z "$KEY" ]; then
  echo "FATAL: could not resolve corpus public key" >&2
  exit 2
fi

if [ "${PROVENANCE_ONLY:-0}" != "1" ]; then
  missing=0
  for v in GO_VERIFY TS_VERIFY RUST_VERIFY PY_VERIFY; do
    if [ -z "${!v}" ]; then
      echo "FATAL: $v is not set (need all four verifier commands)" >&2
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 2
fi

verdict() { # cmd... path -> prints accept/reject
  local path="$1"; shift
  if "$@" "$path" --key "$KEY" >/dev/null 2>&1; then echo accept; else echo reject; fi
}

smoke_verifier() { # label cmd...
  local label="$1"; shift
  local smoke="$CORPUS/golden/01-allow-clean-get.json"
  if [ ! -f "$smoke" ]; then
    echo "FATAL: smoke fixture missing: $smoke" >&2
    exit 2
  fi
  if ! "$@" "$smoke" --key "$KEY" >/dev/null 2>&1; then
    echo "FATAL: $label verifier failed smoke fixture $smoke; check command wiring" >&2
    exit 2
  fi
}

expect_verdict() { # expect-file -> accept/reject
  grep -o '"verdict": *"[a-z]*"' "$1" | head -1 | sed 's/.*"\([a-z]*\)"$/\1/'
}

if [ "${PROVENANCE_ONLY:-0}" != "1" ]; then
smoke_verifier Go $GO_VERIFY
smoke_verifier TypeScript $TS_VERIFY
smoke_verifier Rust $RUST_VERIFY
smoke_verifier Python $PY_VERIFY

fails=0
checked=0
printf "%-38s %-7s %-6s %-6s %-6s %-6s %s\n" FIXTURE EXPECT GO TS RUST PY RESULT
for category in golden malicious edge; do
  for f in "$CORPUS/$category"/*.json; do
    [ -f "$f" ] || continue
    case "$f" in *.expect.json) continue ;; esac
    base="$(basename "$f" .json)"
    expfile="$CORPUS/$category/$base.expect.json"
    [ -f "$expfile" ] || { echo "FATAL: missing expect for $base" >&2; exit 2; }
    exp="$(expect_verdict "$expfile")"

    go="$(verdict "$f" $GO_VERIFY)"
    ts="$(verdict "$f" $TS_VERIFY)"
    rs="$(verdict "$f" $RUST_VERIFY)"
    py="$(verdict "$f" $PY_VERIFY)"
    checked=$((checked + 1))

    result="ok"
    # 1. Cross-language agreement.
    if [ "$go" != "$ts" ] || [ "$go" != "$rs" ] || [ "$go" != "$py" ]; then
      result="DIFFERENTIAL"
      fails=$((fails + 1))
    elif [[ "$POLICY_FIXTURES" == *" $base "* ]]; then
      # Policy fixture: must be unanimous accept (the current known gap).
      if [ "$go" != "accept" ]; then
        result="POLICY-CHANGED"
        fails=$((fails + 1))
      else
        result="policy-skip"
      fi
    elif [ "$go" != "$exp" ]; then
      result="EXPECT-MISMATCH"
      fails=$((fails + 1))
    fi
    printf "%-38s %-7s %-6s %-6s %-6s %-6s %s\n" "$base" "$exp" "$go" "$ts" "$rs" "$py" "$result"
  done
done

echo "----"
echo "checked $checked single-receipt fixtures; $fails failure(s)"
if [ "$checked" -eq 0 ]; then
  echo "FATAL: no fixtures checked; corpus path wrong?" >&2
  exit 2
fi
[ "$fails" -eq 0 ] || exit 1
echo "PASS: all four verifiers agree across the corpus"
fi

for v in GO_PROVENANCE TS_PROVENANCE RUST_PROVENANCE PY_PROVENANCE; do
  if [ -z "${!v}" ]; then
    echo "FATAL: $v is not set (need all four provenance verifier commands)" >&2
    exit 2
  fi
done

read -r -a go_provenance_cmd <<< "$GO_PROVENANCE"
read -r -a ts_provenance_cmd <<< "$TS_PROVENANCE"
read -r -a rust_provenance_cmd <<< "$RUST_PROVENANCE"
read -r -a py_provenance_cmd <<< "$PY_PROVENANCE"

provenance_output() { # path cmd... -> stdout, preserving invalid-stage JSON
  local path="$1"; shift
  local output error_file
  error_file="$(mktemp)" || { echo "FATAL: could not create verifier stderr file" >&2; return 2; }
  output="$("$@" "$path" 2>"$error_file")"
  local status=$?
  if [ "$status" -gt 1 ]; then
    echo "FATAL: provenance verifier command failed with status $status for $path" >&2
    cat "$error_file" >&2
    rm -f "$error_file"
    return 2
  fi
  rm -f "$error_file"
  printf '%s' "$output"
}

provenance_fails=0
provenance_checked=0
printf "\n%-44s %-12s %-12s %-12s %-12s %s\n" PROVENANCE GO TS RUST PY RESULT
for f in "$PROVENANCE_CORPUS"/*.json; do
  [ -f "$f" ] || continue
  case "$f" in *.expect.json) continue ;; esac
  base="$(basename "$f" .json)"
  expfile="$PROVENANCE_CORPUS/$base.expect.json"
  [ -f "$expfile" ] || { echo "FATAL: missing provenance expectation for $base" >&2; exit 2; }
  expected="$(<"$expfile")"

  go="$(provenance_output "$f" "${go_provenance_cmd[@]}")" || exit 2
  ts="$(provenance_output "$f" "${ts_provenance_cmd[@]}")" || exit 2
  rs="$(provenance_output "$f" "${rust_provenance_cmd[@]}")" || exit 2
  py="$(provenance_output "$f" "${py_provenance_cmd[@]}")" || exit 2
  provenance_checked=$((provenance_checked + 1))

  result="ok"
  if [ "$go" != "$ts" ] || [ "$go" != "$rs" ] || [ "$go" != "$py" ]; then
    result="STAGE-DIFFERENTIAL"
    provenance_fails=$((provenance_fails + 1))
  elif [ "$go" != "$expected" ]; then
    # This is the agreement-only-vacuity guard: four implementations making
    # the same mistake still fail the frozen normative known answer.
    result="KNOWN-ANSWER-MISMATCH"
    provenance_fails=$((provenance_fails + 1))
  fi
  printf "%-44s %-12s %-12s %-12s %-12s %s\n" "$base" "$(printf '%s' "$go" | sed -n 's/.*\"overall\":\"\([^\"]*\)\".*/\1/p')" "$(printf '%s' "$ts" | sed -n 's/.*\"overall\":\"\([^\"]*\)\".*/\1/p')" "$(printf '%s' "$rs" | sed -n 's/.*\"overall\":\"\([^\"]*\)\".*/\1/p')" "$(printf '%s' "$py" | sed -n 's/.*\"overall\":\"\([^\"]*\)\".*/\1/p')" "$result"
done

for expfile in "$PROVENANCE_CORPUS"/*.expect.json; do
  [ -f "$expfile" ] || continue
  fixture="${expfile%.expect.json}.json"
  [ -f "$fixture" ] || { echo "FATAL: orphan provenance expectation $(basename "$expfile")" >&2; exit 2; }
done

echo "----"
echo "checked $provenance_checked provenance fixtures (including signed chains); $provenance_fails failure(s)"
if [ "$provenance_checked" -eq 0 ]; then
  echo "FATAL: no provenance fixtures checked; corpus path wrong?" >&2
  exit 2
fi
[ "$provenance_fails" -eq 0 ] || exit 1
echo "PASS: all four verifiers emit byte-identical staged provenance results and match normative vectors"
