#!/usr/bin/env bash
# Cross-language AARP assurance-envelope conformance gate.
#
# Runs the four reference verifiers (Go, TypeScript, Rust, Python) over every
# fixture in the AARP hostile corpus and FAILS if:
#
#   1. for an "appraise" fixture, the four verifiers do not all emit the SAME
#      comparable appraisal bytes (a cross-language differential — the exact bug
#      class this gate exists to prevent), or any verifier's bytes diverge from
#      the committed <name>.appraisal.json; or
#   2. for a "fatal" fixture, any verifier does not reject (non-zero exit).
#
# The bug class: a claim one verifier inflates that another rejects. Every
# fixture asserts all four verifiers produce the SAME correct, non-inflated
# result.
#
# Each verifier command is the prefix up to and including the `aarp` subcommand;
# the gate appends `<fixture> --trust <trust.json> [--chain] --json`.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="${CORPUS:-$ROOT/testdata/aarp-corpus}"
TRUST="${TRUST:-$CORPUS/trust.json}"

GO_AARP="${GO_AARP:-}"      # e.g. "/path/pipelock-verifier aarp"
TS_AARP="${TS_AARP:-}"      # e.g. "node sdk/verifiers/ts/dist/src/cli.js aarp"
RUST_AARP="${RUST_AARP:-}"  # e.g. "sdk/verifiers/rust/target/release/pipelock-verifier-rs aarp"
PY_AARP="${PY_AARP:-}"      # e.g. "python -m pipelock_aarp_verify"

missing=0
for v in GO_AARP TS_AARP RUST_AARP PY_AARP; do
  if [ -z "${!v}" ]; then
    echo "FATAL: $v is not set (need all four AARP verifier commands)" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 2
[ -f "$TRUST" ] || { echo "FATAL: trust file missing: $TRUST" >&2; exit 2; }

# run_verifier CMD... FIXTURE CHAINFLAG -> sets globals OUT (stdout) and RC (exit)
run_verifier() {
  local fixture="$1"; local chainflag="$2"; shift 2
  if [ "$chainflag" = "chain" ]; then
    OUT="$("$@" "$fixture" --trust "$TRUST" --chain --json 2>/dev/null)"; RC=$?
  else
    OUT="$("$@" "$fixture" --trust "$TRUST" --json 2>/dev/null)"; RC=$?
  fi
}

# field VALUE-of KEY from a flat expect.json (string values only).
expect_field() { grep -o "\"$2\": *\"[^\"]*\"" "$1" | head -1 | sed 's/.*"\([^"]*\)"$/\1/'; }

# Smoke: every verifier must appraise the baseline golden fixture and exit 0.
smoke() {
  local label="$1"; shift
  local smoke_fixture="$CORPUS/golden/g01-single-ed25519-mediated.aarp.json"
  run_verifier "$smoke_fixture" envelope "$@"
  if [ "$RC" -ne 0 ]; then
    echo "FATAL: $label verifier failed smoke fixture (exit $RC); check command wiring" >&2
    exit 2
  fi
}
smoke Go $GO_AARP
smoke TypeScript $TS_AARP
smoke Rust $RUST_AARP
smoke Python $PY_AARP

fails=0
checked=0
printf "%-42s %-9s %-4s %-4s %-4s %-4s %s\n" FIXTURE VERDICT GO TS RUST PY RESULT
for category in golden malicious edge chain; do
  for expfile in "$CORPUS/$category"/*.expect.json; do
    [ -f "$expfile" ] || continue
    base="$(basename "$expfile" .expect.json)"
    verdict="$(expect_field "$expfile" verdict)"
    informat="$(expect_field "$expfile" input_format)"

    chainflag="envelope"
    fixture="$CORPUS/$category/$base.aarp.json"
    if [ "$informat" = "chain" ]; then
      chainflag="chain"
      fixture="$CORPUS/$category/$base.aarp.jsonl"
    fi
    [ -f "$fixture" ] || { echo "FATAL: missing fixture for $base" >&2; exit 2; }

    run_verifier "$fixture" "$chainflag" $GO_AARP;   go_rc=$RC;   go_out="$OUT"
    run_verifier "$fixture" "$chainflag" $TS_AARP;   ts_rc=$RC;   ts_out="$OUT"
    run_verifier "$fixture" "$chainflag" $RUST_AARP; rs_rc=$RC;   rs_out="$OUT"
    run_verifier "$fixture" "$chainflag" $PY_AARP;   py_rc=$RC;   py_out="$OUT"
    checked=$((checked + 1))

    # accept/reject summary per language for the matrix row.
    rc_label() { [ "$1" -eq 0 ] && echo ok || echo rej; }
    result="ok"

    if [ "$verdict" = "fatal" ]; then
      # Every verifier must reject (non-zero exit). No body comparison.
      if [ "$go_rc" -eq 0 ] || [ "$ts_rc" -eq 0 ] || [ "$rs_rc" -eq 0 ] || [ "$py_rc" -eq 0 ]; then
        result="FATAL-NOT-REJECTED"; fails=$((fails + 1))
      fi
    else
      # appraise: all four exit 0, identical bytes, equal to committed appraisal.
      want="$(cat "$CORPUS/$category/$base.appraisal.json")"
      if [ "$go_rc" -ne 0 ] || [ "$ts_rc" -ne 0 ] || [ "$rs_rc" -ne 0 ] || [ "$py_rc" -ne 0 ]; then
        result="APPRAISE-REJECTED"; fails=$((fails + 1))
      elif [ "$go_out" != "$ts_out" ] || [ "$go_out" != "$rs_out" ] || [ "$go_out" != "$py_out" ]; then
        result="DIFFERENTIAL"; fails=$((fails + 1))
      elif [ "$(printf '%s' "$go_out")" != "$(printf '%s' "$want")" ]; then
        result="EXPECT-MISMATCH"; fails=$((fails + 1))
      fi
    fi
    printf "%-42s %-9s %-4s %-4s %-4s %-4s %s\n" "$base" "$verdict" \
      "$(rc_label "$go_rc")" "$(rc_label "$ts_rc")" "$(rc_label "$rs_rc")" "$(rc_label "$py_rc")" "$result"
  done
done

echo "----"
echo "checked $checked AARP fixtures; $fails failure(s)"
if [ "$checked" -eq 0 ]; then
  echo "FATAL: no fixtures checked; corpus path wrong?" >&2
  exit 2
fi
[ "$fails" -eq 0 ] || exit 1
echo "PASS: all four verifiers agree across the AARP corpus (no inflation, no differential)"
