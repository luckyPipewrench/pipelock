#!/usr/bin/env bash
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
# Chain (.jsonl) fixtures are intentionally NOT run here: the corpus encodes
# chains as bare receipts, while the receipt readers expect flight-recorder
# entries, and several malicious chain fixtures test chain-level policy
# (replay, verdict-chain consistency) that the reference verifiers do not yet
# implement. Chain parity is tracked separately.
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

# Policy fixtures: all four verifiers UNANIMOUSLY accept these because none yet
# implement the verifier-policy check they exercise. They are not a
# differential. Keep this list in sync with sdk/conformance/corpus_test.go.
POLICY_FIXTURES=" m03-expired-timestamp m12-header-injection-null-byte "

if [ -z "$KEY" ]; then
  KEY="$(grep -o '"public_key_hex": *"[0-9a-f]*"' "$CORPUS/test-key.json" | sed 's/.*"\([0-9a-f]*\)"$/\1/')"
fi
if [ -z "$KEY" ]; then
  echo "FATAL: could not resolve corpus public key" >&2
  exit 2
fi

missing=0
for v in GO_VERIFY TS_VERIFY RUST_VERIFY PY_VERIFY; do
  if [ -z "${!v}" ]; then
    echo "FATAL: $v is not set (need all four verifier commands)" >&2
    missing=1
  fi
done
[ "$missing" -eq 0 ] || exit 2

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
