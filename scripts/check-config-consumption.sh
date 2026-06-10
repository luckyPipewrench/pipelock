#!/usr/bin/env bash
set -euo pipefail

# Tripwire: flag config schema fields that nothing outside internal/config
# consumes. Strict YAML parsing rejects UNKNOWN fields; this guards the other
# direction — a field that parses, validates, and is documented but that no
# runtime code reads is a silent lie to the operator (2026-06: five conductor
# follower knobs shipped validated-but-inert, and the guide claimed behavior).
#
# Heuristic: a field counts as consumed when `.FieldName` appears in any
# non-test Go file outside internal/config/. Common field names (Enabled,
# Action, ...) are shared across many structs, so they always count as
# consumed — false negatives are accepted; the tripwire exists to catch
# uniquely-named fields with ZERO references, which is exactly how dead knobs
# look. Deliberately-reserved fields go in config-consumption-allowlist.txt
# with a comment explaining what future slice they reserve.
#
# Fails CLOSED: if the schema or corpus cannot be scanned, error loudly.

cd "$(dirname "$0")/.."

SCHEMA="internal/config/schema.go"
ALLOWLIST="scripts/config-consumption-allowlist.txt"

[ -r "$SCHEMA" ] || { echo "ERROR: cannot read $SCHEMA" >&2; exit 2; }

# Corpus: every non-test Go file outside internal/config (enterprise included).
CORPUS="$(mktemp)"
trap 'rm -f "$CORPUS"' EXIT
find . -name '*.go' ! -name '*_test.go' ! -path './internal/config/*' \
  ! -path './vendor/*' -exec cat {} + > "$CORPUS"
[ -s "$CORPUS" ] || { echo "ERROR: empty scan corpus" >&2; exit 2; }

# Field names: tab-indented exported identifiers carrying a yaml tag in schema.go.
FIELDS="$(grep -P '^\t[A-Z][A-Za-z0-9]*\s+\S+.*yaml:"' "$SCHEMA" \
  | grep -oP '^\t[A-Z][A-Za-z0-9]*' | tr -d '\t' | sort -u)"
[ -n "$FIELDS" ] || { echo "ERROR: no schema fields extracted" >&2; exit 2; }

fail=0
while IFS= read -r field; do
  if ! grep -qE "\.${field}\b" "$CORPUS"; then
    if [ -f "$ALLOWLIST" ] && grep -qE "^${field}([[:space:]]|$)" "$ALLOWLIST"; then
      continue
    fi
    echo "UNCONSUMED config field: ${field} (no non-test reference outside internal/config; wire it, remove it, or allowlist it as documented-reserved)"
    fail=1
  fi
done <<< "$FIELDS"

if [ "$fail" -eq 0 ]; then
  echo "config-consumption: OK (every schema field consumed or documented-reserved)"
fi
exit "$fail"
