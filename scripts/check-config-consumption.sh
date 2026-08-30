#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Tripwire: flag config schema fields that nothing outside internal/config
# consumes. Strict YAML parsing rejects UNKNOWN fields; this guards the other
# direction — a field that parses, validates, and is documented but that no
# runtime code reads is a silent lie to the operator (2026-06: five conductor
# follower knobs shipped validated-but-inert, and the guide claimed behavior).
#
# Heuristic: a field counts as consumed when `.FieldName` or a conventional
# `.FieldNameEnabled()` accessor call appears in any non-test Go file outside
# internal/config/. The accessor form keeps tri-state/default semantics in one
# place without making this gate misclassify a live field as inert. Common field names (Enabled,
# Action, ...) are shared across many structs, so they always count as
# consumed — false negatives are accepted; the tripwire exists to catch
# uniquely-named fields with ZERO references, which is exactly how dead knobs
# look. Deliberately-reserved fields go in config-consumption-allowlist.txt
# with a comment explaining what future slice they reserve.
# Fields decoded once into a runtime-only field go in
# config-consumption-derived-fields.txt. A mapping counts only when the source
# is read inside internal/config and the derived field is consumed outside it.
#
# Fails CLOSED: if the schema or corpus cannot be scanned, error loudly.

cd "$(dirname "$0")/.."

SCHEMA="internal/config/schema.go"
ALLOWLIST="scripts/config-consumption-allowlist.txt"
DERIVED_FIELDS="scripts/config-consumption-derived-fields.txt"

[ -r "$SCHEMA" ] || { echo "ERROR: cannot read $SCHEMA" >&2; exit 2; }

# Corpus: every non-test Go file outside internal/config (enterprise included).
CORPUS="$(mktemp)"
CONFIG_CORPUS="$(mktemp)"
trap 'rm -f "$CORPUS" "$CONFIG_CORPUS"' EXIT
find . -name '*.go' ! -name '*_test.go' ! -path './internal/config/*' \
  ! -path './vendor/*' -exec cat {} + > "$CORPUS"
[ -s "$CORPUS" ] || { echo "ERROR: empty scan corpus" >&2; exit 2; }
find internal/config -name '*.go' ! -name '*_test.go' -exec cat {} + > "$CONFIG_CORPUS"
[ -s "$CONFIG_CORPUS" ] || { echo "ERROR: empty internal/config scan corpus" >&2; exit 2; }

# Field names: tab-indented exported identifiers carrying a yaml tag in schema.go.
FIELDS="$(grep -P '^\t[A-Z][A-Za-z0-9]*\s+\S+.*yaml:"' "$SCHEMA" \
  | grep -oP '^\t[A-Z][A-Za-z0-9]*' | tr -d '\t' | sort -u)"
[ -n "$FIELDS" ] || { echo "ERROR: no schema fields extracted" >&2; exit 2; }

fail=0
while IFS= read -r field; do
  if ! grep -qE "\.${field}\b" "$CORPUS" && ! grep -qE "\.${field}Enabled\(" "$CORPUS"; then
    derived=""
    if [ -f "$DERIVED_FIELDS" ]; then
      derived="$(awk -v source="$field" '$1 == source { print $2; exit }' "$DERIVED_FIELDS")"
    fi
    if [ -n "$derived" ]; then
      if ! grep -qE "\.${field}\b" "$CONFIG_CORPUS"; then
        echo "INVALID derived config mapping: ${field} -> ${derived} (source is not read inside internal/config)"
        fail=1
        continue
      fi
      if ! grep -qE "\.${derived}\b" "$CORPUS"; then
        echo "UNCONSUMED derived config field: ${field} -> ${derived} (no non-test runtime reference outside internal/config)"
        fail=1
        continue
      fi
      continue
    fi
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
