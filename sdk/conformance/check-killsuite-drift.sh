#!/usr/bin/env bash
# Drift check for the Evidence Theater Kill Suite.
#
# The kill suite is GENERATED in this repo by the Go reference verifier (it needs
# the reference appraiser to produce the golden appraisals), so this repo is the
# source of truth and testdata/aarp-corpus/killsuite is the pinned copy the gate
# runs against. The suite is also PUBLISHED, as a neutral category artifact, in
# the agent-egress-bench repo under receipts/v0/evidence-theater. This script
# compares the two byte-for-byte so they cannot silently diverge.
#
# This is a MANUAL / release-time check, NOT a core CI gate: Pipelock CI runs the
# kill-suite gate against the in-tree pinned copy only and never fetches the
# sibling repo, so an edit in agent-egress-bench can never redden Pipelock CI on
# its own. Run this when publishing or syncing the suite.
#
# Usage:
#   AEB_LOCAL=~/dev/agent-egress-bench sdk/conformance/check-killsuite-drift.sh
#   sdk/conformance/check-killsuite-drift.sh            # clones agent-egress-bench@main
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$ROOT/testdata/aarp-corpus"
PINNED_KS="$CORPUS/killsuite"
AEB_REMOTE="${AEB_REMOTE:-https://github.com/luckyPipewrench/agent-egress-bench.git}"
AEB_REF="${AEB_REF:-main}"
AEB_LOCAL="${AEB_LOCAL:-}"
SUBPATH="receipts/v0/evidence-theater"

cleanup() { [ -n "${TMP:-}" ] && [ -z "$AEB_LOCAL" ] && rm -rf "$TMP"; }
trap cleanup EXIT

if [ -n "$AEB_LOCAL" ]; then
  PUBLISHED="$AEB_LOCAL/$SUBPATH"
else
  TMP="$(mktemp -d)"
  echo "cloning $AEB_REMOTE@$AEB_REF ..."
  if ! git clone --quiet --depth 1 --branch "$AEB_REF" "$AEB_REMOTE" "$TMP" 2>/dev/null; then
    echo "FATAL: could not clone $AEB_REMOTE@$AEB_REF" >&2
    exit 2
  fi
  PUBLISHED="$TMP/$SUBPATH"
fi

if [ ! -d "$PUBLISHED" ]; then
  echo "FATAL: published kill suite not found at $PUBLISHED" >&2
  exit 2
fi

drift=0

# cmp_pair compares one file that must be byte-identical in both copies.
cmp_pair() {
  local label="$1" a="$2" b="$3"
  if [ ! -f "$a" ]; then
    echo "DRIFT: $label missing from pinned copy ($a)"; drift=1; return
  fi
  if [ ! -f "$b" ]; then
    echo "DRIFT: $label present in pinned copy but missing from published copy ($b)"; drift=1; return
  fi
  if ! cmp -s "$a" "$b"; then
    echo "DRIFT: $label differs between pinned and published copy"; drift=1
  fi
}

# Shared trust + key material lives at the aarp-corpus root; the published copy
# carries its own neutral copy alongside the fixtures.
cmp_pair "trust.json" "$CORPUS/trust.json" "$PUBLISHED/trust.json"
cmp_pair "test-keys.json" "$CORPUS/test-keys.json" "$PUBLISHED/test-keys.json"

# Every fixture file (envelope, expect, appraisal, svid sidecar) must match.
# README.md is intentionally NOT compared: each repo frames the suite for its own
# audience, and the framing prose is not part of the security artifact.
while IFS= read -r pf; do
  rel="${pf#"$PINNED_KS"/}"
  [ "$rel" = "README.md" ] && continue
  cmp_pair "killsuite/$rel" "$pf" "$PUBLISHED/killsuite/$rel"
done < <(find "$PINNED_KS" -type f -name '*.json' | sort)

# Symmetric pass: any published fixture file must exist in the pinned copy.
while IFS= read -r ff; do
  rel="${ff#"$PUBLISHED"/killsuite/}"
  if [ ! -f "$PINNED_KS/$rel" ]; then
    echo "DRIFT: killsuite/$rel present in published copy but missing from pinned copy"
    drift=1
  fi
done < <(find "$PUBLISHED/killsuite" -type f -name '*.json' 2>/dev/null | sort)

if [ "$drift" -ne 0 ]; then
  echo "----"
  echo "FAIL: kill suite has drifted between this repo and agent-egress-bench@$AEB_REF" >&2
  echo "Re-publish: regenerate (-update-aarp), then copy killsuite/*.json + trust.json + test-keys.json to $SUBPATH." >&2
  exit 1
fi
echo "PASS: kill suite matches agent-egress-bench@$AEB_REF byte-for-byte"
