#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Drift guard for the vendored conformance corpus.
#
# The corpus under testdata/corpus is a VENDORED copy of the master maintained
# in the agent-egress-bench repository (receipts/v0/conformance). Vendoring
# keeps pipelock CI self-contained (no cross-repo checkout to run the gate), but
# a vendored copy can silently drift from the master — which is the exact bug
# class this whole effort fixes. This script fetches the agent-egress-bench
# master and fails if any vendored fixture (or the pinned test key) differs
# byte-for-byte.
#
# Merge ordering: the agent-egress-bench corpus change must land on its default
# branch BEFORE this guard passes on pipelock, because it compares against that
# branch. Point AEB_REF at an integration branch during a coordinated rollout.
#
# Env:
#   AEB_REMOTE  git remote for agent-egress-bench
#               (default: https://github.com/luckyPipewrench/agent-egress-bench.git)
#   AEB_REF     branch/tag/sha to compare against (default: main)
#   AEB_LOCAL   path to an existing local checkout; if set, skips cloning
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDORED="$ROOT/testdata/corpus"
AEB_REMOTE="${AEB_REMOTE:-https://github.com/luckyPipewrench/agent-egress-bench.git}"
AEB_REF="${AEB_REF:-main}"
AEB_LOCAL="${AEB_LOCAL:-}"
SUBPATH="receipts/v0/conformance"

cleanup() { [ -n "${TMP:-}" ] && [ -z "$AEB_LOCAL" ] && rm -rf "$TMP"; }
trap cleanup EXIT

if [ -n "$AEB_LOCAL" ]; then
  MASTER="$AEB_LOCAL/$SUBPATH"
else
  TMP="$(mktemp -d)"
  echo "cloning $AEB_REMOTE@$AEB_REF ..."
  if ! git clone --quiet --depth 1 --branch "$AEB_REF" "$AEB_REMOTE" "$TMP" 2>/dev/null; then
    echo "FATAL: could not clone $AEB_REMOTE@$AEB_REF" >&2
    exit 2
  fi
  MASTER="$TMP/$SUBPATH"
fi

if [ ! -d "$MASTER" ]; then
  echo "FATAL: master corpus not found at $MASTER" >&2
  exit 2
fi

drift=0

vendored_to_master() {
  case "$1" in
    test-key.json) echo "_generator/test-key.json" ;;
    CORPUS-README.md) echo "README.md" ;;
    *) echo "$1" ;;
  esac
}

master_to_vendored() {
  case "$1" in
    _generator/test-key.json) echo "test-key.json" ;;
    _generator/*) echo "" ;;
    README.md) echo "CORPUS-README.md" ;;
    *) echo "$1" ;;
  esac
}

# Compare every vendored corpus file, including top-level documentation and
# keys. _generator/main.go and _generator/go.mod stay only in the master repo;
# the vendored copy includes just the deterministic test key material.
while IFS= read -r vf; do
  rel="${vf#"$VENDORED"/}"
  master_rel="$(vendored_to_master "$rel")"
  mf="$MASTER/$master_rel"
  if [ ! -f "$mf" ]; then
    echo "DRIFT: $rel present in vendored copy but not in agent-egress-bench master"
    drift=1
  elif ! cmp -s "$vf" "$mf"; then
    echo "DRIFT: $rel differs from agent-egress-bench master $master_rel"
    drift=1
  fi
done < <(find "$VENDORED" -type f | sort)

# Symmetric pass: any source corpus file that should be vendored must exist in
# the copy here. Generator source files are intentionally not vendored.
while IFS= read -r mf; do
  rel="${mf#"$MASTER"/}"
  vendored_rel="$(master_to_vendored "$rel")"
  [ -n "$vendored_rel" ] || continue
  if [ ! -f "$VENDORED/$vendored_rel" ]; then
    echo "DRIFT: $rel present in agent-egress-bench master but missing from vendored copy"
    drift=1
  fi
done < <(find "$MASTER" -type f | sort)

if [ "$drift" -ne 0 ]; then
  echo "----"
  echo "FAIL: vendored corpus has drifted from agent-egress-bench@$AEB_REF" >&2
  echo "Re-vendor from $SUBPATH (golden/ malicious/ edge/ + _generator/test-key.json)." >&2
  exit 1
fi
echo "PASS: vendored corpus matches agent-egress-bench@$AEB_REF byte-for-byte"
