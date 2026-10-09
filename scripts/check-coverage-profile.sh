#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Fail unless a Go coverage profile exists and records at least one block.
# Codecov uploads are best-effort, so an upload step cannot tell a real profile
# from a missing or empty one; this check can. Codecov waits for a fixed number
# of uploads, so a silently empty upload would let it judge partial coverage.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: check-coverage-profile.sh PROFILE" >&2
  exit 2
fi
profile="$1"

if [ ! -s "$profile" ]; then
  echo "check-coverage-profile: $profile is missing or empty" >&2
  exit 1
fi
first="$(head -n 1 "$profile")"
case "$first" in
  "mode: set" | "mode: count" | "mode: atomic") ;;
  *)
    echo "check-coverage-profile: $profile does not start with a Go coverage mode line" >&2
    exit 1
    ;;
esac
# A block line looks like file.go:12.3,14.5 2 1
blocks="$(grep -cE '^[^ ]+\.go:[0-9]+\.[0-9]+,[0-9]+\.[0-9]+ [0-9]+ [0-9]+$' "$profile" || true)"
if [ "$blocks" -lt 1 ]; then
  echo "check-coverage-profile: $profile records no coverage blocks" >&2
  exit 1
fi
echo "check-coverage-profile: $profile has $blocks blocks"
