#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Retry a command up to 3 times with linear backoff, to absorb transient
# network flakes (e.g. a one-off module-proxy blip on `go mod download`)
# without failing a whole CI matrix leg. Usage: ci-retry.sh <cmd> [args...]
set -euo pipefail

for attempt in 1 2 3; do
  if "$@"; then
    exit 0
  fi
  if [ "$attempt" -eq 3 ]; then
    exit 1
  fi
  echo "ci-retry: attempt ${attempt} of 3 failed; retrying in $((attempt * 5))s" >&2
  sleep $((attempt * 5))
done
