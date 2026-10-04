#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

repo=$(cd "$(dirname "$0")/../.." && pwd)
make -C "$repo" build
cd "$repo"
go run ./scripts/receipt-load --binary "$repo/pipelock" --out "$1" \
  --requests "${RECEIPT_LOAD_REQUESTS:-1000000}" \
  --concurrency "${RECEIPT_LOAD_CONCURRENCY:-128}" \
  --modes "${RECEIPT_LOAD_MODES:-off,best,required}"
