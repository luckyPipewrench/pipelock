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
lock_args=()
if [[ -n ${RECEIPT_LOAD_LOCK:-} ]]; then
  lock_args=(--lock-file "$RECEIPT_LOAD_LOCK")
fi
go run ./scripts/receipt-load --binary "$repo/pipelock" --out "$1" \
  --requests "${RECEIPT_LOAD_REQUESTS:-1000000}" \
  --warmup "${RECEIPT_LOAD_WARMUP:-1000}" \
  --concurrency "${RECEIPT_LOAD_CONCURRENCY:-128}" \
  --chains "${RECEIPT_LOAD_CHAINS:-1}" \
  --modes "${RECEIPT_LOAD_MODES:-off,best,required}" \
  --rules "${RECEIPT_LOAD_RULES:-empty}" \
  --seed "${RECEIPT_LOAD_SEED:-1}" \
  --window "${RECEIPT_LOAD_WINDOW:-5s}" \
  ${lock_args[@]+"${lock_args[@]}"}
