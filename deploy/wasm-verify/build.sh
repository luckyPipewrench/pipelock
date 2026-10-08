#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/out}"

install -d -m 0750 "${OUT_DIR}"

GOOS=js GOARCH=wasm go build -o "${OUT_DIR}/pipelock-verifier.wasm" "${REPO_ROOT}/cmd/pipelock-verifier-wasm"
install -m 0600 "$(go env GOROOT)/lib/wasm/wasm_exec.js" "${OUT_DIR}/wasm_exec.js"
# The stock Go browser shim has an ENOSYS-only filesystem. Receipt-group
# verification needs bounded temporary files for the existing verifier and
# SQLite inventory, so install its private in-memory filesystem before the
# page starts the WASM runtime.
cat "${SCRIPT_DIR}/receipt-memfs.js" >> "${OUT_DIR}/wasm_exec.js"
chmod 0600 "${OUT_DIR}/pipelock-verifier.wasm"

test -s "${OUT_DIR}/pipelock-verifier.wasm"
test -s "${OUT_DIR}/wasm_exec.js"

printf 'built %s\n' "${OUT_DIR}/pipelock-verifier.wasm"
printf 'copied %s\n' "${OUT_DIR}/wasm_exec.js"
