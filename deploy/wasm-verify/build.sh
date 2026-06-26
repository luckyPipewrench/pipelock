#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${1:-${SCRIPT_DIR}/out}"

install -d -m 0750 "${OUT_DIR}"

GOOS=js GOARCH=wasm go build -o "${OUT_DIR}/pipelock-verifier.wasm" "${REPO_ROOT}/cmd/pipelock-verifier-wasm"
install -m 0600 "$(go env GOROOT)/lib/wasm/wasm_exec.js" "${OUT_DIR}/wasm_exec.js"
chmod 0600 "${OUT_DIR}/pipelock-verifier.wasm"

test -s "${OUT_DIR}/pipelock-verifier.wasm"
test -s "${OUT_DIR}/wasm_exec.js"

printf 'built %s\n' "${OUT_DIR}/pipelock-verifier.wasm"
printf 'copied %s\n' "${OUT_DIR}/wasm_exec.js"
