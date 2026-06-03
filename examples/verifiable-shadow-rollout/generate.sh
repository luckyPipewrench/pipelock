#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0
#
# Regenerates the verifiable-shadow-rollout example bundle from scratch.
# All output is deterministic: re-running produces byte-identical artifacts
# (except recorder/evidence-proxy-0.jsonl whose outer timestamp uses wall
# clock; the receipt inside it is deterministic).
#
# Prerequisites: Go 1.25+ and the pipelock source tree.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}"

echo "=== Generating verifiable-shadow-rollout example ==="
echo "repo root: ${REPO_ROOT}"
echo "output:    ${OUT_DIR}"

# Clean previous artifacts (preserve generate.sh and README.md).
find "${OUT_DIR}" -mindepth 1 \
  ! -name generate.sh \
  ! -name README.md \
  -not -path "${OUT_DIR}" \
  -delete

cd "${REPO_ROOT}"

# Build the generator tool into a repo-local temp dir to avoid noexec /tmp.
BUILD_DIR="$(mktemp -d "${REPO_ROOT}/.gen-shadow-XXXXXX")"
cleanup_build() { rm -rf "${BUILD_DIR}"; }
trap cleanup_build EXIT

echo "--- building generator ---"
go build -o "${BUILD_DIR}/gen-shadow-example" ./tools/gen-shadow-example

# Run it.
echo "--- generating artifacts ---"
"${BUILD_DIR}/gen-shadow-example" --out "${OUT_DIR}"

echo ""
echo "=== Verification command ==="
echo "The generator verified the receipt using the Go contractreceipt.VerifyWithKey API."
echo ""
echo "To verify independently with the standalone verifier:"
echo ""
echo "  go run ./cmd/pipelock-verifier receipt --key ${OUT_DIR}/receipt-signing.pub --expect-payload-kind shadow_delta --expect-contract sha256:example-contract ${OUT_DIR}/shadow-delta-receipt.json"
echo ""
echo "  go run ./cmd/pipelock-verifier chain --key ${OUT_DIR}/receipt-signing.pub --expect-payload-kind shadow_delta --expect-contract sha256:example-contract ${OUT_DIR}/recorder/evidence-proxy-0.jsonl"
echo ""
echo "Or inspect verification-result.json for the recorded verification outcome."
echo ""
echo "=== Done ==="
