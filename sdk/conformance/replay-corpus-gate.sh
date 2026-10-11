#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# All four interpreters must satisfy the same independently specified bytes
# and rejection substrings for every registered transform profile, v1-v5.
# Dependencies must already be installed; this gate performs no installation.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="${PYTHON:-$ROOT/sdk/verifiers/python/.venv/bin/python}"
cd "$ROOT"
python3 sdk/conformance/generate-html5-entities.py --check
go test ./sdk/conformance -run 'TestEvidenceProvenance(TransformCorpus|V[45]Corpus|V5HTML5Table)$|TestEvidenceProvenanceTransformCorpusV[23]$' -count=1
(
  cd sdk/verifiers/ts
  npm run build
  node --test dist/tests/evidence-provenance.test.js
)
(
  cd sdk/verifiers/python
  "$PYTHON" -m pytest tests/test_evidence_provenance_transform.py
)
(
  cd sdk/verifiers/rust
  cargo test --locked --offline --test provenance evidence_provenance
)
printf 'PASS: Go, TypeScript, Python, and Rust replay corpora v1-v5\n'
