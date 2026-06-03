<!-- Copyright 2026 Josh Waldrep -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# AARP v0.1 assurance-envelope verifier (Python)

This is the Python reference verifier for the AARP (Agent Action Receipt
Profile) v0.1 assurance envelope. It is one of four reference verifiers (Go,
TypeScript, Rust, Python). The Go implementation in `internal/aarp/` is the
reference; this package ports **from** it so that, given the same envelope and
the same trust file, every verifier emits byte-identical comparable output.
Cross-language divergence is the bug class the shared hostile corpus
(`sdk/conformance/testdata/aarp-corpus/`) exists to kill.

The normative contract is `sdk/conformance/AARP-CORPUS-CONTRACT.md`.

**This is a conformance reference impl, not a published package.** Like the
in-repo TypeScript (`sdk/verifiers/ts`) and Rust (`sdk/verifiers/rust`)
verifiers, it exists only to prove the AARP spec is unambiguous across languages
in CI; nobody `pip install`s it. The shipped, user-facing Python verifier is
`pipelock-verify` on PyPI (which already covers receipt v1/v2); folding AARP into
that package is a separate, deliberate release. The `pyproject.toml` here is
marked `Private :: Do Not Upload` so it can never be published by accident.

## What it does

Given an AARP envelope (or a JSONL chain of envelopes) and a pinned trust file,
the verifier appraises the envelope and reports — grouped by axis — exactly which
claims it could cryptographically confirm, plus the fixed `does_not_assert` list.
It never emits "trusted" or "safe". Per-signature problems (unknown suite,
untrusted key, bad signature) are reported per signature, never as an envelope
rejection, so one bad parallel signature can neither mask nor poison a good one.

## CLI

```
python -m pipelock_aarp_verify aarp PATH --trust TRUST_JSON [--chain] [--json]
```

- `PATH`: a single envelope (`*.aarp.json`) or, with `--chain`, a JSONL stream
  (`*.aarp.jsonl`, one envelope per line).
- `--trust TRUST_JSON`: the pinned trust file. Optional; absent means empty trust
  (every signature is `unknown_key`).
- `--json`: print the cross-language comparable output on stdout.
- `--chain`: verify Rung-1 chain linkage instead of single-envelope appraisal.

Exit codes: `0` appraised / linked, `1` fatal / not linked, `2` I/O or
trust-file error, `64` usage error. A fatal envelope with `--json` prints
`{"envelope_fatal": true, ...}` and exits non-zero.

There is no console-script entry point on purpose (this is a reference impl, not
a CLI product): always invoke it as the module form above.

## Running without installing

The conformance gate and CI run it straight from the source tree, no install:

```
PYTHONPATH=sdk/verifiers/python/src python -m pipelock_aarp_verify aarp \
    <envelope> --trust <trust.json> --json
```

The only runtime dependency is `cryptography` (Ed25519 verification); no network
access is performed in any code path.

## Install (hash-pinned, offline-friendly)

```
pip install --require-hashes -r sdk/verifiers/python/requirements.txt
pip install --no-deps sdk/verifiers/python
```

`requirements.txt` pins `cryptography` and its transitive tree (`cffi`,
`pycparser`) with hashes, matching the install style already used in CI for the
companion v1-receipt verifier.

## Formatter and linter

This package uses **ruff** as both formatter and linter (the project default).
Configuration lives in `pyproject.toml` (`[tool.ruff]`). Before committing:

```
cd sdk/verifiers/python
ruff format .
ruff check .
```

## Tests

```
cd sdk/verifiers/python
PYTHONPATH=src pytest --cov=pipelock_aarp_verify --cov-report=term-missing
```

The suite includes a corpus-driven conformance test over **every** fixture in
`sdk/conformance/testdata/aarp-corpus/`: appraise fixtures must produce output
byte-equal to the committed `.appraisal.json` and exit `0`; fatal fixtures must
exit non-zero. The four-language gate (`sdk/conformance/aarp-corpus-gate.sh`)
additionally checks that this verifier agrees with the Go reference on every row.

## Cross-language hazards handled

- **JCS canonicalization** matches Go `json.Marshal` per string exactly: NFC
  normalization; `<` `>` `&` → `<` `>` `&`; U+2028 / U+2029 →
  ` ` / ` `; the Go short control escapes (`\b \t \n \f \r`) with
  `\u00xx` for other controls; all other code points (DEL U+007F and any
  non-ASCII) emitted raw UTF-8. Object keys are sorted by Unicode code point;
  NFC key collisions are rejected.
- **I-JSON number safety**: a strict parser preserves number literals so float /
  exponent / negative-zero / out-of-range detection happens on the source text
  before any lossy conversion. Duplicate keys at any depth and trailing tokens
  are rejected.
- **RFC3339Nano timestamps** are validated against an explicit grammar plus a
  calendar check, matching Go's `time.Parse(time.RFC3339Nano, ...)` acceptance
  (Python's `datetime.fromisoformat` is too lenient).
