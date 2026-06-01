# Receipt Verifier Conformance Corpus (v0)

A vendor-neutral test corpus for **receipt verifier implementations**. Each fixture
is a JSON receipt (or JSONL chain) paired with an `.expect.json` describing the
verdict any correct verifier MUST emit. Drop your verifier into the harness, run
it across the corpus, and compare its output line-by-line against the expected
verdicts.

This is the receipt-verifier sibling of the bench's `cases/` directory: where
`cases/` tests **network security tools** (proxies, firewalls, MCP wrappers),
this corpus tests **receipt verifiers** that consume the signed evidence chain
those tools emit.

## What a receipt is

A `Receipt` is a self-signed proof of a single mediated action. It bundles:

- An `action_record` describing the action (type, target, verdict, principal,
  policy hash, chain position).
- An Ed25519 `signature` over `SHA-256(canonical-JSON(action_record))`.
- The `signer_key` (Ed25519 public key, 32-byte hex).

Receipts compose into a tamper-evident chain by setting each receipt's
`action_record.chain_prev_hash` to the SHA-256 hex of the prior receipt.
`"genesis"` is the chain start marker.

Production receipts are wrapped in flight-recorder entries (`evidence.jsonl`),
but the receipt itself is verifiable in isolation when extracted.

## Test key

All fixtures are signed with a deterministic test key derived from
`sha256("agent-egress-bench-receipt-conformance-test-key-v1")`. The keypair is committed in
`_generator/test-key.json` so any verifier can pin it during conformance runs.

**This key is for testing only.** Never use it for production signing.

## Corpus layout

```text
receipts/v0/conformance/
├── README.md             (this file)
├── _generator/           Reproducible generator + test-key material
│   ├── main.go           stdlib-only, produces all fixtures
│   ├── go.mod
│   └── test-key.json     committed for reproducibility
├── golden/               Receipts every correct verifier MUST accept
├── malicious/            Forged/broken receipts every verifier MUST reject
└── edge/                 Tricky-but-valid boundary cases
```

## Fixture format

Each fixture is two files sharing a base name:

- `<name>.json` for single-receipt fixtures and receipt-bundle wrappers, or `<name>.jsonl` for raw chain fixtures (the input to the verifier). Chains are JSONL with one receipt per line.
- `<name>.expect.json` for the expected verifier output.

### `.expect.json` schema

```json
{
  "fixture_id": "string, immutable",
  "category": "golden | malicious | edge",
  "input_format": "receipt | chain | receipt_bundle",
  "verdict": "accept | reject",
  "reject_reason": "machine-readable enum (omitted when accept)",
  "description": "human prose",
  "expected_chain_length": 5,
  "expected_signer_key": "32-byte hex string (omitted when reject for malformed)",
  "expected_root_hash": "sha256 hex of final receipt (omitted when not applicable)",
  "notes": "verifier-author guidance"
}
```

### Reject reasons (closed enum)

A correct verifier emits exactly one of these when it rejects a fixture. The
mapping is intentionally tight — vendors should be able to read this README,
implement against the enum, and produce identical reject codes.

| `reject_reason`                | Meaning                                                                |
|--------------------------------|------------------------------------------------------------------------|
| `signature_invalid`            | Signature does not verify against `signer_key`                         |
| `signer_key_untrusted`         | Signature math is valid but `signer_key` is not pinned                 |
| `signer_key_mismatch`          | Embedded `signer_key` does not match expected/pinned key               |
| `expired`                      | `action_record.timestamp` older than verifier's `max_age` policy       |
| `replay_detected`              | Duplicate `action_id` or duplicate `(session_id, chain_seq)` pair      |
| `malformed_json`               | Receipt is not valid JSON (truncation, BOM, trailing junk)             |
| `missing_required_field`       | A schema-required field is absent                                      |
| `padding_attack`               | Declared length disagrees with body length                             |
| `chain_break`                  | A receipt's `chain_prev_hash` does not match prior receipt's hash      |
| `verdict_chain_mismatch`       | `verdict` in receipt disagrees with computed chain state               |
| `receipt_count_mismatch`       | Wrapper declares a count that disagrees with payload                   |
| `body_tampered`                | Signature was valid for an earlier body, current body differs          |
| `header_injection`             | Disallowed control byte (NUL, etc.) embedded in a string field         |
| `unsupported_version`          | `version` or `action_record.version` outside accepted range            |
| `invalid_action_type`          | `action_type` not in the closed action-model enum                      |
| `duplicate_key`                | A JSON object contains the same key twice at any nesting depth         |

### Verifier policy assumptions

Conformance assumes the verifier is configured as follows:

- **Pinned key:** `test-key.json` `public_key_hex` is the only trusted signer.
- **Max age:** `8760h` (1 year) for the `expired` fixture. This window is wide
  enough that ordinary corpus drift will not flip golden fixtures into
  `expired` until 2027-04-15.
- **Replay window:** keep the last 10000 `action_id` values per session.
- **Schema version:** accept `version: 1` and `action_record.version: 1` only.
- **Strict JSON:** reject BOM, trailing data, embedded NUL bytes in strings,
  and duplicate object keys at any nesting depth (see the `duplicate_key` reject
  reason). Last-wins duplicate handling is a parser-differential smuggling
  vector and MUST be rejected at parse time, before signature verification.

## Running the corpus

A reference Go runner is **not** shipped in this directory by design — the
point is that any verifier in any language can be evaluated. To validate the
corpus is self-consistent (each `.expect.json` matches its fixture's known
property), use the generator:

```bash
cd _generator && go run . --verify
```

The generator's `--verify` flag re-derives expected hashes/signatures and
compares against the committed fixtures, catching accidental drift.

## Regenerating

The generator is the source of truth. If a fixture needs to change, change the
generator first:

```bash
cd _generator && go run . --write
```

This rewrites every `*.json` and `*.expect.json` under `golden/`, `malicious/`,
and `edge/` deterministically.

## Versioning

This corpus is `v0`. Breaking changes go in a sibling `v1/` directory; this
directory's fixtures and expect outputs are frozen. Adding new fixtures to
`v0` is allowed only if they preserve the verifier-behaviour-already-specified
property — i.e. an existing correct verifier must still pass without code
changes.

"Already-specified behaviour" is defined by the receipt schema and signing
protocol in this directory, whose source of truth is the Go `ActionRecord`
struct and signer (see *Source* below) — **not** by whatever a given verifier
happened to accept before. A fixture that exercises a field or rule the schema
always required, but that earlier fixtures did not cover, is a coverage-gap
closure and is allowed in `v0`: a verifier that fails it was never conformant
against production receipts. Frozen means existing fixtures are never edited;
additions follow the rule above.

### Spec revisions

- **2026-05-31** — Coverage + one new requirement, both non-breaking (no honest
  receipt changes verdict):
  - Added golden fixtures `09-allow-shield-summary` and
    `10-full-field-differential` exercising the full `ActionRecord` field set
    (notably `parent_action_id` and the nested `shield` object). These are
    coverage-gap closures: the Go signer has always emitted these fields, but no
    earlier fixture carried them, so reference verifiers that dropped them
    verified against a different byte string than Go and silently failed real
    receipts.
  - Added the `duplicate_key` reject reason and malicious fixture
    `m13-duplicate-key-verdict`, and added duplicate-key rejection to the
    Strict-JSON requirements. No honest receipt has duplicate keys, so this
    hardens against a parser-differential smuggling vector without changing any
    honest receipt's verdict — it does not warrant a `v1` fork.
- **2026-06-01** — Added boundary fixtures that lock down cross-language
  canonicalization assumptions:
  - `e09-maximum-json-nesting-depth` accepts an ignored probe field that brings
    the whole JSON document to exactly 128 levels deep, proving verifiers share
    the same depth boundary.
  - `e10-non-bmp-map-key-order` exercises Go-compatible map-key ordering for
    non-BMP Unicode keys.
  - `e11-html-escape-canonicalization` exercises Go's JSON HTMLEscape behavior
    for `<`, `>`, `&`, U+2028, and U+2029.
  - `m14-duplicate-key-nested-unicode` rejects duplicate keys hidden inside an
    array using a unicode-escaped equivalent key.

## What a passing verifier looks like

A correct verifier configured with the test-key pin runs the entire corpus and:

1. Accepts every fixture in `golden/` with `expected_signer_key` matching the
   pinned key.
2. Rejects every fixture in `malicious/` with `reject_reason` exactly equal to
   the value in the corresponding `.expect.json`.
3. Accepts every fixture in `edge/`, with any documented quirks (e.g. multi-byte
   UTF-8 in agent identifiers) preserved byte-for-byte.

Vendors are encouraged to publish their verifier's corpus output as a single
JSONL file alongside their tool releases so consumers can audit conformance
without rerunning the suite.

## Source

Receipt schema and signing protocol: the inline schema and generator in this
directory.
