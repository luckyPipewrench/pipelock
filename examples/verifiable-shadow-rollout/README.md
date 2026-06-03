# Verifiable Shadow Rollout Example

This directory contains a reproducible fixture for Pipelock's verifiable shadow
rollout workflow: captured agent traffic, a signed candidate behavioral
contract, a shadow replay report, and cryptographically signed `shadow_delta`
receipts that prove what changed.

## What is here

| File | Description |
|------|-------------|
| `candidate-contract.json` | Signed candidate contract (Ed25519 envelope) |
| `contract-signing.pub` | Public key (hex) that signed the contract |
| `sessions/` | Deterministic capture session JSONL (one URL verdict) |
| `shadow.md` | Human-readable shadow replay report |
| `shadow.json` | Machine-readable shadow replay report |
| `recorder/` | Recorder chain with signed shadow_delta receipt entries |
| `shadow-delta-receipt.json` | Standalone EvidenceReceipt v2 (shadow_delta) extracted from the recorder |
| `receipt-signing.pub` | Public key (hex) that signed the receipt |
| `verification-result.json` | Recorded verification outcome from the generator |
| `generate.sh` | Script that regenerates all artifacts from scratch |

## Quick start

```bash
# From the pipelock repo root:
go run ./tools/gen-shadow-example --out /tmp/shadow-verify-check

# Verify the standalone receipt with the shipped verifier:
go run ./cmd/pipelock-verifier receipt \
  --key /tmp/shadow-verify-check/receipt-signing.pub \
  --expect-payload-kind shadow_delta \
  --expect-contract sha256:example-contract \
  /tmp/shadow-verify-check/shadow-delta-receipt.json

# Verify the recorder chain:
go run ./cmd/pipelock-verifier chain \
  --key /tmp/shadow-verify-check/receipt-signing.pub \
  --expect-payload-kind shadow_delta \
  --expect-contract sha256:example-contract \
  /tmp/shadow-verify-check/recorder/evidence-proxy-0.jsonl
```

## How the receipts are verified

Shadow_delta receipts are **EvidenceReceipt v2** records (`record_type:
evidence_receipt_v2`). They use JCS-canonicalized Ed25519 signatures over
the full receipt envelope (excluding the signature field).

The standalone `pipelock-verifier` verifies both individual EvidenceReceipt v2
envelopes and recorder JSONL chains. Pass `--key receipt-signing.pub` to pin the
trusted Ed25519 receipt-signing public key; without `--key`, v2 chain
verification is self-consistency only and does not prove provenance.

The `--expect-*` flags bind the verification to the intended evidence class and
candidate contract. They are defense in depth: a receipt signed by another key,
for another payload kind, or for another contract is rejected.

## Reproducibility

All artifacts except `recorder/evidence-proxy-0.jsonl` are byte-reproducible
across runs. The recorder JSONL wrapper uses wall-clock timestamps from
`recorder.Record()`, but the EvidenceReceipt v2 inside its `detail` field is
fully deterministic (fixed clock, fixed event IDs, deterministic Ed25519 seed).

The deterministic receipt signer seed is:
```text
sha256("pipelock deterministic shadow receipt signer")
```

## Command sequence (what the generator does)

1. Derive deterministic Ed25519 key pairs for contract signing and receipt signing
2. Write a capture session with one URL verdict (`GET https://api.vendor.example/repos/bar -> allow`)
3. Build and sign a candidate contract with one rule (`rule-api` for `api.vendor.example`, paths: `/repos/foo`)
4. Replay the capture against the candidate contract (the observed path `/repos/bar` does not match the contract's `/repos/foo`, producing a shadow delta)
5. Analyze the replay results into a shadow report
6. Emit a signed shadow_delta receipt into the recorder chain
7. Extract the receipt, verify its Ed25519 signature, and write the verification result

Shadow replay evaluates a candidate contract before promotion, so these
`shadow_delta` receipts intentionally omit `active_manifest_hash`. They are bound
to the candidate via `contract_hash`; lifecycle and runtime receipts bind the
active manifest after promotion.
