# Frozen v1 receipt fixtures

These three files are **immutable**. Do not edit them. They exist so that
`TestFrozenV1ReceiptFixtures` in `sdk/conformance/` can prove the current verifier
still accepts them across every release — a forward-compatibility regression guard.

The test embeds the SHA-256 of each file. Mutating any fixture will cause the test to
fail with a "frozen fixture drift" error, making the edit visible before merge.

## Files

| File | What | SHA-256 |
|------|------|---------|
| `action-receipt-v1-single.json` | Canonical ActionReceipt v1 single envelope | `c7475b5cca93c10dc97892335034e8f9a2cb935e473c9c1c84d803b7d8ff5b75` |
| `action-receipt-v1-chain.jsonl` | Canonical ActionReceipt v1 chain (5 entries) | `f17357e9e3ed6ce7926ae4579c184404bbe7f92444e89465c1af323730d4b8e2` |
| `aarp-v0.1-envelope.aarp.json` | Canonical AARP v0.1 assurance envelope (golden g01) | `1c873a078f0ba4b3a75a87c6f3dd423fcb0b52939a1aac9c9e785082ed11a46e` |

## Source

These files are copies of:
- `sdk/conformance/testdata/valid-single.json` (ActionReceipt v1 single)
- `sdk/conformance/testdata/valid-chain.jsonl` (ActionReceipt v1 chain)
- `sdk/conformance/testdata/aarp-corpus/golden/g01-single-ed25519-mediated.aarp.json` (AARP v0.1)

The trust file for the AARP fixture is
`sdk/conformance/testdata/aarp-corpus/test-keys.json`.

Versioning policy: `docs/receipts/versioning.md`.
