# Pipelock Action Receipt Format v0.1 (SUPERSEDED)

> **Status:** SUPERSEDED 2026-05-22.
> **Authoritative implementation spec:** https://pipelab.org/learn/action-receipt-spec/
> **Prior-art mapping:** [receipt-prior-art-mapping.md](./receipt-prior-art-mapping.md)

This file is a tombstone. A v0.1 receipt format draft dated 2026-04-04 circulated
internally before any binary emitted receipts. The draft proposed:

- A nested envelope of the shape `{ "receipt": { ... }, "signature": "...", "key_id": "sha256:<hex>" }`.
- RFC 8785 (JSON Canonicalization Scheme) canonicalization with three additional rules
  (NFC, millisecond-precision timestamps, omit-null).
- A `key_id` field carrying `sha256:` plus the hex SHA-256 fingerprint of the public key.
- Three conformance levels: Local Self-Signed, Org-Signed, Countersigned.

None of those shapes match what Pipelock ships. The shipped Pipelock ActionReceipt v1
envelope is flat:

```json
{
  "version": 1,
  "action_record": { ... },
  "signature": "ed25519:<128 hex chars>",
  "signer_key": "<64 hex chars>"
}
```

Canonicalization is the byte output of `json.Marshal` over `internal/receipt/action.go`'s
`ActionRecord` struct in declaration order, not JCS. The signing input is `SHA-256` of
the canonical action record, with the Ed25519 signature taken over that digest. There is
no `key_id` field; `signer_key` carries the raw 32-byte public key as hex.

Pipelock 2.4 added a second envelope, EvidenceReceipt v2, for contract-lifecycle and
shadow evidence. EvidenceReceipt v2 canonicalizes via RFC 8785 JCS over typed payloads,
discriminates payload kinds by a `record_type` field rather than by reusing the v1
`version` integer, and rejects unknown fields recursively. v1 and v2 envelopes ship side
by side in the same release.

## Why the v0.1 draft was set aside

A receipt format is interoperable only when a working producer ships it. The v0.1 draft
was an architecture proposal, not a description of any binary. Locking the wire format
in a design document before the producer existed produced two artifacts that disagreed:
the draft and the code. Pipelock's posture now is the inverse:

1. The producer (Pipelock) writes the receipts.
2. The implementation spec at https://pipelab.org/learn/action-receipt-spec/ documents
   the bytes the binary emits.
3. The conformance corpus at [`sdk/conformance/testdata/`](../../sdk/conformance/testdata/)
   is the cross-language contract; Go, TypeScript, Rust, and Python verifiers produce
   identical pass/fail verdicts on every fixture.
4. The standards posture is about lifting receipt primitives into existing standards
   (SCITT statement format, RFC 9421 transport binding, OpenTelemetry GenAI signed-event
   extension, in-toto run-time complement, CSA AARM authority delegation), not adopting
   a new Pipelock-controlled format.

The per-primitive prior-art mapping lives at
[receipt-prior-art-mapping.md](./receipt-prior-art-mapping.md).

## Where the live format is documented

| Surface | What it is |
|---|---|
| https://pipelab.org/learn/action-receipt-spec/ | Implementation spec, canonical. |
| [`internal/receipt/`](https://github.com/luckyPipewrench/pipelock/tree/main/internal/receipt) | Go reference implementation. |
| [`cmd/pipelock-verifier/`](https://github.com/luckyPipewrench/pipelock/tree/main/cmd/pipelock-verifier) | Standalone verifier binary (no network surface, drop-in for CI). |
| [`sdk/verifiers/ts/`](https://github.com/luckyPipewrench/pipelock/tree/main/sdk/verifiers/ts) | TypeScript verifier. |
| [`sdk/verifiers/rust/`](https://github.com/luckyPipewrench/pipelock/tree/main/sdk/verifiers/rust) | Rust verifier. |
| [`pipelock-verify-python`](https://github.com/luckyPipewrench/pipelock-verify-python) | Python verifier, `pip install pipelock-verify`. |
| [`sdk/conformance/testdata/`](https://github.com/luckyPipewrench/pipelock/tree/main/sdk/conformance/testdata) | Cross-language conformance fixtures. |
| [`sdk/audit-packet/`](https://github.com/luckyPipewrench/pipelock/tree/main/sdk/audit-packet) | Audit Packet v0 schema (locked) and Go bindings. |
| https://pipelab.org/schemas/audit-packet-v0.schema.json | Audit Packet v0 JSON Schema, served. |
| [`agent-egress-bench/receipts/v0/conformance/`](https://github.com/luckyPipewrench/agent-egress-bench/tree/main/receipts/v0/conformance) | Vendor-neutral receipt-verifier conformance corpus. |

## Why this file exists at all

A future reader who finds the v0.1 nested envelope quoted in an old draft, blog comment,
or branch needs a forward pointer to what ships today. This file is that pointer. The
shape on this page is historical context, not a target. Anyone proposing receipt-format
work should start from the implementation spec and the prior-art mapping, not from the
v0.1 draft.
