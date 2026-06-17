# Fleet Receipt Report v1: Offline Verification

This document describes how an auditor verifies a Fleet Receipt Report v1 offline,
using only the published signer public key and the free Apache-licensed binary.

## Prerequisites

- A Fleet Receipt Report DSSE envelope (`.dsse.json` file).
- The fleet report signer's Ed25519 public key (hex string or file).
- `pipelock` binary (any platform, free tier; no license required for verification).

## Verify a Fleet Receipt Report

```bash
pipelock verify-receipt fleet-receipt.dsse.json --fleet-report --key <public-key-hex>
```

The `--key` flag accepts either a 64-character hex Ed25519 public key or a path to a
file containing the key. The verifier exits 0 on success and 1 on any failure.

Example with a key file:

```bash
pipelock verify-receipt fleet-receipt.dsse.json --fleet-report --key fleet-report.pub
```

Successful output:

```text
FLEET RECEIPT OK: fleet-receipt.dsse.json
  Signer:           fleet-report-test-signer
  Payload SHA-256:  <hex>
  Org/Fleet:        org-example/fleet-example
  Report ID:        rpt-frozen-001
  Level:            L1
  Source batches:   1
  Total actions:    10
  Mediated fraction: 1
  Limit:            L1 verifies the signed report, source-batch anchors, ordering, summary arithmetic, and completeness arithmetic.
  Limit:            L1 does not replay raw audit-batch payloads during offline verification.
  Limit:            Actions outside included signed audit batches are not claimed by this report.
```

The `Limit:` lines are the report's own declared verification limits. Read them as the boundary of the proof: a PASS means the signed report is internally consistent and anchored, **not** that the raw audit payloads were replayed or that no bypass occurred outside the included signed batches.

## What L1 verification checks

L1 (the only level supported by the current verifier) checks:

1. **DSSE envelope structure** -- exactly one signature with `payloadType`
   `application/vnd.in-toto+json`, algorithm `ed25519`, and key purpose
   `fleet-report-signing`.
2. **Ed25519 signature** over the DSSE PAE (Pre-Authentication Encoding) of the
   payload type and canonical payload bytes.
3. **Payload canonicality** -- the decoded payload must equal its JCS
   (JSON Canonicalization Scheme) re-encoding.
4. **in-toto Statement v1** -- `_type` and `predicateType` match the fleet-receipt/v1
   profile.
5. **Subject/source-batch binding** -- one subject per source batch, each subject's
   `digest.sha256` matching its `envelopeHash`.
6. **Source batch ordering** -- per-follower batches are sequence-ordered with no
   overlaps or duplicates.
7. **Summary arithmetic** -- every count breakdown (`byFollower`, `byTransport`,
   `byActionType`, `byVerdict`, `byLayer`, `bySeverity`) sums to `totalActions`.
8. **Completeness arithmetic** -- `mediatedFraction` equals
   `mediatedActions / observedActions` as an exact decimal.

## What L1 does NOT check

L1 does not replay raw audit-batch payloads. It does not verify follower
audit-batch signatures or recompute the report summary from recorder entries.
These are reserved for a future L2 forensic profile; the current verifier rejects
`verificationLevel: "L2"` rather than accepting a claim it did not perform.

## Unpinned verification

Without `--key`, the verifier resolves the signer identity from the envelope's
`keyid` field directly and performs structural-only verification. The output shows
`FLEET RECEIPT UNPINNED` and exits non-zero unless `--allow-unpinned` is passed:

```bash
pipelock verify-receipt fleet-receipt.dsse.json --fleet-report --allow-unpinned
```

Unpinned verification proves internal consistency (valid signature, valid
structure, valid arithmetic) but not provenance: anyone with any Ed25519 key can
produce an internally-consistent report.

## Frozen conformance fixtures

The repository ships frozen fixtures for auditor and cross-implementation
verification at `sdk/conformance/testdata/fleet-receipt-v1/`:

| File | Description |
|------|-------------|
| `valid-l1.dsse.json` | Valid L1 fleet receipt report, pinned verification passes. |
| `valid-l1.golden` | Expected verifier output for the valid fixture. |
| `test-key.json` | Deterministic test signer public key (hex + seed phrase). |
| `wrong-key.dsse.json` | Valid report; fails when verified with a different key. |
| `wrong-key-purpose.dsse.json` | Envelope with `receipt-signing` instead of `fleet-report-signing`. |
| `tampered-summary-arithmetic.dsse.json` | Summary `totalActions` mismatches breakdown sums. |
| `duplicate-source-batch.dsse.json` | Same source batch appears twice. |
| `reordered-source-batch.dsse.json` | Per-follower batches in wrong sequence order. |
| `unpinned-rejected.dsse.json` | Valid report; fails without `--key` (unpinned rejection). |
| `l2-rejected.dsse.json` | `verificationLevel: "L2"` rejected by the L1 verifier. |

Each negative fixture demonstrates one tampering class the verifier must reject.
The conformance test (`sdk/conformance/fleet_receipt_conformance_test.go`) verifies
that the current verifier accepts the valid fixture and fails closed on every
negative fixture with the correct error class.

To verify the valid fixture with the frozen test key:

```bash
pipelock verify-receipt sdk/conformance/testdata/fleet-receipt-v1/valid-l1.dsse.json \
  --fleet-report \
  --key 917443604f8b06cd18f2cee66a2c49ef23e8aa4f9e674c364f19216926685bea
```

The test key is derived deterministically from `sha256("pipelock-fleet-receipt-corpus-signer-v1")`.
It is a test key; never use it for production signing.

## Schema

The JSON Schema for the fleet-receipt/v1 predicate is at
`schemas/fleet-receipt-v1.schema.json`.

## Related

- [Fleet Receipt Report v1 specification](fleet-receipt-v1.md) -- full predicate
  and envelope specification.
