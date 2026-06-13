# Fleet Receipt Report v1

Fleet Receipt Report v1 is a signed, offline-verifiable rollup of accepted
Conductor audit batches for one fleet and one report window.

The report is an evidence artifact for mediated actions. It does not claim that
unmediated actions were impossible or absent. The completeness fields say what
fraction of the observed action records inside the included signed audit batches
were mediated by Pipelock.

## Envelope

A Fleet Receipt Report is a DSSE v1 envelope:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 JCS-canonical in-toto Statement v1 JSON>",
  "signatures": [
    {
      "keyid": "<hex Ed25519 public key>",
      "key_purpose": "fleet-report-signing",
      "algorithm": "ed25519",
      "sig": "ed25519:<base64 signature>"
    }
  ]
}
```

The signature is Ed25519 over DSSE PAE for the payload type and canonical
payload bytes. The profile requires one signature and the
`fleet-report-signing` key purpose.

## Statement

The payload is an in-toto Statement v1:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "conductor-audit-batch:pipelab/dogfood/pl-1/audit-1",
      "digest": {
        "sha256": "<sourceBatches[].envelopeHash>"
      }
    }
  ],
  "predicateType": "https://pipelab.org/attestation/fleet-receipt/v1",
  "predicate": {}
}
```

Subjects anchor the report to the immutable source set. Producers MUST include
exactly one subject per included audit batch. The subject name is
`conductor-audit-batch:<orgId>/<fleetId>/<instanceId>/<batchId>`, and
`digest.sha256` MUST equal that batch's `sourceBatches[].envelopeHash`.

## Predicate

Required fields:

| Field | Meaning |
|---|---|
| `schemaVersion` | Must be `1`. |
| `reportId` | Unique report identifier. |
| `generatedAt` | RFC3339 UTC timestamp. |
| `orgId` / `fleetId` | Fleet namespace. |
| `reportWindow` | Inclusive source window selected by the producer. |
| `verificationLevel` | `L1` for this verifier profile. |
| `conductor` | Conductor identity and optional version. |
| `sourceBatches` | Ordered accepted audit-batch references. |
| `summary` | Action counts by follower, transport, action type, verdict, layer, severity. |
| `completeness` | Signed mediated-fraction fields. |

`sourceBatches` are ordered per follower. A verifier rejects duplicates,
overlaps, and reordered sequence ranges for the same `(orgId, fleetId,
instanceId)`.

## Verification Levels

L1 verifies the report envelope, schema, source-batch subject/digest set,
summary arithmetic, completeness arithmetic, duplicate detection, and sequence
ordering.
It is the default procurement artifact.

`L2` is reserved for a future forensic profile. A future `L2` verifier must
replay operator-supplied raw audit batch envelopes and payloads, verify follower
audit-batch signatures, and recompute the report summary from recorder entries.
This v1 verifier rejects `L2` rather than accepting a stronger claim it did not
perform.

## Completeness Semantics

`completeness.mediatedFraction` is a decimal string between `0` and `1`.

The value means:

> fraction of observed fleet action records in included signed audit batches
> that were mediated by Pipelock

It does not mean:

> no bypass occurred

Traffic outside Pipelock, outside enrolled followers, outside the report window,
or omitted from unavailable audit batches is outside the claim.

## Verification

Use the free Apache binary:

```bash
pipelock verify-receipt fleet-receipt.dsse.json --fleet-report --key fleet-report.pub
```

Without `--key`, verification is structural-only and exits non-zero unless
`--allow-unpinned` is passed.
