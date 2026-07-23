# Pipelock Anchor Bundle v1

This directory publishes the JSON shape emitted by `pipelock anchor receipts
--out`. It is for external witnesses, archival systems, and verifiers that need
to parse a Pipelock-created checkpoint without importing Pipelock's internal Go
package.

| File | What it is |
| --- | --- |
| `v1.json` | JSON Schema draft 2020-12 description of the emitted v1 shape. |
| `example.json` | Fully populated structural fixture. Its placeholder proof is not cryptographically valid. |

## Stability status

**Experimental compatibility notice:** This document and `v1.json` describe the
anchor bundle emitted by current Pipelock builds when `version` is `1`. They are
an interoperability snapshot, not a promise of long-term wire compatibility.
Until this format is declared stable, Pipelock may revise v1 in place, including
changes that break producers or consumers. Pin the exact Pipelock release or
commit and the exact schema revision you build against, and test against a real
bundle emitted by that build. Do not infer support for an anchor backend from
this schema. No backward- or forward-compatibility guarantee is made yet.

The real-checkpoint end-to-end test is the gate for declaring this format
stable. Publishing the current shape does not make that stability claim.

## Scope

The schema describes JSON structure only. It does not:

- verify the covered receipt chain or its signer keys;
- prove that receipt timestamps or `created_at` are truthful;
- verify backend signatures, inclusion, consistency, or non-equivocation;
- define a backend-neutral canonical checkpoint digest;
- provide an anchor-backend plugin API; or
- make `example.json` valid cryptographic evidence.

An external witness must state exactly which bytes or digest it anchors and how
that value is verified. Consuming this JSON does not make the witness a
Pipelock-supported backend and does not make its proof verifiable by
`pipelock-verifier`.

See [the field and verification
specification](../../docs/specs/anchor-bundle-v1.md) for the complete field
table and trust boundaries.
