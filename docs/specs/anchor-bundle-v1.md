# Anchor Bundle v1

`pipelock anchor receipts` verifies a signed receipt chain, builds a checkpoint,
submits that checkpoint to the selected backend, and writes a machine-readable
JSON bundle with `--out`. The published schema is
[`sdk/anchor-bundle/v1.json`](../../sdk/anchor-bundle/v1.json), with a fully
populated structural fixture at
[`sdk/anchor-bundle/example.json`](../../sdk/anchor-bundle/example.json).

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

## Field reference

All objects reject unknown fields when Pipelock loads a bundle. JSON numbers
used by `final_seq`, `receipt_count`, `log_index`, and `tree_size` are Go
`uint64` values; consumers must preserve integer precision across the full
unsigned 64-bit range.

| Field | Type | Meaning |
| --- | --- | --- |
| `version` | integer | Bundle format version. v1 is exactly `1`. |
| `backend` | string | Backend identifier copied from `proof.backend`. Pipelock verification requires the two values to match. A name here is not proof that the running Pipelock binary supports that backend. |
| `created_at` | RFC 3339 timestamp | Bundle assembly time from the Pipelock process clock. It is not a trusted or independently witnessed timestamp. |
| `checkpoint` | object | Receipt-chain checkpoint covered by the backend proof. |
| `proof` | object | Generic proof coordinates plus optional built-in-backend material. |
| `limits` | string array | Human-readable limitations emitted for the selected backend. Pipelock verification reports canonical built-in limits and does not trust claims inserted into this array. |

### `checkpoint`

| Field | Type | Meaning |
| --- | --- | --- |
| `session_id` | string | Receipt-chain session identifier. |
| `final_seq` | uint64 | Sequence number of the final covered receipt. |
| `root_hash` | string | Lowercase hexadecimal SHA-256 hash of the final covered receipt. Because receipts are hash-linked, it commits to the covered prefix when the receipt chain verifies. |
| `receipt_count` | uint64 | Number of receipts covered by the checkpoint. |
| `start_time` | RFC 3339 timestamp | Timestamp signed into the first covered receipt. It is evidence from the receipt signer, not an independent wall-clock attestation. |
| `end_time` | RFC 3339 timestamp | Timestamp signed into the final covered receipt. It has the same trust boundary as `start_time`. |
| `signer_keys` | string array | Ordered, de-duplicated trusted Ed25519 public keys for the covered chain segments, encoded as lowercase hexadecimal. A relying party still has to establish that these are the expected keys. |

### `proof`

| Field | Type | Meaning |
| --- | --- | --- |
| `backend` | string | Backend identifier. The verifier selects backend-specific proof semantics; the schema does not. |
| `log_id` | string | Backend-defined log or witness identifier. |
| `log_index` | uint64 | Backend-defined entry position. |
| `entry_hash` | string | Backend-defined entry digest. Its algorithm and preimage are backend semantics. |
| `log_root_hash` | string | Backend-defined log root or checkpoint digest. |
| `rekor` | object, conditionally required | Proof material emitted by the built-in Rekor backend: required when `proof.backend` is `rekor`, forbidden otherwise. Other backend names do not gain a generic extension object in v1. |

The generic fields are a common envelope, not a universal proof protocol. v1
does not define a backend-neutral canonical serialization or digest for
`checkpoint`. External witnesses must publish exactly which bytes or digest
they anchor and how a verifier recomputes it.

### `proof.rekor`

This optional object documents the current built-in Rekor output. Its presence
does not make the overall format Rekor-specific.

| Field | Type | Meaning |
| --- | --- | --- |
| `url` | URI | Explicit Rekor base URL used for submission. |
| `uuid` | string | Rekor entry UUID. |
| `body` | base64 string | Encoded Rekor entry body. The body contains a digest of the checkpoint, not plaintext checkpoint fields. |
| `public_key` | string | PEM public key paired with the Rekor entry signature. |
| `signature` | base64 string | Signature over the Rekor checkpoint digest. |
| `integrated_time` | int64 | Rekor integrated time in Unix seconds. It is backend evidence, not `created_at`. |
| `signed_entry_timestamp` | base64 string | Rekor Signed Entry Timestamp. |
| `inclusion_proof` | object | Merkle inclusion material returned by Rekor. |

### `proof.rekor.inclusion_proof`

| Field | Type | Meaning |
| --- | --- | --- |
| `root_hash` | hexadecimal string | Merkle-tree root. Rekor verification requires it to match `proof.log_root_hash`. |
| `log_index` | uint64 | Included entry index. Rekor verification requires it to match `proof.log_index`. |
| `tree_size` | uint64 | Size of the tree covered by the proof. |
| `hashes` | string array | Merkle audit-path hashes. |
| `checkpoint` | string | Signed Rekor checkpoint text. |

## What verification proves

Schema validation proves only that a document has the expected JSON shape. A
valid anchor verification additionally requires:

1. the receipt chain to verify under keys the relying party trusts;
2. the recomputed receipt checkpoint to match `checkpoint`;
3. top-level `backend` to match `proof.backend`; and
4. the selected backend verifier to authenticate and validate the proof.

Successful anchoring constrains undetected rewriting or omission after the
anchored point. It does not prove that receipt timestamps are truthful, that the
signer did not fabricate evidence before anchoring, that no conflicting
checkpoint was also anchored, or that traffic outside Pipelock's mediated
boundary did not happen.

The local backend is deterministic development plumbing, not an
operator-independent witness. Rekor verification requires a pinned log public
key. An external chain, transparency log, or other witness can consume an
emitted bundle without a Pipelock code change, but its proof remains external
unless Pipelock gains explicit backend and verifier support for it.
