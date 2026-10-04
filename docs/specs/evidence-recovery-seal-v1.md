# Evidence recovery seal v1

## Judgment

A signed recovery seal is the right long-term shape for recording a specific observed break between process-run receipt chains. It lets an offline verifier establish that a signer observed a damaged shard, identify the exact shard bytes and complete prefix, and bind the successor run that opened afterward. A normal predecessor link can't express those facts without changing the meaning of continuous history.

The seal is an observation signed by the successor run's operator key. It can't establish that the damage was accidental or that no earlier evidence was removed. A directory writer with access to the evidence files can deliberately make a shard appear torn and cause a seal to be emitted. Deleting the seal leaves an unlinked successor, so omission remains visible only as a gap. Detecting a fully omitted run requires a head commitment anchored outside this directory.

The seal uses a new `recovery_seal` record in the existing exclusive predecessor claim slot, `chain-link-<predecessor-session>.json`. This preserves create-if-absent publication and the one-successor rule. The existing `ChainLink` v1 schema keeps its meaning and describes continuous receipt history. A separate filename would create a second predecessor claim, while adding damage fields to `ChainLink` would blur continuous history with an observed discontinuity.

New Go, TypeScript, and Rust directory verifiers recognize the seal and report `attested_discontinuity` separately from a continuous link. A valid seal doesn't make the evidence healthy because the retained shard remains damaged and verification exits unsuccessfully. Missing seals remain ordinary unlinked runs. Invalid, tampered, misplaced, or replayed seals don't attach. Older strict link readers reject the unfamiliar kind or fields and can't report the recovery as clean; operators should expect a link finding or an unlinked run. Mixed-version deployments can roll out writers and readers independently, but older directory readers will reject recovery artifacts until upgraded. Standalone receipt verification does not inspect directory continuity and cannot establish recovery across runs.

If seal publication fails, Pipelock reports on stderr that recovery starts unlinked and continues recording durable successor receipts. The damaged predecessor stays untouched, and the pending seal is retried on the next reload in the same process. Recovery does not make the offline evidence report healthy, even after a seal is published.

## Wire format

The signed projection serializes these fields in this exact order; input JSON field order is not significant. Every field is required and non-null, including `signature`.

1. `kind` (string): `recovery_seal`.
2. `version` (integer): `1`.
3. `predecessor_session` (string): Damaged process-run session.
4. `shard` (string): Evidence-root-relative basename of the damaged shard.
5. `shard_size` (integer): Raw shard size in bytes.
6. `shard_sha256` (string): Lowercase SHA-256 of all raw shard bytes, including damage.
7. `damage_offset` (integer): Byte offset at the end of the complete newline-terminated prefix.
8. `last_good_seq` (integer): Recorder sequence number at the complete-prefix end; zero for an empty prefix.
9. `last_good_hash` (string): Recorder hash at the complete-prefix end; `genesis` for an empty prefix.
10. `predecessor_tail_seq` (integer): Last complete ActionReceipt v1 chain sequence; zero when no complete receipt exists.
11. `predecessor_tail_hash` (string): Hash of the last complete ActionReceipt v1; `genesis` when none exists.
12. `predecessor_signer_key` (string): Lowercase hex Ed25519 public key for the last complete ActionReceipt v1, or the observing key when none exists.
13. `successor_session` (string): Fresh process-run session that continued after recovery.
14. `successor_signer_key` (string): Lowercase hex Ed25519 public key that signs this seal and the successor opening receipt.
15. `successor_open_hash` (string): Receipt hash of the successor run's signed genesis `session_open`.
16. `observed_at` (string): Canonical UTC RFC3339Nano observation time.
17. `signature` (string): `ed25519:` followed by 128 lowercase hexadecimal characters.

All integer fields are non-negative safe integers no larger than `2^53 - 1`, so JSON implementations with IEEE-754 numbers preserve them exactly. The shard name must identify the predecessor session and contain no path separator. Both sessions must be distinct sessions of the same base; the successor must be a fresh process-run session. The predecessor may be a legacy base session. The shard must have nonzero size and `damage_offset` must be less than `shard_size`. Hashes are lowercase SHA-256 hex, except the two explicitly allowed `genesis` heads. Keys are lowercase Ed25519 public-key hex.

The predecessor binding has two heads because recorder entries and receipts have separate sequences and hashes. `last_good_*` binds the end of the complete recorder prefix. `predecessor_tail_*` binds the last complete ActionReceipt v1 in that prefix. Every readable ActionReceipt v1 and EvidenceReceipt v2 chain is verified, including a valid final record whose newline is missing; that final record is excluded from the complete-prefix heads. The raw size and digest bind the full damaged shard, including bytes after `damage_offset`.

## Signature and validation

The signature covers the fields above except `signature`, serialized in the listed order with Go's `encoding/json` and the same replacement-escape normalization used by signed chain links. The signed message is `pipelock-recovery-seal-v1\0 || canonical-json`.

The signature value uses the existing `ed25519:<lowercase-hex>` form. Parsers reject duplicate keys, aliases, missing or null fields, unknown fields, trailing JSON, unsupported versions, invalid field values, and invalid signatures.

Verification also checks the artifact's placement and contents. The filename must claim `predecessor_session`; the verifier re-reads that session's damaged shard and compares its basename, size, raw digest, damage offset, complete-prefix heads, receipt tail, and predecessor signer key. It verifies the successor session and requires its first receipt to be the signed genesis `session_open` whose receipt hash is `successor_open_hash` and whose key is `successor_signer_key`. These checks prevent moving a valid seal to another shard or run.

The embedded successor key proves only that the seal and opening receipt use the same key. Directory verification requires that key to be explicitly trusted when it differs from the predecessor signer key. `evidence doctor` checks signatures and placement but doesn't decide whether a key is trusted. For a damaged predecessor containing key rotations, pin every signer key with the trusted-key option. Recovery verification does not use rotation endorsements to expand that trusted set. Fresh-start observation and evidence doctor verify signatures and rotation bindings without deciding operator key trust.

## Verifier behavior

* **Valid seal with matching shard and successor:** New Go, TypeScript, and Rust verifiers report `attested_discontinuity` and the damaged evidence. Directory verification is unhealthy and exits nonzero. Older strict link verifiers reject the unfamiliar record and don't report a clean continuous link.
* **No seal:** New and older verifiers report the successor as unlinked, as before.
* **Tampered seal or shard:** New verifiers report an invalid recovery seal and exit nonzero. Older verifiers reject the unrecognized or invalid link artifact and fail where their CLI treats link findings as errors.
* **Seal copied to another shard, predecessor, or successor:** New verifiers fail binding or placement checks and attach no discontinuity. Older verifiers reject the unfamiliar record and don't report a clean continuous link.

The Go verifier, TypeScript verifier, and Rust verifier consume the same conformance fixture under `sdk/conformance/testdata/recovery-seals/`. The fixture documents schema and implementation agreement; its test signing seed is public and must never be used for production evidence.

## Operator interpretation

An attested discontinuity means Pipelock recorded that it found a damaged predecessor shard and opened a successor run. It doesn't restore missing evidence, establish why the shard was damaged, or prove that no earlier run was omitted. The doctor continues to report damage, and the verifier keeps the directory unhealthy. Don't edit the shard or create a seal by hand to clear the finding; retain the evidence and investigate the storage and process history.
