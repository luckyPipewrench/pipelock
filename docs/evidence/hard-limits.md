# Evidence Hard Limits

## How to Read This

These limits are not loopholes in receipt verification. They are the boundary of what signed, hash-chained evidence can honestly prove without extra witnesses, configuration attestation, or containment attestation.

## L-KEYHOLDER-OMIT - Keyholder Omission

**Category:** completeness

**Summary:** No in-domain mechanism proves completeness against the party holding the signing key.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** C2 second recorder / C4 counterparty (separately keyed).

**How the verifier surfaces it:** Passing verification prints `L-KEYHOLDER-OMIT` with this summary when the verified surface is subject to the limit.

## L-OMIT-PRE-ANCHOR - Pre-Anchor Omission

**Category:** completeness

**Summary:** Whole-session omission BEFORE the first anchor is undetectable.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** Anchor interval + genesis anchor_head binding.

**How the verifier surfaces it:** Passing verification prints `L-OMIT-PRE-ANCHOR` with this summary when the verified surface is subject to the limit.

## L-FORGED-KEY - Compromised Signing Key

**Category:** completeness

**Summary:** A record forged under a COMPROMISED signing key is in-domain indistinguishable from a real one.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** Anchor interval + C2 (attacker lacks the agent-side key).

**How the verifier surfaces it:** Passing verification prints `L-FORGED-KEY` with this summary when the verified surface is subject to the limit.

## L-RECORDER-BINARY - Recorder Binary Trust

**Category:** recorder-integrity

**Summary:** A malicious/modified recorder binary IS the attacker; its output cannot vouch for itself.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** Release signing + contain-install binary-hash TOFU pin + external attestation.

**How the verifier surfaces it:** Passing verification prints `L-RECORDER-BINARY` with this summary when the verified surface is subject to the limit.

## L-RECORDER-DISABLED - Recorder Disabled

**Category:** config

**Summary:** A disabled recorder / receipts-off config is a no-op success; nothing is proven.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** Recorder-enabled state attested and MIN'd into the grade.

**How the verifier surfaces it:** Passing verification prints `L-RECORDER-DISABLED` with this summary when the verified surface is subject to the limit.

## L-VERIFIER-DRIFT - Verifier Drift

**Category:** cross-impl

**Summary:** Divergent verdicts across verifier implementations/versions break the shared-truth property.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** Cross-language mutation harness (identical verdicts on identical bytes).

**How the verifier surfaces it:** Passing verification prints `L-VERIFIER-DRIFT` with this summary when the verified surface is subject to the limit.

## L-METADATA-PRIVACY - Metadata Privacy

**Category:** privacy

**Summary:** Fingerprints/headers/session-id/timestamps/signer-keys in shared or anchored bundles leak metadata.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** Metadata-privacy budget; redact shareable bundles.

**How the verifier surfaces it:** Passing verification prints `L-METADATA-PRIVACY` with this summary when the verified surface is subject to the limit.

## L-CONNECT-OPACITY - CONNECT Opacity

**Category:** observability

**Summary:** CONNECT/TLS passthrough yields only host:port + byte counts; inner method/path/body are uninspectable.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** TLS interception where deployed; else the fingerprint degrades honestly.

**How the verifier surfaces it:** Passing verification prints `L-CONNECT-OPACITY` with this summary when the verified surface is subject to the limit.

## L-FSYNC-HONESTY - Fsync Honesty

**Category:** recorder-integrity

**Summary:** Hardware fsync honesty vs lying storage is unprovable.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** Attest storage config + capture the syscall return.

**How the verifier surfaces it:** Passing verification prints `L-FSYNC-HONESTY` with this summary when the verified surface is subject to the limit.

## L-FSYNC-DOS - Fsync Backpressure

**Category:** availability

**Summary:** fsync/backpressure is a DoS surface; fail-closed blocking under storage stall can stall egress.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** fsync_errors_total SLO + alerting; a deliberate integrity-over-availability tradeoff.

**How the verifier surfaces it:** Passing verification prints `L-FSYNC-DOS` with this summary when the verified surface is subject to the limit.

## L-CONTAINMENT-UNPROVEN - Containment Unproven

**Category:** completeness

**Summary:** "The boundary is the witness" holds only under attested containment; the binary alone cannot prove non-bypass.

**Why no rung closes it:** The receipt chain can prove byte integrity, ordering, and signer binding for records it sees. This limit describes a condition outside that in-domain proof.

**Bound:** Containment-attestation grade (item d).

**How the verifier surfaces it:** Passing verification prints `L-CONTAINMENT-UNPROVEN` with this summary when the verified surface is subject to the limit.

## What Pipelock DOES Prove

Pipelock receipts prove that the verified bytes were signed by the trusted key, chained in order, and checked by the verifier without mutation. Anchors and containment evidence can narrow specific gaps, but they do not turn these hard limits into stronger claims than the evidence supports.
