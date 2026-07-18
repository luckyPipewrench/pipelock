# Evidence Terminology

Pipelock produces several evidence surfaces with different proof boundaries.
This page is a starting point that distinguishes their roles and points to the
authoritative guide for each. It organizes claims made elsewhere rather than
introducing new ones; where this page and a linked specification disagree, the
specification wins.

Read [Evidence Hard Limits](hard-limits.md) alongside this page. It catalogs
what signed, hash-chained evidence cannot prove without additional witnesses,
configuration attestation, or containment attestation.

## Quick reference

| Term | What it is | Authoritative doc |
|------|------------|-------------------|
| **ActionReceipt v1** | Signed per-action evidence for a mediated decision, carrying verdict, policy and transport context, actor fields, and hash-chain linkage. | [Verifiable Evidence](../security-assurance.md#verifiable-evidence), [schema versioning](../receipts/versioning.md) |
| **EvidenceReceipt v2** | RFC 8785/JCS-canonicalized typed evidence for contract lifecycle, shadow, drift, and contract-aware proxy decisions. | [Verifiable Evidence](../security-assurance.md#verifiable-evidence), [Learn-and-Lock](../guides/learn-and-lock.md) |
| **Flight recorder** | Configured evidence storage: a hash-chained JSONL log with chain continuity and signed checkpoints. It records blocks; allow receipts require the configured receipt mode, and clean stream frames may be summarized rather than emitted one by one. | [Flight Recorder](../guides/flight-recorder.md) |
| **Flight recorder record** | One JSONL entry, tagged with a type: `decision`, `checkpoint`, `action_receipt`, `evidence_receipt`, `transcript_root`, `capture`, `capture_drop`. | [Flight Recorder](../guides/flight-recorder.md), [schema versioning](../receipts/versioning.md) |
| **Checkpoint** | A periodic entry summarizing the preceding N entries, with an Ed25519 signature over the chain state. Verifying it confirms the chain was intact at that point. Signing is on by default but can be disabled. | [Flight Recorder](../guides/flight-recorder.md) |
| **Transcript root** | The hash of the final receipt in a chain, serving as a tamper-evident summary of the session. Computing one requires a pinned key. | [Computing a transcript root](../guides/receipt-verification.md#computing-a-transcript-root) |
| **Anchor** | A verified chain head written to an anchor backend, constraining deletion or rewriting *after* the anchored point. The Rekor backend submits checkpoint material to a remote transparency log; the local backend is development plumbing, not an operator-independent witness. | [Anchoring receipts](../guides/receipt-verification.md#anchoring-receipts) |
| **Coverage certificate** | A signed summary over an observed evidence set. Its completeness field reports `LIMITED`, `BROKEN`, or `UNVERIFIED` — `LIMITED` is the ceiling, never `COMPLETE`. | [Verifiable Evidence](../security-assurance.md#verifiable-evidence), [`pipelock dashboard`](../cli/dashboard.md) |
| **Audit Packet v0** | A posture-bundled set of receipts plus verifier output. Its relying party must pin the expected trust inputs. | [Audit Packet threat model](../security/audit-packet-threat-model.md) |
| **AARP v0.1** | Experimental, and *not* a receipt format: a separately signed appraisal artifact that sits alongside a frozen receipt, references it by digest without rewriting it, and reports what a verifier could confirm versus what the producer claimed. Verifier-side only — the live proxy and MCP paths do not consume it in allow/deny decisions. | [AARP v0.1 envelope](../specs/aarp-v0.1-envelope.md) |

## Integrity is not completeness

The distinction that most often causes evidence to be over-read:

- **Integrity of supplied records** — verification proves that the bytes it was
  given were signed by the trusted key, are linked in order, and were not
  mutated. This is what a passing verification establishes.
- **Completeness of mediated activity** — whether the record set contains
  *everything* that happened. Verification does not establish this.

A chain can be perfectly intact and still be missing records. The party holding
the signing key can omit records, a compromised key can be used to forge records
that are in-domain indistinguishable from real ones, and whole-session omission
before the first anchor is undetectable. Those are catalogued as
`L-KEYHOLDER-OMIT`, `L-FORGED-KEY`, and `L-OMIT-PRE-ANCHOR` in
[Evidence Hard Limits](hard-limits.md).

Anchors and coverage certificates narrow specific gaps. They do not convert
missing mediation into a completeness claim: `LIMITED` is the best completeness
result a coverage certificate can report, never `COMPLETE`.

## Pinned verification is the security claim

Verification comes in two strengths, and only one of them is a trust claim:

- **Pinned** — the verifier is given the expected public key or a trusted
  roster. A pass means *this specific trusted signer* produced the bytes. This
  is the security claim.
- **Unpinned (structural-only)** — the verifier confirms the signature is
  self-consistent and the hash linkage holds, but cannot establish *who* signed.
  This is explicitly weaker.

Unpinned runs are not a pass on their own: `pipelock verify-receipt` prints an
`UNPINNED` banner and exits non-zero unless `--allow-unpinned` is passed to
acknowledge the reduced guarantee. See
[Unpinned (structural-only) verification](../guides/receipt-verification.md#unpinned-structural-only-verification).

Signature validity proves that the key holder signed the verified bytes. It does
not prove that the key holder was honest, that no record was omitted, or that no
unmediated action occurred.

Four independent cross-language verifier implementations (Go, TypeScript, Rust,
and Python) exercise a shared conformance corpus. The browser wasm surface
reuses the Go implementation and is not counted as a separate implementation.
Divergent verdicts across implementations would break the shared-truth property,
catalogued as `L-VERIFIER-DRIFT` in [Evidence Hard Limits](hard-limits.md).

## Where to go next

- [Receipt verification](../guides/receipt-verification.md) — verify a receipt,
  a chain, or an Audit Packet, and the cross-implementation conformance suite.
- [Evidence Hard Limits](hard-limits.md) — the full catalog of what evidence
  cannot prove, and what would be needed to bound each limit.
- [Security Assurance](../security-assurance.md) — trust boundaries, security
  requirements, and how evidence maps to them.
- [Receipt transport coverage](../guides/receipt-transports.md) — which
  transports emit receipts.
