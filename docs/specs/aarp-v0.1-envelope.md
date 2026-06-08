# AARP v0.1 — Assurance Envelope and Appraisal Profile

> **Status:** Experimental. Pipelock owns the `aarp/v0.1` profile namespace.
> **Implementation:** `internal/aarp/` (Go reference verifier and signer).
> **Depends on:** the shipped RFC 8785 JCS canonicalization (`internal/contract`)
> and the offline X.509-SVID substrate (`internal/svid`).
> **Companion docs:** [in-toto agent-action-receipt v0.1](./in-toto-agent-action-receipt-v0.1.md),
> [receipt prior-art mapping](./receipt-prior-art-mapping.md).

## What AARP is

AARP — Agent Action Receipt Profile — is **not a new receipt format**. It is an
*appraisal profile*: a separate, independently-signed assurance artifact that
sits **alongside** a frozen Pipelock receipt and reports exactly what a verifier
could cryptographically confirm versus what the producer merely claimed.

The shipped receipts stay byte-for-byte frozen. AARP references them by digest
and never rewrites them:

| Receipt | Wire format | AARP relationship |
|---|---|---|
| **ActionReceipt v1** | flat JSON, Ed25519 over `SHA-256` of canonical bytes | immutable subject, referenced by digest |
| **EvidenceReceipt v2** | typed payloads, RFC 8785 JCS | immutable subject, referenced by digest |

The AARP verifier **never emits a `trusted` or `safe` verdict.** It emits a
structured appraisal: verified claims grouped by axis, the producer's
claimed-but-unverified set, and an explicit `does_not_assert` list.

## Core principle: validity is not assurance

A valid signature proves record integrity — these bytes were signed by this key
and not altered. It proves nothing about whether the decision was correct,
whether anything bypassed the mediator, or whether the receipt is the whole
story. AARP's job is to make that distinction machine-readable.

## The envelope

```jsonc
{
  "profile": "aarp/v0.1",
  "subject": {
    "action_record_sha256": "<64 lowercase hex>",
    "receipt_envelope_sha256": "<64 lowercase hex>",
    "receipt_signer_key": "<64 lowercase hex; the receipt's Ed25519 public key>",
    "receipt_type": "action_receipt_v1 | evidence_receipt_v2"
  },
  "assertion": {
    "claimed": ["mediated", "complete-mediation"],
    "mediator_id": "pipelock-prod-1",
    "trust_domain": "example.org",
    "complete_mediation": true,
    "evidence_refs": ["spiffe_svid"],
    "issued_at": "2026-06-01T00:00:00Z"
  },
  "chain": {
    "issuer_id": "issuer-1",
    "seq": "42",
    "prior_hash": "<64 lowercase hex of the previous link's payload digest>"
  },
  "signatures": [
    {
      "protected": {
        "profile": "aarp/v0.1",
        "canon": "jcs-rfc8785-nfc",
        "alg": "ed25519",
        "key_type": "ed25519",
        "key_id": "mediator-key-1",
        "signer_role": "mediator",
        "crit": []
      },
      "sig": "ed25519:<base64-std>"
    }
  ],
  "crit_ext": [],
  "ext": {}
}
```

### Signed payload

Every signature covers the **canonical payload**: the JCS bytes of
`{profile, subject, assertion, crit_ext, chain}`. `crit_ext` is signed so a
man-in-the-middle cannot strip a critical extension a producer flagged.
Signatures never cover `signatures` (signatures do not sign each other) or `ext`
(non-critical extensions are advisory and ignored safely). The canonical payload
digest (lowercase-hex `SHA-256` of the canonical bytes) is the single value all
parallel signatures bind, and is the value the SVID attestation binding
references as `assurance_assertion_sha256`.

### Signing input (domain separation)

Each signature signs the JCS canonicalization of:

```jsonc
{
  "context": "pipelock-aarp-v0.1/assurance-assertion",
  "payload_sha256": "<canonical payload digest>",
  "protected": { /* that signature's protected suite header */ }
}
```

The `context` is a **signed field**, never a sibling label — real cryptographic
domain separation. String concatenation is never used to form a signing input.
Embedding the `protected` header in the signing input means each signature
commits to its own suite, which defeats algorithm substitution; binding the
shared `payload_sha256` means all signatures cover **identical payload bytes**.

## Authenticated agility: the protected suite

The `protected` header is the signature's agility descriptor, and it is covered
by the signature. It carries the profile version, canonicalization id,
algorithm, key type, key id, signer role, and the critical-extension list.

**Fail-closed rule:** an unknown `signature_suite` (unrecognized algorithm,
profile, or canonicalization) never verifies and is **never downgraded** to
verification under a different suite. There is no fallback. A signature under an
unknown suite is reported `unknown_suite`; one under a recognized-but-
unimplemented suite (the post-quantum slot) is reported `unimplemented`. Neither
ever counts as a verified signature.

## Parallel multi-signature

The envelope holds **N parallel protected signatures over identical canonical
payload bytes**. They are parallel — each independently binds the same payload
digest under its own suite — **not chained** over one another. Countersignature
(continuity over a prior signature) is a deliberately distinct, separately-typed
construct and is not mixed into the parallel set.

v0.1 ships **Ed25519** as the default and only implemented suite. The
**ML-DSA-65** post-quantum slot is typed and structurally first-class: a hybrid
(`ed25519` + `ml-dsa-65`) or PQ-only envelope is a valid shape today, and adding
a PQ signature slot requires **no format bump**. The PQ signer/verifier is
deferred until FIPS 204 / ML-DSA errata settle; until then a PQ signature is
reported `unimplemented`, never verified.

## JCS number safety

JSON numbers are interoperable across language verifiers only inside the I-JSON
safe-integer range `[-(2^53-1), 2^53-1]`. Outside it, a JavaScript (or other)
verifier silently rounds to the nearest `float64`, which changes the canonical
bytes and breaks the signature.

AARP therefore:

- allows raw JSON numbers **only** inside the I-JSON safe-integer range;
- forbids floats, exponent form, and negative zero outright;
- requires every identity, digest, counter, nanosecond-timestamp, and amount
  field to be a **typed string** with an explicit grammar:
  - digest / key: exactly 64 lowercase hex characters;
  - counter / sequence / ns-timestamp: unsigned decimal, no leading zeros,
    within `uint64`;
  - amount: fixed-point decimal, optional minus, no leading/trailing zeros, no
    exponent, no negative zero;
  - time: RFC 3339 with a mandatory zone (`RFC3339Nano`).

A raw JSON number outside the safe range, anywhere in the envelope, is rejected
at decode. The same value as the typed-string grammar verifies identically
across every conforming verifier.

## Schema, extensions, and exact digest targeting

- **Strict decode.** Duplicate object keys are rejected at the raw-JSON layer at
  any nesting depth (parser-differential smuggling guard). Unknown fields in
  AARP-controlled objects are rejected — unlike legacy v1 receipt objects, where
  unknown fields are ignored for backward compatibility and never counted as
  signed.
- **Extension governance.** `crit` (per signature) and `crit_ext` (envelope)
  list critical-extension names the verifier **must** understand; an unknown one
  fails closed. The *scope* of that failure follows what is signed. A per-
  signature `crit` lives in one signature's protected header, and the signatures
  array is not itself signed (it is appendable), so an unknown per-signature
  `crit` makes only **that signature** unverifiable (`unknown_suite`) — it never
  rejects an envelope that also carries a verifiable signature, so an appended
  junk signature cannot deny a valid receipt. An unknown **envelope-level**
  `crit_ext` is part of the signed payload (an attacker cannot append it without
  breaking every signature), so it **rejects the whole envelope**. The same scope
  rule applies to a signature's protected `profile`/`canon`: a mismatch is
  per-signature `unknown_suite`, while the signed top-level `profile` is
  envelope-fatal. Unknown **non-critical** extensions (`ext`) are ignored safely
  and are not part of the signed payload.
- **Exact digest targeting.** `subject.receipt_type` names which frozen receipt
  format the digests target (`action_record_sha256` is the v1 canonical
  ActionRecord digest or the v2 EvidenceReceipt signable-preimage digest, per
  type). Every digest is a named, typed-string field — never an ambiguous "hash
  of the thing".

## Rung-1 timestamp trust: the chain primitive

The optional `chain` object places an envelope in an issuer's append-only,
hash-linked stream. It is **issuer-agnostic**: any issuer that maintains a
monotonic `seq` and links each receipt's payload digest to the prior one
(`prior_hash`) gets backdating detection, with no dependency on a specific
issuer deployment.

Because the chain link is part of the signed payload, `seq` and `prior_hash`
cannot be altered after signing. A verifier checking a stream confirms a single
issuer, a sequence incrementing by exactly one, and each link's `prior_hash`
equal to the previous envelope's payload digest. Inserting, reordering, or
backdating a receipt within the stream breaks the linkage and the signature, and
is detected. The genesis link carries `seq` `"0"` and the all-zero `prior_hash`.

## Key-time evidence

A verified `mediated` claim binds a signing key to an **authority namespace**,
never to a bare key: it requires a verifier-side trust entry naming the mediator
identity (and, when set, the signer role and trust domain) that the verifying
signature's key id matches. An attacker self-signing with `signer_role=mediator`
and no matching trust entry gets `mediated` reported claim-only.

Revocation status is **snapshotted at signing time** and is a distinct, additive
artifact from any later-compromise evidence; a verifier never re-fetches live
material to reinterpret an old receipt.

## SVID attestation binding (verified workload identity)

A producer may attach **X.509-SVID** evidence that cryptographically proves the
workload identity that mediated the action. Only X.509-SVID counts toward
verified workload identity; JWT-SVID is a bearer token and stays claim-only.

The SVID leaf's private key signs a **binding payload**, JCS-canonicalized, which
carries a signed domain-separation context field
`pipelock-aarp-v0.1/svid-receipt-binding` (JCS sorts object keys, so the context
is part of the signed bytes but not necessarily first in canonical order):

```jsonc
{
  "context": "pipelock-aarp-v0.1/svid-receipt-binding",
  "profile": "aarp/v0.1",
  "action_record_sha256": "<v1 ActionRecord digest>",
  "receipt_envelope_sha256": "<receipt envelope digest>",
  "assurance_assertion_sha256": "<the envelope's canonical payload digest>",
  "receipt_signer_key": "<receipt Ed25519 public key>",
  "mediator_id": "pipelock-prod-1",
  "spiffe_id": "spiffe://example.org/mediators/pipelock-prod",
  "issued_at": "RFC3339Nano",
  "nonce": "<128-bit random, base64url>"
}
```

The verifier confirms, all offline and fail-closed:

- the SVID chain validates to a **pinned historical trust bundle** at the
  **action time** (not "now"), via the shared `internal/svid` substrate;
- the SVID's trust domain matches and its SPIFFE ID is permitted by policy;
- the binding's `assurance_assertion_sha256` equals the envelope's canonical
  payload digest, and `receipt_signer_key` matches the receipt — so the SVID is
  bound to *this* receipt and assertion (the `nonce` defeats cross-action replay);
- the proof-of-possession signature verifies under the SVID leaf key (ECDSA-P256
  or Ed25519; a declared algorithm that disagrees with the leaf key type fails
  closed).

On success the verifier adds `signing_workload_svid_chain_validated` and
`signing_workload_svid_bound` to the **identity** axis and
`signing_workload_svid_valid_at_action_time` to the **freshness** axis. Because an
SVID identity is not a containment proof, it also adds the paired negatives
`does_not_assert_network_non_bypass_from_identity` and
`does_not_assert_deployment_enforcement_from_identity` to `does_not_assert`, and
emits the `svid_identity_is_not_deployment_non_bypass` overclaim risk. Attestation
is only considered on a **signed** assertion (the binding ties to the signed
assertion digest). An SVID that fails any check never removes a core claim and
never adds an attestation one; the producer's workload-identity claim is reported
claimed-but-unverified, with a warning.

## Appraisal vocabulary

The verifier reports claims grouped by axis — `identity`, `authority`,
`integrity`, `freshness`, `transparency`, `deployment` — never a single linear
trust score, because the axes rest on orthogonal kinds of proof. "An appraisal
was made" never implies "action allowed", "policy passed", or "human approved".

The fixed `does_not_assert` list is reported verbatim on every appraisal:
`absence_of_bypass`, `action_safety`, `all_tools_discovered`,
`complete_mediation`, `delegated_actions_mediated`, `efficacy`,
`hosted_saas_actions_mediated`, `intent_correctness`, `key_non_compromise`,
`local_side_effects_mediated`, `policy_correctness`, and
`semantic_equivalence_after_modify`. Complete mediation is **always** claim-only
in v0.1: there is no local evidence that proves the absence of an out-of-band
path.

Token spelling, to avoid confusion: the producer claim string placed in
`assertion.claimed` is the hyphenated `complete-mediation`; the snake_case
`complete_mediation` is the boolean field on the assertion and the entry in
`does_not_assert`. All forms are claim-only; the verifier never moves complete
mediation into `verified_claims`.

## Not externally registry-verifiable by default

The default `aarp/v0.1` receipt is JCS + Ed25519 and is independently verifiable
by the AARP verifier offline. It is **deliberately not** verifiable by external
registry-based runtime-control or audit standards by default: those registries
do not bless Ed25519. Interop with such a standard is delivered, if and when
needed, by a derivative **external-audit projection** — and a projection is a
*lossy export of a stronger source*, never the source receipt itself:

> AARP core receipts are independently verifiable but are not, by default,
> verifiable under external registry-based audit standards. An external-audit
> projection is a derivative export, not the source receipt.

## v1 permanence

v1 receipt verification is **permanent product surface**. The v1 fields, its
`json.Marshal` canonicalization, and its Ed25519-over-SHA-256 signing are frozen
forever, with published test vectors. AARP may optionally countersign an old v1
receipt over the v1 receipt hash to add continuity, but it must **never** mutate
or reinterpret v1 evidence.

## Designed, not yet implemented

These slots are designed here so they drop in additively with no breaking
migration. Their implementations are gated on external foundations.

### External-audit projection + anti-laundering invariants

A projection re-expresses an AARP appraisal for a consumer of an external
runtime-control or audit standard. The **format must carry**, and a verifier
must enforce:

- the **source canonical payload hash** (binds the projection to one receipt);
- the source profile + version, and the source signature reference (key id +
  alg) it derives from;
- the projection **mapping version** and **projection issuer**, and a timestamp;
- an explicit list of **dropped, narrowed, and renamed** fields.

**Anti-laundering invariant:** a projected claim may **never** be stronger than
its source claim. A projection that asserts a claim the source reported
claim-only, or that drops the `does_not_assert` list, is invalid. Concrete
field mappings to specific external standards are defined only once those
standards publish a stable, testable version with a conformance story; the
projection format and the anti-laundering invariants above are fixed now and are
standard-agnostic.

### Rung-2 external TSA slot

An RFC 3161 Trusted Timestamping Authority token may be stapled to an envelope
under a non-critical extension, with the TSA certificate bundled for offline
verification. The slot is config-wired; the TSA is operated by an external party
(no infrastructure for Pipelock). Implementation may land later.

### Rung-3 transparency log

Self-hosted transparency log / SCITT / Rekor verification stays v0.2+ and
document-only. The `transparency` axis is claim-only in v0.1. Pipelock does not
operate a log.

## Verifier result contract

```jsonc
{
  "profile": "aarp/v0.1",
  "assertion_signed": true,
  "signatures": [ { "key_id": "...", "alg": "ed25519", "signer_role": "mediator", "status": "verified" } ],
  "assurance_claimed": ["mediated", "complete-mediation"],
  "verified_claims": ["receipt_signature_valid", "mediator_key_pinned"],
  "claimed_unverified": ["complete-mediation"],
  "axes": {
    "identity": ["mediator_key_pinned"],
    "integrity": ["receipt_signature_valid"]
  },
  "does_not_assert": ["absence_of_bypass", "action_safety", "all_tools_discovered", "complete_mediation", "delegated_actions_mediated", "efficacy", "hosted_saas_actions_mediated", "intent_correctness", "key_non_compromise", "local_side_effects_mediated", "policy_correctness", "semantic_equivalence_after_modify"],
  "overclaim_risks": ["signature_valid_is_not_transparency_inclusion"],
  "assurance": { "axes_with_verified_claims": ["identity", "integrity"] },
  "warnings": []
}
```

The default human (`--json`-off) view leads with `does_not_assert` and
`overclaim_risks` BEFORE the verified claims: the first thing a reader sees is
what the evidence does NOT prove. `assurance.axes_with_verified_claims` is a
computed descriptor of evidence breadth (which of the six axes hold a verified
claim), never a grade or score.

`assertion_signed` is the single cryptographic gate: true only when at least one
parallel signature verified under a trusted key. A relying party applies its own
claim policy to `verified_claims` and `axes`. There is no global threshold and
no `trusted`/`safe` field.

## Governance

Pipelock maintains `aarp/v0.x` as an open implementation profile; governance can
move once independent implementers exist. No foundation cosplay, no self-run
transparency log, no certification mark.
