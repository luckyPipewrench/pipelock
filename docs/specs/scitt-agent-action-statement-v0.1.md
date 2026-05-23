# SCITT Signed-Statement Profile: Agent Action v0.1

> **Status:** Individual proposal, pre-Internet-Draft. Seeking feedback on the SCITT
> mailing list (`scitt@ietf.org`). Not seeking WG adoption in v0.1.
> **Profile of:** [`draft-ietf-scitt-architecture-22`](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)
> **Companion docs:**
> - [Pipelock Action Receipt implementation spec](https://pipelab.org/learn/action-receipt-spec/)
> - [Receipt prior-art mapping](./receipt-prior-art-mapping.md) (see the IETF SCITT section)
> - [in-toto attestation predicate (parallel artifact)](./in-toto-agent-action-receipt-v0.1.md)

## Terminology and naming collision

SCITT uses **"Receipt"** specifically for a transparency-service inclusion proof of a
Signed Statement. Pipelock uses **"receipt"** for its per-action runtime evidence
envelope. The terms are not the same and this profile is careful to keep them
separated:

| Pipelock vocabulary | SCITT vocabulary | This profile |
|---|---|---|
| ActionReceipt v1 / EvidenceReceipt v2 envelope | Signed Statement | "Agent Action Signed Statement" |
| `signer_key` (Ed25519 hex) | Issuer (and its key) | Issuer key |
| `target` on the action record | Subject | Subject |
| Pipelock policy bundle digest | Issuance context | Carried in the payload as `action_record.policy_hash` (per `internal/receipt/action.go`); this profile does not lift it into a COSE header parameter. |
| (none — no inclusion proof today) | Receipt (TS inclusion proof) | **Out of scope of v0.1.** Anchoring is the TS's job. |
| (combined for relying parties) | Transparent Statement (Signed Statement + Receipt) | Out of scope; produced by the TS after submission. |

**Throughout this document, "Statement" always means a SCITT Signed Statement and
"Receipt" always means a SCITT transparency-service Receipt.** When Pipelock's
runtime evidence envelope is meant, the document uses the explicit name
"ActionReceipt v1" or "EvidenceReceipt v2."

## What this is

This profile defines how a Pipelock mediator emits an agent-action verdict as a
**SCITT Signed Statement** so that the verdict can be submitted to any
SCITT-architecture Transparency Service for append-only anchoring, public
non-repudiation, and downstream verifiable retrieval.

It is **not** a new content model. The Statement payload carries the same
`action_record` bytes that Pipelock's ActionReceipt v1 already signs today. The
COSE_Sign1 wrapper around it is what makes the artifact a SCITT Signed Statement.

## What this is not

- **Not a Pipelock-controlled SCITT statement format.** SCITT statements are
  payload-format agnostic by design. This profile picks one payload encoding for
  one producer (Pipelock) and one shape of evidence (mediator-side agent action
  verdicts). Other producers, other payloads, and other agent-evidence shapes
  remain in scope of SCITT generally.
- **Not a competing draft to existing AI-agent statement proposals.** This
  profile complements the in-flight individual drafts in the SCITT WG; see
  "Position relative to existing drafts" below.
- **Not a charter expansion request.** v0.1 is an individual profile suitable for
  the SCITT architecture as currently chartered. No new TS behavior, no new COSE
  algorithm, no new mailing list goal.

## Why a SCITT profile at all

Pipelock already emits signed per-action receipts. The shipped envelope gives
tamper-evidence within a session through chain linkage. It does **not** give public
non-repudiation: a relying party three years from now has no way to prove that a
specific receipt was emitted on the date it claims, except by trusting Pipelock's
in-process state.

SCITT exists to solve exactly that gap — append-only anchoring of signed claims by
a third party — and is the standards-body convergence point for that capability
across supply chain, AI, and runtime-attestation work. Defining a profile means a
Pipelock receipt can be submitted to any SCITT TS without payload-format ambiguity,
and downstream auditors can verify the Statement (issuer signature + payload
structure) and the TS Receipt (inclusion proof) as two separate, independent
properties.

## Profile

### Statement structure (COSE_Sign1)

The Statement is a COSE_Sign1 ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html))
object with the following header parameters.

**Protected header:**

| Label | Name | Value | Description |
|---|---|---|---|
| 1 | `alg` | -8 | EdDSA per RFC 9053. The EdDSA algorithm identifier covers Ed25519 and Ed448; this profile pins the curve to Ed25519 out-of-band via the `kid` binding (the relying party's trust list records the 32-byte Ed25519 public key). A future revision MAY add an explicit curve-binding header. |
| 3 | `content-type` | `application/vnd.pipelock.action-record+json` | Distinguishes Pipelock action-record payloads from other AI-agent statement formats on the same TS. |
| 4 | `kid` | raw 32-byte Ed25519 public key | Same bytes as the Pipelock ActionReceipt v1 `signer_key` hex-decoded. SCITT architecture-22 places `kid` in the protected header when `x5t`/`x5chain` are not present; this profile relies on `kid` for key identification. Pinning the same `kid` across the v1 ActionReceipt and the SCITT Statement lets a relying party verify both wire formats with one trust anchor. |
| 15 | `CWT_Claims` | CWT claims map | Carries `iss` (CWT claim 1), `sub` (CWT claim 2), and `iat` (CWT claim 6). Label 15 is the IANA-registered COSE header parameter for `CWT_Claims` per RFC 9597; SCITT architecture-22 reuses it to bind issuer + subject identity to the Signed Statement. **Producers MUST place `CWT_Claims` only in the protected header.** RFC 9597 forbids the parameter from appearing more than once across the protected and unprotected headers of a single COSE structure. |

The protected header defined above satisfies the conformance requirements of
draft-ietf-scitt-architecture-22 §4.2 for Signed Statements (protected `kid`
plus `CWT_Claims` carrying `iss` and `sub`).

**Unprotected header:**

No required parameters in v0.1. Producers MAY include `x5chain` (label 33) or
other RFC 9052 parameters in the unprotected header but consumers conforming to
this profile MUST NOT rely on unprotected-header content for verification
decisions.

**Payload:**

The `payload` field of the COSE_Sign1 is the **canonical bytes of the Pipelock
ActionReceipt v1 `action_record`** — the same bytes Pipelock hashes with SHA-256
and then signs with Ed25519 on the v1 path (per `internal/receipt/receipt.go`:
`sum := sha256.Sum256(data); sig := ed25519.Sign(privKey, sum[:])`). The
COSE_Sign1 signature is taken over the COSE Sig_structure per RFC 9052 §4.4,
which composes its own digest internally; the SCITT signature and the v1
signature are over different sig-structures even though both sign the same
payload bytes.

**Canonicalization is mandatory and non-obvious.** The v1 ActionReceipt
canonicalizes by serializing the `ActionRecord` struct in **Go
struct-declaration order** (per `internal/receipt/action.go`), not RFC 8785
JCS. Producers MUST produce the same byte stream Pipelock's `pipelock-verifier`
and the cross-language SDK verifiers (`sdk/verifiers/ts`, `sdk/verifiers/rust`,
`pipelock-verify-python`) accept; arbitrary alphabetic-key-order JSON
serializers will produce different bytes and the COSE_Sign1 signature will not
verify. Cross-language producers that emit SCITT Statements without using
Pipelock's own emitter MUST mirror the struct-declaration order documented in
the implementation spec. The EvidenceReceipt v2 path uses RFC 8785 JCS — a
v0.2 SCITT profile may switch the payload to v2 bytes to remove this gotcha.

A future v0.2 may switch the payload to the EvidenceReceipt v2 typed-payload bytes,
which canonicalize via RFC 8785 JCS. v0.1 stays on v1 canonicalization to keep the
producer path simple — a v0.1 Statement is a re-wrapping of bytes Pipelock already
signs.

### CWT claims

| CWT claim | Source | Notes |
|---|---|---|
| `iss` (1) | Pipelock mediator identity URI | A SCITT Issuer identifier (URI). A v0.1 producer derives this from its persistent identity material; the recommended form is `https://pipelab.org/issuer/<mediatorId>` where `<mediatorId>` is a stable, deployment-bound, non-routable opaque identifier. The URI is an identifier, not a fetch endpoint; relying parties resolve it against their own trust list. |
| `sub` (2) | `action_record.target` | The "what was acted on" target string from the v1 ActionRecord, lifted as the SCITT Subject. |
| `iat` (6) | `action_record.timestamp` | UNIX seconds. Derived from the v1 `timestamp` field. |
| `exp` (4) | (absent) | Statements about historical actions do not expire. |

### Issuer trust model

A SCITT relying party verifies the Statement by:

1. Decoding the COSE_Sign1 envelope.
2. Looking up the Issuer's verification key (`kid` parameter) under the
   relying party's own trust policy.
3. Verifying the Ed25519 signature over the COSE_Sign1 sig-structure.

The Issuer key is the **action-receipt signing key** configured at
`flight_recorder.signing_key_path` in `pipelock.yaml` (per
`internal/config/schema.go`: "Ed25519 private key for checkpoint signing and
action receipts"). Note this is a **different key** than the mediation-envelope
signing key (`mediation_envelope.signing_key_path`); the latter signs HTTP-injected
mediation headers per RFC 9421 and is what Pipelock's
`/.well-known/http-message-signatures-directory` advertises. A v0.1 SCITT
Statement is signed with the flight-recorder key, not the mediation-envelope key.

SCITT explicitly leaves participant discovery out of scope. A v0.1 producer
publishes the Issuer public key via whatever channel its operator and relying
parties have agreed on — out-of-band trust-list distribution, organizational
PKI, or any other operator-managed mechanism. (Pipelock's
`pipelock envelope trust` CLI is **not** suitable for SCITT issuer-key
management; that CLI is scoped to mediation-envelope peers, which use a
different key.) Relying parties pin the 32-byte raw Ed25519 public key by
fingerprint and rotate via the channel of their choice. This profile defines no
new discovery mechanism.

## Submission to a Transparency Service

A relying party (or Pipelock itself, when configured) submits the COSE_Sign1
Statement to a SCITT TS via the [SCITT Reference APIs (SCRAPI)](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/).
The TS validates the Statement's syntactic structure, applies its own registration
policy (which MAY include payload-format-specific rules — for `application/vnd.pipelock.action-record+json`,
a TS may require Issuer identity from a specific trust domain), appends the
Statement to its verifiable data structure, and returns a SCITT Receipt — the
inclusion proof.

The Pipelock binary does NOT include a built-in TS client in v0.1. Producers may
submit Statements out of band; first-party SCRAPI submission is a v0.2 candidate.

## Position relative to existing SCITT-WG individual drafts

| Draft | Author | Layer | This profile's relationship |
|---|---|---|---|
| [`draft-emirdag-scitt-ai-agent-execution`](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/) | Pinar Emirdag (VERIDIC) | Post-execution business-process audit (Agent Interaction Record) | **Parallel — different granularity, same submission path.** Both define COSE_Sign1 SCITT Statements for AI-agent evidence and target the same SCITT TS submission path. AIR is a business-process record of an agent interaction (request, response, evidence); this profile is a per-network-action mediator verdict with a different issuer (the mediator, not the agent operator). A single AIR could reference multiple agent-action Statements as evidence. Neither profile is WG-adopted; consolidation under a future charter is explicitly welcome and this profile is offered as an input to that conversation, not as a competing claim on the same slot. |
| [`draft-nelson-agent-delegation-receipts`](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/) | Ryan Nelson (Authproof) | Pre-execution authorization (Delegation Receipt Protocol) | **Complementary.** DRP attests authorization before an agent acts. This profile attests what the mediator did when the agent acted. Three layers (pre-auth, action, post-execution) of the same evidence story. |
| [`draft-kamimura-scitt-refusal-events`](https://datatracker.ietf.org/doc/draft-kamimura-scitt-refusal-events/) | (Kamimura) | TS-side refusal evidence | Orthogonal. The agent-action Statement is the Issuer-side artifact; refusal events are TS-side. |
| [`draft-munoz-scitt-permit-profile`](https://datatracker.ietf.org/doc/draft-munoz-scitt-permit-profile/) | (Munoz) | Permit-style profile | Adjacent. Not on the agent-action surface. |

This profile does NOT attempt to consolidate or replace any of the above. Authors
of those drafts are invited to comment on the agent-action Statement shape.

## Active SCITT-WG context

Charter-expansion conversation around AI-agent evidence work has surfaced on
the SCITT mailing list in 2026. This profile is consistent with the **current**
charter (it's an individual profile of the existing architecture and requires
no charter change). It is also a candidate input to any future agent-evidence
convergence if the WG decides to scope new work. Anyone evaluating this profile
should check the active SCITT mail archive at
<https://mailarchive.ietf.org/arch/browse/scitt/> for the latest charter or
BoF threads before drawing conclusions about WG appetite.

## Verification flow (relying party)

1. Receive a SCITT Transparent Statement (Statement + Receipt) from a TS, or the
   bare Statement from a Pipelock instance.
2. Decode the COSE_Sign1 envelope; check `alg == EdDSA`, `content-type ==
   application/vnd.pipelock.action-record+json`, and that the protected
   header carries `CWT_Claims` (label 15).
3. Resolve the Issuer key by `kid` against the relying party's trust list.
4. Verify the COSE_Sign1 signature.
5. Parse the payload as a Pipelock action_record. Validate it against the
   [implementation spec](https://pipelab.org/learn/action-receipt-spec/) or the
   v0.1 schema used by Pipelock's first-party verifiers (`internal/receipt/`,
   `sdk/verifiers/{ts,rust}/`, `pipelock-verify-python`).
6. If a SCITT Receipt is attached: verify the TS inclusion proof against the TS's
   public verifiable data structure root. The Receipt verifies temporal anchoring;
   it does **not** re-verify the Statement signature.
7. Apply consumer policy on the v1 ActionRecord payload fields: `verdict`,
   `action_type`, `target`, `principal`, `actor`. The mediator identity is the
   CWT `iss` claim plus the COSE `kid` parameter, not a payload field — the v1
   ActionRecord carries no `mediator` object. Unknown payload fields MUST be
   treated as informational per the in-toto monotonic principle (mirror-borrowed
   here for the agent-action payload).

## Worked example

Same scenario as the [in-toto profile worked example](./in-toto-agent-action-receipt-v0.1.md#worked-example):
Pipelock blocks an MCP tool call attempting to exfiltrate an Anthropic API key.

The Statement is a COSE_Sign1 (binary CBOR). The CBOR diagnostic notation below is
**illustrative** — the protected-header bytes shown are placeholder bytes; real
implementations encode the protected map exactly per RFC 9052 §4.4. Use this as a
structural reference, not a wire-byte target.

```cbor-diag
/ COSE_Sign1 tag (18) /
18(
  [
    / 1. protected header — bstr-wrapped CBOR map /
    << {
      1: -8,                                       / alg = EdDSA /
      3: "application/vnd.pipelock.action-record+json",
      4: h'0000000000000000000000000000000000000000000000000000000000000000', / kid - synthetic example, not a real signing key /
      15: {                                        / CWT_Claims (RFC 9597) /
        1: "https://pipelab.org/issuer/pipelock-7f3c2b1e",  / iss /
        2: "api.attacker.example/v1/upload",       / sub /
        6: 1779730201                              / iat /
      }
    } >>,

    / 2. unprotected header (empty in v0.1) /
    {},

    / 3. payload — canonical bytes of the Pipelock action_record /
    h'<canonical action_record JSON bytes — see in-toto profile worked example
        for the decoded JSON content of this payload>',

    / 4. signature — Ed25519 over the Sig_structure per RFC 9052 §4.4 /
    h'<64-byte Ed25519 signature>'
  ]
)
```

The decoded payload is the same `action_record` bytes that the Pipelock binary
already signs with its native v1 envelope. Cross-format verification (v1
ActionReceipt vs SCITT Statement) succeeds when both envelopes' payload bytes
hash to the same SHA-256 digest.

## Differences from `draft-emirdag-scitt-ai-agent-execution`

For clarity, since both this profile and `draft-emirdag-scitt-ai-agent-execution`
define COSE_Sign1 SCITT Statements for AI-agent evidence:

| Axis | This profile (`agent-action` v0.1) | `draft-emirdag-scitt-ai-agent-execution` |
|---|---|---|
| **Granularity** | One Statement per mediated network action (DNS, HTTP, MCP tool call, WebSocket frame) | One Statement per agent interaction (request + response + evidence) |
| **Issuer** | The mediator (Pipelock instance) | The agent operator |
| **Trust model** | Mediator runs outside the agent's trust boundary; signs what the mediator decided | Agent operator runs the agent and attests after the fact |
| **Payload** | `application/vnd.pipelock.action-record+json` (Pipelock action_record bytes) | `AgentInteractionRecord` (AIR) — agent-operator-defined |
| **Use cases** | Procurement evidence "this agent could not have exfiltrated X because the mediator blocked it"; runtime SOC monitoring; per-action audit trail | Business-process audit, regulatory reporting per EU AI Act / DORA / NIST AI RMF / PCI DSS |
| **Composition** | An AIR can carry references to many agent-action Statements as evidence | The agent-action Statement is a primitive AIR can cite |

The two formats are not in tension. They serve different audiences and answer
different questions about the same agent activity.

## Open questions

- **`content-type` IANA registration.** `application/vnd.pipelock.action-record+json`
  is a vendor-tree media type per RFC 6838 §3.2; vendor-tree types are
  registered via IANA Expert Review. v0.1 ships as an experimental
  pre-registration profile; the registration request is a v0.2 deliverable
  once the receipt format itself is more publicly visible.
- **CWT claims label allocation.** v0.1 uses the IANA-registered COSE header
  parameter for `CWT_Claims` (label 15, RFC 9597). The SCITT architecture's
  identity-binding convention is built on top of this registration; if a future
  architecture revision adds additional SCITT-specific header parameters, this
  profile will track them at the next minor version.
- **Multi-signature.** v0.1 emits one signature. Co-signing (e.g., mediator +
  organizational signer) is a v0.x consideration; the COSE_Sign envelope (NOT
  COSE_Sign1) covers that case if needed.
- **Transparency-service onboarding.** No specific TS implementation is named in
  v0.1. Conformance to SCRAPI is the goal.

## References

- [SCITT Architecture (draft-ietf-scitt-architecture-22)](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)
- [SCITT Reference APIs (draft-ietf-scitt-scrapi-10)](https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/)
- [SCITT WG documents](https://datatracker.ietf.org/group/scitt/documents/)
- [SCITT mailing list archive](https://mailarchive.ietf.org/arch/browse/scitt/)
- [`draft-emirdag-scitt-ai-agent-execution`](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/)
- [`draft-nelson-agent-delegation-receipts`](https://datatracker.ietf.org/doc/draft-nelson-agent-delegation-receipts/)
- [RFC 9052 (COSE)](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 9053 (COSE algorithms)](https://www.rfc-editor.org/rfc/rfc9053.html)
- [RFC 9597 (CWT Claims in COSE Headers — defines `CWT_Claims` as label 15)](https://www.rfc-editor.org/rfc/rfc9597.html)
- [RFC 8392 (CWT)](https://www.rfc-editor.org/rfc/rfc8392.html)
- [RFC 8032 (Ed25519)](https://www.rfc-editor.org/rfc/rfc8032.html)
- [Pipelock Action Receipt implementation spec](https://pipelab.org/learn/action-receipt-spec/)
- [Pipelock receipt prior-art mapping](./receipt-prior-art-mapping.md)
