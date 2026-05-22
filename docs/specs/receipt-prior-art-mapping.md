# Action Receipt Prior-Art Mapping

> **Status:** Reference doc. Not normative.
> **Companion to:** the implementation spec at https://pipelab.org/learn/action-receipt-spec/
> and the v0.1 tombstone at [receipt-format-v01.md](./receipt-format-v01.md).

Pipelock's action receipt format is mechanical on purpose: Ed25519 over SHA-256 of a
canonical JSON action record, chained by hash. That mechanical shape lets it overlap
with existing evidence formats without asking any of them to change. This doc maps the
shipped receipt primitives to the standards they touch, calls out the gaps, and points
each primitive at the body where standards work would land.

The intent is that Pipelock leads a **reference implementation plus conformance corpus**,
not a Pipelock-controlled format. When an existing standard already covers a primitive,
the path forward is to lift the primitive into that standard rather than ship a parallel
Pipelock spec.

## Per-primitive map

| Pipelock primitive | Where it lives in the spec | Closest existing standard | Gap | Filing destination |
|---|---|---|---|---|
| Flat receipt envelope (`version`, `action_record`, `signature`, `signer_key`) | [Envelope](https://pipelab.org/learn/action-receipt-spec/#envelope) | None 1:1; COSE_Sign1 (RFC 9052, structures; RFC 9053, algorithms) or DSSE wrap the same shape | No standard wrapper today; envelope is custom JSON | SCITT (statement payload), in-toto (DSSE) |
| Ed25519 signature over SHA-256 digest | [Signing](https://pipelab.org/learn/action-receipt-spec/#signing) | RFC 8032 (Ed25519), FIPS 180-4 (SHA-256) | None | n/a |
| Canonical JSON in struct-declaration order with HTML-safe escaping | [Canonicalization](https://pipelab.org/learn/action-receipt-spec/#canonicalization) | RFC 8785 (JCS) for the v2 envelope | v1 canonicalization is not RFC 8785; cross-language verifiers must mirror Go struct order | RFC 8785 canonicalization in the next v1 successor; EvidenceReceipt v2 already uses JCS |
| Hash-chain linkage (`chain_prev_hash`, `chain_seq`) | [Chain linkage](https://pipelab.org/learn/action-receipt-spec/#chain-linkage) | SCITT (transparency ledger), in-toto attestation chains | No inclusion proof; chain is session-local, not anchored to a transparency log | IETF SCITT WG |
| `action_id` (UUIDv7) | [Action record](https://pipelab.org/learn/action-receipt-spec/#action-record) | RFC 9562 UUID v7 | None | n/a |
| `action_type` enum (`read`, `write`, `delegate`, `authorize`, `spend`, `commit`, `actuate`, `derive`, `unclassified`) | [Action types](https://pipelab.org/learn/action-receipt-spec/#action-types) | OWASP Agentic Skills Top 10 vocabulary (in development); CSA AARM authority taxonomy | No cross-vendor agreement on action-type names today | OWASP Agentic Skills Top 10; CSA AARM TWG |
| `principal` and `actor` strings | [Action record](https://pipelab.org/learn/action-receipt-spec/#action-record) | SPIFFE workload identity; Cloudflare Signed Agents (vendor identity) | Identity binding is a loose `type:identifier` string today | SPIFFE SDK integration; cross-reference Signed Agents in the spec |
| `delegation_chain` array | [Action record](https://pipelab.org/learn/action-receipt-spec/#action-record) | OAuth 2 token delegation; CSA AARM authority delegation | No standard machine-readable delegation grammar | CSA AARM TWG |
| `policy_hash` | [Action record](https://pipelab.org/learn/action-receipt-spec/#action-record) | in-toto attestation predicates; SLSA build-policy hashing | Policy bundle format is Pipelock-specific | in-toto / SLSA community |
| `verdict` enum (`allow`, `block`, `warn`, `ask`, `strip`, `forward`, `redirect`) | [Verdicts](https://pipelab.org/learn/action-receipt-spec/#verdicts) | OpenTelemetry span status (coarse) | No fine-grained verdict vocabulary in any general telemetry standard | OpenTelemetry GenAI semantic conventions |
| `transport` (free-form: `fetch`, `forward`, `intercept`, `websocket`, `mcp_stdio`, `mcp_http`, `mcp_http_upstream`, `mcp_http_listener`, `mcp_ws`) | [Transports](https://pipelab.org/learn/action-receipt-spec/#transports) | MCP security spec transport taxonomy | MCP draft does not yet enumerate audit transport identifiers | OASIS CoSAI Ws4 MCP security spec |
| `signer_key` (raw hex public key) | [Envelope](https://pipelab.org/learn/action-receipt-spec/#envelope) | RFC 7517 JWK; RFC 9421 `keyid` parameter | Raw hex is not portable across JWK consumers | JWK profile for receipt verifiers |
| Audit Packet wrapping (posture, verifier verdict, summary buckets) | [`sdk/audit-packet/v0.json`](../../sdk/audit-packet/v0.json) | SCITT inclusion bundle; in-toto attestation bundle | Audit Packet schema is Pipelock-specific | SCITT (as inclusion proof container) |
| EvidenceReceipt v2 typed payloads + `record_type` discriminator | [EvidenceReceipt v2](https://pipelab.org/learn/action-receipt-spec/#evidencereceipt-v2-v2-4) | COSE_Sign1 (RFC 9052/9053) typed payloads | Not COSE-wrapped today | COSE/JOSE profile for SCITT compatibility |
| `parent_action_id` (action-lineage correlation) | [Action record](https://pipelab.org/learn/action-receipt-spec/#action-record) | OpenTelemetry `parent_span_id`; W3C Trace Context | No standard linkage from receipts to OTel parent/child IDs | OpenTelemetry GenAI signed-event extension |
| `intent` (free-form action purpose) | [Action record](https://pipelab.org/learn/action-receipt-spec/#action-record) | None | Free-form text; no standard intent vocabulary | OWASP Agentic Skills Top 10 (informational only) |
| `data_classes_in` / `data_classes_out` (DLP class labels) | [Action record](https://pipelab.org/learn/action-receipt-spec/#action-record) | OWASP MCP Top 10 DLP category; NIST AI RMF data-class taxonomy (draft) | No closed cross-vendor vocabulary today | OWASP MCP Top 10; CSA AARM |
| `side_effect_class` enum (`none`, `external_read`, `external_write`, `financial`, `physical`) | [Side effect classes](https://pipelab.org/learn/action-receipt-spec/#side-effect-classes) | CSA AARM action-impact taxonomy (in development) | No agreed enum across vendors | CSA AARM TWG |
| `reversibility` enum (`full`, `compensatable`, `irreversible`, `unknown`) | [Reversibility](https://pipelab.org/learn/action-receipt-spec/#reversibility) | CSA AARM remediation taxonomy | No agreed enum across vendors | CSA AARM TWG |
| `method`, `layer`, `pattern`, `severity`, `request_id` (scanner verdict context) | [Optional fields](https://pipelab.org/learn/action-receipt-spec/#optional-fields-omitempty) | OWASP API Security Top 10 fields; OpenTelemetry HTTP semconv | No standard binding | OpenTelemetry GenAI signed-event extension |
| Taint-and-task fields (`session_taint_level`, `session_contaminated`, `recent_taint_sources`, `session_task_id`, `session_task_label`, `authority_kind`, `taint_decision`, `taint_decision_reason`, `task_override_applied`) | [Optional fields](https://pipelab.org/learn/action-receipt-spec/#optional-fields-omitempty) | None 1:1; the family of session-contamination controls in OWASP Agentic Skills Top 10 covers similar concerns | Adaptive-enforcement context vocabulary is Pipelock-specific | OWASP Agentic Skills Top 10; OpenTelemetry GenAI extension |
| Contract-binding fields (`contract_winning_source`, `contract_live_verdict`, `contract_policy_sources`, `contract_rule_id`, `active_manifest_hash`, `contract_hash`, `contract_selector_id`, `contract_generation`) | [Optional fields](https://pipelab.org/learn/action-receipt-spec/#optional-fields-omitempty) | in-toto attestation predicate "policy" linkage; SCITT statement issuer-binding | Contract format is Pipelock-specific; the hash-bound shape maps cleanly into in-toto predicates and SCITT statement payload | in-toto / SLSA community; IETF SCITT WG |
| `redaction` summary (DLP outcome: profile, parser, totals by class, cache-boundary kept) | [Optional fields](https://pipelab.org/learn/action-receipt-spec/#optional-fields-omitempty) | OWASP MCP Top 10 DLP control mapping | Pipelock-specific shape; the per-class counts could feed a standard DLP-outcome predicate | OWASP MCP Top 10; OpenTelemetry GenAI extension |
| `shield` summary (Browser Shield response rewrites: extension probes, tracking beacons, agent traps, SVG vectors) | [Optional fields](https://pipelab.org/learn/action-receipt-spec/#optional-fields-omitempty) | OWASP MCP Top 10 indirect-injection controls; OWASP Top 10 web | Pipelock-specific; no standard browser-shield outcome vocabulary | OWASP MCP Top 10 |
| Jurisdiction fields (`venue`, `jurisdiction`, `rulebook_id`, `remedy_class`, `contestation_window`, `precedent_refs`) | [Optional fields](https://pipelab.org/learn/action-receipt-spec/#optional-fields-omitempty) | CSA AARM authority-and-remedy taxonomy; W3C VC dispute model | Reserved for forward compatibility; not populated by current binaries | CSA AARM TWG |

The rest of this doc is per-standard reference notes that expand the table.

## IETF SCITT

**Standard:** Supply Chain Integrity, Transparency, and Trust ([draft-ietf-scitt-architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)).

**What it defines:** A generic architecture for append-only transparency services that
accept signed claims ("statements") from issuers, bind them into a Merkle-tree-backed
ledger, and emit verifiable inclusion receipts. Payload format is generic by
design through COSE_Sign1 (RFC 9052/9053) wrapping.

| SCITT concept | Receipt primitive | Notes |
|---|---|---|
| Statement payload | The signed action_record (or v2 evidence payload) | A receipt is a SCITT-compatible statement once wrapped in COSE_Sign1. |
| Issuer | `signer_key` plus org binding | SCITT expects an issuer identity; Pipelock signs from a mediator key bound to the deployment. |
| Statement hash | `SHA-256(canonical(action_record))` | Same bytes Pipelock uses for `chain_prev_hash` linkage. |
| Inclusion receipt | Not in scope today | Pipelock chains receipts to each other; SCITT additionally proves inclusion in a transparency log. |
| Verifier | `pipelock verify-receipt`, `pipelock-verifier`, `sdk/verifiers/*` | Verifies without a transparency log; can compose with one. |

**Relationship:** Orthogonal. SCITT is "this statement was recorded publicly and cannot
be retracted." Receipts are "what's inside the statement." A SCITT transparency service
could ingest Pipelock receipts today without spec changes; from SCITT's point of view
the receipt is opaque payload bytes.

**Scope clarification:** Receipts are not a transparency log. Chain linkage within a
session gives tamper-evidence, not public non-repudiation. For non-repudiation, layer
SCITT or an equivalent log on top.

## RFC 9421: HTTP Message Signatures

**Standard:** [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) signs HTTP requests
and responses so intermediaries can verify origin and integrity.

| RFC 9421 concept | Receipt primitive | Notes |
|---|---|---|
| Signed components | `target`, `method`, `transport` on the action record | Receipts capture the action semantically, not the byte-for-byte request. |
| `keyid` parameter | `signer_key` | RFC 9421 `keyid` is an application-defined key identifier; receipts use raw hex today. A JWK or JWK-thumbprint (RFC 7638) profile would make the identifier resolver-friendly. |
| Signature algorithm | `ed25519` | RFC 9421 supports ed25519. |
| Integration point | `X-Pipelock-Block-Reason-Receipt` response header (opaque ULID receipt ID) | Block responses already carry a receipt ID per the [block-reason header spec](./block-reason-header.md); relying parties can fetch the matching receipt through the transports documented at [`docs/guides/receipt-transports.md`](../guides/receipt-transports.md). Embedding a full receipt inline in an HTTP header is a possible future profile, not shipped today. |

**Relationship:** Different problem. RFC 9421 proves "this HTTP message has not been
modified." Receipts prove "an authorized agent caused this semantic action." Both can
apply to the same request:

1. Agent to Pipelock: unsigned request on loopback.
2. Pipelock to origin: RFC 9421 signed request (optional).
3. Pipelock emits a receipt covering the decision to make that request.

Pipelock already ships RFC 9421 envelope signing and a `/.well-known/http-message-signatures-directory`
endpoint for verifier key discovery; that's transport-side, separate from receipt
content.

**Scope clarification:** Receipts do not replace transport-level signatures. They
describe the action, not the bytes.

## OpenTelemetry GenAI semantic conventions

**Standard:** [OTel GenAI](https://opentelemetry.io/docs/specs/semconv/gen-ai/) semantic
conventions for LLM and agent telemetry.

| OTel attribute | Receipt primitive | Notes |
|---|---|---|
| `gen_ai.agent.id` / `gen_ai.agent.name` | `actor` | The `type:identifier` shape fits the flat `actor` string. |
| `gen_ai.tool.name` | `method` (when transport starts with `mcp_`) | MCP tool name is carried in the top-level `method` field. |
| Span status | `verdict` | `allow` / `block` / `warn` maps to OK / Error / Unset for coarse alerting. |
| `trace_id` / `span_id` | Not in v1 | The v1 schema has no `trace_id` field; correlating spans to receipts today means matching on `action_id` or maintaining an out-of-band map. A `trace_id` extension is an obvious successor addition. |
| `gen_ai.system` | Not in v1 | No mediator-version field on v1; the EvidenceReceipt v2 envelope carries deployment context for contract-aware payloads. |

**Relationship:** OpenTelemetry provides **traces**; receipts provide **evidence**.
Traces are sampled, mutable, and exist to debug performance. Receipts are mandatory
(one per action), signed, and exist to adjudicate disputes. Both should exist for the
same action.

**Engagement notes:** A "signed event" extension to OTel GenAI in which a span carries
an optional `gen_ai.evidence.receipt_id` pointer is the natural overlap. Position as
complementary, not competitive.

## Cloudflare Signed Agents

**Proposal:** A Cloudflare proposal for cryptographically verified bot identity through
HTTP headers. Site owners can allow specific signed agent identities past bot defenses.

| Signed Agents concept | Receipt primitive | Notes |
|---|---|---|
| Agent identity | `actor` | Same "who" question, single flat string on the action record. |
| Issuer | Typically the model or runtime vendor | Signed Agents binds to vendor identity; receipts bind to mediator identity (`signer_key`). Different signers, same wire surface. |
| Scope | "This bot exists" | Receipts add: "This bot was authorized by this principal to take this action right now." |
| Verification point | Target origin server | Both target the origin server deciding whether to accept the request. |

**Relationship:** Two layers of the same stack. Identity (Signed Agents) answers
"is this the claimed agent or runtime?"; authority (receipts) answers "is this agent
session allowed to perform this action under this principal's budget?" A site that
gates on Signed Agents to decide who to talk to and on receipts to decide what to let
them do gets both.

**Scope clarification:** Receipts do not solve bot identity. They do not replace
Signed Agents.

## SPIFFE / SPIRE

**Standard:** [SPIFFE](https://spiffe.io/) workload identity framework. SPIRE is the
reference implementation.

| SPIFFE concept | Receipt primitive | Notes |
|---|---|---|
| SPIFFE ID | `actor` | Drop-in substitute; use `spiffe://...` as the `actor` string. |
| SPIFFE bundle | Trust anchor for `signer_key` | Mediator signing keys could be issued from a SPIFFE trust domain. Pipelock 2.4 added SPIFFE actor identity in the mediation envelope. |

**Relationship:** SPIFFE gives identity to **workloads**; receipts give authority
trails to **actions taken by workloads**. Clean compose. No automatic SVID rotation
yet on the receipt path; receipts accept whatever string goes in `actor`.

## in-toto / SLSA

**Standard:** [in-toto](https://in-toto.io/) attestation format and SLSA supply-chain
framework.

| in-toto concept | Receipt primitive | Notes |
|---|---|---|
| Envelope | Receipt envelope | Both are signed JSON wrappers. in-toto uses DSSE; Pipelock uses a flat Ed25519-over-SHA256 shape. A DSSE profile would let SLSA pipelines ingest receipts unchanged. |
| Subject | `target` | in-toto attests about an artifact; receipts attest about an action on a target. |
| Predicate | `action_type`, `side_effect_class`, `reversibility`, `verdict`, `principal`, `actor`, `delegation_chain`, `policy_hash` | The "what happened" payload sits flat on the action record. |
| Issuer | `signer_key` | Same concept. |

**Relationship:** Different lifecycle stage. in-toto is build-time ("this binary came
from this commit built by this runner"). Receipts are run-time ("this running agent
took this action under this authority"). They should coexist: in-toto proves the agent
software is trustworthy; receipts prove it stayed within its authority after
deployment.

**Engagement notes:** Position receipts as the run-time complement to SLSA provenance.
The audience already understands why build-time provenance is insufficient when the
built binary is an agent.

## CSA AARM (Autonomous Action Runtime Management)

**Proposal:** AARM ([arXiv 2602.09433](https://arxiv.org/abs/2602.09433)) was donated
to the Cloud Security Alliance in April 2026 and is now under a CSA Technical Working
Group. It defines a runtime-management taxonomy for autonomous-action systems covering
authority delegation, action classification, action mediation, and evidence retention.

| AARM concept | Receipt primitive | Notes |
|---|---|---|
| Authority delegation | `principal`, `actor`, `delegation_chain` | Pipelock's flat fields express AARM authority transfer with no transformation. |
| Action classification | `action_type`, `side_effect_class`, `reversibility` | Pipelock's enums are a candidate vocabulary; the AARM taxonomy is still settling. |
| Action mediation | `verdict`, `policy_hash`, `transport` | Receipt verdicts express mediator decisions; `policy_hash` binds the policy generation. |
| Evidence retention | Receipt chain + Audit Packet | Pipelock's signed chain + posture-bound packet is one concrete model for the evidence layer AARM names. |

**Relationship:** AARM is the closest standards-body overlap Pipelock has open. The
conformance-evidence table maps cleanly to receipt fields; engagement should propose
receipts as a candidate reference for the evidence-retention pillar.

## OASIS CoSAI Ws4 MCP security spec

**Status:** Draft, actively evolving inside OASIS CoSAI (Coalition for Secure AI),
working group 4 on secure design of agentic systems.

| MCP security concept | Receipt primitive | Notes |
|---|---|---|
| Tool call log entry | `action_type`, `method`, `target`, `verdict` | Receipts cover every MCP tool call Pipelock mediates. |
| Transport identification | `transport` ∈ {`mcp_stdio`, `mcp_http`, `mcp_http_upstream`, `mcp_http_listener`, `mcp_ws`} | All MCP transports are first-class. |
| Policy identifier | `policy_hash` | Flat field: hex SHA-256 of the MCP policy bundle that governed the call. |
| Tool inventory binding | `action_type` derived from MCP method | Pipelock's `ClassifyMCPTool` maps MCP methods to typed actions. |

**Relationship:** Upstream dependency. The MCP security spec defines what access
control for MCP should look like; receipts are a candidate audit-record format the
spec can reference. The receipt format already covers the MCP transports the spec
calls out.

**Engagement notes:** Offer the receipt format as a reference audit record in the
audit section of the MCP security spec. Do not push on authentication or
authorization; those are separate conversations.

## OWASP Agentic Skills Top 10

**Project:** OWASP Agentic Skills Top 10 lists the most common security risks
introduced by agent skill ecosystems (poisoned skills, scope inflation, exfiltration
through tool outputs, and so on).

| Top 10 concept | Receipt primitive | Notes |
|---|---|---|
| Skill inventory drift | EvidenceReceipt v2 `contract_drift` payload | A divergence between observed action and active contract emits a signed drift receipt. |
| Scope inflation | `delegation_chain`, `authority_kind` | The chain records which grants authorized the action; scope-inflated actions are visible against the recorded chain. |
| Exfiltration via tool output | `verdict=block`, `layer=dlp`, `data_classes_out` | Receipts capture DLP blocks with the matched layer and data class. |
| Poisoned tool description | EvidenceReceipt v2 `contract_drift` payload (drift_kind variants) | Drift kinds cover poisoned tool descriptions and rug-pull updates. |

**Relationship:** A natural mapping target. Receipts give the Top 10 a concrete signed
audit-record shape that can be cited as one proven implementation.

## W3C Verifiable Credentials

**Standard:** [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/).

| VC concept | Receipt primitive | Notes |
|---|---|---|
| Credential subject | `actor` | VCs describe a subject; receipts describe an action by an actor. |
| Issuer | `signer_key` | Same concept. |
| Claims | `action_type`, `verdict`, `principal`, `delegation_chain`, `policy_hash` | Receipts carry action and authority claims as flat fields. |
| Proof | `signature` | VCs allow many proof formats; receipts pick Ed25519 over SHA-256 of canonical action record. |

**Relationship:** Tenuous. VCs are identity-centric, flexible, and heavy. Receipts
are action-centric, narrow, and light. A mapping is possible but the data model
mismatch means bending one format to fit the other. Not a high-priority engagement target.

## How to read this doc

The per-primitive table is the canonical view; per-standard sections expand each entry
with field-level mapping and scope notes. When proposing receipt content into a
standard, start from the table and quote the relevant per-standard section.

Honest about what receipts are not:

- Not a transparency log (no public non-repudiation without SCITT or equivalent).
- Not transport-level integrity (no message-byte signing without RFC 9421 or equivalent).
- Not bot identity (Signed Agents and SPIFFE answer that).
- Not telemetry (OTel does that; receipts are signed evidence).
- Not a credential format (W3C VC fits a different shape).

Receipts are run-time evidence of mediated agent action. The rest of the stack composes
around that.
