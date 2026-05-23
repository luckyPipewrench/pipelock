# in-toto Attestation Predicate: `agent-action-receipt` v0.1

> **Status:** Experimental, individual proposal. Not adopted into the in-toto.io
> predicate catalog. Pipelock owns the namespace at `https://pipelab.org/attestation/`.
> **Predicate type URL:** `https://pipelab.org/attestation/agent-action-receipt/v0.1`
> **Versioning:** SemVer. The TypeURI carries the major version only; 0.X is itself a
> major version per Pipelock's versioning convention.
> **Schema:** [`schemas/in-toto-agent-action-receipt-v0.1.schema.json`](../../schemas/in-toto-agent-action-receipt-v0.1.schema.json)
> **Companion docs:**
> - [Pipelock Action Receipt implementation spec](https://pipelab.org/learn/action-receipt-spec/)
> - [Receipt prior-art mapping](./receipt-prior-art-mapping.md) (see the in-toto / SLSA row)
> - [SCITT signed-statement profile (parallel artifact)](./scitt-agent-action-statement-v0.1.md)

## What this is

This predicate type lets Pipelock emit an **in-toto Attestation Statement** that
describes one mediated agent action — a DNS lookup, an HTTP request, an MCP tool
call, a WebSocket frame — and the runtime verdict Pipelock applied to it. It is
designed for consumers that already ingest in-toto / DSSE / SLSA bundles and want
to layer **run-time evidence of agent action** alongside **build-time evidence of
agent provenance**.

It is **not** a redefinition of Pipelock's canonical ActionReceipt v1 envelope. It
is a parallel wire format for in-toto consumers. The receipt content — the
`actionRecord` fields, the verdict vocabulary, the signing key — is the same as the
shipped binary emits. The DSSE wrapper around it is what makes the artifact
in-toto-compatible.

## Where this fits

Pipelock already emits two receipt envelopes from the same binary:

| Envelope | Used for | Wire format |
|---|---|---|
| **ActionReceipt v1** | Per-action runtime evidence | Flat JSON, Ed25519 over SHA-256 of canonical bytes |
| **EvidenceReceipt v2** | Contract lifecycle, shadow evidence, drift | Typed payloads, RFC 8785 JCS canonicalization |
| **Audit Packet v0** | Posture-bundled batch of receipts + verifier verdict | Schema at `pipelab.org/schemas/audit-packet-v0.schema.json` |

This in-toto predicate is a **third export format**: the same `action_record`
content re-laid out as a `lowerCamelCase` predicate object, wrapped in an in-toto
Statement v1, and signed with a DSSE envelope. v0.1 produces the in-toto bytes on
demand from a Pipelock ActionReceipt v1 envelope; the runtime path does not emit
DSSE directly yet. The conversion is **deterministic from a given ActionReceipt v1
input**, but not bit-round-trippable in both directions — the predicate adds
profile-level fields (`mediator.id`, `mediator.buildCommit`) that the v1 envelope
does not carry, and the subject digest cryptographically anchors the in-toto
Statement to the v1 bytes so a relying party can cross-check.

The closest existing in-toto predicate is
[`runtime-trace/v0.1`](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md),
which captures a monitor + monitoredProcess + monitorLog from a build runner. That
predicate is build-time: it describes a process under hermeticity supervision. The
gap that `agent-action-receipt/v0.1` fills is **per-action runtime verdicts** —
"this agent tried to do this, the mediator decided this, here is the signed
evidence" — which `runtime-trace` does not model and SLSA Provenance does not cover.

## Statement layout

Throughout this document, "Statement" refers to the **in-toto Statement v1**
JSON object. The SCITT-WG specification also defines a "Signed Statement"
artifact; that artifact is a different wire format (COSE_Sign1, not DSSE) and
is covered in the [companion SCITT profile](./scitt-agent-action-statement-v0.1.md).

An `agent-action-receipt` Statement follows in-toto Statement v1:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "agent-action:<actionId>",
      "digest": {
        "sha256": "<hex SHA-256 of canonical actionRecord bytes>"
      }
    }
  ],
  "predicateType": "https://pipelab.org/attestation/agent-action-receipt/v0.1",
  "predicate": { /* see below */ }
}
```

### Subject construction

The subject digest is the **SHA-256 of the canonical bytes of the underlying
Pipelock ActionReceipt v1 `action_record`** — the same SHA-256 digest the
Pipelock binary signs with Ed25519 on the v1 path (per
`internal/receipt/receipt.go`: `sum := sha256.Sum256(data); sig :=
ed25519.Sign(privKey, sum[:])`). This makes the in-toto Statement
content-addressable against the same digest that any other Pipelock verifier
(`pipelock-verifier`, the Go / TypeScript / Rust / Python SDK verifiers) checks.

The subject `name` is `agent-action:<actionId>` where `actionId` is the UUIDv7
from the underlying receipt. Statement subjects MUST be an array with at least one
entry per in-toto Statement v1; arrays of more than one subject are reserved
for batched future profiles and SHALL NOT be emitted by v0.1 producers.

## Predicate fields

All field names are `lowerCamelCase` per the in-toto new-predicate guidelines.
Timestamps are RFC 3339 with `Z` suffix.

| Field | Type | Required | Description |
|---|---|---|---|
| `actionId` | string (UUIDv7) | yes | Globally unique per action. Matches `action_id` on the underlying ActionReceipt v1. |
| `actionType` | enum | yes | One of: `read`, `write`, `delegate`, `authorize`, `spend`, `commit`, `actuate`, `derive`, `unclassified`. Same vocabulary as ActionReceipt v1. |
| `target` | string | yes | The host:port, URL, MCP tool name, or other target identifier the action acted on. Free-form by transport. |
| `transport` | string | yes | One of: `fetch`, `forward`, `intercept`, `websocket`, `mcp_stdio`, `mcp_http`, `mcp_http_upstream`, `mcp_http_listener`, `mcp_ws`. |
| `verdict` | enum | yes | One of: `allow`, `block`, `warn`, `ask`, `strip`, `forward`, `redirect`. |
| `verdictReason` | string | conditional | Required when `verdict` is `block`, `warn`, `ask`, or `redirect`. MUST be omitted for `allow` and `forward` (both are pass-through verdicts). Optional for `strip`. Value is a canonical block-reason code from Pipelock's shipped vocabulary (e.g., `dlp_match`, `prompt_injection`, `ssrf_private_ip`, `tool_policy_deny`, `tool_chain_blocked`, `tool_poisoning`, `airlock_active`, `kill_switch_active`, `contract_default_deny`, `contract_enforce_default`). The full enumeration is defined in `internal/blockreason/blockreason.go` and mirrored in the [block-reason-header spec](./block-reason-header.md). The v1 ActionReceipt envelope does not carry this field directly; a v0.1 producer sources it from the same structured rejection code Pipelock emits in the `X-Pipelock-Block-Reason` HTTP header (and in JSON-RPC error metadata for MCP-internal blocks). |
| `principal` | string | yes | Identity of the human or system authorizing the action (e.g., `spiffe://example.org/user/alice`, `oauth:user@example.com`, `local:operator`). |
| `actor` | string | yes | Identity of the agent / workload that initiated the action. SPIFFE IDs preferred per Pipelock 2.4+ federation. |
| `mediator` | object | yes | The Pipelock instance that decided the verdict. See "Mediator object" below. |
| `decidedAt` | string (RFC 3339) | yes | When Pipelock decided the verdict. Millisecond precision. |
| `policy` | ResourceDescriptor | yes | Reference to the policy bundle that governed the decision. `digest.sha256` MUST match the `policy_hash` field on the underlying ActionReceipt v1. |
| `delegationChain` | string[] | no | Authority chain from `principal` to `actor` if multi-hop. Empty / absent for direct authorization. |
| `parentActionId` | string (UUIDv7) | no | Causal predecessor action, when this action was triggered by an earlier one within the same session. |
| `sessionId` | string | no | Pipelock session identifier. Opaque; not a stable cross-session identity. |
| `findings` | array | no | DLP / injection / SSRF detector hits that contributed to the verdict. See "Findings" below. |
| `sideEffectClass` | enum | no | `none`, `external_read`, `external_write`, `financial`, `physical`. CSA AARM-aligned classification. |
| `reversibility` | enum | no | `full`, `compensatable`, `irreversible`, `unknown`. |
| `dataClassesIn` | string[] | no | DLP class labels carried into the request body. |
| `dataClassesOut` | string[] | no | DLP class labels carried out of the response body (when applicable). |
| `notes` | string | no | Free-form human-readable context. Producers SHOULD NOT include secrets, PII, or raw request bytes here. |

### Mediator object

```json
{
  "id": "<opaque deployment-bound identifier>",
  "version": "<semver of the Pipelock binary>",
  "buildCommit": "<git commit short SHA of the running binary>",
  "signingKey": {
    "algorithm": "ed25519",
    "publicKeyHex": "<64-character hex>"
  }
}
```

`mediator.id`, `mediator.version`, and `mediator.signingKey` are REQUIRED;
`mediator.buildCommit` is OPTIONAL but RECOMMENDED for reproducibility.
`mediator.id` SHOULD be stable across reloads and unique per deployment. A v0.1
producer derives it from the producer's persistent identity material; this
profile does not specify the derivation. The `signingKey.publicKeyHex` MUST
match the `signer_key` on the underlying ActionReceipt v1 (which Pipelock
sources from `flight_recorder.signing_key_path` per
`internal/config/schema.go`) so a relying party can pin one key across both
envelope formats.

### Findings

Each finding is an object:

```json
{
  "layer": "dlp" | "injection" | "ssrf" | "tool_policy" | "contract" | "chain" | "redaction",
  "rule": "<scanner-specific rule identifier>",
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "position": "<optional structural pointer; never raw matched bytes>"
}
```

Producers MUST NOT include the matched bytes or any secret-bearing context in
`findings`. The structural pointer is informational (e.g., `body.messages[3].content`)
not a byte offset, and consumers MUST NOT rely on it for replay.

## Envelope and signing

Statements MUST be wrapped in **DSSE v1.0** ([spec](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md))
with:

- `payloadType`: `application/vnd.in-toto+json`
- `payload`: base64-encoded JSON of the in-toto Statement
- `signatures`: array of one or more DSSE signature blocks. DSSE v1.0 defines
  `signature.keyid` as OPTIONAL with no required shape; this profile pins
  `keyid` to the raw hex public key (64 chars) so it cross-references the same
  key on Pipelock's other envelope formats. The keyid shape is a profile choice,
  not a DSSE-defined requirement. Multi-signature is supported but v0.1
  producers emit a single signature from `mediator.signingKey`.

The signing algorithm is **Ed25519 over the DSSE pre-authentication encoding**
(`PAE("DSSEv1", payloadType, payload)`), per the DSSE v1.0 spec — NOT over a SHA-256
digest of the Statement (that is the v1 envelope's signing input, deliberately
different).

A consumer that verifies the DSSE envelope verifies the in-toto Statement bytes; it
does NOT separately verify the underlying ActionReceipt v1 envelope. The Statement
is self-contained.

## Verification flow

1. Verify the DSSE envelope (Ed25519 over `PAE`).
2. Decode the payload, check `_type == https://in-toto.io/Statement/v1` and
   `predicateType == https://pipelab.org/attestation/agent-action-receipt/v0.1`.
3. Validate the predicate against the JSON Schema published alongside this spec.
4. Match the subject digest against the canonical bytes of the underlying
   ActionReceipt v1 `action_record` if cross-checking with a separate Pipelock
   verifier. (Optional — the DSSE signature is sufficient for in-toto consumers.)
5. Apply the consumer's own policy on `verdict`, `actionType`, `target`, `principal`,
   `actor`, `mediator.id`, `mediator.signingKey.publicKeyHex`.

Consumers MUST treat unknown predicate fields as informational and MUST ignore
them. This mirrors the in-toto attestation framework's monotonic principle
(paraphrased: ignoring an attestation or a field within one must not flip a deny
to an allow). In practice this means a `verdict: block` MUST always be
respected, regardless of whether the consumer recognizes every layer in
`findings`.

## Worked example

A Pipelock instance blocks an MCP tool call attempting to exfiltrate an Anthropic
API key:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "agent-action:01934e1c-cd60-7abc-823a-d6f5e6f7a8b9",
      "digest": {
        "sha256": "9c46a3f8b1c2d4e5f60718293a4b5c6d7e8f9012345678901234567890abcdef"
      }
    }
  ],
  "predicateType": "https://pipelab.org/attestation/agent-action-receipt/v0.1",
  "predicate": {
    "actionId": "01934e1c-cd60-7abc-823a-d6f5e6f7a8b9",
    "actionType": "write",
    "target": "api.attacker.example/v1/upload",
    "transport": "mcp_http",
    "verdict": "block",
    "verdictReason": "dlp_match",
    "principal": "spiffe://example.org/user/alice",
    "actor": "spiffe://example.org/agent/claude-code-cli",
    "mediator": {
      "id": "pipelock-7f3c2b1e",
      "version": "2.5.0",
      "buildCommit": "dcd25d8",
      "signingKey": {
        "algorithm": "ed25519",
        "publicKeyHex": "0000000000000000000000000000000000000000000000000000000000000000"
      }
    },
    "decidedAt": "2026-05-22T19:43:21.118Z",
    "policy": {
      "name": "pipelock-default-policy",
      "digest": {
        "sha256": "3f29a1b5c7d8e9f01234567890abcdef9c46a3f8b1c2d4e5f60718293a4b5c6d"
      }
    },
    "findings": [
      {
        "layer": "dlp",
        "rule": "anthropic_api_key",
        "severity": "critical",
        "position": "body.messages[0].content"
      }
    ],
    "sideEffectClass": "external_write",
    "reversibility": "irreversible",
    "dataClassesIn": ["secret"]
  }
}
```

Wrapped in DSSE:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 of the Statement above>",
  "signatures": [
    {
      "keyid": "0000000000000000000000000000000000000000000000000000000000000000",
      "sig": "<base64 Ed25519 signature over PAE>"
    }
  ]
}
```

## Relationship to other predicates

| Predicate | Lifecycle | Overlap with `agent-action-receipt/v0.1` |
|---|---|---|
| [SLSA Provenance v1](https://slsa.dev/spec/v1.0/provenance) | Build-time | Provenance attests the agent binary's build. `agent-action-receipt` attests one runtime action that binary took. Composes: SLSA Provenance proves the agent code is trustworthy; `agent-action-receipt` proves the running agent stayed within its authority. |
| [`runtime-trace/v0.1`](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md) | Build-time hermeticity | `runtime-trace` captures process / network / file-access logs from a build runner under hermeticity supervision. `agent-action-receipt` is per-action, not per-build, and carries verdicts (allow / block / etc.) which `runtime-trace` does not. Complementary, not overlapping. |
| [VSA (Verification Summary)](https://slsa.dev/spec/v1.0/verification_summary) | Post-build | VSA attests "this artifact was verified against this policy at this time." `agent-action-receipt` is per-action; an aggregated VSA-shaped successor is possible but out of scope for v0.1. |
| [SCAI](https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md) | Cross-cutting | SCAI attaches free-form security claims. `agent-action-receipt` is a structured per-action subset; SCAI could carry an `agent-action-receipt` reference in `attributes`. |

A future v0.2 may align field names and shape with whatever vocabulary the in-toto
catalog converges on for runtime-action evidence. v0.1 is deliberately scoped to
the Pipelock receipt content as it ships today.

## Open questions and non-goals

- **No transparency-log binding.** This predicate carries no SCITT-style inclusion
  proof. Anchoring a Pipelock receipt to a transparency log is a separate concern;
  see the [SCITT profile](./scitt-agent-action-statement-v0.1.md).
- **No multi-action batching.** v0.1 emits one Statement per action. Aggregate
  envelopes (`audit-packet` shape) are emitted under Pipelock's own schema, not
  in-toto Bundle layout. A Bundle-layer profile is a future possibility.
- **No standard `agent-action` taxonomy.** The `actionType` and `sideEffectClass`
  enums match Pipelock's shipped vocabulary. CSA AARM, OWASP Agentic Skills Top 10,
  and OASIS CoSAI Ws4 are still settling on cross-vendor names; a future v0.x will
  align once one of those vocabularies stabilizes.
- **No vetting submission.** v0.1 is published under `pipelab.org/attestation/` so
  it does not require in-toto.io catalog review. A vetting submission via the
  predicate-template path is on the roadmap once a second producer or a corpus of
  receipts in the wild exists.

## References

- [in-toto Attestation Framework spec v1](https://github.com/in-toto/attestation/blob/main/spec/v1/README.md)
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [in-toto Envelope v1 (DSSE)](https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md)
- [in-toto new-predicate guidelines](https://github.com/in-toto/attestation/blob/main/docs/new_predicate_guidelines.md)
- [in-toto predicates catalog](https://github.com/in-toto/attestation/blob/main/spec/predicates/README.md)
- [DSSE v1.0](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md)
- [SLSA Provenance v1.0](https://slsa.dev/spec/v1.0/provenance)
- [Pipelock Action Receipt implementation spec](https://pipelab.org/learn/action-receipt-spec/)
- [Pipelock receipt prior-art mapping](./receipt-prior-art-mapping.md)
- [RFC 8032 (Ed25519)](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 3339 (date/time)](https://www.rfc-editor.org/rfc/rfc3339.html)
- [RFC 9562 (UUID v7)](https://www.rfc-editor.org/rfc/rfc9562.html)
