# Security Assurance Case

**Status:** Living assurance case. Unless a section names a release, its claims
apply to the repository revision that contains this file. Release support and
security-fix eligibility remain defined by [SECURITY.md](../SECURITY.md).

This assurance case states what Pipelock is intended to protect, which trust
boundaries must exist for those protections to hold, what evidence the product
can produce, and what that evidence cannot prove. It is a product security
argument, not a certification and not a claim that every deployment is secure.

The reporting policy, supported release line, and severity framework are in
[SECURITY.md](../SECURITY.md). Known unmediated paths are maintained separately
in [current unsupported paths](security/current-unsupported-paths.md).

## Security Objectives

Pipelock is designed to reduce these risks at agent communication boundaries:

1. **Credential and data exfiltration:** secrets or sensitive workspace data
   leaving through URLs, headers, bodies, WebSocket frames, MCP arguments, or
   tool results.
2. **SSRF and destination abuse:** requests reaching metadata services, private
   networks, blocked destinations, or rebinding targets through a mediated
   transport.
3. **Prompt injection and tool poisoning:** attacker-controlled content or MCP
   descriptions manipulating an agent across a boundary Pipelock inspects.
4. **Tool misuse:** dangerous MCP calls reaching a server despite configured
   tool, argument, chain, integrity, provenance, or session policy.
5. **Unverifiable enforcement:** operators being unable to show which mediated
   action Pipelock evaluated, what it decided, and which policy context applied.
6. **Fleet control-plane compromise:** unsigned, stale, wrongly scoped, or
   unauthorized policy and emergency messages reaching Enterprise followers.

These objectives map to the [OWASP Top 10 for Agentic Applications](owasp-mapping.md),
the [OWASP Agentic AI Threats and Mitigations](owasp-agentic-top15-mapping.md),
and the [NIST SP 800-53 mapping](compliance/nist-800-53.md).

## Trust Boundaries

### 1. Agent to Pipelock

```text
+----------------------+      +----------------------+      +------------------+
| Agent environment    |      | Pipelock boundary    |      | External systems |
| secrets + workspace  | ---> | network + tool       | ---> | APIs, MCP, A2A   |
| no direct egress     |      | policy, no secrets   |      | and web content  |
+----------------------+      +----------------------+      +------------------+
        deployment                 binary-enforced                untrusted
        enforcement                mediated paths
```

Pipelock enforces decisions only for traffic that reaches a Pipelock proxy,
wrapper, listener, hook, or containment path. The deployment must prevent the
agent from opening an unmediated route around that boundary. Host containment,
separate users or processes, container networking, Kubernetes NetworkPolicy,
firewall rules, or an equivalent control provide that no-bypass property.

Pipelock reads configured local values for leak detection, but the proxy is not
intended to hold the agent's provider credentials. A deployment that gives the
proxy the same broad secret and workspace access as the agent weakens capability
separation.

### 2. MCP Client to MCP Server

`pipelock mcp proxy` and Pipelock MCP listeners mediate the JSON-RPC path.
Requests can be checked for input injection, DLP, tool policy, tool chains,
binary integrity, provenance, session binding, contracts, media policy, and
taint. Responses and tool descriptions can be checked before the client
consumes them. An MCP server launched or contacted outside these paths is not
covered merely because Pipelock is installed.

### 3. Tool Call to Execution

MCP `tools/call` policy runs before a mediated request reaches the MCP server.
It scopes which tools and argument shapes may run. It does not mint a separate
credential for every action, prove the model's intent, or control a tool invoked
through an unwrapped local path.

### 4. Operator and Configuration to Runtime

Configuration, trusted keys, signing keys, exemptions, suppression rules, and
deployment topology are security inputs. A permissive operator can intentionally
reduce coverage. `pipelock check`, `pipelock doctor`, `pipelock audit score`,
`pipelock contain verify`, and `pipelock assess` expose different parts of the
configured-versus-enforceable state; none can prove that an unseen bypass does
not exist.

### 5. Follower to Enterprise Conductor

Conductor followers enforce locally and do not send agent credentials to the
control plane. Deployment-provided mTLS identifies followers; signed,
audience-bound messages carry policy, rollback, and emergency state. The
Conductor boundary includes its deployment PKI, role tokens, signing-key roster,
storage, retention policy, and backup process. See the
[Conductor threat model](security/agent-firewall-conductor-threat-model.md) and
[production runbook](guides/conductor-production-runbook.md).

### 6. Evidence Producer to Verifier

The process holding an evidence signing key is a trusted producer. A verifier
must pin the expected public key or a trusted roster. Signature validity proves
that the key holder signed the verified bytes; it does not prove that the key
holder was honest, that no record was omitted, or that no unmediated action
happened.

## Security Requirements and Evidence

| Requirement | Product mechanism | Verification and limit |
|---|---|---|
| SR-1: Mediate the claimed transport before enforcing it | Fetch, forward, reverse, TLS-intercept, WebSocket, MCP, hook, sandbox, host-containment, and deployment integrations | Transport tests and `doctor`/`contain verify`; direct-egress prevention remains deployment-enforced. |
| SR-2: Apply non-disableable minimum URL protections | Literal-IP SSRF and core DLP floors run independently of configured policy | Unit, integration, fuzz, and evasion tests; novel encodings and opaque encrypted content remain residual risks. |
| SR-3: Deny before a blocked mediated action executes | Scanner, request, MCP, contract, kill-switch, and policy gates run before forwarding on their covered paths | Black-box transport and exploit regression tests; observe/off modes intentionally do not enforce. |
| SR-4: Reject unsafe or ambiguous security state where the feature promises enforcement | Validation, unknown-action rejection, context checks, authenticated listeners, trusted-key pinning, and feature-specific fail-closed paths | Negative tests cover malformed, missing, expired, revoked, and stale inputs; behavior is feature- and mode-specific rather than universally fail-closed. |
| SR-5: Make recorded mediated decisions tamper-evident | Signed receipts, hash-linked chains, signed checkpoints, and offline verifiers | Verification proves integrity and ordering of supplied records, not completeness outside the observed chain. |
| SR-6: Keep evidence claims scoped to the identity actually observed | Receipts record mediator-attested actor, principal, delegation, transport, policy, and verdict context | The mediator's signature is not workload non-repudiation; runtime SVID binding is not claimed where only offline appraisal exists. |
| SR-7: Keep fleet policy and emergency control scoped, authenticated, and recoverable | mTLS follower identity, signed audience-bound messages, monotonic state, rollback, remote kill, key rosters, backup and restore | Conductor tests and operator runbooks; availability and PKI custody remain deployment responsibilities. |
| SR-8: Make shipped artifacts inspectable and attributable | Reproducible OSS build check, signed releases, provenance, checksums, SBOMs, CodeQL, gosec, dependency and vulnerability scanning | Build provenance covers the released artifact, not the honesty of the running host or operator. |

## Ordered URL Scanner Pipeline

The URL scanner checks maximum length before parsing. After parsing and hostname
canonicalization, the current order is:

1. Scheme restriction to HTTP or HTTPS
2. CRLF injection
3. Path traversal
4. Strict-mode allowlist
5. Domain blocklist
6. Core literal-IP SSRF floor, including private and metadata addresses
7. SigV4 presigned-URL credential carve-out
8. Core DLP floor
9. Configured DLP
10. Path entropy
11. Subdomain entropy
12. DNS-based SSRF, private-address, metadata, and rebinding checks
13. Rate limiting
14. Data budget
15. Final context check

Core and configured DLP run before DNS resolution, so a detected secret can be
blocked before the proxy performs a destination lookup. Response, body,
streaming, WebSocket, MCP, A2A, and tool-policy paths add controls appropriate
to the bytes and semantics each transport exposes.

## Failure Behavior

"Fail closed" applies to a named enforcement path, not to every Pipelock mode or
subsystem:

- A block verdict on a mediated enforcement path is denied before forwarding.
- Unknown policy actions, expired context, and security-sensitive validation
  failures are rejected.
- HITL timeouts and non-terminal operator input block rather than silently
  approving the action.
- Parse-error behavior is configurable on some inspection surfaces and must be
  reviewed in the deployment configuration.
- Observe and off modes intentionally allow traffic and must not be represented
  as enforcement.
- Receipt emission is best-effort by default. With
  `flight_recorder.require_receipts`, an allow-path receipt failure blocks before
  forwarding. Block-path receipts remain best-effort because the action is
  already denied.
- A fail-closed evidence or storage setting trades availability for integrity;
  storage stalls can therefore become a denial-of-service condition.

## Verifiable Evidence

Pipelock ships several evidence surfaces with different proof boundaries:

- **ActionReceipt v1:** signed per-action evidence for mediated decisions,
  including verdict, policy and transport context, actor fields, and hash-chain
  linkage.
- **EvidenceReceipt v2:** RFC 8785/JCS-canonicalized typed evidence for contract
  lifecycle, shadow, drift, and contract-aware proxy decisions.
- **Flight recorder:** configured evidence storage with chain continuity and
  signed checkpoints. It records blocks; allow receipts require the configured
  receipt mode, and clean stream frames may be summarized rather than emitted
  one by one.
- **Audit Packet v0:** posture-bundled receipts plus verifier output. Its relying
  party must pin the expected trust inputs described in the
  [Audit Packet threat model](security/audit-packet-threat-model.md).
- **Coverage certificates:** signed summaries over an observed evidence set.
  They may honestly report `LIMITED`; they do not convert missing mediation into
  `COMPLETE`.
- **Anchors:** local or Rekor checkpoints can constrain later deletion or
  rewriting after an observed anchor. They do not prove whole-session
  completeness before the first trusted anchor.

Four independent cross-language verifier implementations (Go, TypeScript, Rust,
and Python) exercise a shared conformance corpus. The browser wasm surface
reuses the Go implementation and is not counted as an independent fifth
implementation. Pinned verification is the security claim; unpinned structural
inspection is explicitly weaker.

The complete evidence caveats are cataloged in
[Evidence Hard Limits](evidence/hard-limits.md). In particular, a key holder can
omit records or forge records under a compromised key, a modified recorder
cannot vouch for itself, and receipts cannot prove traffic was unable to bypass
the mediator.

## Key Lifecycle

Signing and trust material must have an operator-owned lifecycle:

- **Create:** generate purpose-bound keys with restricted file permissions.
- **Rotate:** introduce new trust before retiring old trust so historical
  evidence remains verifiable.
- **Revoke:** distribute signed revocation or roster state and stop accepting the
  retired key for new artifacts.
- **Recover:** use the documented root or high-water recovery path rather than
  weakening verification.
- **Inspect:** record fingerprints, purposes, provenance, blast radius, and
  current status in an operator-visible trust inventory.

The [key rotation runbook](security/key-rotation-runbook.md), dashboard Trust &
Keys view, receipt-verification guide, and Conductor runbooks cover the shipped
surfaces. Hardware-backed custody and KMS/HSM integration remain deployment
choices unless a specific integration says otherwise.

## Known Limitations

- Pipelock does not detect a maliciously trained or compromised model merely
  because it produced a request.
- Novel parser differentials, encoding chains, semantic evasions, steganography,
  timing channels, or encrypted exfiltration may require new controls.
- CONNECT passthrough exposes destination and connection metadata, not the
  encrypted request or response body. Payload claims require TLS interception
  or another content-visible path.
- Same-process or otherwise unwrapped tools and MCP servers are outside the
  boundary.
- Agent identity is often configured or mediator-observed. It is not universally
  certificate-bound workload identity.
- Local evidence is not an independent witness when the same operator controls
  the runtime, signing key, and retained records.
- Pipelock does not encrypt every audit store at rest. Regulated deployments must
  provide storage encryption, access control, retention, and backup protection.
- High availability, RTO, RPO, support response, and legal compliance depend on
  the deployment and commercial agreement; the repository does not promise
  them without separate proof.

## Verification Program

Security requirements are exercised through:

1. Unit and integration tests, including race-detector CI shards.
2. Fuzz targets and public evasion tests for malformed and adversarial input.
3. Black-box binary tests across real HTTP, WebSocket, MCP, and deployment paths.
4. A private adversarial corpus for regression classes whose full payload set is
   not published.
5. Cross-language receipt and Audit Packet conformance vectors.
6. Static analysis with CodeQL, golangci-lint, and gosec.
7. Dependency monitoring, `govulncheck`, signed releases, provenance, SBOMs, and
   reproducible-build checks.

Every confirmed security finding should become a durable regression test. A
green test run proves the tested invariant at that revision; it does not erase
the limitations above.

## Review Cadence

This assurance case should receive a human review at least annually and after a
material change to transport coverage, containment, identity, evidence formats,
key lifecycle, or the Enterprise control plane. The reviewer should compare the
claims with non-test call sites, negative tests, current unsupported paths, and
the shipped release before recording the review.

### Review Record

| Date | Reviewer | Scope and result |
|---|---|---|
| 2026-07-17 | Joshua Waldrep, project lead | Reviewed the security objectives, trust boundaries, requirements, evidence claims, and stated limitations against the shipped implementation and approved the assurance case for publication. |
