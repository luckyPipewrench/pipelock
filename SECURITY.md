# Security Policy

Pipelock is a security boundary for agent egress and tool traffic. This policy explains how to report vulnerabilities, which release lines are supported, what Pipelock is designed to enforce, and where the boundary depends on deployment configuration.

## Vulnerability Reporting

Report security vulnerabilities privately through the [private security advisory form](https://github.com/luckyPipewrench/pipelock/security/advisories/new).

Do not open a public issue for a security vulnerability. Public reports may expose users before a fix or mitigation is available.

Include:

- Description of the vulnerability
- Affected version or commit, if known
- Steps to reproduce
- Impact assessment
- Suggested fix or mitigation, if any

The full coordinated disclosure policy is in [docs/security/coordinated-disclosure.md](docs/security/coordinated-disclosure.md). Project security-response governance is in [CHARTER.md](CHARTER.md).

## Response SLA and Coordinated Disclosure

Timing is measured from receipt of a complete report.

| Severity | ACK target | Patch or mitigation target |
|---|---:|---:|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 3 business days | 30 days |
| Low | 5 business days | 90 days |

Critical and High issues may be pre-disclosed under embargo to material relying parties when they are actively exposed and need time to patch. Embargoed notice is limited to affected versions, available mitigation, and the expected fix timeline.

Public disclosure happens after a fix has shipped, a documented mitigation is available, or the coordinated disclosure deadline has elapsed. The default coordinated disclosure deadline is 90 days from the initial complete report. The deadline may be extended with reporter agreement when there is active progress, or shortened when there is evidence of active exploitation.

CVE reservation is used when an issue affects released versions, has meaningful user impact, and benefits from ecosystem-wide tracking.

## Supported Versions

Pipelock supports the current major release line. Security fixes are shipped on the latest supported minor and patch release unless a separate maintenance release is announced.

| Version | Supported |
|---|---:|
| 3.x | Yes |
| Earlier release lines | No |

The current shipped release line is documented in [CHANGELOG.md](CHANGELOG.md).

## Threat Model

Pipelock protects against agent egress and tool-boundary failures that cross a boundary Pipelock can observe or mediate. The full assurance case is in [docs/security-assurance.md](docs/security-assurance.md).

### Trust Boundaries

**Agent to proxy.** Pipelock is designed for capability separation: the agent has workspace access and secrets, while Pipelock has network access and performs policy decisions. This no-bypass property is deployment-enforced through process, user, container, network, or operating-system controls. The binary enforces decisions for traffic actually routed through Pipelock; it does not magically intercept unrelated direct egress.

**MCP client to MCP server.** When an MCP server is launched through `pipelock mcp proxy` or reached through a Pipelock MCP listener, Pipelock mediates the JSON-RPC boundary. Client requests are checked for DLP leaks, injection, tool policy, and session-binding failures before forwarding. Server responses and tool descriptions are checked before the agent consumes them.

**Tool call to execution.** `mcp_tool_policy` evaluates MCP `tools/call` requests before they reach the server. These rules scope which tools may run and which argument patterns are allowed. This is tool-access scoping, not per-action credential minting.

### Threat Categories

- Credential exfiltration through URLs, request bodies, headers, MCP tool arguments, or tool results
- Prompt injection in fetched content, tool output, or MCP server responses
- Tool misuse caused by malicious context, unsafe configuration, or overbroad tool access
- Tool poisoning through malicious or drifting MCP tool descriptions
- Data exfiltration through legitimate-looking egress channels

## Severity Framework

Severity is based on exploitability against shipped Pipelock versions, impact on the security boundary, and whether the issue gives an attacker a practical path to credential theft, policy bypass, or evidence forgery.

**Critical**

- Ed25519 signature forgery or a receipt-verification bypass that lets forged evidence verify under a trusted key
- Remote unauthenticated deactivation of the kill-switch or equivalent emergency control
- Fail-open behavior that lets blocked egress proceed across multiple mediated transports without operator opt-in

**High**

- SSRF that reaches a metadata or private-network target through a wrapped transport despite SSRF protection
- DLP bypass that leaks a real credential through the proxy or MCP boundary
- Prompt-injection bypass that causes a blocked tool call to execute through a mediated MCP path

**Medium**

- Scanner evasion limited to one transport when another shipped control still blocks the same attack class
- Audit-log injection that corrupts display or search output without breaking signed receipt or hash-chain integrity
- Configuration parsing behavior that weakens enforcement without exposing secrets or bypassing the primary egress boundary

**Low**

- False-positive-driven denial of service caused by a crafted but valid configuration
- Non-secret information disclosure in local error output
- Hard-to-trigger diagnostics or reporting bugs that do not change enforcement decisions

## Scope

The following are in scope:

- Bypass of URL scanning, including blocklist, DLP, entropy, and encoding-aware detection
- SSRF in the fetch proxy or wrapped transports
- Bypass of MCP response scanning and prompt-injection detection
- Ed25519 signature forgery or verification bypass
- Receipt hash-chain tampering that is not detected by the verifier
- Integrity monitoring bypass, including undetected modification of monitored files
- Audit log injection or tampering
- Config parsing vulnerabilities, including validation bypass, panics on operator input, and unsafe default handling
- Privilege escalation in network restriction or sandbox mode
- Any issue that could lead to credential exfiltration through a mediated path

The following are out of scope for this policy:

- Attacks that require direct network egress bypassing the proxy, unless a shipped containment mode claims to block that exact path and fails to do so
- Operator social engineering
- Vulnerabilities in wrapped third-party MCP servers, except for the effect on Pipelock's mediation boundary
- Denial of service from pathological but valid operator configuration
- Physical or administrative access to the signing key or host
- Theoretical attacks without a working proof of concept against a shipped version

## Verifiable Security Evidence

For mediated decisions, Pipelock can emit signed, hash-chained, offline-verifiable receipts. A receipt records the mediated action, policy context, verdict, transport context, mediator-attested identity, and chain linkage.

The receipt record includes identity fields such as `action_id`, `principal`, `actor`, and `delegation_chain`; policy and taint fields such as `policy_hash`, `verdict`, `session_taint_level`, and `recent_taint_sources`; and chain fields such as `chain_prev_hash`, `chain_seq`, and `run_nonce`. The implementation is in [internal/receipt/action.go](internal/receipt/action.go).

Chain verification is implemented in [internal/receipt/chain.go](internal/receipt/chain.go). Verifiers check signatures, sequence numbers, previous-hash linkage, and trusted signer keys. A valid chain is tamper-evident for the receipts it contains; it is not proof that no unmediated action happened outside Pipelock.

Offline verification uses `pipelock verify-receipt`, implemented in [internal/cli/signing/receipt.go](internal/cli/signing/receipt.go). Verification reads receipt files or evidence directories from disk and does not require the Pipelock process that emitted them to be running. Verification without a trusted signer key is structural-only and exits non-zero unless the operator explicitly passes `--allow-unpinned`.

Example trusted public key for receipt verification:

```text
70b991eb77816fc4ef0ae6a54d8a4119ddc5a16c9711c332c39e743079f6c63e
```

The published receipt predicate schema is [schemas/in-toto-agent-action-receipt-v0.1.schema.json](schemas/in-toto-agent-action-receipt-v0.1.schema.json), with `$id` `https://pipelab.org/attestation/agent-action-receipt/v0.1.schema.json`.

Receipt emission is evidence by default, not enforcement by itself. `flight_recorder.require_receipts` makes allow-path receipt emission fail closed: Pipelock emits the allow receipt before forwarding, and if emission fails the request is blocked instead of leaving the proxy. Block-path receipts remain best-effort because the action is already denied.

## Honest Limitations

**No-bypass requires deployment enforcement.** Pipelock enforces decisions for traffic routed through it. Capability separation, direct-egress blocking, and no-bypass guarantees require containment recipes, user/process separation, network controls, or equivalent deployment enforcement. The `contain` and `assess` commands help install, test, and report those boundaries, but a binary running beside an unrestricted process cannot stop that process from opening its own direct socket. Known unsupported paths are documented in [docs/security/current-unsupported-paths.md](docs/security/current-unsupported-paths.md).

**Receipts prove integrity, not completeness.** Signed receipts and hash chains make recorded mediated actions tamper-evident. They do not prove that every action on the host or network was mediated, and they do not prove that an action matched the user's intent.

**Detection is not semantic understanding.** Pipelock uses boundary mediation, policy checks, scanners, and evidence verification. It does not perform general semantic analysis of model intent, source code behavior, or arbitrary retrieved content. New or deeper variants of homoglyph abuse, three-or-more-field splitting, parser differentials, steganography, timing channels, or encrypted exfiltration may require scanner, parser, or deployment updates.

**Identity is mediator-attested.** Receipts bind the identity information observed or configured at the mediation boundary to the mediator's signature. That is not the same as agent non-repudiation or proof that a workload signed the action itself.

## Reporter Credit

Reporters are credited by name, handle, organization, or anonymous credit in the published advisory unless they request otherwise. The published advisory is the canonical credit record.

## Advisory History

None to date.
