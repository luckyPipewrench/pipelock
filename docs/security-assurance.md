# Security Assurance Case

This document describes Pipelock's security model, trust boundaries, threat coverage, and known limitations. It serves as the project's assurance case — a structured argument that security requirements are met.

## Threat Model

Pipelock protects against AI agents being tricked into harmful actions. The primary threats are:

1. **Credential exfiltration** — Agent leaks API keys, tokens, or secrets through HTTP requests, DNS queries, URL parameters, or MCP tool arguments.
2. **Prompt injection** — Attacker-controlled text in web pages or tool results redirects the agent's behavior.
3. **Tool misuse** — Agent executes destructive commands (file deletion, force-push, reverse shells) due to injection or misconfiguration.
4. **Tool poisoning** — MCP server descriptions contain hidden instructions or change definitions mid-session to manipulate agent behavior.
5. **Data exfiltration** — Agent sends sensitive workspace data to external endpoints through legitimate-looking requests.

These map to the [OWASP Top 10 for Agentic Applications](owasp-mapping.md) and are tested against [200+ evasion techniques](../CONTRIBUTING.md).

## Trust Boundaries

Pipelock enforces a capability separation architecture:

```text
+-----------------------+          +------------------------+          +----------+
|       Agent           |   --->   |     Pipelock Proxy     |   --->   | Internet |
| (has secrets/API keys |          | (has network access,   |          |          |
|  no network access)   |          |  no secrets)           |          |          |
+-----------------------+          +------------------------+          +----------+
```

**Trust boundary 1: Agent → Proxy.** All outbound HTTP traffic passes through the fetch proxy. The agent cannot reach the network directly (enforced by container networking, firewall rules, or OS-level restrictions).

**Trust boundary 2: MCP Client → MCP Server.** The MCP proxy sits between the agent and any MCP server, scanning both directions. Client requests are checked for DLP leaks and injection. Server responses are checked for prompt injection and poisoned tool descriptions.

**Trust boundary 3: Tool call → Execution.** The tool call policy engine evaluates MCP `tools/call` requests against configurable rules before they reach the server. Destructive operations can be blocked regardless of how the agent was tricked into requesting them.

## Security Controls

### Defense in Depth

No single control is assumed to be sufficient. The scanner pipeline applies 9 layers:

| Layer | Protects Against |
|-------|-----------------|
| Scheme enforcement | Non-HTTP protocol abuse |
| Domain blocklist/allowlist | Known-bad destinations, scope control |
| DLP pattern matching | Credential leakage (15+ patterns, encoding-aware) |
| Path entropy analysis | Exfiltration via high-entropy URL segments |
| Subdomain entropy analysis | DNS-based exfiltration |
| SSRF protection | Private network access, DNS rebinding |
| Rate limiting | Slow-drip exfiltration |
| URL length limits | Oversized exfiltration payloads |
| Data budgets | Per-domain byte limits |

Response scanning adds prompt injection detection on fetched content. MCP scanning adds bidirectional inspection of tool calls and results.

### Fail-Closed Design

All ambiguous states default to blocking:

- HITL timeout → block
- Non-terminal input → block
- JSON parse errors → block (configurable)
- Context cancellation → block
- Unknown policy actions → treated as block

### Evasion Resistance

DLP and injection scanners are tested against encoding chains (base64, hex, multi-layer URL encoding), Unicode confusables (Cyrillic, Greek, Armenian, Cherokee), combining marks, control character insertion, field splitting, and whitespace manipulation. See the test suite for the full evasion catalog.

## What Pipelock Does NOT Protect Against

Honest assessment of limitations:

- **Model-level attacks** — If the model itself is compromised or fine-tuned to be malicious, Pipelock cannot detect this. We operate at the communication boundary, not inside the model.
- **Novel evasion techniques** — Pattern-based detection catches known techniques. Novel bypasses require scanner updates. We do not claim complete coverage.
- **Encrypted or steganographic exfiltration** — Data hidden within legitimate-looking content (e.g., encoded in image pixels or timing channels) is beyond pattern-based detection.
- **Insider threats** — If the agent operator intentionally configures Pipelock to be permissive, the tool respects that configuration.
- **Attacks that don't cross a boundary** — If an agent and its tools run in the same process with no proxy, Pipelock has nothing to inspect.

## Compliance Mappings

Detailed mappings to security frameworks:

- [OWASP Top 10 for Agentic Applications](owasp-mapping.md) — Coverage of ASI01–ASI10
- [OWASP Agentic AI Threats & Mitigations](owasp-agentic-top15-mapping.md) — Coverage of T1–T15
- [EU AI Act Compliance Mapping](compliance/eu-ai-act-mapping.md) — Articles 9, 12–15, 26 with NIST AI RMF crosswalk

## Verification

Security claims are verified through:

- **Unit and integration tests** — 1,900+ tests, race detector enabled in CI, 96%+ statement coverage
- **Evasion test suite** — 200+ attack techniques tested against scanners
- **Static analysis** — CodeQL (security-and-quality) and golangci-lint with gosec
- **Dependency monitoring** — Dependabot alerts, govulncheck in CI
- **Signed releases** — Cosign signatures, SLSA provenance attestations, CycloneDX SBOM
- **Vulnerability disclosure** — Responsible disclosure via [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories)
