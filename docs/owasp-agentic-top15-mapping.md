# OWASP Agentic AI Threats & Mitigations — Pipelock Coverage

How Pipelock addresses the [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/) framework (15 threats, published by the OWASP Agentic Security Initiative).

This is separate from the [OWASP Top 10 for Agentic Applications](owasp-mapping.md) (ASI01-ASI10). Both frameworks overlap but the Threats & Mitigations list is broader.

| Threat | Coverage | Status |
|--------|----------|--------|
| T1 Memory Poisoning | Strong | Shipped |
| T2 Tool Misuse | Strong | Shipped |
| T3 Privilege Compromise | Strong | Shipped |
| T4 Resource Overload | Partial | Shipped |
| T5 Cascading Hallucination Attacks | — | Out of scope |
| T6 Intent Breaking & Goal Manipulation | Moderate | Shipped |
| T7 Misaligned & Deceptive Behaviors | Strong | Shipped |
| T8 Repudiation & Untraceability | Strong | Shipped |
| T9 Identity Spoofing & Impersonation | Partial | Shipped |
| T10 Overwhelming Human-in-the-Loop | Recognized gap | Roadmap |
| T11 Unexpected RCE and Code Attacks | Moderate | Shipped |
| T12 Agent Communication Poisoning | Strong | Shipped |
| T13 Rogue Agents in Multi-Agent Systems | Strong | Shipped |
| T14 Human Attacks on Multi-Agent Systems | Partial | Shipped |
| T15 Human Manipulation | — | Out of scope |

---

## Covered Threats (8 checked on submission)

### T1: Memory Poisoning

**Threat:** Malicious data injected into agent memory corrupts future decisions. Poisoned workspace files, config, or context documents alter agent behavior long after the initial injection.

**Pipelock coverage:**

- **Workspace integrity monitoring** — `pipelock integrity init/check/update` tracks SHA256 hashes of all workspace files. Any modification, addition, or deletion is detected and reported.
- **Ed25519 signing** — manifests and files can be cryptographically signed. Tampered content fails verification.
- **Response scanning** — fetched content (a common source of memory/context data) is scanned for prompt injection before the agent sees it.

**Coverage: Strong.** Integrity monitoring catches file-level poisoning. Response scanning catches injection in fetched content.

**Roadmap:** Signed integrity manifests for multi-agent trust chains.

---

### T2: Tool Misuse

**Threat:** Agents misuse legitimate tools due to prompt injection, misalignment, or unsafe delegation. Tools get called with destructive parameters or chained in unexpected ways.

**Pipelock coverage:**

- **Fetch proxy as controlled tool** — the agent's only network access is through the proxy. Every request goes through the 7-layer scanner pipeline.
- **MCP proxy** — `pipelock mcp proxy` wraps MCP servers and scans tool responses for injection payloads.
- **HITL approvals** — suspicious requests can trigger human-in-the-loop terminal approval before proceeding.

**Coverage: Strong.** Controls the HTTP fetch tool, scans MCP responses for injection, and scans MCP requests for DLP leaks and injection in tool arguments. Does not restrict shell/filesystem operations.

---

### T3: Privilege Compromise

**Threat:** Unauthorized escalation or misuse of permissions within an agent. Leaked credentials let agents operate beyond their intended scope.

**Pipelock coverage:**

- **Capability separation** — the agent process (holds secrets, no network) and the proxy (has network, no secrets) run separately. Neither has both.
- **Domain allowlisting** — agents can only reach explicitly allowed API endpoints.
- **SSRF protection** — blocks requests to internal/private IP ranges with DNS rebinding prevention.
- **DLP scanning** — 8 built-in patterns detect API keys, tokens, and credentials in outbound traffic.
- **Environment variable leak detection** — detects the proxy's own env var values (raw + base64) in URLs.

**Coverage: Strong.** Multiple layers prevent credential leakage and limit agent network access.

---

### T7: Misaligned & Deceptive Behaviors

**Threat:** Agents act deceptively due to misaligned objectives or reasoning. A compromised agent may exfiltrate data while appearing to function normally.

**Pipelock coverage:**

- **DLP scanning** — catches API keys, tokens, and credentials in outbound URLs regardless of why the agent is sending them.
- **Entropy analysis** — flags high-entropy URL segments that look like encoded secrets, even if they don't match known patterns.
- **Domain blocklist** — known exfiltration targets (pastebin, transfer.sh, etc.) are blocked.
- **Audit logging** — every request is logged with zerolog, creating a verifiable trail of all agent network activity.

**Coverage: Strong.** DLP + entropy + blocklist catches most exfiltration attempts. Audit trail enables post-incident analysis.

---

### T8: Repudiation & Untraceability

**Threat:** Agent actions can't be reliably traced or accounted for. Insufficient logging makes incident reconstruction impossible.

**Pipelock coverage:**

- **Structured audit logging** — every proxy request is logged as structured JSON (zerolog) with: URL, domain, agent name, result (allowed/blocked), scanner reason, timestamp.
- **Per-agent identification** — agents identify via `X-Pipelock-Agent` header. All log entries include the agent name.
- **Prometheus metrics** — `/metrics` endpoint exports request counts, scanner hits, and latency histograms for dashboards.
- **JSON stats** — `/stats` endpoint provides real-time top domains and block reasons.
- **Grafana dashboard** — `configs/grafana-dashboard.json` provides a ready-to-import security overview.

**Coverage: Strong.** Every proxy interaction is logged, attributed, and exportable. This is one of Pipelock's strongest areas.

---

### T11: Unexpected RCE and Code Attacks

**Threat:** Unsafe code generation leads to remote code execution. Agents execute attacker-controlled code or exfiltrate results.

**Pipelock coverage:**

- **Egress blocking** — even if an agent executes malicious code, outbound network access is restricted to allowed domains. Callback/exfil to attacker-controlled servers is blocked.
- **MCP proxy scanning** — tool results are scanned for injection payloads before the agent processes them, reducing the chance of code injection through tool responses.
- **Content extraction** — HTML is converted to clean text via go-readability, removing scripts and executable content from fetched pages.

**Coverage: Moderate.** Pipelock limits the blast radius of RCE by blocking exfiltration, but does not sandbox code execution itself.

**Roadmap:** For OS-level sandboxing, see [Anthropic srt](https://github.com/anthropic-experimental/sandbox-runtime).

---

### T12: Agent Communication Poisoning

**Threat:** False or malicious information injected into inter-agent communication channels. Poisoned tool responses redirect agent behavior.

**Pipelock coverage:**

- **MCP response scanning** — `pipelock mcp proxy` scans all JSON-RPC tool results for prompt injection patterns. Text is concatenated across content blocks, catching injection split across multiple blocks.
- **MCP input scanning** — client requests are also scanned for injection patterns and DLP leaks in tool arguments. Catches poisoned payloads being sent *to* tools, not just returned *from* them.
- **Response scanning** — fetched web content is scanned with the same injection detector.
- **Configurable actions** — response scanning: `block` (reject), `strip` (redact matched text), `warn` (log and pass through), `ask` (human approval). Input scanning: `block` or `warn` only (no `ask` — request path has no terminal interaction).

**Coverage: Strong.** MCP traffic is scanned bidirectionally (requests and responses). HTTP channels are scanned for injection.

**Gap:** Regex-based detection can miss novel injection patterns. Future: classifier-based detection.

---

### T13: Rogue Agents in Multi-Agent Systems

**Threat:** Compromised or misaligned agents disrupt coordinated operations. A rogue agent modifies shared workspace files, poisoning other agents.

**Pipelock coverage:**

- **Workspace integrity monitoring** — detects unauthorized file modifications in shared workspaces. If Agent A writes a poisoned config file, integrity check catches it before Agent B reads it.
- **Per-agent egress filtering** — each agent runs behind its own proxy instance with its own allowlist.
- **Ed25519 signing** — agents sign their outputs. Other agents can verify authenticity before trusting shared data.
- **Audit logging** — per-agent request logs enable identifying which agent is behaving anomalously.

**Coverage: Strong.** This is the lateral movement defense described in the [blog post](https://pipelab.org/pipelock/blog/2025/05/15/lateral-movement/).

---

## Partially Covered Threats

### T4: Resource Overload

**Threat:** Attackers exhaust computational or memory resources to disrupt agent performance.

**Pipelock coverage:**

- **Per-domain rate limiting** — sliding window rate limiter prevents bulk requests.
- **Response size limits** — `max_response_mb` caps fetched content size.
- **Request timeouts** — configurable per-request timeout prevents hanging connections.

**Coverage: Partial.** Limits network-level resource consumption. Does not address CPU/memory exhaustion from agent compute.

### T6: Intent Breaking & Goal Manipulation

**Threat:** Attackers alter or redirect agent goals toward unintended actions.

**Coverage: Moderate.** Overlaps with T1/T12 (injection scanning). Response scanning catches explicit "ignore previous instructions" patterns. Does not detect subtle goal manipulation through carefully crafted context.

### T9: Identity Spoofing & Impersonation

**Threat:** Adversaries impersonate agents or users for unauthorized access.

**Coverage: Partial.** Ed25519 signing provides agent identity verification for file-level operations. `X-Pipelock-Agent` header identifies agents in proxy traffic. No certificate-based agent authentication yet.

### T14: Human Attacks on Multi-Agent Systems

**Threat:** Humans exploit inter-agent trust relationships to trigger cascading failures.

**Coverage: Partial.** Integrity monitoring and signing create trust boundaries. Audit logging enables detection. No automated trust policy enforcement between agents yet.

---

## Not Addressed

### T5: Cascading Hallucination Attacks

**Threat:** False information from one model spreads through interconnected systems.

**Why out of scope:** Pipelock operates at the network/content layer. Hallucination detection requires model-level semantic analysis, which is outside Pipelock's architecture.

### T10: Overwhelming Human-in-the-Loop

**Threat:** Attackers overload human overseers with excessive approval requests to reduce scrutiny.

**Why not yet addressed:** Pipelock's HITL feature (`action: ask`) prompts for human approval, but has no rate limiting or batching of approval requests. High-volume approval flooding could reduce human attention. This is a recognized gap.

**Roadmap:** Approval rate limiting, auto-escalation thresholds, summary batching.

### T15: Human Manipulation

**Threat:** Exploiting user trust in AI to deceive humans into unsafe actions.

**Why out of scope:** This is a social engineering threat at the human-AI interaction layer. Pipelock operates at the infrastructure layer between agents and external systems.

---

## Summary

Pipelock provides coverage for **12 of 15** threats in the OWASP Agentic AI framework:

- **Strong (7):** T1, T2, T3, T7, T8, T12, T13
- **Moderate (2):** T6, T11
- **Partial (3):** T4, T9, T14
- **Not yet addressed (1):** T10
- **Out of scope (2):** T5, T15

The strongest coverage areas are egress filtering, DLP, audit logging, integrity monitoring, and MCP scanning. The primary gaps are in HITL flood protection (T10), agent identity/authentication (T9), and semantic content analysis (T5/T6).

For coverage of the OWASP Top 10 for Agentic Applications (ASI01-ASI10), see [owasp-mapping.md](owasp-mapping.md). For a competitive feature comparison, see [comparison.md](comparison.md).
