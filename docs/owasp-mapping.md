# OWASP Agentic Top 10 — Pipelock Coverage

How Pipelock addresses the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

| Threat | Coverage | Status |
|--------|----------|--------|
| ASI01 Agent Goal Hijack | Strong | Shipped |
| ASI02 Tool Misuse | Partial | Shipped |
| ASI03 Identity & Privilege Abuse | Strong | Shipped |
| ASI04 Supply Chain Vulnerabilities | Partial | Shipped |
| ASI05 Unexpected Code Execution | Moderate | Shipped |
| ASI06 Memory & Context Poisoning | Moderate | Shipped |
| ASI07 Insecure Inter-Agent Communication | Partial | Shipped |
| ASI08 Cascading Failures | Moderate | Shipped |
| ASI09 Human-Agent Trust Exploitation | Partial | Shipped |
| ASI10 Rogue Agents | Strong | Shipped |

---

## ASI01: Agent Goal Hijack

**Threat:** Attackers redirect agent objectives through malicious text in external data (web pages, tool results, documents).

**Pipelock coverage:**

- **Response scanning** — fetched web content is scanned for prompt injection patterns before reaching the agent. Actions: `block` (reject entirely), `strip` (redact matched text), `warn` (log and pass through), `ask` (human approval).
- **MCP response scanning** — `pipelock mcp proxy` wraps MCP servers and scans JSON-RPC tool results through the same injection detector. Text is concatenated across content blocks, catching injection split across multiple blocks.
- **MCP input scanning** — client requests are scanned for injection patterns in tool arguments before reaching the MCP server. Catches injection payloads being sent *to* tools, not just returned *from* them. Actions: `block` or `warn` (no `ask` — input scanning runs on the request path with no terminal interaction).
- **Pattern matching** — detects "ignore previous instructions," system/role overrides, jailbreak templates (DAN, developer mode), and multi-language variants.

**Configuration:**
```yaml
response_scanning:
  enabled: true
  action: block  # block, strip, warn, or ask
  # 5 patterns ship by default (prompt injection, system override,
  # role override, new instructions, jailbreak). Example:
  patterns:
    - name: "Prompt Injection"
      regex: '(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|context)'
```

Use `pipelock generate config --preset balanced` for the complete default pattern set.

**Gap:** Regex-based detection can miss novel injection patterns. Future: classifier-based detection (see roadmap).

---

## ASI02: Tool Misuse

**Threat:** Agents misuse legitimate tools due to prompt injection, misalignment, or unsafe delegation — calling tools with destructive parameters or chaining tools in unexpected ways.

**Pipelock coverage:**

- **Fetch proxy as a controlled tool** — instead of giving agents raw `curl`/`fetch`, the proxy is the only network tool. Every request goes through the full scanner pipeline.
- **MCP response scanning** — tool results from MCP servers are scanned for injection payloads before the agent processes them.
- **MCP input scanning** — client requests are scanned for DLP leaks and injection in tool arguments before reaching the server. Catches secrets or injection payloads being passed as tool call parameters.
- **Input validation** — URLs are validated, parsed, and scanned before any HTTP request is made. Malformed URLs are rejected.

**Gap:** Pipelock controls the HTTP fetch tool and scans MCP traffic bidirectionally (requests and responses). It does not restrict shell/filesystem operations. For shell/filesystem controls, see [agentsh](https://github.com/canyonroad/agentsh) or [srt](https://github.com/anthropic-experimental/sandbox-runtime).

---

## ASI03: Identity & Privilege Abuse

**Threat:** Attackers exploit inherited or cached credentials, delegated permissions, or agent-to-agent trust to access resources beyond intended scope.

**Pipelock coverage:**

- **Capability separation** — the agent process (which holds secrets) runs in a network-restricted environment. The fetch proxy (which has network access) holds no secrets. Neither process has both.
- **Domain allowlisting** — the agent can only reach explicitly allowed API endpoints (e.g., `*.anthropic.com`, `github.com`).
- **SSRF protection** — blocks requests to internal/private IP ranges (RFC 1918, link-local, loopback) with DNS rebinding prevention. Custom DialContext resolves DNS and validates all returned IPs before connecting.
- **Docker Compose isolation** — `pipelock generate docker-compose` creates a network topology where the agent container has no direct internet access.

---

## ASI04: Supply Chain Vulnerabilities

**Threat:** Malicious or tampered tools, skill packages, models, or agent personas compromise execution.

**Pipelock coverage:**

- **Workspace integrity monitoring** — SHA256 manifests detect any file modification, addition, or removal in the workspace. A compromised skill that modifies config files is detected.
- **MCP response scanning** — compromised MCP servers that inject prompt injection payloads into tool results are detected.
- **Ed25519 signing** — files and manifests can be signed for tamper-evident verification. Unsigned or re-signed files are flagged.

**Gap:** No dependency scanning (use [Trivy](https://github.com/aquasecurity/trivy) or Dependabot for that). No MCP server identity verification yet.

---

## ASI05: Unexpected Code Execution

**Threat:** Agents generate or execute attacker-controlled code, either directly or through manipulated tool outputs.

**Pipelock coverage:**

- **MCP proxy scanning** — `pipelock mcp proxy` scans tool results before the agent sees them, catching injection payloads that could trick agents into executing malicious code.
- **Content extraction** — HTML is converted to clean text via go-readability, removing scripts, styles, and other executable content from fetched pages.
- **DLP pattern matching** — detects API key formats in URLs and request bodies, which can indicate code execution results leaking secrets.

**Gap:** Pipelock does not sandbox code execution itself. For OS-level sandboxing, see [srt](https://github.com/anthropic-experimental/sandbox-runtime) or [agentsh](https://github.com/canyonroad/agentsh).

---

## ASI06: Memory & Context Poisoning

**Threat:** Attackers corrupt the data sources an agent relies on for knowledge and decision-making, leading to flawed or malicious outcomes.

**Pipelock coverage:**

- **Response scanning** — fetched web content (the most common knowledge source for coding agents) is scanned for injection before entering the agent's context.
- **Content extraction** — go-readability strips non-content elements, reducing the attack surface of fetched pages.
- **Workspace integrity monitoring** — detects unauthorized modifications to memory files, config files, and other workspace data the agent reads.

**Gap:** No semantic analysis of retrieved content. Pipelock detects pattern-based injection but not subtly misleading information.

---

## ASI07: Insecure Inter-Agent Communication

**Threat:** Agents in a multi-agent system attack each other through shared resources, message passing, or lateral movement through workspace files.

**Pipelock coverage:**

- **Multi-agent identification** — each agent identifies itself via `X-Pipelock-Agent` header. All audit log entries include the agent name, enabling per-agent monitoring.
- **File integrity monitoring** — `pipelock integrity init/check/update` detects unauthorized workspace modifications. An agent that tampers with shared handoff files is detected.
- **Ed25519 signing** — agents can sign and verify files/manifests. Tampered content is cryptographically detectable.

**Gap:** No runtime inter-agent communication policy yet. See roadmap issue [#44](https://github.com/luckyPipewrench/pipelock/issues/44).

---

## ASI08: Cascading Failures

**Threat:** Failures propagate through agent chains — one agent's error or compromise triggers failures in downstream agents.

**Pipelock coverage:**

- **Per-domain rate limiting** — sliding window rate limiter prevents bulk requests from one agent overwhelming external services.
- **Response size limits** — `max_response_mb` caps the size of fetched content, preventing memory exhaustion.
- **Request timeouts** — configurable per-request timeout prevents hanging connections that block agent pipelines.
- **Structured logging** — every request is logged with zerolog, enabling rapid diagnosis of failure chains across agents.

**Gap:** No circuit-breaker pattern or agent-level health checks yet.

---

## ASI09: Human-Agent Trust Exploitation

**Threat:** Attackers exploit the trust humans place in agent outputs, using agents as intermediaries to deliver manipulated content or unauthorized actions.

**Pipelock coverage:**

- **HITL terminal approval** — `action: ask` prompts the human operator with a terminal y/N/s dialog when suspicious content is detected. The human can approve, deny, or strip before the request proceeds.
- **Audit logging** — every request and scanner detection is logged, giving humans a verifiable record to review.
- **Prometheus metrics** — `/metrics` and `/stats` endpoints surface block rates, scanner hits, and top domains for human oversight dashboards.

**Gap:** No user-facing UI for non-terminal environments. HITL is terminal-only in v0.1.4.

---

## ASI10: Rogue Agents

**Threat:** Agents act outside their intended boundaries due to compromised objectives, misalignment, or adversarial manipulation.

**Pipelock coverage:**

- **Principle of least privilege** — the agent only reaches allowed API domains. Everything else is blocked.
- **Capability separation** — the agent process has no direct network access. Only the proxy (which has no secrets) can reach the internet.
- **Configurable enforcement modes** — strict (block on detection, tight thresholds), balanced (warn on detection, default thresholds), audit (detect and log without blocking).
- **Domain blocklist** — known exfiltration targets (pastebin, transfer.sh) are explicitly blocked.
- **Rate limiting** — per-domain sliding window prevents bulk data transfer even to allowed domains.
- **Environment variable leak detection** — detects the proxy's own env var values in outbound traffic (raw + base64).
- **Entropy analysis** — flags high-entropy strings that look like encoded secrets.
- **URL length limits** — unusually long URLs (potential data exfiltration) are flagged.

---

## Summary

Pipelock provides strong coverage for 3/10 OWASP Agentic threats (ASI01, ASI03, ASI10), moderate coverage for 3/10 (ASI05, ASI06, ASI08), and partial coverage for 4/10 (ASI02, ASI04, ASI07, ASI09). The primary gaps are in inter-agent communication policy (ASI07, [roadmap](https://github.com/luckyPipewrench/pipelock/issues/44)) and semantic content analysis (ASI06).

No single tool covers all 10 threats. Pipelock focuses on the **network egress + content inspection + workspace integrity** layers. For OS-level sandboxing, see [Anthropic srt](https://github.com/anthropic-experimental/sandbox-runtime). For shell-level policy, see [agentsh](https://github.com/canyonroad/agentsh). See [comparison.md](comparison.md) for a full feature matrix.
