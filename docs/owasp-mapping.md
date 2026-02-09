# OWASP Agentic Top 10 — Pipelock Coverage

How Pipelock addresses the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-agentic-ai-top-10/).

| Threat | Coverage | Status |
|--------|----------|--------|
| ASI01 Prompt Injection | Strong | Shipped |
| ASI02 Insecure Tool Implementation | Strong | Shipped |
| ASI03 Privilege Escalation | Strong | Shipped |
| ASI04 Insecure Output Handling | Strong | Shipped |
| ASI05 Multi-Agent Orchestration | Partial | Shipped |
| ASI06 Excessive Agency | Strong | Shipped |
| ASI07 Supply Chain Attacks | Partial | Shipped |
| ASI08 Knowledge Base Poisoning | Moderate | Shipped |
| ASI09 Insufficient Logging | Strong | Shipped |
| ASI10 Uncontrolled Resource Consumption | Strong | Shipped |

---

## ASI01: Prompt Injection

**Threat:** Malicious instructions embedded in external data (web pages, tool results, documents) that hijack agent behavior.

**Pipelock coverage:**

- **Response scanning** — fetched web content is scanned for prompt injection patterns before reaching the agent. Actions: `block` (reject entirely), `strip` (redact matched text), `warn` (log and pass through).
- **MCP response scanning** — `pipelock mcp scan` pipes MCP JSON-RPC tool results through the same injection detector. Text is concatenated across content blocks, catching injection split across multiple blocks.
- **Pattern matching** — detects "ignore previous instructions," system/role overrides, jailbreak templates (DAN, developer mode), and multi-language variants.

**Configuration:**
```yaml
response_scanning:
  enabled: true
  action: block  # block, strip, or warn
  patterns:
    - name: "Prompt Injection"
      regex: '(?i)(ignore|disregard)\s+(all\s+)?(previous|prior)\s+(instructions|prompts)'
```

**Gap:** Regex-based detection can miss novel injection patterns. Future: classifier-based detection (see roadmap).

---

## ASI02: Insecure Tool Implementation

**Threat:** Tools that execute without proper validation, allowing agents to misuse them for unintended actions.

**Pipelock coverage:**

- **Fetch proxy as a controlled tool** — instead of giving agents raw `curl`/`fetch`, the proxy is the only network tool. Every request goes through the full scanner pipeline.
- **MCP response scanning** — tool results from MCP servers are scanned for injection payloads before the agent processes them.
- **Input validation** — URLs are validated, parsed, and scanned before any HTTP request is made. Malformed URLs are rejected.

---

## ASI03: Privilege Escalation

**Threat:** An agent gains access to resources or capabilities beyond what it should have.

**Pipelock coverage:**

- **Capability separation** — the agent process (which holds secrets) runs in a network-restricted environment. The fetch proxy (which has network access) holds no secrets. Neither process has both.
- **Domain allowlisting** — the agent can only reach explicitly allowed API endpoints (e.g., `*.anthropic.com`, `github.com`).
- **SSRF protection** — blocks requests to internal/private IP ranges (RFC 1918, link-local, loopback) with DNS rebinding prevention. Custom DialContext resolves DNS and validates all returned IPs before connecting.
- **Docker Compose isolation** — `pipelock generate docker-compose` creates a network topology where the agent container has no direct internet access.

---

## ASI04: Insecure Output Handling

**Threat:** Agent outputs (from tools, web fetches, etc.) are passed to downstream consumers without sanitization.

**Pipelock coverage:**

- **Response scanning** — all fetched content is scanned before being returned. Injection patterns are blocked, stripped, or warned about.
- **Content extraction** — HTML is converted to clean text via go-readability, removing scripts, styles, and other executable content.
- **MCP scanning** — tool results are scanned for injection even when returned as structured JSON-RPC responses.

---

## ASI05: Multi-Agent Orchestration

**Threat:** Agents in a multi-agent system can attack each other through shared resources, message passing, or lateral movement.

**Pipelock coverage:**

- **Multi-agent identification** — each agent identifies itself via `X-Pipelock-Agent` header. All audit log entries include the agent name, enabling per-agent monitoring.
- **File integrity monitoring** — `pipelock integrity init/check/update` detects unauthorized workspace modifications. An agent that tampers with shared files is detected.
- **Ed25519 signing** — agents can sign and verify files/manifests. Tampered content is cryptographically detectable.

**Gap:** No runtime inter-agent communication policy yet. See roadmap issue [#44](https://github.com/luckyPipewrench/pipelock/issues/44).

---

## ASI06: Excessive Agency

**Threat:** An agent has more capabilities than it needs, creating a larger attack surface.

**Pipelock coverage:**

- **Principle of least privilege** — the agent only reaches allowed API domains. Everything else is blocked.
- **Configurable enforcement modes** — strict (no network), balanced (allowlisted APIs + fetch proxy), audit (log everything).
- **Domain blocklist** — known exfiltration targets (pastebin, transfer.sh) are explicitly blocked.
- **Rate limiting** — per-domain sliding window prevents bulk data transfer even to allowed domains.

---

## ASI07: Supply Chain Attacks

**Threat:** Compromised dependencies, tools, or MCP servers introduce malicious behavior.

**Pipelock coverage:**

- **Workspace integrity monitoring** — SHA256 manifests detect any file modification, addition, or removal in the workspace.
- **MCP response scanning** — compromised MCP servers that inject prompt injection payloads into tool results are detected.
- **Ed25519 signing** — files and manifests can be signed for tamper-evident verification.

**Gap:** No dependency scanning (use [Trivy](https://github.com/aquasecurity/trivy) or Dependabot for that). No MCP server identity verification yet.

---

## ASI08: Knowledge Base Poisoning

**Threat:** Poisoned data in knowledge bases, RAG pipelines, or fetched web content manipulates agent behavior.

**Pipelock coverage:**

- **Response scanning** — fetched web content (the most common knowledge source for coding agents) is scanned for injection.
- **Content extraction** — go-readability strips non-content elements, reducing the attack surface of fetched pages.

**Gap:** No semantic analysis of retrieved content. Pipelock detects pattern-based injection but not subtly misleading information.

---

## ASI09: Insufficient Logging

**Threat:** Lack of audit trails makes it impossible to detect, investigate, or respond to security incidents.

**Pipelock coverage:**

- **Structured JSON logging** — every request is logged with zerolog: URL, agent, scanner results, action taken, timestamp.
- **Prometheus metrics** — `/metrics` endpoint for alerting and dashboards. Custom registry avoids global state pollution.
- **JSON stats** — `/stats` endpoint with top blocked domains, scanner hit counts, block rate.
- **Per-agent attribution** — every log entry includes the agent name for filtering and investigation.
- **Configurable verbosity** — log allowed requests, blocked requests, or both.

---

## ASI10: Uncontrolled Resource Consumption

**Threat:** An agent consumes excessive resources (API calls, compute, storage) through runaway loops or amplification attacks.

**Pipelock coverage:**

- **Per-domain rate limiting** — sliding window rate limiter prevents bulk requests to any single domain.
- **Response size limits** — `max_response_mb` caps the size of fetched content.
- **URL length limits** — unusually long URLs (potential data exfiltration) are flagged.
- **Request timeouts** — configurable per-request timeout prevents hanging connections.

---

## Summary

Pipelock provides strong coverage for 7/10 OWASP Agentic threats, partial coverage for 2/10, and moderate coverage for 1/10. The primary gaps are in multi-agent communication policy (ASI05, [roadmap](https://github.com/luckyPipewrench/pipelock/issues/44)) and semantic content analysis (ASI08).

No single tool covers all 10 threats. Pipelock focuses on the **network egress + content inspection + workspace integrity** layers. For OS-level sandboxing, see [Anthropic srt](https://github.com/anthropic-experimental/sandbox-runtime). For shell-level policy, see [agentsh](https://github.com/canyonroad/agentsh). See [comparison.md](comparison.md) for a full feature matrix.
