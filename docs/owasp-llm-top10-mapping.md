# OWASP Top 10 for LLM Applications (2025): Pipelock Coverage

How Pipelock addresses the [OWASP Top 10 for Large Language Model Applications (2025)](https://genai.owasp.org/llmrisk/).

| Threat | Coverage | Status |
|--------|----------|--------|
| LLM01 Prompt Injection | Strong | Shipped |
| LLM02 Sensitive Information Disclosure | Strong | Shipped |
| LLM03 Supply Chain Vulnerabilities | Partial | Shipped |
| LLM04 Data and Model Poisoning | N/A | Out of scope |
| LLM05 Improper Output Handling | Moderate | Shipped |
| LLM06 Excessive Agency | Strong | Shipped |
| LLM07 System Prompt Leakage | Moderate | Shipped |
| LLM08 Vector and Embedding Weaknesses | N/A | Out of scope |
| LLM09 Misinformation | N/A | Out of scope |
| LLM10 Unbounded Consumption | Partial | Shipped |

---

## LLM01: Prompt Injection

**Threat:** Attackers craft inputs that override the model's instructions, either directly (user input) or indirectly (injected into fetched content, tool results, or documents the model reads).

**Pipelock coverage:**

- **Response scanning:** fetched web content is scanned for prompt injection patterns before reaching the agent. Detects "ignore previous instructions," system/role overrides, jailbreak templates (DAN, developer mode), and multi-language variants. Actions: `block`, `strip`, `warn`, or `ask` (human approval).
- **MCP response scanning:** `pipelock mcp proxy` wraps MCP servers and scans JSON-RPC tool results through the same injection detector. Text is concatenated across content blocks, catching injection split across multiple responses.
- **MCP input scanning:** client requests are scanned for injection patterns in tool arguments before reaching the MCP server. Catches injection payloads being sent *to* tools, not just returned *from* them.
- **Content extraction:** HTML is converted to clean text via go-readability, removing scripts, styles, and hidden elements that could carry injection payloads.

**Coverage: Strong.** This is Pipelock's core feature. Injection scanning covers all network transports (fetch, forward proxy, WebSocket, MCP stdio, MCP HTTP/SSE).

**Gap:** Regex-based detection can miss novel injection patterns. Future: classifier-based detection (see roadmap).

---

## LLM02: Sensitive Information Disclosure

**Threat:** The model leaks sensitive data (API keys, credentials, PII, proprietary information) through its outputs, tool calls, or network requests.

**Pipelock coverage:**

- **DLP pattern matching:** 44 built-in patterns detect API keys, tokens, and credentials in outbound URLs and request bodies. Covers AWS, GCP, GitHub, GitLab, Stripe, OpenAI, Anthropic, Groq, xAI, and 30+ other providers.
- **Environment variable leak detection:** detects the proxy's own env var values in outbound traffic (raw + base64 encoded). Catches secrets passed via environment that the agent tries to exfiltrate.
- **Entropy analysis:** flags high-entropy URL segments and subdomains that look like encoded secrets, even if they don't match known patterns.
- **Domain blocklist:** known exfiltration targets (pastebin, transfer.sh, requestbin, ngrok) are blocked by default.
- **Cross-request exfiltration detection (CEE):** tracks secret fragments across multiple requests. An agent that splits a key across 5 separate URLs is still caught.
- **Data budget:** per-domain and global byte budgets limit how much data an agent can send to any destination.

**Coverage: Strong.** Multiple detection layers (pattern, entropy, env leak, cross-request) make single-layer bypasses insufficient.

---

## LLM03: Supply Chain Vulnerabilities

**Threat:** Malicious or tampered tools, packages, models, or plugins compromise the application through its dependencies.

**Pipelock coverage:**

- **MCP tool scanning:** `tools/list` responses are scanned for poisoned tool descriptions containing hidden instructions, file exfiltration directives, or cross-tool manipulation. SHA256 baseline per session detects rug-pull changes to tool definitions mid-session.
- **Workspace integrity monitoring:** SHA256 manifests detect any file modification, addition, or removal in the workspace. A compromised plugin that modifies config files is detected.
- **Ed25519 signing:** files and manifests can be signed for tamper-evident verification.

**Coverage: Partial.** Detects poisoned MCP tool descriptions and workspace file tampering. Does not scan software dependencies or verify model provenance. For dependency scanning, see [Trivy](https://github.com/aquasecurity/trivy) or Dependabot.

---

## LLM04: Data and Model Poisoning

**Threat:** Training data is manipulated to embed backdoors, biases, or targeted vulnerabilities into the model itself.

**Why out of scope:** Pipelock operates at the network and content layer between agents and external systems. Training data integrity is a model-level concern that requires controls during model development, not at runtime.

---

## LLM05: Improper Output Handling

**Threat:** LLM outputs are passed to downstream systems without validation, enabling injection attacks (XSS, SSRF, command injection) through generated content.

**Pipelock coverage:**

- **MCP response scanning:** tool results are scanned for injection payloads before the agent processes them. Catches cases where a tool returns content that would trick the agent into executing dangerous downstream actions.
- **Content extraction:** HTML is converted to clean text via go-readability, stripping scripts, iframes, and other executable content from fetched pages before the agent sees them.
- **SSRF protection:** if an agent tries to use LLM-generated URLs to access internal services, the SSRF scanner blocks requests to private IP ranges, link-local addresses, and cloud metadata endpoints. DNS rebinding prevention validates resolved IPs.

**Coverage: Moderate.** Pipelock scans content entering the agent and blocks dangerous outbound requests the agent makes. It does not control what the agent does with clean content after it passes scanning (that's the application's responsibility).

---

## LLM06: Excessive Agency

**Threat:** The LLM has unnecessary permissions, autonomy, or access to tools and systems beyond what the task requires.

**Pipelock coverage:**

- **Capability separation:** the agent process (which holds secrets) runs in a network-restricted environment. The proxy (which has network access) holds no agent secrets. Neither process has both capabilities.
- **Domain allowlisting (strict mode):** in strict mode, the agent can only reach explicitly allowed API endpoints. Everything else is blocked. In balanced/audit modes, the allowlist is configured but enforcement depends on the scanner pipeline rather than a hard gate.
- **MCP tool policy:** pre-execution allow/deny rules with regex argument matching. Shell obfuscation detection catches base64/hex-encoded commands. Actions: `block` or `ask` (human approval).
- **Tool chain detection:** subsequence matching on tool call sequences detects multi-step attack patterns (e.g., list files then read then exfiltrate).
- **HITL terminal approval:** `action: ask` prompts the human operator with a y/N/s dialog when suspicious activity is detected.
- **Per-agent profiles (license-gated):** each agent gets independent mode, allowlist, DLP rules, rate limits, and data budget. Multi-agent profiles require a signed license token.

**Coverage: Strong.** Enforces least privilege at the network layer, controls tool execution policy, and supports human-in-the-loop approval.

---

## LLM07: System Prompt Leakage

**Threat:** The system prompt is exposed through crafted queries, revealing internal instructions, business logic, access controls, or API keys embedded in the prompt.

**Pipelock coverage:**

- **DLP scanning:** if an agent leaks its system prompt through outbound network requests, DLP patterns detect any API keys, tokens, or credentials contained in the prompt. Environment variable leak detection catches env-sourced secrets.
- **Egress filtering:** even if the prompt leaks, the agent can only send data to allowed domains. Exfiltration targets are blocked.
- **Cross-request exfiltration detection:** catches prompt fragments split across multiple requests.

**Coverage: Moderate.** Pipelock catches system prompts being exfiltrated through network traffic and detects credentials within leaked prompts. It does not prevent the model from revealing prompt content in its conversational output (that's a model-level control or application-level output filter).

---

## LLM08: Vector and Embedding Weaknesses

**Threat:** Vulnerabilities in RAG retrieval pipelines allow attackers to manipulate vector embeddings, inject malicious content through similarity search, or poison the knowledge base.

**Why out of scope:** Pipelock operates at the network transport layer. Vector database internals, embedding generation, and retrieval ranking are application-layer concerns. For RAG security, see application-level guardrails and embedding validation.

---

## LLM09: Misinformation

**Threat:** The model generates false, misleading, or fabricated information that appears authoritative.

**Why out of scope:** Pipelock scans network traffic for security threats (injection, exfiltration, SSRF). Evaluating the truthfulness of model output requires semantic analysis at the application layer, not the network layer.

---

## LLM10: Unbounded Consumption

**Threat:** The application allows unlimited or poorly controlled resource consumption, enabling denial-of-service through excessive API calls, token usage, or data transfer.

**Pipelock coverage:**

- **Per-domain rate limiting:** sliding window rate limiter prevents bulk requests from one agent overwhelming external services.
- **Response size limits:** `max_response_mb` caps the size of fetched content.
- **Request timeouts:** configurable per-request timeout prevents hanging connections.
- **Data budget:** per-domain and global byte budgets limit total data transfer.
- **URL length limits:** unusually long URLs (potential data exfiltration or resource abuse) are flagged.

**Coverage: Partial.** Limits network-level resource consumption. Does not control token usage, compute time, or memory consumption at the model or application layer.

---

## Summary

Pipelock provides coverage for **7 of 10** threats in the OWASP Top 10 for LLM Applications:

- **Strong (3):** LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency)
- **Moderate (2):** LLM05 (Improper Output Handling), LLM07 (System Prompt Leakage)
- **Partial (2):** LLM03 (Supply Chain), LLM10 (Unbounded Consumption)
- **Out of scope (3):** LLM04 (Data/Model Poisoning), LLM08 (Vector/Embedding), LLM09 (Misinformation)

The 3 strong areas map directly to Pipelock's core capabilities: injection scanning, DLP/exfiltration prevention, and least-privilege enforcement. The 3 out-of-scope threats are about model internals and output truthfulness, which sit at a different layer than network-level security.

For coverage of the OWASP Top 10 for Agentic Applications (ASI01-ASI10), see [owasp-mapping.md](owasp-mapping.md). For the broader OWASP Agentic AI Threats framework (T1-T15), see [owasp-agentic-top15-mapping.md](owasp-agentic-top15-mapping.md). For a competitive feature comparison, see [comparison.md](comparison.md).
