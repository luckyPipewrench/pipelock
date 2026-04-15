# OWASP MCP Top 10: Pipelock Coverage

How Pipelock addresses the [OWASP Top 10 for Model Context Protocol (MCP)](https://owasp.org/www-project-mcp-top-10/).

See also: [OWASP Agentic Top 10 mapping](../owasp-mapping.md) | [OWASP AIVSS coverage](../owasp-agentic-top15-mapping.md) | [EU AI Act mapping](eu-ai-act-mapping.md)

> **Note:** Coverage levels reflect architectural capabilities against known attack patterns, not guarantees of threat prevention. Pipelock is a network-layer proxy; some MCP risks require complementary controls at the client, server, or identity layer. This mapping is for informational purposes and does not constitute compliance certification.

**Last updated:** April 2026 (reviewed against v2.1.3 feature set: mediation envelope, signed action receipts across all MCP transports including stdio / HTTP / HTTP reverse proxy, taint-aware policy escalation with task boundaries, media policy and SVG active-content hardening, posture verify CLI, companion-proxy deployment via `pipelock init sidecar`)

---

## Coverage Summary

| ID | Risk | Coverage | Status |
|----|------|----------|--------|
| MCP01:2025 | Token Mismanagement & Secret Exposure | **Strong** | Shipped |
| MCP02:2025 | Privilege Escalation via Scope Creep | **Moderate** | Shipped |
| MCP03:2025 | Tool Poisoning | **Strong** | Shipped |
| MCP04:2025 | Software Supply Chain Attacks & Dependency Tampering | **Moderate** | Shipped |
| MCP05:2025 | Command Injection & Execution | **Strong** | Shipped |
| MCP06:2025 | Prompt Injection via Contextual Payloads | **Strong** | Shipped |
| MCP07:2025 | Insufficient Authentication & Authorization | **Partial** | Roadmap |
| MCP08:2025 | Lack of Audit and Telemetry | **Strong** | Shipped |
| MCP09:2025 | Shadow MCP Servers | **Moderate** | Shipped |
| MCP10:2025 | Context Injection & Over-Sharing | **Moderate** | Shipped |

---

## MCP01:2025 — Token Mismanagement & Secret Exposure

**Risk:** Hard-coded credentials, long-lived tokens, and secrets stored in model memory or protocol logs can expose sensitive environments.

**Pipelock coverage:**

- **DLP scanning:** 47 regex patterns with 4 checksum validators (Luhn, mod97, ABA, WIF) detect secrets in tool arguments, URLs, headers, and request bodies. Patterns cover AWS, GitHub, Slack, Stripe, Anthropic, OpenAI, and 30+ other provider key formats.
- **Environment leak detection:** `dlp.scan_env` reads the local environment and flags any outbound request containing env var values above a minimum length threshold.
- **MCP input scanning:** scans tool call arguments (client-to-server) for secrets before they reach the MCP server. Catches agents forwarding credentials to untrusted tools.
- **Encoding resistance:** 6-pass normalization decodes base64, hex, and URL encoding before pattern matching. Secrets encoded to evade detection are decoded and caught.

**Configuration:** `dlp`, `mcp_input_scanning`

**Gap:** Token rotation, vault integration, and credential lifecycle management are outside scope. Pipelock detects secret exposure at the transport layer; credential management requires complementary tools.

---

## MCP02:2025 — Privilege Escalation via Scope Creep

**Risk:** Temporary or loosely defined permissions within MCP servers often expand over time, granting agents excessive capabilities.

**Pipelock coverage:**

- **Session binding:** `mcp_session_binding` pins the tool inventory (names + schemas) at session start. If tools are added mid-session (scope expansion), the change is detected and flagged.
- **Tool policy rules:** `mcp_tool_policy` enforces pre-execution allow/deny rules on tool calls. Rules constrain which tools an agent can invoke and with what arguments, regardless of what the MCP server offers.
- **Adaptive enforcement:** automatic escalation from warn to block based on session risk patterns. An agent that triggers multiple warnings gets progressively restricted.
- **Per-agent budgets:** rate limiting and data budgets constrain how much each agent identity can do per time window.

**Configuration:** `mcp_session_binding`, `mcp_tool_policy`, `adaptive_enforcement`

**Gap:** Pipelock detects scope expansion at runtime but doesn't manage server-side permission grants. Reducing over-provisioned OAuth scopes or capability declarations is a governance task outside the proxy layer.

---

## MCP03:2025 — Tool Poisoning

**Risk:** Adversary compromises the tools, plugins, or their outputs that an AI model depends on, injecting malicious, misleading, or biased context.

**Pipelock coverage:**

- **Tool description scanning:** `mcp_tool_scanning` detects poisoning patterns in tool definitions: instruction tags (`<IMPORTANT>`), file exfiltration directives, cross-tool manipulation, and dangerous capability claims.
- **Full-schema extraction:** scans all text-bearing schema fields including `description`, `title`, `default`, `const`, `enum`, `examples`, `pattern`, `$comment`, and vendor extensions (`x-*`). Recurses through `allOf`, `anyOf`, `oneOf`, `$defs`, and composition keywords.
- **Rug-pull detection:** SHA-256 baseline tracking detects tool definition changes between sessions. If a tool's description or schema changes after initial registration, a drift alert fires.
- **Parameter name scanning:** suspicious parameter names like `content_from_reading_ssh_id_rsa` are expanded (underscore/camelCase splitting) and scanned through the injection and DLP pipelines.

**Configuration:** `mcp_tool_scanning`

**Gap:** Source-code-level skill scanning (pre-deployment static analysis) requires complementary tools like Snyk Agent Scan or SkillScan.

---

## MCP04:2025 — Software Supply Chain Attacks & Dependency Tampering

**Risk:** A compromised dependency can alter agent behavior or introduce execution-level backdoors.

**Pipelock coverage:**

- **Community rule bundles:** Ed25519-signed YAML rule bundles with integrity verification. Rules loaded from `~/.pipelock/rules/` are verified against a trusted keyring before use.
- **Binary integrity monitoring:** `pipelock integrity` commands verify the pipelock binary itself has not been modified.
- **Tool drift detection:** rug-pull detection catches tool definitions that change after initial registration, which can indicate a compromised or updated MCP server package.
- **SBOM and provenance:** GoReleaser produces SLSA provenance attestation and SBOM for every release. OpenSSF Scorecard 8.6/10 + Best Practices Silver badge.

**Configuration:** `rules`, `pipelock integrity`

**Gap:** Pipelock does not validate MCP server package origin, registry attestation, or dependency trees. Pre-deployment supply chain verification requires tools like Docker MCP Catalog (image signing), Snyk, or npm audit.

---

## MCP05:2025 — Command Injection & Execution

**Risk:** AI agent constructs and executes system commands, shell scripts, API calls, or code snippets using untrusted input without proper validation.

**Pipelock coverage:**

- **Tool policy with shell normalization:** `mcp_tool_policy` includes 17 default rules covering destructive operations, persistence mechanisms, and credential access. Shell obfuscation (octal encoding, hex encoding, brace expansion, variable assignment, command substitution, IFS manipulation) is normalized before matching.
- **Argument-level matching:** `arg_key` scopes pattern matching to specific tool argument keys, preventing overly broad rules.
- **Sandbox containment (v2.0):** Landlock LSM + network namespaces + seccomp restrict filesystem access, network egress, and syscall surface for sandboxed agent processes. Even if injection succeeds, the command runs in a contained environment.

**Configuration:** `mcp_tool_policy`, `sandbox`

**Gap:** None for network-visible command execution. Commands executed entirely within the agent's local runtime without tool calls are outside the proxy's visibility.

---

## MCP06:2025 — Prompt Injection via Contextual Payloads

**Risk:** Malicious text designed to override agent instructions, embedded in tool results, web content, or error messages.

**Pipelock coverage:**

- **Response scanning:** 6-pass normalization pipeline (NFKC + zero-width stripping, invisible char replacement, leetspeak, optional-whitespace, vowel folding, base64/hex decode) with 25 default patterns covering prompt injection, jailbreak templates, role/behavior overrides, credential solicitation, memory persistence directives, and CJK-language instruction overrides.
- **MCP response scanning:** tool results are scanned through the same pipeline before reaching the agent.
- **State/control poisoning patterns:** detect credential solicitation ("provide your API key"), memory persistence ("save this for future sessions"), preference poisoning ("from now on, always use this tool"), and silent credential handling.
- **Pre-filter optimization:** keyword-based gating skips expensive regex on clean content. Typical scan latency under 50us for clean responses.

**Configuration:** `response_scanning`

**Gap:** Pipelock uses deterministic pattern matching, not ML-based classification. Novel injection phrasing not matching any pattern variant will pass through. Pattern coverage is continuously expanded based on adversarial testing.

---

## MCP07:2025 — Insufficient Authentication & Authorization

**Risk:** MCP servers, tools, or agents fail to properly verify identities or enforce access controls during interactions.

**Pipelock coverage:**

- **Per-agent identity:** agents are identified by name in config, with independent budgets, rate limits, and policy rules per agent.
- **Kill switch API authentication:** bearer-token authentication for the remote kill switch API, with optional IP allowlist and port isolation.
- **Capability separation:** architectural enforcement that agents cannot access the network directly. All traffic is mediated by pipelock.

**Configuration:** `agents`, `kill_switch`

**Gap:** Pipelock does not enforce MCP-level authentication (OAuth 2.1, client certificates) between agent and MCP server. mTLS agent authentication and zero-trust agent identity are on the enterprise roadmap. Channel-level auth is an MCP client/server responsibility per the MCP spec.

---

## MCP08:2025 — Lack of Audit and Telemetry

**Risk:** Limited telemetry from MCP servers and agents impedes investigation and incident response.

**Pipelock coverage:**

- **Structured audit logging:** every scan decision (allow, block, warn, ask, strip) is logged as structured JSON with timestamp, agent identity, tool name, scan result, scanner reason, and duration.
- **Three emission targets:** webhook (async buffered), syslog (UDP), and OTLP (HTTP/protobuf). All fire-and-forget to avoid blocking the proxy.
- **Prometheus metrics:** counters and histograms for all scan categories, exportable to any monitoring stack.
- **Session profiling:** per-session event history with risk scoring for forensic analysis.
- **SARIF output:** `pipelock audit` produces SARIF for integration with GitHub Code Scanning and CI/CD workflows.
- **Severity enforcement:** event severity is hardcoded per event type. Users control the emission threshold (`min_severity`), not the severity itself, preventing misconfiguration from hiding critical events.

**Configuration:** `logging`, `emit`, `session_profiling`, `metrics_listen`

**Gap:** Guaranteed delivery (persistent queue with retry) for critical audit events is on the enterprise roadmap. Current emission is best-effort (queue overflow drops with counter).

---

## MCP09:2025 — Shadow MCP Servers

**Risk:** Unapproved or unsupervised deployments of MCP instances operating outside organizational security governance.

**Pipelock coverage:**

- **Discovery:** `pipelock discover` auto-detects MCP server configurations across Claude Code, Cursor, Windsurf, VS Code, Gemini CLI, and other agent platforms on the local machine.
- **Preflight checks:** `pipelock preflight` validates deployment readiness (network isolation, config completeness, proxy routing).
- **Diagnostics:** `pipelock diagnose` reports environment state, connectivity, and configuration issues.

**Configuration:** CLI tools (`discover`, `preflight`, `diagnose`)

**Gap:** Current discovery is local config parsing across a handful of clients, not runtime or fleet-wide inventory. Continuous shadow MCP monitoring across an organization (like Runlayer's OpenClaw Watch via MDM) requires fleet-level tooling on the enterprise roadmap.

---

## MCP10:2025 — Context Injection & Over-Sharing

**Risk:** Sensitive information from one task, user, or agent may be exposed to another when context windows are shared or insufficiently isolated.

**Pipelock coverage:**

- **Cross-request exfiltration detection (CEE):** tracks entropy budget across requests to detect slow data exfiltration spread across multiple tool calls within a session.
- **Per-agent isolation:** separate config profiles, budgets, and session state per agent identity prevent cross-agent data leakage through the proxy layer.
- **Data budget enforcement:** per-domain byte limits prevent bulk data extraction through allowed endpoints.
- **DLP on all surfaces:** secrets in tool results, error messages, and nested JSON are caught by DLP pattern matching with full encoding resistance.

**Configuration:** `cross_request_detection`, `agents`, `dlp`

**Gap:** Context window isolation (preventing one agent's conversation from leaking into another's) is an agent-framework responsibility, not a network proxy concern. Content fingerprinting for cross-session contamination is not implemented.

---

## Architectural Note

Pipelock operates at the **network transport layer** between the MCP client (agent) and MCP server. This provides visibility into all traffic regardless of the agent framework, programming language, or MCP server implementation. However, some MCP risks that exist purely at the application layer (in-memory state, local variable access, semantic argument validation) are outside the proxy's architectural scope.

For comprehensive MCP security, combine network-layer enforcement (Pipelock) with:
- **Pre-deployment scanning** (Snyk Agent Scan, Aguara) for static tool/skill analysis
- **Server-side protection** (mcp-context-protector) for server-level injection prevention
- **Identity management** (Oasis, Keycard, Alter) for agent identity and access control
- **Container isolation** (Docker MCP Gateway, NemoClaw) for process-level containment
