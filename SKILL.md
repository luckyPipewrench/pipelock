---
name: pipelock
description: Secure agent HTTP requests through a scanning proxy that catches credential leaks, SSRF, and prompt injection
homepage: https://github.com/luckyPipewrench/pipelock
user-invocable: true
metadata:
  clawdbot:
    emoji: "\U0001F512"
    requires:
      bins: ["pipelock"]
      os: ["darwin", "linux"]
---

# Pipelock Security Harness

Pipelock is a fetch proxy that sits between you and the internet. Every outbound HTTP request passes through a 7-layer scanner pipeline that catches API key leaks, SSRF attempts, prompt injection, and data exfiltration.

## Installation

```bash
# Homebrew (macOS/Linux)
brew install luckyPipewrench/tap/pipelock

# Or Go
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest
```

## Quick Start

Generate a config and start the proxy:

```bash
pipelock generate config --preset balanced -o pipelock.yaml
pipelock run --config pipelock.yaml
```

The proxy listens on `http://localhost:8888`. Route your HTTP requests through it:

```bash
curl "http://localhost:8888/fetch?url=https://example.com/api/data"
```

## Using with MCP Servers

Wrap any MCP server to scan its responses for prompt injection:

```bash
pipelock mcp proxy -- npx @modelcontextprotocol/server-filesystem /path/to/dir
```

## What It Catches

1. **SSRF** - blocks requests to internal IPs, catches DNS rebinding
2. **Domain blocklist** - blocks exfiltration targets (pastebin, transfer.sh)
3. **Rate limiting** - detects unusual request bursts
4. **DLP patterns** - detects API keys (Anthropic, OpenAI, AWS, GitHub) in URLs and bodies
5. **Env var leaks** - detects your actual env var values in outbound traffic
6. **Entropy analysis** - flags high-entropy strings that look like secrets
7. **URL length limits** - flags unusually long URLs suggesting exfiltration

## Actions

Configure what happens when a threat is detected:

- `block` - reject the request
- `strip` - redact the match and forward
- `warn` - log and pass through
- `ask` - terminal prompt for human approval (y/N/s)

## Presets

- `balanced` - default, good for most setups
- `strict` - blocks aggressively, tight thresholds
- `audit` - detect and log only, never blocks
- `claude-code` - tuned for Claude Code agent workflows
- `cursor` - tuned for Cursor IDE
- `generic-agent` - works with any agent framework

## Workspace Integrity

Detect unauthorized changes to your workspace files:

```bash
pipelock integrity init ./workspace
pipelock integrity check ./workspace
```

## More Info

- [OWASP Agentic Top 10 mapping](https://github.com/luckyPipewrench/pipelock/blob/main/docs/owasp-mapping.md)
- [Claude Code integration guide](https://github.com/luckyPipewrench/pipelock/blob/main/docs/guides/claude-code.md)
- Apache 2.0 license, single binary, zero dependencies
