# OpenClaw + Pipelock Deployment Guide

Pipelock sits between your AI agent and the OpenClaw gateway, scanning all MCP traffic for secret exfiltration, prompt injection, and tool poisoning. This guide covers deploying pipelock as a security layer for OpenClaw.

## Why

CVE-2026-25253 (CVSS 8.8) is a cross-site WebSocket hijacking attack against OpenClaw gateways. The attack chain:

1. Victim clicks a malicious link
2. Attacker's page opens a WebSocket to the victim's localhost gateway (no origin validation)
3. Browser auto-sends the gateway auth token
4. Attacker steals the token, connects to the gateway, disables sandbox and safety guardrails
5. Attacker invokes `node.invoke` for arbitrary code execution on the host

Pipelock blocks the post-compromise steps of this chain: tool policy blocks dangerous tool invocations, input scanning catches secret exfiltration in tool arguments, and response scanning detects injection in tool results. Pipelock does not currently perform handshake-level DLP on inbound WebSocket connections (that requires listener mode, which is planned but not yet implemented for WS upstreams).

## Quick Start

**1. Install pipelock:**

```bash
# Homebrew
brew install luckyPipewrench/tap/pipelock

# Or download binary
curl -L https://github.com/luckyPipewrench/pipelock/releases/latest/download/pipelock_linux_amd64.tar.gz | tar xz
```

**2. Generate a wrapped config:**

Input must be a JSON file with a top-level `mcpServers` object.

```bash
# Wrap all MCP servers in your config with pipelock scanning
pipelock generate mcporter -i servers.json -o wrapped.json

# Or modify in-place (creates .bak backup)
pipelock generate mcporter -i servers.json --in-place --backup
```

**3. Restart your agent.** All MCP traffic now routes through pipelock.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Host                           │
│                                                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐   │
│  │          │    │          │    │                  │   │
│  │  Agent   │───>│ Pipelock │───>│ OpenClaw Gateway │   │
│  │          │    │ MCP Proxy│    │   (ws/http)      │   │
│  │ (secrets,│    │          │    │                  │   │
│  │  no net) │    │ (no      │    └──────────────────┘   │
│  │          │    │  secrets, │           │               │
│  └──────────┘    │  scans   │           │               │
│                  │  traffic)│           ▼               │
│                  └──────────┘    ┌──────────────┐       │
│                                 │   Internet   │       │
│                                 └──────────────┘       │
└─────────────────────────────────────────────────────────┘
```

The agent has secrets but no direct network access. Pipelock has no secrets but full network access. This capability separation prevents a compromised agent from exfiltrating secrets directly.

## Two Protection Layers

### Layer 1: MCP Proxy (tool calls and responses)

Wraps the OpenClaw gateway connection with bidirectional scanning:

- **Response scanning** detects prompt injection in tool results
- **Input scanning** catches DLP violations and injection in tool arguments
- **Tool scanning** detects poisoned tool descriptions and rug-pull drift
- **Tool policy** blocks dangerous tool invocations (shell commands, file access)
- **Chain detection** catches suspicious tool call sequences (read-then-exfil patterns)
- **Session binding** pins the tool inventory per session to prevent tool swapping

### Layer 2: HTTP Proxy (fetch and forward)

When the agent makes outbound HTTP requests through pipelock's fetch proxy:

- 9-layer URL scanning (blocklist, DLP, SSRF, rate limiting, entropy checks)
- Response injection detection on fetched content
- Data budget tracking per domain

## Configuration

### Stdio-to-WebSocket (most common)

Your agent talks to pipelock over stdin/stdout. Pipelock connects to the OpenClaw gateway over WebSocket.

```json
{
  "mcpServers": {
    "openclaw": {
      "command": "pipelock",
      "args": [
        "mcp", "proxy",
        "--config", "/path/to/pipelock.yaml",
        "--env", "OPENCLAW_GATEWAY_URL",
        "--env", "OPENCLAW_GATEWAY_TOKEN",
        "--upstream", "ws://localhost:3000/mcp"
      ],
      "env": {
        "OPENCLAW_GATEWAY_URL": "ws://localhost:3000",
        "OPENCLAW_GATEWAY_TOKEN": "your-token-here"
      }
    }
  }
}
```

### Stdio-to-HTTP

If your OpenClaw gateway exposes an HTTP MCP endpoint:

```json
{
  "mcpServers": {
    "openclaw": {
      "command": "pipelock",
      "args": [
        "mcp", "proxy",
        "--config", "/path/to/pipelock.yaml",
        "--upstream", "http://localhost:3000/mcp"
      ]
    }
  }
}
```

### Using `generate mcporter`

Instead of manually editing configs, use the generator:

```bash
# Preview what will change (outputs to stdout)
pipelock generate mcporter -i mcporter.json

# Write to a new file
pipelock generate mcporter -i mcporter.json -o wrapped.json

# Modify in-place with backup
pipelock generate mcporter -i mcporter.json --in-place --backup

# Custom pipelock binary path and config
pipelock generate mcporter -i mcporter.json \
  --pipelock-bin /usr/local/bin/pipelock \
  --config /etc/pipelock/pipelock.yaml
```

The generator is idempotent. Running it twice produces identical output. Servers already wrapped with pipelock are detected and skipped.

## Kubernetes Sidecar Deployment

Run pipelock as a sidecar container alongside your agent:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: your-agent:latest
          env:
            - name: HTTPS_PROXY
              value: "http://localhost:8888"
            # MCP servers configured to use pipelock binary

        - name: pipelock
          image: ghcr.io/luckypipewrench/pipelock:latest
          args: ["run", "--listen", "0.0.0.0:8888"]
          ports:
            - containerPort: 8888
          volumeMounts:
            - name: config
              mountPath: /etc/pipelock
              readOnly: true

      volumes:
        - name: config
          configMap:
            name: pipelock-config
```

Add a NetworkPolicy to restrict the agent container's egress to only the pipelock sidecar:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress
spec:
  podSelector:
    matchLabels:
      app: agent
  policyTypes:
    - Egress
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: agent
      ports:
        - port: 8888
```

## What Pipelock Mitigates

Mapped to the CVE-2026-25253 attack chain:

| Attack Step | Pipelock Defense | Layer |
|---|---|---|
| Token theft via WS handshake | Not yet mitigated (requires WS listener mode, planned) | -- |
| Sandbox disable via tool call | Tool policy blocks dangerous tool invocations | MCP proxy |
| RCE via `node.invoke` | Tool policy deny rules for shell/exec tools | MCP proxy |
| Data exfiltration via tool args | Input scanning catches secrets in outbound calls | MCP proxy |
| Prompt injection in tool results | Response scanning detects injection attempts | MCP proxy |
| Read-then-exfil tool sequences | Chain detection catches multi-step patterns | MCP proxy |
| Outbound HTTP exfiltration | 9-layer URL scanning, DLP on request URLs | HTTP proxy |

Pipelock does not patch the CVE itself (that requires OpenClaw origin validation). It adds defense-in-depth by scanning all traffic between agent and gateway, catching exploitation attempts at multiple points in the attack chain.

## Troubleshooting

### Connection refused to upstream

Check that the OpenClaw gateway is running and accessible at the configured URL:

```bash
# For WebSocket upstreams
wscat -c ws://localhost:3000/mcp

# For HTTP upstreams
curl http://localhost:3000/mcp
```

### DLP false positives

If pipelock blocks legitimate traffic containing strings that match DLP patterns, add suppression rules to your config:

```yaml
suppress:
  - rule: "dlp_*"
    path: "*.example.com"
    reason: "Known safe endpoint"
```

### Tool policy blocks

If pipelock blocks a tool invocation your agent needs:

```yaml
mcp_tool_policy:
  enabled: true
  action: warn  # Change from "block" to "warn" for debugging
  rules:
    - name: "allow my tool"
      tool_pattern: "^your_tool_name$"
      action: warn
```

### Checking what pipelock scanned

Enable verbose logging by including allowed (non-blocked) events:

```yaml
logging:
  include_allowed: true
  include_blocked: true
```

Or check the structured audit log for specific events.

## See Also

- [Configuration Reference](../configuration.md) for all pipelock config fields
- [Deployment Recipes](deployment-recipes.md) for Docker Compose, Kubernetes, iptables, and macOS PF examples
- [Transport Modes](transport-modes.md) for a comparison of all proxy modes and their scanning capabilities
- [Attacks Blocked](../attacks-blocked.md) for real-world attack examples and how pipelock handles them
- [Finding Suppression](suppression.md) for managing DLP false positives
- [Tool Policy Spec](../policy-spec-v0.1.md) for the full tool policy rule format
