# Using Pipelock with Claude Code

Pipelock sits between Claude Code and MCP servers, scanning every response for
prompt injection before it reaches the agent. This guide covers both MCP proxy
mode and HTTP fetch proxy mode.

## Quick Start

```bash
# 1. Install pipelock
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

# 2. Verify it works
pipelock version

# 3. Wrap an MCP server
pipelock mcp proxy --config configs/claude-code.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## MCP Proxy Mode

Pipelock wraps any MCP server as a stdio proxy with bidirectional scanning.
Client requests are scanned for DLP leaks and injection in tool arguments.
Server responses are scanned for prompt injection before forwarding to the client.

```text
Claude Code  <-->  pipelock mcp proxy  <-->  MCP Server
  (client)         (scan both directions)     (subprocess)
```

### How It Works

1. Pipelock starts the MCP server as a child process
2. Client requests (stdin) are scanned for DLP patterns, env leaks, and injection
3. Clean requests are forwarded; flagged requests are blocked or warned per config
4. Server responses (stdout) are scanned line-by-line for injection patterns
5. Clean responses are forwarded; threats trigger the configured action
6. Server stderr is forwarded to pipelock's stderr for diagnostics

### Actions

| Action | Behavior | Use When |
|--------|----------|----------|
| `warn` | Log detection, forward response unchanged | Tuning patterns, low-risk environments |
| `block` | Replace response with JSON-RPC error (-32000) | Production, unattended agents |
| `strip` | Redact matched patterns, forward modified response | When partial content is acceptable |
| `ask` | Terminal y/N/s prompt with timeout (requires TTY) | Attended sessions, manual review |

## Configuring Claude Code

### Project-Level (`.mcp.json`)

Create `.mcp.json` in your project root. This is shared via git so all team
members get the same MCP security configuration.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "pipelock",
      "args": [
        "mcp", "proxy",
        "--config", "pipelock.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
      ]
    }
  }
}
```

### User-Level (`~/.claude.json`)

For personal MCP servers that shouldn't be in git:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "pipelock",
      "args": [
        "mcp", "proxy",
        "--config", "/home/you/.config/pipelock.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"
      ]
    }
  }
}
```

### Multiple Servers

Wrap each MCP server independently:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "pipelock",
      "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "postgres": {
      "command": "pipelock",
      "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--",
               "npx", "-y", "@modelcontextprotocol/server-postgres",
               "postgresql://localhost/mydb"]
    },
    "github": {
      "command": "pipelock",
      "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--",
               "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

## HTTP Fetch Proxy Mode

For scanning URLs fetched by Claude Code (via WebFetch or other tools), run
pipelock as an HTTP proxy server:

```bash
# Start the proxy (background or separate terminal)
pipelock run --config configs/claude-code.yaml
```

The proxy listens on `127.0.0.1:8888` by default and exposes:

| Endpoint | Purpose |
|----------|---------|
| `/fetch?url=<target>` | Fetch a URL through the scanner |
| `/health` | Health check |
| `/metrics` | Prometheus metrics |
| `/stats` | JSON statistics |

### Claude Code Hooks

You can configure a Claude Code hook to route WebFetch requests through
pipelock. Example hook script:

```bash
#!/bin/bash
# pipelock-scan.sh — scan URLs before Claude Code fetches them
URL="$1"
ENCODED=$(python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$URL")
RESULT=$(curl -s "http://127.0.0.1:8888/fetch?url=${ENCODED}")
echo "$RESULT"
```

## Choosing a Config

Pipelock ships with agent-specific presets in `configs/`:

| Preset | Action | Entropy | Rate Limit | Best For |
|--------|--------|---------|------------|----------|
| `claude-code.yaml` | block | 5.0 | 120/min | Claude Code (unattended) |
| `cursor.yaml` | block | 5.0 | 120/min | Cursor IDE (unattended) |
| `generic-agent.yaml` | warn | 5.5 | 120/min | New agents (tuning phase) |
| `balanced.yaml` | warn | 4.5 | 60/min | General purpose |
| `strict.yaml` | block | 3.5 | 30/min | High-security environments |

Start with `generic-agent.yaml` if you're unsure. Once you've verified there
are no false positives for your workflow, switch to `claude-code.yaml` or
`strict.yaml`.

## Troubleshooting

### MCP server not starting

Verify the command works without pipelock first:

```bash
# Test the server directly
npx -y @modelcontextprotocol/server-filesystem /tmp

# Then wrap it
pipelock mcp proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Config file not found

Use an absolute path in `.mcp.json` if the relative path doesn't resolve:

```json
"args": ["mcp", "proxy", "--config", "/absolute/path/to/pipelock.yaml", "--", ...]
```

### False positives

If legitimate responses are being blocked, switch to `warn` mode first to see
what's being flagged:

```yaml
response_scanning:
  action: warn  # log but don't block
```

Check stderr output for detection logs, then adjust patterns or thresholds.

### Seeing pipelock output

Pipelock logs to stderr (which Claude Code captures). To see real-time output
during development, run the MCP server manually:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  pipelock mcp proxy --config configs/claude-code.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp
```
