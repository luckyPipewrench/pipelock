# Using Pipelock with OpenAI Agents SDK

Pipelock wraps MCP servers used by OpenAI Agents as a stdio proxy, scanning
every request and response for credential leaks, prompt injection, and tool
description poisoning. This guide covers `MCPServerStdio` integration and
Docker Compose deployment.

## Quick Start

```bash
# 1. Install pipelock
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

# 2. Generate a config (or copy a preset)
pipelock generate config --preset generic-agent > pipelock.yaml

# 3. Verify
pipelock version
```

```python
from agents import Agent
from agents.mcp import MCPServerStdio

server = MCPServerStdio(
    command="pipelock",
    args=[
        "mcp", "proxy",
        "--config", "pipelock.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
    ],
)

agent = Agent(
    name="Research Assistant",
    instructions="You help users research information using available tools.",
    mcp_servers=[server],
)
```

That's it. Pipelock intercepts all MCP traffic between the agent and the
filesystem server, scanning in both directions.

## How It Works

```text
OpenAI Agent  <-->  pipelock mcp proxy  <-->  MCP Server
  (client)         (scan both ways)          (subprocess)
```

Pipelock scans three things:

1. **Outbound requests.** Catches credentials leaking through tool arguments
   (API keys, tokens, private key material).
2. **Inbound responses.** Catches prompt injection in tool results.
3. **Tool descriptions.** Catches poisoned tool definitions and mid-session
   rug-pull changes.

## Integration Patterns

### Pattern A: Single MCP Server

The simplest case — one MCP server wrapped with Pipelock:

```python
import asyncio
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async def main():
    server = MCPServerStdio(
        command="pipelock",
        args=[
            "mcp", "proxy",
            "--config", "pipelock.yaml",
            "--",
            "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
        ],
    )

    agent = Agent(
        name="File Analyst",
        instructions="You analyze files in the workspace.",
        mcp_servers=[server],
    )

    async with server:
        result = await Runner.run(agent, "List all files in the workspace")
        print(result.final_output)

asyncio.run(main())
```

### Pattern B: Multiple MCP Servers

Wrap each server independently. If one returns a poisoned response, Pipelock
blocks it without affecting the others:

```python
from agents import Agent
from agents.mcp import MCPServerStdio

filesystem = MCPServerStdio(
    command="pipelock",
    args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
          "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
)

database = MCPServerStdio(
    command="pipelock",
    args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
          "python", "-m", "mcp_server_sqlite", "--db", "/data/app.db"],
)

github = MCPServerStdio(
    command="pipelock",
    args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
          "npx", "-y", "@modelcontextprotocol/server-github"],
)

agent = Agent(
    name="Dev Assistant",
    instructions="You help with code, data, and project management.",
    mcp_servers=[filesystem, database, github],
)
```

### Pattern C: Strict Schema Mode

The OpenAI Agents SDK supports strict JSON schema validation for MCP tools.
This pairs well with Pipelock — the SDK validates schema structure while
Pipelock validates content:

```python
from agents.mcp import MCPServerStdio

server = MCPServerStdio(
    command="pipelock",
    args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
          "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
)

agent = Agent(
    name="Strict Agent",
    instructions="You work with files.",
    mcp_servers=[server],
    mcp_config={"convert_schemas_to_strict": True},
)
```

### Pattern D: Multi-Agent Handoffs

When using the SDK's handoff feature, each agent can have its own set of
Pipelock-wrapped MCP servers with different configs:

```python
from agents import Agent

# Researcher gets broad access, warn mode
researcher = Agent(
    name="Researcher",
    instructions="You research topics using web and file tools.",
    mcp_servers=[
        MCPServerStdio(
            command="pipelock",
            args=["mcp", "proxy", "--config", "pipelock-warn.yaml", "--",
                  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"],
        ),
    ],
)

# Writer gets restricted access, block mode
writer = Agent(
    name="Writer",
    instructions="You write reports based on research.",
    mcp_servers=[
        MCPServerStdio(
            command="pipelock",
            args=["mcp", "proxy", "--config", "pipelock-strict.yaml", "--",
                  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/output"],
        ),
    ],
    handoffs=[researcher],
)
```

## Docker Compose

Network-isolated deployment where the agent container has no direct internet
access:

```yaml
networks:
  pipelock-internal:
    internal: true
    driver: bridge
  pipelock-external:
    driver: bridge

services:
  pipelock:
    image: ghcr.io/luckypipewrench/pipelock:latest
    networks:
      - pipelock-internal
      - pipelock-external
    command: ["run", "--listen", "0.0.0.0:8888", "--config", "/config/pipelock.yaml"]
    volumes:
      - ./pipelock.yaml:/config/pipelock.yaml:ro
    healthcheck:
      test: ["/pipelock", "healthcheck"]
      interval: 10s
      timeout: 3s
      start_period: 5s
      retries: 3

  openai-agent:
    build: .
    networks:
      - pipelock-internal
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - PIPELOCK_FETCH_URL=http://pipelock:8888/fetch
    depends_on:
      pipelock:
        condition: service_healthy
```

The agent container can only reach the `pipelock` service. All HTTP traffic goes
through the fetch proxy. MCP servers running as subprocesses inside the agent
container are wrapped with `pipelock mcp proxy` as shown above.

## Choosing a Config

| Preset | Action | Best For |
|--------|--------|----------|
| `generic-agent.yaml` | warn | New integrations (recommended starting point) |
| `balanced.yaml` | warn | General purpose, fetch proxy tuning |
| `claude-code.yaml` | block | Unattended agents |
| `strict.yaml` | block | High-security, production |

Start with `generic-agent.yaml` to log detections without blocking. Review the
logs, tune thresholds, then switch to `strict.yaml` for production.

## Troubleshooting

### MCP server not starting

Verify the command works without Pipelock first:

```bash
npx -y @modelcontextprotocol/server-filesystem /tmp
```

Then wrap it:

```bash
pipelock mcp proxy -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Seeing Pipelock output

Pipelock logs to stderr. To see real-time output during development:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### False positives

Switch to `warn` mode to see what's being flagged without blocking:

```yaml
response_scanning:
  action: warn
mcp_input_scanning:
  action: warn
mcp_tool_scanning:
  action: warn
```

Review stderr output, then tighten thresholds.

### Config file not found

Use absolute paths if relative paths don't resolve:

```python
MCPServerStdio(
    command="pipelock",
    args=["mcp", "proxy", "--config", "/etc/pipelock/config.yaml", "--",
          "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
)
```
