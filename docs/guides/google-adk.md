# Using Pipelock with Google ADK

Pipelock wraps MCP servers used by Google ADK agents as a stdio proxy, scanning
every request and response for credential leaks, prompt injection, and tool
description poisoning. This guide covers `McpToolset` with `StdioConnectionParams`
and Docker Compose deployment.

## Quick Start

```bash
# 1. Install pipelock
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

# 2. Generate a config (or copy a preset)
pipelock generate config --preset balanced > pipelock.yaml

# 3. Verify
pipelock version
```

```python
from google.adk.agents import Agent
from google.adk.tools import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

filesystem_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="pipelock",
            args=[
                "mcp", "proxy",
                "--config", "pipelock.yaml",
                "--",
                "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
            ],
        )
    )
)

agent = Agent(
    model="gemini-2.0-flash",
    name="research_agent",
    instruction="You help users research information using available tools.",
    tools=[filesystem_toolset],
)
```

That's it. Pipelock intercepts all MCP traffic between the ADK agent and the
filesystem server, scanning in both directions.

## How It Works

```text
ADK Agent  <-->  pipelock mcp proxy  <-->  MCP Server
 (client)       (scan both ways)          (subprocess)
```

Pipelock scans three things:

1. **Outbound requests.** Catches credentials leaking through tool arguments
   (API keys, tokens, private key material).
2. **Inbound responses.** Catches prompt injection in tool results.
3. **Tool descriptions.** Catches poisoned tool definitions and mid-session
   rug-pull changes.

## Integration Patterns

### Pattern A: Single MCP Server with Runner

The standard ADK pattern using `Runner` for agent execution:

```python
import asyncio
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.genai import types
from mcp import StdioServerParameters

async def main():
    toolset = McpToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="pipelock",
                args=[
                    "mcp", "proxy",
                    "--config", "pipelock.yaml",
                    "--",
                    "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
                ],
            )
        )
    )

    agent = Agent(
        model="gemini-2.0-flash",
        name="file_agent",
        instruction="You analyze files in the workspace.",
        tools=[toolset],
    )

    runner = Runner(
        agent=agent,
        app_name="pipelock_demo",
        session_service=InMemorySessionService(),
    )

    session = await runner.session_service.create_session(
        app_name="pipelock_demo", user_id="user1"
    )

    content = types.Content(
        role="user",
        parts=[types.Part(text="List all files in the workspace")]
    )

    async for event in runner.run_async(
        user_id="user1", session_id=session.id, new_message=content
    ):
        if event.is_final_response():
            print(event.content.parts[0].text)

asyncio.run(main())
```

### Pattern B: Multiple MCP Servers

Wrap each server independently with its own Pipelock proxy:

```python
from google.adk.agents import Agent
from google.adk.tools import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

filesystem = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="pipelock",
            args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
                  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
        )
    )
)

database = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="pipelock",
            args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
                  "python", "-m", "mcp_server_sqlite", "--db", "/data/app.db"],
        )
    )
)

agent = Agent(
    model="gemini-2.0-flash",
    name="multi_tool_agent",
    instruction="You work with files and databases.",
    tools=[filesystem, database],
)
```

### Pattern C: Mixed Transports

Wrap stdio servers with Pipelock. Remote servers connect directly and are not
covered by the stdio proxy:

```python
from google.adk.agents import Agent
from google.adk.tools import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import (
    StdioConnectionParams,
    SseConnectionParams,
)
from mcp import StdioServerParameters

# Local server: wrap with pipelock
local = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="pipelock",
            args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
                  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
    )
)

# Remote server: NOT scanned by pipelock
# Pipelock's MCP proxy only wraps stdio servers.
# For remote servers, vet the server before connecting.
remote = McpToolset(
    connection_params=SseConnectionParams(url="https://api.example.com/mcp/sse")
)

agent = Agent(
    model="gemini-2.0-flash",
    name="hybrid_agent",
    instruction="You use local and remote tools.",
    tools=[local, remote],
)
```

**Note:** Pipelock's MCP proxy only wraps stdio-based servers. Remote HTTP/SSE
MCP connections go directly to the remote endpoint and bypass Pipelock. For
outbound HTTP traffic from your agent code (API calls, web fetches), route those
through `pipelock run` as a fetch proxy. See the
[HTTP fetch proxy](#http-fetch-proxy) section below.

### Pattern D: Sub-Agents

ADK supports hierarchical agent architectures. Each sub-agent can have its own
Pipelock-wrapped MCP servers with different security configs:

```python
from google.adk.agents import Agent
from google.adk.tools import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

researcher = Agent(
    model="gemini-2.0-flash",
    name="researcher",
    instruction="You research topics using available tools.",
    tools=[
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="pipelock",
                    args=["mcp", "proxy", "--config", "pipelock-warn.yaml", "--",
                          "npx", "-y", "@modelcontextprotocol/server-fetch"],
                )
            )
        ),
    ],
)

writer = Agent(
    model="gemini-2.0-flash",
    name="writer",
    instruction="You write reports. Delegate research to the researcher.",
    tools=[
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="pipelock",
                    args=["mcp", "proxy", "--config", "pipelock-strict.yaml", "--",
                          "npx", "-y", "@modelcontextprotocol/server-filesystem", "/output"],
                )
            )
        ),
    ],
    sub_agents=[researcher],
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
    # Pin to a specific version for production (e.g., ghcr.io/luckypipewrench/pipelock:v0.2.6)
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

  adk-agent:
    build: .
    networks:
      - pipelock-internal
    environment:
      - GOOGLE_API_KEY=${GOOGLE_API_KEY}
      - PIPELOCK_FETCH_URL=http://pipelock:8888/fetch
    depends_on:
      pipelock:
        condition: service_healthy
```

The agent container can only reach the `pipelock` service. All HTTP traffic goes
through the fetch proxy. MCP servers running as subprocesses inside the agent
container are wrapped with `pipelock mcp proxy` as shown above.

You can also generate this template with:

```bash
pipelock generate docker-compose --agent generic
```

## HTTP Fetch Proxy

For scanning HTTP traffic from ADK agents (web fetches, API calls), run Pipelock
as a fetch proxy:

```bash
pipelock run --config pipelock.yaml
```

Configure your agent to route HTTP requests through `http://localhost:8888/fetch`:

```python
import requests

def fetch_through_pipelock(url: str) -> str:
    resp = requests.get(
        "http://localhost:8888/fetch",
        params={"url": url},
        headers={"X-Pipelock-Agent": "adk-research"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("blocked"):
        raise RuntimeError(f"Pipelock blocked request: {data.get('block_reason')}")
    return data.get("content", "")
```

## Choosing a Config

| Config | Action | Best For |
|--------|--------|----------|
| `balanced` | warn (default) | Recommended starting point (`--preset balanced`) |
| `strict` | block (default) | High-security, production (`--preset strict`) |
| `generic-agent.yaml` | warn (default) | Agent-specific tuning (copy from `configs/`) |
| `claude-code.yaml` | block (default) | Unattended coding agents (copy from `configs/`) |

Start with `balanced` to log detections without blocking. Review the logs,
tune thresholds, then switch to `strict` for production.

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
McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="pipelock",
            args=["mcp", "proxy", "--config", "/etc/pipelock/config.yaml", "--",
                  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
    )
)
```
