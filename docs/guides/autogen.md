# Using Pipelock with AutoGen

Pipelock wraps MCP servers used by AutoGen agents as a stdio proxy, scanning
every request and response for credential leaks, prompt injection, and tool
description poisoning. This guide covers `StdioServerParams` integration with
AutoGen v0.4+ and Docker Compose deployment.

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
import asyncio
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools

async def main():
    server_params = StdioServerParams(
        command="pipelock",
        args=[
            "mcp", "proxy",
            "--config", "pipelock.yaml",
            "--",
            "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
        ],
    )

    tools = await mcp_server_tools(server_params)
    # tools is a list of standard AutoGen tool objects

asyncio.run(main())
```

That's it. The `tools` list contains standard AutoGen tool objects backed by
Pipelock-scanned MCP calls.

## How It Works

```text
AutoGen Agent  <-->  pipelock mcp proxy  <-->  MCP Server
   (client)         (scan both ways)          (subprocess)
```

Pipelock scans three things:

1. **Outbound requests.** Catches credentials leaking through tool arguments
   (API keys, tokens, private key material).
2. **Inbound responses.** Catches prompt injection in tool results.
3. **Tool descriptions.** Catches poisoned tool definitions and mid-session
   rug-pull changes.

## Integration Patterns

### Pattern A: AssistantAgent with MCP Tools

The standard pattern — create MCP tools and pass them to an `AssistantAgent`:

```python
import asyncio
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.ui import Console
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools

async def main():
    server_params = StdioServerParams(
        command="pipelock",
        args=[
            "mcp", "proxy",
            "--config", "pipelock.yaml",
            "--",
            "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
        ],
    )

    tools = await mcp_server_tools(server_params)

    agent = AssistantAgent(
        name="file_analyst",
        model_client=OpenAIChatCompletionClient(model="gpt-4o"),
        tools=tools,
    )

    await Console(agent.run_stream(task="List all files in the workspace"))

asyncio.run(main())
```

### Pattern B: Multiple MCP Servers

Create tools from multiple Pipelock-wrapped servers and combine them:

```python
import asyncio
from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools

async def main():
    model_client = OpenAIChatCompletionClient(model="gpt-4o")

    filesystem_params = StdioServerParams(
        command="pipelock",
        args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
              "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
    )

    database_params = StdioServerParams(
        command="pipelock",
        args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
              "python", "-m", "mcp_server_sqlite", "--db", "/data/app.db"],
    )

    fs_tools = await mcp_server_tools(filesystem_params)
    db_tools = await mcp_server_tools(database_params)

    agent = AssistantAgent(
        name="multi_tool_agent",
        model_client=model_client,
        tools=fs_tools + db_tools,
    )

asyncio.run(main())
```

### Pattern C: Mixed Transports

Wrap stdio servers with Pipelock. Remote servers connect directly and are not
covered by the stdio proxy:

```python
import asyncio
from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.tools.mcp import StdioServerParams, StreamableHttpServerParams, mcp_server_tools

async def main():
    model_client = OpenAIChatCompletionClient(model="gpt-4o")

    # Local server: wrap with pipelock
    local_params = StdioServerParams(
        command="pipelock",
        args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
              "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    )

    # Remote server: NOT scanned by pipelock
    # Pipelock's MCP proxy only wraps stdio servers.
    # For remote servers, vet the server before connecting.
    remote_params = StreamableHttpServerParams(
        url="https://api.example.com/mcp",
        headers={"Authorization": "Bearer token"},
    )

    local_tools = await mcp_server_tools(local_params)
    remote_tools = await mcp_server_tools(remote_params)

    agent = AssistantAgent(
        name="hybrid_agent",
        model_client=model_client,
        tools=local_tools + remote_tools,
    )

asyncio.run(main())
```

> **Note:** `SseServerParams` is deprecated. Use `StreamableHttpServerParams`
> for new remote MCP connections.

**Note:** Pipelock's MCP proxy only wraps stdio-based servers. Remote HTTP/SSE
MCP connections go directly to the remote endpoint and bypass Pipelock. For
outbound HTTP traffic from your agent code (API calls, web fetches), route those
through `pipelock run` as a fetch proxy. See the
[HTTP fetch proxy](#http-fetch-proxy) section below.

### Pattern D: Multi-Agent Teams

AutoGen's team abstractions (`RoundRobinGroupChat`, `SelectorGroupChat`, etc.)
allow agents with different Pipelock configs to collaborate:

```python
import asyncio
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.conditions import TextMentionTermination
from autogen_agentchat.ui import Console
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools

async def main():
    model_client = OpenAIChatCompletionClient(model="gpt-4o")

    # Researcher: broad access, warn mode
    research_tools = await mcp_server_tools(StdioServerParams(
        command="pipelock",
        args=["mcp", "proxy", "--config", "pipelock-warn.yaml", "--",
              "npx", "-y", "@modelcontextprotocol/server-fetch"],
    ))

    researcher = AssistantAgent(
        name="researcher",
        model_client=model_client,
        tools=research_tools,
        system_message="Research topics. Say TERMINATE when done.",
    )

    # Writer: restricted access, block mode
    writer_tools = await mcp_server_tools(StdioServerParams(
        command="pipelock",
        args=["mcp", "proxy", "--config", "pipelock-strict.yaml", "--",
              "npx", "-y", "@modelcontextprotocol/server-filesystem", "/output"],
    ))

    writer = AssistantAgent(
        name="writer",
        model_client=model_client,
        tools=writer_tools,
        system_message="Write reports based on research. Say TERMINATE when done.",
    )

    team = RoundRobinGroupChat(
        participants=[researcher, writer],
        termination_condition=TextMentionTermination("TERMINATE"),
    )

    await Console(team.run_stream(task="Research and write a report on workspace contents"))

asyncio.run(main())
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
    # Pin to a specific version for production (e.g., ghcr.io/luckypipewrench/pipelock:v0.3.0)
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

  autogen-agent:
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

You can also generate this template with:

```bash
pipelock generate docker-compose --agent generic
```

## HTTP Fetch Proxy

For scanning HTTP traffic from AutoGen agents (web fetches, API calls), run
Pipelock as a fetch proxy:

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
        headers={"X-Pipelock-Agent": "autogen-research"},
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
StdioServerParams(
    command="pipelock",
    args=["mcp", "proxy", "--config", "/etc/pipelock/config.yaml", "--",
          "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
)
```
