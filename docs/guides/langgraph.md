# Using Pipelock with LangGraph

Pipelock wraps LangGraph's MCP servers as a stdio proxy, scanning every request
and response for credential leaks, prompt injection, and tool description
poisoning. This guide covers `langchain-mcp-adapters` integration and Docker
deployment.

## Quick Start

```bash
# 1. Install pipelock
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

# 2. Generate a config (or copy a preset)
pipelock generate config --preset generic-agent > pipelock.yaml

# 3. Install the MCP adapter
pip install langchain-mcp-adapters langgraph
```

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model

async def main():
    model = init_chat_model("anthropic:claude-sonnet-4-20250514")

    async with MultiServerMCPClient(
        {
            "filesystem": {
                "transport": "stdio",
                "command": "pipelock",
                "args": [
                    "mcp", "proxy",
                    "--config", "pipelock.yaml",
                    "--",
                    "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
                ],
            }
        }
    ) as client:
        tools = await client.get_tools()
        agent = create_react_agent(model, tools)
        result = await agent.ainvoke(
            {"messages": [("user", "List files in /workspace")]}
        )
```

Pipelock intercepts all MCP traffic between LangGraph and the filesystem server,
scanning in both directions.

## How It Works

```text
LangGraph Agent  <-->  pipelock mcp proxy  <-->  MCP Server
   (client)           (scan both ways)          (subprocess)
```

Pipelock scans three things:

1. **Outbound requests.** Catches credentials leaking through tool arguments.
2. **Inbound responses.** Catches prompt injection in tool results.
3. **Tool descriptions.** Catches poisoned definitions and mid-session changes.

## Integration Patterns

### Pattern A: `create_react_agent` (simplest)

The `create_react_agent` helper builds a tool-calling agent loop. Set `command`
to `pipelock` in the `StdioConnection`:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model

model = init_chat_model("anthropic:claude-sonnet-4-20250514")

async with MultiServerMCPClient(
    {
        "filesystem": {
            "transport": "stdio",
            "command": "pipelock",
            "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--",
                     "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
        },
        "database": {
            "transport": "stdio",
            "command": "pipelock",
            "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--",
                     "python", "-m", "mcp_server_sqlite", "--db", "/data/app.db"],
        },
    }
) as client:
    tools = await client.get_tools()
    agent = create_react_agent(model, tools)
    result = await agent.ainvoke(
        {"messages": [("user", "What tables exist in the database?")]}
    )
```

Each server gets its own Pipelock proxy instance. A poisoned response from one
server doesn't affect the other.

### Pattern B: Custom `StateGraph`

For full control over the agent loop:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.graph import StateGraph, MessagesState, START
from langgraph.prebuilt import ToolNode, tools_condition
from langchain.chat_models import init_chat_model

model = init_chat_model("anthropic:claude-sonnet-4-20250514")

async with MultiServerMCPClient(
    {
        "filesystem": {
            "transport": "stdio",
            "command": "pipelock",
            "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--",
                     "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
        }
    }
) as client:
    tools = await client.get_tools()

    def call_model(state: MessagesState):
        return {"messages": model.bind_tools(tools).invoke(state["messages"])}

    builder = StateGraph(MessagesState)
    builder.add_node("agent", call_model)
    builder.add_node("tools", ToolNode(tools))
    builder.add_edge(START, "agent")
    builder.add_conditional_edges("agent", tools_condition)
    builder.add_edge("tools", "agent")
    graph = builder.compile()

    result = await graph.ainvoke(
        {"messages": [("user", "Read /workspace/config.yaml")]}
    )
```

### Pattern C: `load_mcp_tools` (single server)

For wrapping a single MCP server without `MultiServerMCPClient`:

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langchain_mcp_adapters.tools import load_mcp_tools
from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model

server_params = StdioServerParameters(
    command="pipelock",
    args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
          "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
)

async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        tools = await load_mcp_tools(session)

        model = init_chat_model("anthropic:claude-sonnet-4-20250514")
        agent = create_react_agent(model, tools)
        result = await agent.ainvoke(
            {"messages": [("user", "List files in /workspace")]}
        )
```

### Stdio Transport Fields

| Field | Type | Purpose |
|-------|------|---------|
| `command` | `str` | Set to `"pipelock"` |
| `args` | `list[str]` | Pipelock flags, then `--`, then the real MCP server command |
| `env` | `dict` | Environment variables for the subprocess (optional) |
| `cwd` | `str` | Working directory (optional, useful if config uses relative paths) |
| `transport` | `str` | Must be `"stdio"` |

## Docker Deployment

### LangGraph Docker image with Pipelock

Use `dockerfile_lines` in `langgraph.json` to install Pipelock into the image:

```json
{
    "dependencies": ["."],
    "graphs": {
        "agent": "./graph.py:make_graph"
    },
    "env": ".env",
    "dockerfile_lines": [
        "RUN apt-get update && apt-get install -y curl",
        "RUN PIPELOCK_VERSION=0.2.2 && curl -fsSL https://github.com/luckyPipewrench/pipelock/releases/download/v${PIPELOCK_VERSION}/pipelock_${PIPELOCK_VERSION}_linux_amd64.tar.gz | tar xz -C /usr/local/bin/",
        "COPY pipelock-config.yaml /etc/pipelock/config.yaml"
    ]
}
```

Then in your graph factory:

```python
# graph.py
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model

async def make_graph():
    async with MultiServerMCPClient(
        {
            "filesystem": {
                "transport": "stdio",
                "command": "pipelock",
                "args": ["mcp", "proxy", "--config", "/etc/pipelock/config.yaml", "--",
                         "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
            }
        }
    ) as client:
        tools = await client.get_tools()
        model = init_chat_model("anthropic:claude-sonnet-4-20250514")
        return create_react_agent(model, tools)
```

Build and run:

```bash
langgraph build -t my-agent:latest
langgraph up
```

### Docker Compose with network isolation

For full network isolation, use separate networks so the agent container can't
reach the internet directly:

```yaml
networks:
  pipelock-internal:
    internal: true
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

  langgraph-postgres:
    image: postgres:16
    networks:
      - pipelock-internal
    environment:
      POSTGRES_DB: langgraph
      POSTGRES_USER: langgraph
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "langgraph"]
      interval: 5s
      timeout: 1s
      retries: 5

  langgraph-redis:
    image: redis:6
    networks:
      - pipelock-internal
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 1s
      retries: 5

  langgraph-api:
    build: .
    networks:
      - pipelock-internal
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - PIPELOCK_FETCH_URL=http://pipelock:8888/fetch
      - DATABASE_URI=postgres://langgraph:${POSTGRES_PASSWORD}@langgraph-postgres:5432/langgraph
      - REDIS_URI=redis://langgraph-redis:6379
    depends_on:
      pipelock:
        condition: service_healthy
      langgraph-postgres:
        condition: service_healthy
      langgraph-redis:
        condition: service_healthy

volumes:
  pgdata:
```

The agent container can only reach Pipelock, Postgres, and Redis. All outbound
HTTP goes through the fetch proxy.

You can also generate a base template with:

```bash
pipelock generate docker-compose --agent generic
```

## Choosing a Config

| Preset | Action | Best For |
|--------|--------|----------|
| `generic-agent.yaml` | warn | New agent integrations (recommended starting point) |
| `balanced.yaml` | warn | General purpose, fetch proxy tuning |
| `claude-code.yaml` | block | Claude Code, unattended agents |
| `strict.yaml` | block | High-security, production |

Start with `generic-agent.yaml` to log detections without blocking. Review the
logs, then switch to `strict.yaml` for production.

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

Pipelock logs to stderr. To see output during development:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### False positives

Switch to `warn` mode to see what's being flagged:

```yaml
response_scanning:
  action: warn
mcp_input_scanning:
  action: warn
mcp_tool_scanning:
  action: warn
```

### Environment variable leakage

By default, `StdioConnection` passes a subset of the parent process environment
to the MCP server subprocess. To prevent API keys from leaking to the server
process, set `env` explicitly:

```python
{
    "transport": "stdio",
    "command": "pipelock",
    "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--",
             "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"],
    "env": {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/root",
    },
}
```

This strips everything except `PATH` and `HOME` from the server's environment.
Pipelock's DLP scanner catches credential leaks regardless, but limiting the
environment is defense in depth.
