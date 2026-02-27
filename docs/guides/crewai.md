# Using Pipelock with CrewAI

Pipelock wraps CrewAI's MCP servers as a stdio proxy, scanning every request and
response for credential leaks, prompt injection, and tool description poisoning.
This guide covers both the `mcps=` DSL and the `MCPServerAdapter` approach.

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
from crewai import Agent
from crewai.mcp import MCPServerStdio

agent = Agent(
    role="Research Analyst",
    goal="Research and analyze information",
    backstory="Expert researcher with access to external tools",
    mcps=[
        MCPServerStdio(
            command="pipelock",
            args=[
                "mcp", "proxy",
                "--config", "pipelock.yaml",
                "--",
                "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
            ],
        ),
    ],
)
```

That's it. Pipelock intercepts all MCP traffic between CrewAI and the filesystem
server, scanning in both directions.

## How It Works

```text
CrewAI Agent  <-->  pipelock mcp proxy  <-->  MCP Server
  (client)         (scan both ways)          (subprocess)
```

Pipelock scans three things:

1. **Outbound requests.** Catches credentials leaking through tool arguments
   (API keys, tokens, private key material).
2. **Inbound responses.** Catches prompt injection in tool results.
3. **Tool descriptions.** Catches poisoned tool definitions and mid-session
   rug-pull changes.

## Integration Patterns

### Pattern A: `mcps=` DSL (CrewAI >= 1.4.0)

The `mcps` field on `Agent` accepts `MCPServerStdio` objects. Set `command` to
`pipelock` and put the real server command after `--` in `args`:

```python
from crewai import Agent, Task, Crew
from crewai.mcp import MCPServerStdio

filesystem_server = MCPServerStdio(
    command="pipelock",
    args=[
        "mcp", "proxy",
        "--config", "pipelock.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
    ],
)

database_server = MCPServerStdio(
    command="pipelock",
    args=[
        "mcp", "proxy",
        "--config", "pipelock.yaml",
        "--",
        "python", "-m", "mcp_server_sqlite", "--db", "/data/app.db"
    ],
)

agent = Agent(
    role="Data Analyst",
    goal="Query data and generate reports",
    backstory="An analyst with access to files and databases",
    mcps=[filesystem_server, database_server],
)

task = Task(
    description="Read the sales data from /workspace/sales.csv and summarize it",
    expected_output="A summary of key sales metrics",
    agent=agent,
)

crew = Crew(agents=[agent], tasks=[task])
result = crew.kickoff()
```

Each server gets its own Pipelock proxy instance. If one server returns a
poisoned response, Pipelock blocks it without affecting the other.

### Pattern B: `MCPServerAdapter` (crewai-tools)

The adapter approach uses a context manager and passes tools via the `tools=`
parameter:

```python
from crewai import Agent
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

server_params = StdioServerParameters(
    command="pipelock",
    args=[
        "mcp", "proxy",
        "--config", "pipelock.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
    ],
)

with MCPServerAdapter(server_params) as tools:
    agent = Agent(
        role="File Processor",
        goal="Process files in the workspace",
        backstory="An agent with filesystem access",
        tools=tools,
    )
    # ... create tasks and crew
```

### Pattern C: Multiple servers with mixed transports

Wrap each stdio server individually. Remote servers (SSE/HTTP) connect directly
to the remote endpoint and are **not** covered by the stdio proxy:

```python
from crewai import Agent
from crewai.mcp import MCPServerStdio, MCPServerSSE

agent = Agent(
    role="Multi-tool Agent",
    goal="Use local and remote tools",
    backstory="Agent with diverse tool access",
    mcps=[
        # Local server: wrap with pipelock stdio proxy
        MCPServerStdio(
            command="pipelock",
            args=["mcp", "proxy", "--config", "pipelock.yaml", "--",
                  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        ),
        # Remote server: NOT scanned by pipelock
        # Pipelock's MCP proxy only wraps stdio servers.
        # For remote SSE/HTTP servers, vet the server before connecting.
        MCPServerSSE(
            url="https://api.example.com/mcp/sse",
            headers={"Authorization": "Bearer token"},
        ),
    ],
)
```

**Note:** Pipelock's MCP proxy only wraps stdio-based servers. Remote SSE/HTTP
MCP connections go directly to the remote endpoint and bypass Pipelock. For
outbound HTTP traffic from your agent code (API calls, web fetches), you can
route those through `pipelock run` as a fetch proxy. See the
[HTTP fetch proxy](#http-fetch-proxy) section below.

## What Pipelock Catches

CrewAI's [MCP security documentation](https://docs.crewai.com/en/mcp/security)
identifies several threats. Here's what Pipelock detects at runtime:

| Threat | CrewAI's Guidance | Pipelock's Detection |
|--------|-------------------|---------------------|
| Credential exposure | "Use trusted servers" | DLP scanner catches 22 built-in credential patterns in tool arguments (API keys, tokens, private keys) |
| Prompt injection via tool metadata | "Only connect to trusted servers" | Tool description scanning detects hidden instructions, exfiltration directives, cross-tool manipulation |
| Tool behavior changes mid-session | Not addressed | Rug-pull detection tracks tool definition hashes per session, alerts on changes |
| DNS exfiltration via subdomains | Not addressed | Dot-collapse scanning and subdomain entropy analysis |
| Data exfiltration through responses | Not addressed | Response scanning with injection pattern matching |

CrewAI's `tool_filter` (allowlist/blocklist by name) controls which tools the
agent sees. Pipelock scans what those tools actually say and do.

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

  crewai-agent:
    build: .
    networks:
      - pipelock-internal
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
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

For scanning HTTP traffic from CrewAI agents (web searches, API calls), run
Pipelock as a fetch proxy:

```bash
pipelock run --config configs/balanced.yaml
```

Configure your agent to route HTTP requests through `http://localhost:8888/fetch`.
The endpoint returns JSON with `content`, `blocked`, and `block_reason` fields:

```python
import requests

def fetch_through_pipelock(url: str) -> str:
    resp = requests.get(
        "http://localhost:8888/fetch",
        params={"url": url},
        headers={"X-Pipelock-Agent": "crewai-research"},
    )
    data = resp.json()
    if data.get("blocked"):
        raise RuntimeError(f"Pipelock blocked request: {data.get('block_reason')}")
    return data.get("content", "")
```

## Choosing a Config

| Preset | Action | Best For |
|--------|--------|----------|
| `generic-agent.yaml` | warn | New agent integrations (recommended starting point) |
| `balanced.yaml` | warn | General purpose, fetch proxy tuning |
| `claude-code.yaml` | block | Claude Code, unattended agents |
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

Pipelock logs to stderr. In CrewAI, stderr from stdio subprocesses may be
captured. To see real-time output during development:

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

Use absolute paths if relative paths don't resolve in your CrewAI project
structure:

```python
MCPServerStdio(
    command="pipelock",
    args=["mcp", "proxy", "--config", "/etc/pipelock/config.yaml", "--",
          "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
)
```
