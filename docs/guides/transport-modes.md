# Transport Mode Comparison

Pipelock supports multiple proxy modes, each with different scanning capabilities. Choosing the right mode determines what security checks apply to your agent's traffic.

## Mode Summary

| Mode | Endpoint | Protocol | Content Inspection | Response Scanning | Best For |
|------|----------|----------|-------------------|-------------------|----------|
| Fetch | `/fetch?url=...` | HTTP | Full body | Injection detection | AI agents that need extracted text |
| CONNECT | `HTTPS_PROXY` | HTTPS tunnel | Hostname only | None | Standard HTTPS clients |
| Absolute-URI | `HTTP_PROXY` | HTTP | Hostname only | None | Plaintext HTTP clients |
| WebSocket | `/ws?url=...` | WS/WSS | Bidirectional frames | DLP + injection | Real-time agent communication |
| MCP stdio | `pipelock mcp -- CMD` | stdio | Full messages | Full (6 layers) | Local MCP servers |
| MCP HTTP | `pipelock mcp --upstream URL` | HTTP | Full messages | Full (6 layers) | Remote MCP servers |

## Detailed Breakdown

### Fetch Proxy (`/fetch?url=...`)

The highest-protection mode. Designed for AI agents that need web content.

**Scanning:**
- 9-layer URL scan (scheme, blocklist, DLP, path entropy, subdomain entropy, SSRF, rate limit, URL length, data budget)
- Raw HTML scan for injection in hidden elements (script, style, comments, hidden divs)
- Readability text extraction (strips HTML, returns clean text)
- Response injection detection on extracted content
- Redirect chain: each hop scanned through all 9 layers

**What the agent receives:** Extracted text content, not raw HTML. Hidden injection is detected even though the agent never sees it.

**Use when:** Your agent fetches web pages and you want both URL scanning and content inspection.

```bash
curl "http://localhost:8888/fetch?url=https://example.com"
```

### CONNECT Tunnel (via `HTTPS_PROXY`)

Standard HTTP CONNECT proxy. After the tunnel is established, pipelock cannot see the encrypted traffic.

**Scanning:**
- 9-layer URL scan on the target hostname (before tunnel)
- No content inspection during the tunnel (encrypted bytes)
- No response scanning

**What the agent receives:** Raw HTTPS response from the origin server.

**Use when:** Your agent or SDK uses `HTTPS_PROXY` natively and you want hostname-level protection. Be aware that DLP cannot scan the response body.

```bash
HTTPS_PROXY=http://localhost:8888 curl https://example.com
```

### Absolute-URI Forward Proxy (via `HTTP_PROXY`)

Handles plaintext HTTP requests where the client sends the full URL as the request target.

**Scanning:**
- 9-layer URL scan on the full URL
- No response injection scanning
- Response body streamed through with size limit (MaxResponseMB)
- Data budget tracking on response size

**What the agent receives:** Raw HTTP response from the origin server.

**Use when:** Your application makes plaintext HTTP requests through `HTTP_PROXY`. Note that most modern APIs use HTTPS, making this mode less common.

```bash
HTTP_PROXY=http://localhost:8888 curl http://example.com
```

### WebSocket Proxy (`/ws?url=...`)

Bidirectional WebSocket proxy with frame-level scanning.

**Scanning:**
- 9-layer URL scan on the target URL
- DLP scanning on WebSocket upgrade request headers
- Bidirectional frame scanning (both client-to-server and server-to-client)
- Fragment reassembly for multi-frame messages
- Compression rejection (RSV1 bit check prevents deflate-based DLP bypass)
- Data budget tracking per domain

**What the agent receives:** WebSocket frames, scanned in both directions.

**Use when:** Your agent uses WebSocket connections for real-time communication and you need DLP scanning on the message content.

```bash
# Agent connects to pipelock, which proxies to the target
ws://localhost:8888/ws?url=wss://api.example.com/stream
```

### MCP Stdio Proxy (`pipelock mcp -- COMMAND`)

Wraps a local MCP server process with full bidirectional message scanning.

**Scanning:**
- Response scanning: injection detection in tool results
- Input scanning: DLP + injection in tool arguments (when `mcp_input_scanning` enabled)
- Tool scanning: poisoned description detection + rug-pull drift detection (when `mcp_tool_scanning` enabled)
- Tool policy: pre-execution allow/deny rules with shell obfuscation detection (when `mcp_tool_policy` enabled)
- Chain detection: suspicious tool call sequence patterns (when `tool_chain_detection` enabled)
- Session binding: tool inventory pinning per session (when `mcp_session_binding` enabled)

**What the agent receives:** MCP responses with injection warnings injected, or blocked entirely depending on config action.

**Use when:** Running local MCP servers (filesystem, database, custom tools) and you want to scan all tool interactions.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "pipelock",
      "args": ["mcp", "--config", "pipelock.yaml", "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

### MCP HTTP Proxy (`pipelock mcp --upstream URL`)

Proxies a remote MCP server over HTTP with the same scanning as stdio mode.

**Scanning:** Same 6 layers as MCP stdio (response, input, tool, policy, chain, session binding).

**Transport sub-modes:**
- **Stdio-to-HTTP bridge** (`pipelock mcp --upstream URL`): Translates stdio JSON-RPC to HTTP requests against a streamable HTTP MCP server
- **HTTP reverse proxy** (`pipelock mcp --listen ADDR --upstream URL` or `pipelock run --mcp-listen ADDR --mcp-upstream URL`): Listens on an HTTP port and reverse-proxies to the upstream MCP server

**Use when:** Connecting to remote MCP servers over HTTP and you want the same scanning coverage as local stdio servers.

## Security Implications

### CONNECT Tunnels Do Not Inspect Content

This is the most important distinction. When your agent uses `HTTPS_PROXY`, pipelock creates an encrypted tunnel. It scans the hostname before the tunnel, but once established, all traffic is opaque encrypted bytes.

This means:
- DLP cannot detect secrets in HTTPS request/response bodies
- Response injection scanning does not apply
- Only the 9-layer URL scan provides protection

If your agent handles secrets and you need content-level DLP, use the **fetch proxy** or **MCP proxy** modes instead of CONNECT tunnels.

### Fetch Proxy vs CONNECT: Trade-offs

| Concern | Fetch Proxy | CONNECT Tunnel |
|---------|-------------|----------------|
| URL scanning | 9 layers | 9 layers |
| DLP on responses | Yes | No (encrypted) |
| Injection detection | Yes | No (encrypted) |
| Agent receives | Extracted text | Raw HTTPS response |
| TLS termination | Pipelock terminates | End-to-end (agent to origin) |
| SDK compatibility | Requires `/fetch` API | Native `HTTPS_PROXY` support |
| Performance | Slower (extraction) | Faster (pass-through) |
