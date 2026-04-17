# Transport Mode Comparison

Pipelock supports multiple proxy modes, each with different scanning capabilities. Choosing the right mode determines what security checks apply to your agent's traffic.

## Mode Summary

| Mode | Endpoint | Protocol | Content Inspection | Response Scanning | Best For |
|------|----------|----------|-------------------|-------------------|----------|
| Fetch | `/fetch?url=...` | HTTP | Full body | Injection detection | AI agents that need extracted text |
| CONNECT | `HTTPS_PROXY` | HTTPS tunnel | Hostname only | None | Standard HTTPS clients (no interception) |
| CONNECT + TLS interception | `HTTPS_PROXY` | HTTPS tunnel (MITM) | Full body + headers | Injection detection | Full DLP on HTTPS traffic |
| Absolute-URI | `HTTP_PROXY` | HTTP | Full URL | Injection detection (when enabled) | Plaintext HTTP clients |
| WebSocket | `/ws?url=...` | WS/WSS | Bidirectional frames | DLP + injection | Real-time agent communication |
| MCP stdio | `pipelock mcp proxy -- CMD` | stdio | Full messages | Full (6 layers) | Local MCP servers |
| MCP HTTP | `pipelock mcp proxy --upstream URL` | HTTP | Full messages | Full (6 layers) | Remote MCP servers (HTTP) |
| MCP WebSocket | `pipelock mcp proxy --upstream ws://...` | WS/WSS | Full messages | Full (6 layers) | Remote MCP servers (WS) |

## Detailed Breakdown

### Fetch Proxy (`/fetch?url=...`)

The highest-protection mode. Designed for AI agents that need web content.

**Scanning:**
- 11-layer URL scan (scheme, CRLF injection, path traversal, blocklist, DLP, path entropy, subdomain entropy, SSRF, rate limit, URL length, data budget)
- Raw HTML scan for injection in hidden elements (script, style, comments, hidden divs)
- Readability text extraction (strips HTML, returns clean text)
- Response injection detection on extracted content
- Redirect chain: each hop scanned through all 11 layers

**What the agent receives:** Extracted text content, not raw HTML. Hidden injection is detected even though the agent never sees it.

**Use when:** Your agent fetches web pages and you want both URL scanning and content inspection.

```bash
curl "http://localhost:8888/fetch?url=https://example.com"
```

### CONNECT Tunnel (via `HTTPS_PROXY`)

Standard HTTP CONNECT proxy. Without TLS interception, pipelock cannot see the encrypted traffic after the tunnel is established.

**Scanning (without TLS interception):**
- 11-layer URL scan on the target hostname (before tunnel)
- No content inspection during the tunnel (encrypted bytes)
- No response scanning

**Scanning (with `tls_interception.enabled: true`):**
- 11-layer URL scan on the target hostname (before tunnel)
- Full request body DLP (JSON, form, multipart extraction)
- Request header DLP scanning
- Authority enforcement (Host must match CONNECT target)
- Response injection detection (buffered scan-then-send)
- Compressed response blocking (fail-closed)

**What the agent receives:** Without interception: raw HTTPS response from the origin server. With interception: response re-encrypted by pipelock after scanning.

**Use when:** Your agent or SDK uses `HTTPS_PROXY` natively. Enable TLS interception for full DLP and injection scanning. Without interception, only hostname-level protection applies.

```bash
# Without TLS interception (hostname scanning only)
HTTPS_PROXY=http://localhost:8888 curl https://example.com

# With TLS interception (full body/header DLP + response scanning)
# Requires: tls_interception.enabled: true in config
# Requires: pipelock CA trusted by the agent (pipelock tls install-ca)
HTTPS_PROXY=http://localhost:8888 curl --cacert ~/.pipelock/ca.pem https://example.com
```

### Absolute-URI Forward Proxy (via `HTTP_PROXY`)

Handles plaintext HTTP requests where the client sends the full URL as the request target.

**Scanning:**
- 11-layer URL scan on the full URL
- Response injection scanning (buffer-then-scan-then-send, fail-closed on compressed responses)
- Response body buffered (up to MaxResponseMB), scanned for injection, then forwarded
- Data budget tracking on response size

**What the agent receives:** Raw HTTP response from the origin server.

**Use when:** Your application makes plaintext HTTP requests through `HTTP_PROXY`. Note that most modern APIs use HTTPS, making this mode less common.

```bash
HTTP_PROXY=http://localhost:8888 curl http://example.com
```

### WebSocket Proxy (`/ws?url=...`)

Bidirectional WebSocket proxy with frame-level scanning.

**Scanning:**
- 11-layer URL scan on the target URL
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

### MCP stdio proxy (`pipelock mcp proxy -- COMMAND`)

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
      "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--", "npx", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

### MCP HTTP Proxy (`pipelock mcp proxy --upstream URL`)

Proxies a remote MCP server over HTTP with the same scanning as stdio mode.

**Scanning:** Same 6 layers as MCP stdio (response, input, tool, policy, chain, session binding).

**Transport sub-modes:**
- **Stdio-to-HTTP bridge** (`pipelock mcp proxy --upstream URL`): Translates stdio JSON-RPC to HTTP requests against a streamable HTTP MCP server
- **HTTP reverse proxy** (`pipelock mcp proxy --listen ADDR --upstream URL` or `pipelock run --mcp-listen ADDR --mcp-upstream URL`): Listens on an HTTP port and reverse-proxies to the upstream MCP server

**Use when:** Connecting to remote MCP servers over HTTP and you want the same scanning coverage as local stdio servers.

### MCP WebSocket Proxy (`pipelock mcp proxy --upstream ws://...`)

Proxies a remote MCP server over WebSocket with the same scanning as stdio mode.

**Scanning:** Same 6 layers as MCP stdio (response, input, tool, policy, chain, session binding).

**How it works:** When `--upstream` receives a `ws://` or `wss://` URL, pipelock connects to the upstream over WebSocket and translates between stdin/stdout JSON-RPC and WebSocket text frames. Each JSON-RPC message maps to one WebSocket text frame. Fragment reassembly is handled automatically.

**Use when:** Connecting to MCP servers that expose a WebSocket endpoint (common with OpenClaw gateways and other real-time MCP hosts).

```json
{
  "mcpServers": {
    "remote": {
      "command": "pipelock",
      "args": ["mcp", "proxy", "--config", "pipelock.yaml", "--upstream", "ws://localhost:3000/mcp"]
    }
  }
}
```

## Security Implications

### CONNECT Tunnels: With and Without TLS Interception

Without TLS interception (`tls_interception.enabled: false`, the default), CONNECT tunnels are opaque encrypted bytes after the hostname scan. DLP cannot detect secrets in bodies or headers, and response injection scanning does not apply.

With TLS interception enabled, pipelock performs a TLS MITM: it terminates TLS with the client (forged certificate), scans the decrypted traffic, then forwards to the upstream server over a separate TLS connection. This closes the body-blindness gap.

**Without interception:**
- DLP cannot detect secrets in HTTPS request/response bodies
- Response injection scanning does not apply
- Only the 11-layer URL scan provides protection

**With interception:**
- Full request body DLP (JSON, form, multipart)
- Request header DLP (Authorization, Cookie, etc.)
- Response injection scanning (buffered, scan-then-send)
- Authority enforcement (Host must match CONNECT target)

If your agent handles secrets and you need content-level DLP on HTTPS traffic, either enable TLS interception or use the **fetch proxy** or **MCP proxy** modes.

### Fetch Proxy vs CONNECT: Trade-offs

| Concern | Fetch Proxy | CONNECT (no interception) | CONNECT (TLS interception) |
|---------|-------------|---------------------------|---------------------------|
| URL scanning | 11 layers | 11 layers | 11 layers |
| DLP on request bodies | N/A | No (encrypted) | Yes |
| DLP on responses | Yes | No (encrypted) | Yes |
| Injection detection | Yes | No (encrypted) | Yes |
| Agent receives | Extracted text | Raw HTTPS response | Raw HTTPS response (re-encrypted) |
| TLS termination | Pipelock terminates | End-to-end | Pipelock MITM (forged cert) |
| SDK compatibility | Requires `/fetch` API | Native `HTTPS_PROXY` | Native `HTTPS_PROXY` + CA trust |
| Performance | Slower (extraction) | Fastest (pass-through) | Moderate (decrypt + scan + re-encrypt) |

## Signed Action Receipt Coverage

Every block or allow decision produces a signed action receipt. The table below enumerates which deny paths are covered on each transport. Every row has been exercised by a test in the signed-receipt-coverage suite.

| Transport | Pre-forward blocks | Post-forward blocks | Transport-specific blocks | Receipt path |
|-----------|-------------------|---------------------|---------------------------|--------------|
| Fetch (`/fetch`) | URL scan, DLP, SSRF | Redirect block, response scan, audit-mode escalation, session profiling, header DLP, budget exhaustion, cross-request exfiltration | — | Direct emit to flight recorder |
| CONNECT (no TLS intercept) | URL scan, DLP, SSRF, blocklist | — | Redirect inside tunnel (not visible) | Hostname-only receipts |
| CONNECT + TLS interception | URL scan + full hostname DLP | Body DLP, header DLP, response injection | Authority mismatch | Full content receipts |
| Absolute-URI (forward proxy) | URL scan, DLP, SSRF | Redirect block, response scan, audit-mode escalation, session profiling, header DLP, budget exhaustion, CEE | A2A header scan, A2A stream scan, A2A response body scan | Full content receipts |
| WebSocket (`/ws`) | Handshake-time URL scan, DLP | Frame-level DLP, injection, address poisoning, CEE | Session close reason | Per-frame receipts + session close |
| MCP stdio | Input scan, tool scan, policy | Response injection, chain detection, session binding drift | Tool call, tool response, policy decision | Full content receipts |
| MCP HTTP / SSE | Input scan, tool scan, policy | Response injection, chain detection, session binding drift | Tool call, tool response, policy decision | Full content receipts, stream-aware |
| MCP HTTP reverse proxy | Input scan, tool scan, policy | Response injection, chain detection, session binding drift | Tool call, tool response, policy decision | Full content receipts |

All receipt emission is fire-and-forget on the async flight-recorder channel and survives config reload across all transports. Receipts chain via `chain_prev_hash` / `chain_seq` for tamper-evidence. See [`docs/guides/receipt-verification.md`](receipt-verification.md) for the verify CLI and the cross-implementation conformance suite.

## See Also

- [Configuration Reference](../configuration.md) for all config fields controlling each proxy mode
- [OpenClaw Integration](openclaw.md) for deploying pipelock with OpenClaw gateways
- [Deployment Recipes](deployment-recipes.md) for Docker Compose, Kubernetes, and host-level enforcement
- [`pipelock init sidecar`](../cli/init-sidecar.md) for the generated companion-proxy deployment
- [`pipelock session`](../cli/session.md) for airlock inspection and recovery
- [Bypass Resistance](../bypass-resistance.md) for details on how each scanning layer resists evasion
- [Attacks Blocked](../attacks-blocked.md) for real-world attack examples across all transport modes
