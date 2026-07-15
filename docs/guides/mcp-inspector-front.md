# Pipelock as a Reverse Proxy for MCP Development Listeners

MCP development tools — Inspector, ad-hoc test servers, debugging harnesses — frequently bind to `0.0.0.0` on a high port with no authentication. This makes them trivially reachable from any process on the host (and, via the long-standing `0.0.0.0` browser bypass, from drive-by web pages a developer happens to visit). The class of bug has shipped in production tooling: **CVE-2025-49596** (MCP Inspector pre-0.14.1) accepted `command=` and `args=` query parameters on its SSE endpoint and spawned them as subprocesses, giving any web page that could reach `http://0.0.0.0:6277/sse` a clean RCE.

Pipelock's forward-proxy mode does **not** see this traffic. The forward proxy sits in the agent's egress path; localhost loopback connections from a browser tab to a developer's own machine never pass through it. The right placement is a **reverse proxy in front of the MCP listener**, with Origin enforcement and an auth token gate.

This guide shows how to do that with the `mcp proxy` reverse-proxy mode that pipelock already ships.

## Threat model

Three classes of bug this configuration defends against:

| Bug class | Real-world example | What this configuration adds |
|---|---|---|
| **Unauthenticated query-parameter command injection** | CVE-2025-49596 in MCP Inspector | Auth token required on every mediated request; bad token → 407, never reaches the inspector |
| **Drive-by browser exploitation via 0.0.0.0 bypass** | CVE-2025-49596 (same incident; the bypass is the delivery vector) | Origin allowlist rejects any browser tab whose Origin header isn't on the list |
| **Localhost-port-scanning from rogue processes on the host** | Generic; any malicious script with network access on the dev machine | Listener stays on localhost; Pipelock rejects requests without a valid token (407) before they reach the inspector |

What this configuration does **not** protect against: a determined attacker who already has read access to the developer's shell environment can read `MCP_INSPECTOR_TOKEN` and forge a request. The configuration raises the cost of opportunistic exploitation; it does not replace process isolation or threat-model hygiene on the developer's machine.

## Quick start

Pipelock reverse-proxies MCP traffic via `pipelock mcp proxy --listen ADDR --upstream URL`. The listener accepts MCP requests, runs them through the configured scanner pipeline, and forwards clean traffic to the upstream.

```bash
# Generate a mode-0600 token file for this session
umask 077
head -c 32 /dev/urandom | base64 | tr -d '\n' > /tmp/pipelock-mcp-inspector.token

# Run pipelock in front of MCP Inspector
pipelock mcp proxy \
  --config ~/.config/pipelock/mcp-front.yaml \
  --listen 127.0.0.1:6300 \
  --upstream http://127.0.0.1:6277 \
  --listener-auth-token-file /tmp/pipelock-mcp-inspector.token \
  --listener-allowed-origin https://console.vendor.example
```

Point your IDE or non-browser agent at `http://127.0.0.1:6300` and send the
token in `Proxy-Authorization: Bearer ...`. Browser JavaScript uses
`Authorization: Bearer ...` because browsers reserve `Proxy-Authorization`.
Pipelock consumes whichever header authenticated the listener and never
forwards it. With `Proxy-Authorization`, a separate `Authorization` header can
still carry an upstream MCP credential.
For a browser-facing listener whose upstream also needs a bearer token, add a
mode-0600 `--header-file` containing `Authorization: Bearer ...`; operator-set
upstream headers take precedence over client input.

## Config: `~/.config/pipelock/mcp-front.yaml`

```yaml
# Reverse-proxy front for MCP development listeners.
# Bind to localhost only — never expose this to the network.

forward_proxy:
  enabled: false  # not used in this configuration

mcp_input_scanning:
  enabled: true       # scan tool arguments
  action: block

mcp_tool_scanning:
  enabled: true       # poisoned descriptions, rug-pull drift
  action: warn        # warn during development; promote to block in CI

mcp_session_binding:
  enabled: true       # cap tool inventory at 10k per session

mcp_tool_policy:
  enabled: true
  action: block
  # Tool policy requires at least one rule when enabled; pipelock refuses to
  # start otherwise. Replace this with the rules that match your tool surface.
  rules:
    - name: "Block shell execution"
      tool_pattern: "bash|shell|exec"

# Inspector / dev-server traffic is local; SSRF defaults are fine.
internal: []           # disable SSRF rejections for loopback upstream

# Listener authentication and Origin policy are CLI flags because they protect
# the socket itself, before the MCP scanner parses a request.
```

## Why not just bind the inspector to 127.0.0.1?

You should, where possible. `127.0.0.1` does close the `0.0.0.0` browser-bypass class. But it leaves the inspector reachable from any process on the host. The pipelock-in-front configuration adds:

- A scanner pipeline on every request (input scanning, tool scanning, tool policy)
- A signed audit trail (receipts) for every tool call, including blocked ones
- A clean revocation surface: replace the token file and every existing client using the old token breaks on its next request
- Compatibility with the rest of pipelock's posture (kill switch, adaptive enforcement, etc.)

The right answer for a high-stakes development environment is **both**: bind the inspector to `127.0.0.1`, and front it with pipelock.

## Verifying the configuration

Once running:

```bash
# Confirm pipelock is listening (health intentionally contains no MCP data)
curl -fsS http://127.0.0.1:6300/health

# Confirm an unauthenticated MCP request is rejected
curl -i -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  http://127.0.0.1:6300/
# expected: HTTP/1.1 407 Proxy Authentication Required

# Confirm the 0.0.0.0 bypass class is closed: requests with an
# unexpected Origin header are rejected even with a valid token
curl -i -H "Proxy-Authorization: Bearer $(cat /tmp/pipelock-mcp-inspector.token)" \
     -H "Origin: https://example.com" \
     -H 'Content-Type: application/json' \
     --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
     http://127.0.0.1:6300/
# expected: HTTP/1.1 403 Forbidden
```

Authentication and Origin failures are rejected before MCP parsing and do not
produce action receipts. Requests that reach the scanner retain the normal
policy receipts and audit trail.

## Related guides

- [`docs/guides/deployment-recipes.md`](./deployment-recipes.md) — production deployment patterns
- [`docs/guides/detection-integration.md`](./detection-integration.md) — receipt + SIEM integration
- [`docs/guides/false-positive-tuning.md`](./false-positive-tuning.md) — turning warn into block once the inspector is stable

## References

- CVE-2025-49596 — Critical RCE in Anthropic MCP Inspector, fixed in v0.14.1. Public writeup at `https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596`.
- The 0.0.0.0 browser bypass — long-standing class of bug where browsers allow drive-by access to localhost via `0.0.0.0`. Discussed in the Oligo writeup above.
