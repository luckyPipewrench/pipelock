# Pipelock as a Reverse Proxy for MCP Development Listeners

MCP development tools — Inspector, ad-hoc test servers, debugging harnesses — frequently bind to `0.0.0.0` on a high port with no authentication. This makes them trivially reachable from any process on the host (and, via the long-standing `0.0.0.0` browser bypass, from drive-by web pages a developer happens to visit). The class of bug has shipped in production tooling: **CVE-2025-49596** (MCP Inspector pre-0.14.1) accepted `command=` and `args=` query parameters on its SSE endpoint and spawned them as subprocesses, giving any web page that could reach `http://0.0.0.0:6277/sse` a clean RCE.

Pipelock's forward-proxy mode does **not** see this traffic. The forward proxy sits in the agent's egress path; localhost loopback connections from a browser tab to a developer's own machine never pass through it. The right placement is a **reverse proxy in front of the MCP listener**, with Origin enforcement and an auth token gate.

This guide shows how to do that with the `mcp proxy` reverse-proxy mode that pipelock already ships.

## Threat model

Three classes of bug this configuration defends against:

| Bug class | Real-world example | What this configuration adds |
|---|---|---|
| **Unauthenticated query-parameter command injection** | CVE-2025-49596 in MCP Inspector | Auth token required on every request; bad token → 401, never reaches the inspector |
| **Drive-by browser exploitation via 0.0.0.0 bypass** | CVE-2025-49596 (same incident; the bypass is the delivery vector) | Origin allowlist rejects any browser tab whose Origin header isn't on the list |
| **Localhost-port-scanning from rogue processes on the host** | Generic; any malicious script with network access on the dev machine | Listener stays on localhost; the token-gate shim rejects requests without a valid token (401) before they reach the inspector |

What this configuration does **not** protect against: a determined attacker who already has read access to the developer's shell environment can read `MCP_INSPECTOR_TOKEN` and forge a request. The configuration raises the cost of opportunistic exploitation; it does not replace process isolation or threat-model hygiene on the developer's machine.

## Quick start

Pipelock reverse-proxies MCP traffic via `pipelock mcp proxy --listen ADDR --upstream URL`. The listener accepts MCP requests, runs them through the configured scanner pipeline, and forwards clean traffic to the upstream.

```bash
# Generate a single-use token for this session
export MCP_INSPECTOR_TOKEN="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40)"

# Run pipelock in front of MCP Inspector
pipelock mcp proxy \
  --config ~/.config/pipelock/mcp-front.yaml \
  --listen 127.0.0.1:6300 \
  --upstream http://127.0.0.1:6277
```

Point your IDE / agent at `http://127.0.0.1:6300` and include the token in either the `Authorization: Bearer` header (preferred) or the `X-Pipelock-Token` header.

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
  # Add per-tool allow/deny rules here for development-time policy.

# Inspector / dev-server traffic is local; SSRF defaults are fine.
internal: []           # disable SSRF rejections for loopback upstream

# Origin allowlist enforcement is handled by the reverse-proxy wrapper
# documented below. Pipelock itself does not currently enforce Origin
# allowlists on its mcp proxy listener — wrap with the included
# `mcp-inspector-front.sh` until native support ships.
```

> **Status note.** Native Origin allowlist enforcement and a built-in auth token gate on `pipelock mcp proxy --listen` are tracked for a future release. Until then, run pipelock behind a small `socat`-or-similar shim that enforces the Origin header and the token before pipelock sees the request. The shim is ~20 lines of bash and is documented at the bottom of this page.

## Why not just bind the inspector to 127.0.0.1?

You should, where possible. `127.0.0.1` does close the `0.0.0.0` browser-bypass class. But it leaves the inspector reachable from any process on the host. The pipelock-in-front configuration adds:

- A scanner pipeline on every request (input scanning, tool scanning, tool policy)
- A signed audit trail (receipts) for every tool call, including blocked ones
- A clean revocation surface: rotate the token and every existing client breaks immediately
- Compatibility with the rest of pipelock's posture (kill switch, adaptive enforcement, etc.)

The right answer for a high-stakes development environment is **both**: bind the inspector to `127.0.0.1`, and front it with pipelock.

## Origin allowlist + token gate shim

If your team needs Origin enforcement today (before native support lands), this shim does it. Save it as `~/.local/bin/mcp-inspector-front.sh`, `chmod +x`, and run it instead of pipelock directly. It forwards to `pipelock mcp proxy` after enforcing the Origin and token requirements.

```bash
#!/usr/bin/env bash
# Reject non-allowlisted Origin headers and missing/wrong tokens before
# forwarding to pipelock's mcp proxy reverse-proxy listener.

set -euo pipefail

ALLOWED_ORIGINS=(
  "vscode-webview://"
  "http://localhost:8000"
)
PORT_IN=6300
PORT_PIPELOCK=6301

# (left as an exercise — implement with a small Go program, mitmproxy
# script, or Caddy with a header-check directive. Reach out to the
# Pipelock maintainers if you need a reference implementation.)
```

## Verifying the configuration

Once running:

```bash
# Confirm pipelock is listening
curl -fsS -H "Authorization: Bearer $MCP_INSPECTOR_TOKEN" \
  http://127.0.0.1:6300/health

# Confirm an unauthenticated request is rejected
curl -fsS http://127.0.0.1:6300/health
# expected: HTTP/1.1 401 ... or whatever your shim returns

# Confirm the 0.0.0.0 bypass class is closed: requests with an
# unexpected Origin header are rejected even with a valid token
curl -fsS -H "Authorization: Bearer $MCP_INSPECTOR_TOKEN" \
     -H "Origin: https://example.com" \
     http://127.0.0.1:6300/health
# expected: 403 from the shim
```

If the inspector emits receipts via pipelock, every blocked call appears in the audit log with a `reason` field naming the gate that fired (`origin_not_allowed`, `token_invalid`, `policy_block`).

## Related guides

- [`docs/guides/deployment-recipes.md`](./deployment-recipes.md) — production deployment patterns
- [`docs/guides/detection-integration.md`](./detection-integration.md) — receipt + SIEM integration
- [`docs/guides/false-positive-tuning.md`](./false-positive-tuning.md) — turning warn into block once the inspector is stable

## References

- CVE-2025-49596 — Critical RCE in Anthropic MCP Inspector, fixed in v0.14.1. Public writeup at `https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596`.
- The 0.0.0.0 browser bypass — long-standing class of bug where browsers allow drive-by access to localhost via `0.0.0.0`. Discussed in the Oligo writeup above.
