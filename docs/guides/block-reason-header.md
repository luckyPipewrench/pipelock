# X-Pipelock-Block-Reason Header

When Pipelock blocks a request on an HTTP-capable path, it sets a small set of response headers naming the rule class that fired, the severity, and an optional retry hint. The headers let an agent react to a block intelligently. Without structured block metadata, HTTP clients see only a generic denial and must fall back to generic backoff or human escalation.

The schema is locked at v1. Additive changes (new reason codes, new optional headers) keep v1.

## Headers emitted

| Header | Required? | Example |
|---|---|---|
| `X-Pipelock-Block-Reason` | Always | `dlp_match` |
| `X-Pipelock-Block-Reason-Version` | Always | `1` |
| `X-Pipelock-Block-Reason-Severity` | Always | `critical` |
| `X-Pipelock-Block-Reason-Retry` | Always | `none` |
| `X-Pipelock-Block-Reason-Layer` | Optional | `body_dlp` |
| `X-Pipelock-Block-Reason-Receipt` | Optional | `01J0GNYZ7XSQRTQ8FPYM5BHX2K` |

The version header lets a future v2 schema break compatibility cleanly. Receivers should parse the version header first and reject unknown majors.

## Reason vocabulary

Pipelock's block reasons are grouped by layer. The values are stable strings; agents can switch on them without parsing English.

### Egress / network

| Reason | When |
|---|---|
| `scheme_blocked` | URL scheme is not http/https. |
| `domain_blocklist` | Hostname matches a configured blocklist or rule. |
| `ssrf_private_ip` | DNS resolves to a private / loopback / link-local address. |
| `ssrf_metadata` | DNS resolves to a cloud metadata endpoint (169.254.169.254, etc.). |
| `ssrf_dns_rebind` | Hostname's DNS answer differs between resolution and connect, indicating rebinding. |
| `path_entropy` | URL path triggers the high-entropy detector. |
| `subdomain_entropy` | Subdomain triggers the high-entropy detector. |
| `url_length` | URL exceeds `monitoring.max_url_length`. |
| `rate_limit` | Per-session or per-target rate ceiling exceeded. |
| `data_budget` | Per-session data budget exhausted. |

### Content / payload

| Reason | When |
|---|---|
| `dlp_match` | DLP pattern matched in body, header, or URL. |
| `prompt_injection` | Response body matched an injection pattern. |
| `redaction_failure` | Body could not be redacted safely; fail-closed. |
| `media_policy` | Media policy rejected the response (binary type, EXIF, SVG active content, etc.). |

### MCP / tool

| Reason | When |
|---|---|
| `tool_policy_deny` | A `mcp_tool_policy` rule blocked the call. |
| `tool_chain_blocked` | A configured chain pattern matched the recent tool sequence. |
| `tool_poisoning` | A tool description matched a poisoning pattern (rug-pull, suffix injection, etc.). |
| `session_binding` | The tool inventory drifted from the session-pinned baseline. |

### Posture / runtime

| Reason | When |
|---|---|
| `airlock_active` | Adaptive enforcement raised the airlock; all egress denied for the cooldown window. |
| `kill_switch_active` | The four-source kill switch is asserted (config, API, SIGUSR1, or sentinel file). |
| `envelope_verify_failed` | Inbound mediation envelope verification failed. |
| `outbound_envelope_failed` | Outbound envelope injection, refresh, or signing failed before forwarding. |
| `redirect_scan_denied` | A followed redirect target was denied by the scanner pipeline. |
| `authority_mismatch` | Operator authority for the requested action is missing or below threshold. |
| `escalation_level` | Adaptive enforcement raised an escalation tier that blocks the requested action class. |
| `session_anomaly` | Session profiling rejected the request because anomaly action is `block`. |
| `cross_request_deny` | Cross-request entropy or fragment reassembly denied the request as exfiltration. |

### Generic

| Reason | When |
|---|---|
| `parse_error` | Pipelock could not parse the request safely; fail-closed. |
| `timeout` | A scanner or upstream operation timed out; fail-closed. |
| `pattern_unavailable` | A configured pattern set is not loaded; fail-closed. |
| `not_enabled` | The requested feature is disabled by config. |
| `bad_request` | The request itself is malformed (e.g. missing required headers, bad CONNECT target). |
| `compressed_response` | A compressed response could not be scanned safely. |
| `browser_shield_oversize` | Response exceeded Browser Shield's size limit. |
| `block_reason_overflow` | Internal sentinel used when WebSocket close-frame metadata would exceed RFC 6455's 123-byte payload limit. Distinct from `parse_error` so the operator sees that the block metadata itself was malformed, not the underlying request. |

## Severity

Three values: `info`, `warn`, `critical`. Severity is hardcoded per reason — operators control external sink thresholds (`emit.webhook.min_severity`, `emit.syslog.min_severity`, `emit.otlp.min_severity`), not the severity itself, so misconfiguration can't downgrade a critical event.

## Retry hints

Three values:

- `none` — the block is permanent for this request as-is. Retrying the same request will block again. Don't retry. Examples: `dlp_match`, `ssrf_private_ip`, `tool_policy_deny`.
- `transient` — the block is environmental and time-bound. Retry with backoff is appropriate. Examples: `rate_limit`, `airlock_active`, `timeout`.
- `policy` — the block requires an operator to change pipelock policy before a retry can succeed. Examples: `kill_switch_active`, `authority_mismatch`.

Agents should switch on the retry hint, not on the reason code, when deciding whether to retry. New reason codes can ship in any v1.x release; the hint vocabulary is bounded.

## Optional fields

`X-Pipelock-Block-Reason-Layer` carries the scanner label that fired (e.g. `subdomain_entropy`, `body_dlp`, `tool_policy`). Useful for telemetry attribution. Bounded to 32 characters; longer labels are dropped, not silently truncated.

`X-Pipelock-Block-Reason-Receipt` is reserved for a 26-character Crockford-base32 ULID identifying an action receipt. The header schema and validator (`WithReceipt`) ship in v2.4, but v2.4 production block paths leave it unset — the header surface is reserved for follow-up wiring that supplies a receipt ID at the block emit site. When a block path does populate it, an auditor can pull the receipt by ID from the receipt store. Receipts are signed; see [`receipt-transports.md`](receipt-transports.md).

## Privacy: what the headers do NOT carry

The header validators reject any value not in the fixed vocabulary or the documented ID format. The headers therefore cannot carry:

- Matched secret content (DLP would defeat itself).
- Specific DLP pattern names (an attacker probing patterns gets only `dlp_match`, not the rule name).
- Agent identifiers, session IDs, or tenant IDs.
- Free-form error messages.

Privacy is enforced at validation, not by convention. The `New()` and `NewForReason()` constructors reject any value that is not in the closed vocabulary at construction time; the `MustNew()` / `MustNewForReason()` startup-grade variants panic on invalid input so a programming error is caught at startup, not at runtime. The static **production-path matrix test** (`internal/blockreason/production_path_matrix_test.go`) fails the build if a reason code ships without at least one production emit site or a documented exemption, so the header surface stays bounded by code, not by reviewer attention.

## Transports

The header is set on every HTTP-capable block path. MCP-internal blocks that happen at the JSON-RPC layer carry the same fixed reason vocabulary on the JSON-RPC error metadata where there is no HTTP response surface to attach a header to.

| Transport | Where the block happens | Surface |
|---|---|---|
| Forward proxy (CONNECT, absolute-URI) | `internal/proxy/forward.go` | HTTP response header |
| Fetch (`/fetch?url=...`) | `internal/proxy/proxy.go` (fetch handler) | HTTP response header |
| TLS-intercepted CONNECT | `internal/proxy/intercept.go` | HTTP response header |
| Reverse HTTP proxy | `internal/proxy/reverse.go` | HTTP response header |
| WebSocket | `internal/proxy/websocket.go` | Close-frame payload (RFC 6455 123-byte limit applies) |
| MCP HTTP / SSE | `internal/mcp/proxy_http.go` | HTTP response header |
| MCP stdio (JSON-RPC) | `internal/mcp/proxy.go`, `internal/mcp/input.go` | JSON-RPC error metadata — no HTTP header surface |

WebSocket close-frame payloads have a 123-byte limit (RFC 6455). When the bare `{block_reason: <code>}` payload would exceed that, Pipelock substitutes the dedicated `block_reason_overflow` sentinel rather than truncating the code mid-string.

### Production-path matrix exemptions

Two reason codes intentionally have no HTTP header emit site. They fire at the MCP JSON-RPC layer, where there is no HTTP response surface to carry a header, and the vocabulary is preserved on the JSON-RPC error metadata instead:

| Reason | Where it fires | Why no HTTP header |
|---|---|---|
| `tool_poisoning` | `internal/mcp/proxy.go::blockResponseReason` on `tools/list` responses where a poisoned tool description is detected | The block surfaces as a JSON-RPC error in the MCP response stream, not an HTTP response. |
| `tool_chain_blocked` | `internal/mcp/proxy_http.go` and `internal/mcp/input.go` when a chain matcher rejects a `tools/call` sequence | Same shape: JSON-RPC error in the MCP response stream, no HTTP response to attach a header to. |

These exemptions are encoded in the `nonProductionEmitReasons` table inside `internal/blockreason/production_path_matrix_test.go`. A static analysis gate runs on every commit and fails the build if a new reason ships without a production emit site or a documented exemption — the vocabulary cannot drift away from shipped behavior.

`block_reason_overflow` is also exempt: it is not emitted by a block path at all. It is RESOLVED inside `CloseFramePayload` as a fallback when the constructed metadata exceeds the close-frame ceiling.

## Agent integration

A simple Python pattern:

```python
import requests

resp = requests.get(target, proxies={"https": "http://pipelock:8888"})
if resp.status_code == 403:
    reason = resp.headers.get("X-Pipelock-Block-Reason", "")
    retry  = resp.headers.get("X-Pipelock-Block-Reason-Retry", "policy")
    if retry == "transient":
        time.sleep(backoff)
        # retry the request
    elif retry == "none":
        raise PolicyDenied(reason)
    else:  # policy — operator action required
        notify_operator(reason)
        raise PolicyDenied(reason)
```

The agent does not need to enumerate reason codes. The retry hint plus a generic block-handler covers every case.

## Versioning policy

- Additive changes (new reason codes, new optional headers) keep `version: 1`.
- Removing a reason code, changing the meaning of an existing severity / retry value, or renaming a header bumps the major version.
- Removing the version header bumps the major version.

Receivers that handle unknown reason codes by falling back to the retry hint are forward-compatible across all v1 releases.

## See also

- [`docs/configuration.md`](../configuration.md) — `emit.webhook.min_severity`, `emit.syslog.min_severity`, and `emit.otlp.min_severity` control which event severities reach external sinks.
- [`receipt-transports.md`](receipt-transports.md) — verifying the receipt referenced by `X-Pipelock-Block-Reason-Receipt`.
- [`learn-and-lock.md`](learn-and-lock.md) — contract-aware blocks emit reason codes; learn-and-lock lifecycle and shadow events emit `EvidenceReceipt v2`.
