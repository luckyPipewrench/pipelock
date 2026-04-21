# Receipt Transport Coverage

Pipelock emits Ed25519-signed action receipts for enforcement decisions across proxy transports. Receipts are written to the flight recorder as `action_receipt` entries and linked into a tamper-evident hash chain via `chain_prev_hash` and `chain_seq`.

## Transports and Event Kinds

| Transport | Event Kind | Layer / Subsurface | Description |
|-----------|-----------|--------------------|-------------|
| `fetch` | URL block | scanner layer name | URL scan finding in enforce or escalated audit mode |
| `fetch` | Redirect block | `redirect` | Cross-origin redirect blocked |
| `fetch` | Response size | `response_size` or `budget` | Response exceeds config limit or byte budget |
| `fetch` | Shield oversize | `shield_oversize` | Response exceeds browser shield size limit |
| `fetch` | Media policy | `media_policy` | Blocked media type |
| `fetch` | Response scan | `response_scan` | Prompt injection detected in response content |
| `fetch` | Header DLP | `dlp_header` | Secret found in request headers |
| `fetch` | Session profiling | `session_profiling` | Session recorder blocked the request |
| `fetch` | Session deny | `session_deny` | Adaptive escalation block_all |
| `fetch` | Budget | `budget` | Request/domain budget exceeded |
| `fetch` | Cross-request | `cross_request` | CEE exfiltration detection |
| `fetch` | Allow | (empty) | Successful fetch |
| `websocket` | URL block | scanner layer name | URL scan finding |
| `websocket` | Header DLP | `dlp_header` | Secret in forwarded headers |
| `websocket` | Session profiling | `session_profiling` | Session recorder blocked |
| `websocket` | Session deny | `session_deny` | Adaptive escalation block_all |
| `websocket` | Budget | `budget` | Budget exceeded |
| `websocket` | Airlock | `airlock` | Quarantine admission denied |
| `websocket` | Kill switch | `kill_switch` | Kill switch activated mid-stream |
| `websocket` | Protocol | `ws_protocol` | Binary frames denied, fragment violation, compressed frames |
| `websocket` | Request redaction | `redaction` | Redaction fail-closed on fragmented or non-JSON outbound messages |
| `websocket` | Media policy | `media_policy` | Blocked binary media frame after content sniffing |
| `websocket` | DLP | `dlp` | DLP match in text frame |
| `websocket` | Address protection | `address_protection` | Address poisoning detected |
| `websocket` | Cross-request | `cross_request` | CEE exfiltration in frame |
| `websocket` | Injection | `response_scan` | Prompt injection in upstream frame |
| `websocket` | Session close | `session_close` | Connection closed (verdict reflects blocked status) |
| `connect` | CONNECT deny / allow | scanner layer name, `airlock`, `kill_switch` | CONNECT tunnel admission decisions before interception |
| `forward` | URL block | scanner layer name | URL scan finding |
| `forward` | Request body | `dlp`, `address_protection`, or `redaction` | Request-body DLP, address finding, or redaction fail-closed before upstream |
| `forward` | A2A header | `a2a_header` | A2A-Extensions header blocked URI |
| `forward` | A2A stream | `a2a_stream` | SSE stream finding or compressed stream |
| `forward` | A2A response | `a2a_response` | A2A response body finding |
| `forward` | Response scan | `response_scan` | Prompt injection in response |
| `forward` | Allow | (empty) | Successful forward |
| `intercept` | Request / response / A2A scanning | various | TLS-intercepted traffic inside CONNECT tunnels, including request-body redaction, response-scan, DLP, media policy, and A2A coverage |
| `mcp_stdio` | Input scan | `mcp_input_scanning` | DLP, injection, or tools/call redaction block |
| `mcp_stdio` | Tool scan | `mcp_response_scan` | Poisoned `tools/list` response or schema drift (rug-pull) |
| `mcp_stdio` | Tool policy | `mcp_tool_policy` | Pre-execution allow/deny/redirect decision |
| `mcp_stdio` | Chain detection | `chain_detection` | Multi-call subsequence match |
| `mcp_stdio` | Session binding | `session_binding` | Unknown tool appeared mid-session |
| `mcp_stdio` | Response scan | `mcp_response_scan` | Prompt injection in tool result |
| `mcp_http_upstream` | All of the above | same as stdio | Stdio client bridged to an upstream HTTP / SSE MCP server |
| `mcp_http_listener` | All of the above | same as stdio | Listener-bound HTTP / SSE MCP proxy variant |
| `mcp_ws` | All of the above | same as stdio | WebSocket MCP proxy variant |

MCP response transports (`mcp_stdio`, `mcp_http`, `mcp_http_listener`, `mcp_ws`) emit `mcp_response_scan` for prompt-injection findings and `media_policy` when a tool result carries blocked base64 media in `content[].data`, `content[].blob`, or `content[].raw`.

## Receipt Fields

Every receipt contains these fields:

| Field | Source | Description |
|-------|--------|-------------|
| `action_id` | `receipt.NewActionID()` | UUIDv7 correlation handle |
| `action_type` | Classified from method/tool | `read`, `write`, `delegate`, etc. |
| `verdict` | `block`, `allow`, `warn` | Enforcement outcome |
| `transport` | `fetch`, `websocket`, `connect`, `forward`, `intercept`, `mcp_stdio`, `mcp_http_upstream`, `mcp_http_listener`, `mcp_ws`, `reverse` | Which proxy mode handled the action |
| `method` | HTTP method or `WS` | Request method |
| `target` | URL | Target URL |
| `layer` | Scanner layer name | Which scanning layer triggered |
| `pattern` | Reason string | What was matched |
| `request_id` | Per-request UUID | Request correlation |
| `redaction` | Request redaction summary | Present only when request-side redaction replaced one or more values; includes `profile`, `total_redactions`, and `by_class` |
| `agent` | Agent identity | Which agent made the request |
| `chain_prev_hash` | SHA-256 of previous receipt | Hash chain linkage |
| `chain_seq` | Monotonic counter | Position in chain |
| `policy_hash` | Config hash | Which config version was active |

Taint-aware fields (when session profiling is active):

| Field | Description |
|-------|-------------|
| `session_taint_level` | Current taint risk level |
| `session_contaminated` | Whether session is contaminated |
| `recent_taint_sources` | Recent taint source references |
| `session_task_id` | Current task ID |
| `session_task_label` | Current task label when present |
| `authority_kind` | Authority classification |
| `taint_decision` | Policy decision after taint evaluation |
| `taint_decision_reason` | Stable reason string for the taint decision |
| `task_override_applied` | True when a runtime task-scoped override allowed the action |

When request-side redaction succeeds, the receipt keeps the underlying transport verdict and adds the `redaction` summary block. When no values were rewritten, the field is omitted so legacy receipts remain byte-identical.

## Chain Integrity

All receipts from a single proxy instance share a hash chain. The first receipt has `chain_prev_hash: "genesis"`. Each subsequent receipt's `chain_prev_hash` is the SHA-256 of the previous receipt's canonical JSON. `chain_seq` increments by 1 for each receipt.

Verify a single file with `pipelock verify-receipt evidence-proxy-0.jsonl`. Verify chain integrity across rotated or restarted evidence files with `pipelock verify-receipt --chain <evidence-dir>`.

## Fail-Open on Emit

Receipt emission failures are logged but never fail the request. The receipt is evidence, not enforcement. If signing fails or the recorder is unavailable, the proxy decision still completes normally.
