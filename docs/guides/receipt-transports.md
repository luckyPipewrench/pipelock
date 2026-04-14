# Receipt Transport Coverage

Pipelock emits Ed25519-signed action receipts for enforcement decisions across proxy transports. Receipts are written to the flight recorder as `action_receipt` entries and linked into a tamper-evident hash chain via `chain_prev_hash` and `chain_seq`.

## Transports and Event Kinds

| Transport | Event Kind | Layer | Description |
|-----------|-----------|-------|-------------|
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
| `websocket` | DLP | `dlp` | DLP match in text frame |
| `websocket` | Address protection | `address_protection` | Address poisoning detected |
| `websocket` | Cross-request | `cross_request` | CEE exfiltration in frame |
| `websocket` | Injection | `response_scan` | Prompt injection in upstream frame |
| `websocket` | Session close | `session_close` | Connection closed (verdict reflects blocked status) |
| `forward` | URL block | scanner layer name | URL scan finding |
| `forward` | A2A header | `a2a_header` | A2A-Extensions header blocked URI |
| `forward` | A2A stream | `a2a_stream` | SSE stream finding or compressed stream |
| `forward` | A2A response | `a2a_response` | A2A response body finding |
| `forward` | Response scan | `response_scan` | Prompt injection in response |
| `forward` | Allow | (empty) | Successful forward |
| `intercept` | (all layers) | various | TLS-intercepted traffic (19 emission points) |

## Receipt Fields

Every receipt contains these fields:

| Field | Source | Description |
|-------|--------|-------------|
| `action_id` | `receipt.NewActionID()` | UUIDv7 correlation handle |
| `action_type` | Classified from method/tool | `read`, `write`, `delegate`, etc. |
| `verdict` | `block`, `allow`, `warn` | Enforcement outcome |
| `transport` | `fetch`, `websocket`, `forward`, `intercept` | Which proxy mode |
| `method` | HTTP method or `WS` | Request method |
| `target` | URL | Target URL |
| `layer` | Scanner layer name | Which scanning layer triggered |
| `pattern` | Reason string | What was matched |
| `request_id` | Per-request UUID | Request correlation |
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
| `authority_kind` | Authority classification |

## Chain Integrity

All receipts from a single proxy instance share a hash chain. The first receipt has `chain_prev_hash: "genesis"`. Each subsequent receipt's `chain_prev_hash` is the SHA-256 of the previous receipt's canonical JSON. `chain_seq` increments by 1 for each receipt.

Verify chain integrity with `pipelock verify-receipt --chain <evidence-dir>`.

## Fail-Open on Emit

Receipt emission failures are logged but never fail the request. The receipt is evidence, not enforcement. If signing fails or the recorder is unavailable, the proxy decision still completes normally.
