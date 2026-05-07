# X-Pipelock-Block-Reason Header Schema (v1)

When pipelock blocks an outbound request, the response carries a small set of HTTP headers that explain *why* in machine-readable form. Agents that read these headers can react intelligently — back off, switch tools, surface the right error to the user — instead of treating every block as an opaque 403.

This document is the canonical schema. Once an agent in production reads `dlp_match`, the vocabulary is locked. Renaming a code in v2 breaks every consumer.

> **Status:** the schema and emit package land first (this PR). The transport refactor that wires every block path to call `Info.SetHeaders` lands in a follow-up PR. Until that PR merges, the vocabulary below is the *target* — it is not currently emitted on production blocks. The split is intentional: locking the operator-facing vocabulary before any block site commits to it.

## Header set

| Header | Required | Example | Meaning |
|---|---|---|---|
| `X-Pipelock-Block-Reason` | yes (on every block) | `dlp_match` | Machine-readable reason code. See vocabulary below. |
| `X-Pipelock-Block-Reason-Version` | yes (on every block) | `1` | Schema version. Increment for breaking changes. |
| `X-Pipelock-Block-Reason-Severity` | yes (on every block) | `critical` | Matches pipelock's existing severity vocabulary: `info`, `warn`, `critical`. |
| `X-Pipelock-Block-Reason-Retry` | yes (on every block) | `none` | Retry hint: `none` (permanent), `transient` (retry with backoff), `policy` (retry only after policy change). |
| `X-Pipelock-Block-Reason-Layer` | optional | `dlp` | Scanner pipeline layer label. Uses `internal/scanner/` `Scanner*` constants verbatim so operators can correlate header-driven agent behavior with their existing audit logs and Prometheus labels. See the layer-label vocabulary below. |
| `X-Pipelock-Block-Reason-Receipt` | optional | `01J0GNYZ7XSQRTQ8FPYM5BHX2K` | Receipt ID. Exactly 26 characters, Crockford-base32 (ULID alphabet: `0-9` plus `A-Z` minus `I`, `L`, `O`, `U`). Lets the agent fetch the matching receipt (via the receipt-transports endpoint) for additional context. The strict format keeps the slot opaque so attacker-controlled metadata cannot reach agent-visible response headers. |

Absent headers are treated as a generic block. Agents that don't read the headers continue to work unchanged — the headers are purely additive.

## Layer-label vocabulary

The optional `X-Pipelock-Block-Reason-Layer` header reuses `internal/scanner/` `Scanner*` constants verbatim. These are intentionally short — they exist to correlate with audit logs and Prometheus labels, not to be human-friendly. The reason code (the main `X-Pipelock-Block-Reason` header) carries the human-friendlier vocabulary.

| Layer label (header) | Source constant | Approximate reason mapping |
|---|---|---|
| `scheme` | `scanner.ScannerScheme` | `scheme_blocked` |
| `blocklist` | `scanner.ScannerBlocklist` | `domain_blocklist` |
| `dlp` | `scanner.ScannerDLP` | `dlp_match`, `redaction_failure` |
| `entropy` | `scanner.ScannerEntropy` | `path_entropy` |
| `subdomain_entropy` | `scanner.ScannerSubdomainEntropy` | `subdomain_entropy` |
| `ssrf` | `scanner.ScannerSSRF` | `ssrf_private_ip`, `ssrf_metadata`, `ssrf_dns_rebind` |
| `ratelimit` | `scanner.ScannerRateLimit` | `rate_limit` |
| `length` | `scanner.ScannerLength` | `url_length` |
| `databudget` | `scanner.ScannerDataBudget` | `data_budget` |
| `parser` | `scanner.ScannerParser` | `parse_error` |

Layers without a `Scanner*` constant (MCP layer, posture layer) leave the layer header unset; the reason code already conveys the layer at the granularity agents need.

## Reason vocabulary (v1)

Reason codes are lowercase snake_case. The v1 set is derived from existing pipelock block paths — every code below maps to an existing block path that the follow-up transport PR will wire to emit this header.

### Egress / network layer

| Code | When | Severity | Retry |
|---|---|---|---|
| `scheme_blocked` | URL scheme other than http/https. | `warn` | `none` |
| `domain_blocklist` | Hostname matched the configured blocklist. | `critical` | `policy` |
| `ssrf_private_ip` | Resolved IP is in private/loopback/link-local range. | `critical` | `none` |
| `ssrf_metadata` | Resolved IP is a cloud metadata endpoint (169.254.169.254, etc.). | `critical` | `none` |
| `ssrf_dns_rebind` | DNS resolution flipped between scan and dial (TOCTOU). | `critical` | `transient` |
| `path_entropy` | URL path entropy exceeded configured ceiling (covert channel signal). | `warn` | `policy` |
| `subdomain_entropy` | Hostname subdomain entropy exceeded configured ceiling. | `warn` | `policy` |
| `url_length` | URL length exceeded configured ceiling. | `warn` | `policy` |
| `rate_limit` | Per-session or per-host rate limit exceeded. | `warn` | `transient` |
| `data_budget` | Per-session data budget exceeded. | `warn` | `policy` |

### Content / payload layer

| Code | When | Severity | Retry |
|---|---|---|---|
| `dlp_match` | Outbound payload matched a DLP pattern (secret, credential, PII). | `critical` | `none` |
| `prompt_injection` | Inbound response matched an injection pattern. | `critical` | `none` |
| `redaction_failure` | Outbound redaction stage encountered an unrecoverable parse error and fail-closed. | `critical` | `transient` |
| `media_policy` | Image / audio / video policy block (size, type, count). | `warn` | `policy` |

### MCP / tool layer

| Code | When | Severity | Retry |
|---|---|---|---|
| `tool_policy_deny` | An `mcp_tool_policy` rule denied the call. | `critical` | `policy` |
| `tool_chain_blocked` | A configured tool-chain detection sequence triggered. | `critical` | `none` |
| `tool_poisoning` | A poisoned tool description or rug-pull drift was detected. | `critical` | `none` |
| `session_binding` | The current call's tool inventory diverged from the session's pinned baseline. | `critical` | `policy` |

### Posture / runtime layer

| Code | When | Severity | Retry |
|---|---|---|---|
| `airlock_active` | Adaptive enforcement escalated this session into the airlock tier. | `critical` | `transient` |
| `kill_switch_active` | One of the four kill-switch sources is active. | `critical` | `transient` |
| `envelope_verify_failed` | Inbound mediation envelope did not verify (signature / replay / trust). | `critical` | `none` |
| `outbound_envelope_failed` | Outbound envelope injection / refresh / signing failed before the request left pipelock. Distinct from `envelope_verify_failed` so agents can tell inbound verification from outbound emission. | `critical` | `transient` |
| `redirect_scan_denied` | A followed redirect target was denied by the scanner pipeline (SSRF, blocklist, etc.). Distinct from the same scanner firing pre-redirect so clients can detect open-redirect probes. | `critical` | `none` |
| `authority_mismatch` | Posture-capsule authority did not match the request's claimed authority. | `critical` | `policy` |
| `escalation_level` | Per-session escalation level exceeded the configured ceiling. | `critical` | `transient` |
| `session_anomaly` | Session profiling marked the session as anomalous (`session_profiling.anomaly_action=block`). Distinct from `airlock_active` so receipts and headers agree on the enforcement source. | `critical` | `transient` |
| `cross_request_deny` | Cross-request entropy / fragment-reassembly (CEE) denied the request because a multi-request payload was reconstructed. Distinct from `dlp_match` so clients can tell single-request DLP from cross-request reconstruction. | `critical` | `none` |

### Generic

| Code | When | Severity | Retry |
|---|---|---|---|
| `parse_error` | Unparseable input on a fail-closed surface. | `warn` | `none` |
| `timeout` | Scanner or HITL timed out (fail-closed default). | `warn` | `transient` |
| `pattern_unavailable` | Scanner pattern set unavailable at startup; fail-closed until ready. | `warn` | `transient` |
| `not_enabled` | Endpoint exists but the feature is disabled in config. | `info` | `policy` |
| `bad_request` | Malformed client request (missing parameter, invalid URL, etc.). | `info` | `none` |
| `compressed_response` | Compressed (gzip/br/zstd) response cannot be scanned safely. Operator must enable upstream decompression in pipelock or change the upstream's `Accept-Encoding` policy to clear the block. | `warn` | `policy` |
| `browser_shield_oversize` | Response body exceeded the configured Browser Shield size limit. Operator must raise the limit or exempt the host to clear the block. | `warn` | `policy` |
| `block_reason_overflow` | Internal sentinel: the block-emit metadata itself was malformed (oversized Reason value, etc.). Pipelock falls back to this rather than silently downgrading to `parse_error` so audit fidelity is preserved. Agents should treat this as a malformed-block signal worth logging. | `warn` | `transient` |

### Contract / learn-and-lock layer

Emitted by the runtime evaluator when an active learn-and-lock contract claims jurisdiction over the request. The first four are real blocks; `contract_observed_only` is an info-tier annotation surfaced by shadow / capture modes when the contract path would have produced a non-allow live verdict but the configured mode does not enforce. `contract_observed_only` never appears on a 4xx response surface — it travels only on receipts and drift telemetry.

| Code | When | Severity | Retry |
|---|---|---|---|
| `contract_default_deny` | Active contract claims jurisdiction (at least one host has an enforce rule with comparable evidence) and no allow rule matched the request. | `critical` | `none` |
| `contract_enforce_default` | Active contract has an enforce rule that matched the request's host but no rule matched the full method / path / action shape. | `critical` | `none` |
| `contract_non_default_port` | Active contract enforce rule matched the host but the request used a non-default port (rule scope excludes non-443 / non-80). | `warn` | `none` |
| `contract_invalid_path` | Active contract enforce rule matched the host but the request path failed RFC 3986 canonicalization. | `warn` | `retry-with-canonical-path` |
| `contract_observed_only` | Shadow / capture annotation: contract path would have blocked under live mode but the configured mode did not enforce. Never emitted on a block surface. | `info` | `none` |

## Severity

Aligns with `internal/config/schema.go` constants:

- `info` — informational; agent can ignore or surface as a status line.
- `warn` — agent should log and continue, but the operator may want to investigate.
- `critical` — the block represents a real security event. Agent should not retry without an operator-driven policy change.

The `info` / `warn` / `critical` values match pipelock's existing emit pipeline (`Emit.MinSeverity`, etc.). Reusing the same vocabulary lets operators correlate header-driven agent behavior with their existing emit / receipt streams.

## Retry hints

- `none` — the block is permanent for the current request. Retrying without changing the input will produce the same block. Examples: `dlp_match`, `ssrf_private_ip`, `prompt_injection`.
- `transient` — the underlying condition is time-bound. A retry after backoff may succeed. Examples: `rate_limit`, `airlock_active`, `kill_switch_active`, `dns_rebind` (resolver may stabilize).
- `policy` — only retry after the operator changes pipelock policy. Examples: `domain_blocklist`, `tool_policy_deny`, `data_budget`.
- `retry-with-canonical-path` — the input as posed will not succeed because it carries a non-canonical URL path. The agent SHOULD canonicalize the request path (RFC 3986 dot-segment removal, percent-encoding normalization) and retry; no operator change is required. Today emitted only by `contract_invalid_path`.

## Privacy

The header is **operational metadata only**. The following must never appear in any header value:

- Matched secret content. The reason `dlp_match` is fine; the matched substring is not.
- DLP pattern names that would identify the regex (e.g. `aws_access_key_id`). Pattern fingerprints are too tight a signal because they invite probing.
- Agent identifiers, session IDs, or any user-attributable data.
- Internal IPs, private hostnames, or cluster-internal details.

The optional `X-Pipelock-Block-Reason-Receipt` header carries an opaque ULID. The 26-character Crockford-base32 format is enforced by the emit package's `WithReceipt` validator; non-conforming receipts are rejected at construction so call sites cannot smuggle arbitrary strings into the slot. The receipt itself (fetched separately via the receipt-transports endpoint) may contain richer context, but the header value is just the opaque ID.

The required header values (`Reason`, `Severity`, `Retry`) are validated against fixed allowlists at construction. The `Layer` value is restricted to ASCII alphanumeric and underscore (the shape of `internal/scanner/Scanner*` constants). Any value that does not match its validator is rejected before the header reaches the wire.

## Versioning

The schema version sits in `X-Pipelock-Block-Reason-Version`. v1 covers everything in this document. Breaking changes — renames, removed codes, semantic shifts — increment the version. Additive changes (new codes, new optional headers) leave the version unchanged.

Agents should treat unknown reason codes as a generic block at the declared severity. Agents should treat unknown versions as a generic block.

## Transport coverage

The follow-up transport PR wires the header onto every pipelock block path. There is no transport split — the schema is the same on every surface; only the framing differs (HTTP headers vs WebSocket close-frame JSON).

| Transport | Mechanism |
|---|---|
| Forward proxy (CONNECT + absolute-URI) | HTTP response headers on the 403/etc. |
| TLS-intercept (MITM) | HTTP response headers on the synthetic block response. |
| Fetch endpoint (`/fetch?url=...`) | HTTP response headers on the 403 JSON body. |
| Reverse proxy (`pipelock run --reverse-listen`) | HTTP response headers on the synthetic block response (request-side and response-side). |
| MCP HTTP / SSE | HTTP response headers on the 403. |
| WebSocket | Close-frame reason payload as a JSON document carrying the same fields (see below). |

### WebSocket close-frame payload

WebSocket blocks happen via close frames, not response headers. The close-frame `Reason` field carries a UTF-8 JSON document with the same shape as the headers:

```json
{
  "block_reason": "dlp_match",
  "version": "1",
  "severity": "critical",
  "retry": "none",
  "layer": "dlp",
  "receipt": "01HZ8..."
}
```

Per RFC 6455 the close-frame reason payload is limited to 123 bytes. Agents should plan for truncation: if the JSON would exceed the limit, fields drop in this order — `receipt`, `layer`, `retry`, `severity`, `version` — leaving `block_reason` as the always-present floor.

MCP stdio is not covered. There is no HTTP layer to attach headers to; MCP-stdio errors flow through the JSON-RPC error envelope. Block-reason taxonomy in JSON-RPC errors is tracked separately.

## Compatibility

- Agents that ignore the header continue to work. The 403 status code and existing JSON body are unchanged.
- Agents that read the header but don't recognize a code or severity should fall back to "generic block" handling.
- Adding a new reason code is an additive change. Removing or renaming a code is a breaking change requiring a version bump.

## Why design first

Once an agent in production reads `dlp_match`, renaming the code to `secret_detected` later breaks that agent. The header is operator-facing — long-lived, hard to migrate. Locking the vocabulary before any code commits to it is the only honest path. v2.4 ships v1; v2 (if ever needed) will be a deliberate, versioned migration.
