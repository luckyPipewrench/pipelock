# Metrics Reference

Pipelock exposes Prometheus metrics at `/metrics` on the proxy listen port
(default 8888). All metric names are prefixed with `pipelock_` (or
`pipelock_learn_` for the observation-pipeline family).

## Scrape Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: pipelock
    static_configs:
      - targets: ["pipelock:8888"]
```

For Kubernetes deployments using a PodMonitor:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: pipelock
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: pipelock
  podMetricsEndpoints:
    - port: metrics
      path: /metrics
      interval: 30s
```

## HTTP Request Metrics

These track plain HTTP requests flowing through the proxy. HTTPS traffic
uses CONNECT tunnels (see below) and does not increment request counters.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_requests_total` | counter | `result`, `agent` | Total HTTP requests. `result` is `allowed` or `blocked`. `agent` is the agent *profile* name (matched against the `agents` config section), not the raw `X-Pipelock-Agent` header — bounded cardinality for Prometheus. Unknown/unmatched agents fall to `_default`. For per-request raw agent identity, read the `actor` field on signed receipts. |
| `pipelock_request_duration_seconds` | histogram | (none) | HTTP request latency. Buckets: 10ms to 10s. |
| `pipelock_scanner_hits_total` | counter | `scanner`, `agent` | Blocks by scanner type (e.g. `dlp`, `prompt_injection`, `domain`). `agent` follows the same profile-mapping rule as `pipelock_requests_total`. |

## CONNECT Tunnel Metrics

In forward-proxy mode, HTTPS traffic uses CONNECT tunnels, which are opaque TCP
pipes that pipelock cannot inspect beyond the hostname. These are the primary
traffic metrics for forward-proxy deployments.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_tunnels_total` | counter | `result`, `agent` | Total CONNECT tunnels. `result` is `completed` or `blocked`. |
| `pipelock_tunnel_duration_seconds` | histogram | (none) | Tunnel lifetime. Buckets: 1s to 300s. |
| `pipelock_tunnel_bytes_total` | counter | (none) | Total bytes transferred through all tunnels. |
| `pipelock_active_tunnels` | gauge | (none) | Currently open CONNECT tunnels. |
| `pipelock_sni_total` | counter | `category`, `agent` | SNI verification results. `category` is `match`, `mismatch`, `not_tls`, `no_extension`, `malformed_tls`, or `timeout`. |

## TLS Interception Metrics

When `tls_interception.enabled` is true, pipelock performs TLS MITM on
CONNECT tunnels and records additional metrics for interception outcomes,
handshake latency, and per-request/response blocking.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_tls_intercept_total` | counter | `outcome` | Total TLS-intercepted CONNECT tunnels. `outcome` is `intercepted` or `handshake_error`. |
| `pipelock_tls_handshake_duration_seconds` | histogram | `side` | TLS handshake latency. `side` is `client` or `upstream`. Buckets: 1ms to 500ms. |
| `pipelock_tls_request_blocked_total` | counter | `reason` | Requests blocked inside intercepted tunnels. `reason` is `authority_mismatch`, `body_dlp`, `body_prompt_injection`, or `header_dlp`. |
| `pipelock_tls_response_blocked_total` | counter | `reason` | Responses blocked inside intercepted tunnels. `reason` is `compressed`, `read_error`, `oversized`, or `injection`. |
| `pipelock_tls_cert_cache_size` | gauge | (none) | Current number of cached forged leaf certificates. |

## Request Scanning Metrics

Request body and header scanning detects secrets and prompt injection in POST/PUT/PATCH bodies,
form data, multipart uploads, and HTTP headers on forward-proxy traffic.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_body_dlp_hits_total` | counter | `action`, `agent` | Request body DLP detections. `action` is `warn` or `block`. |
| `pipelock_body_prompt_injection_hits_total` | counter | `action`, `agent` | Request body prompt-injection detections. `action` is `warn` or `block`. |
| `pipelock_body_redactions_total` | counter | `transport`, `agent`, `provider`, `parser`, `class` | Request body redactions by transport surface, agent profile, provider format, parser, and redaction class. Incremented once per redacted field (not per request), so a single request body can produce several counts. |
| `pipelock_dlp_warn_matches_total` | counter | `pattern`, `transport` | Warn-mode DLP matches by pattern name and transport. Only incremented when the configured DLP action is `warn`; blocked matches are reflected in `pipelock_body_dlp_hits_total` instead. |
| `pipelock_header_dlp_hits_total` | counter | `action`, `agent` | Request header DLP detections. `action` is `warn` or `block`. |
| `pipelock_response_scan_exempt_total` | counter | `reason`, `transport` | Response scanning exemptions. `reason` is `exempt_domain` or `suppress`; current emitters use transports such as `fetch`, `forward`, `connect`, `reverse`, and `websocket`. Every skipped response scan is counted so operators can quantify how much traffic bypasses injection scanning. |

## WebSocket Proxy Metrics

WebSocket connections are upgraded from CONNECT tunnels when the target
matches a known WebSocket API host. Unlike opaque tunnels, pipelock can
inspect WebSocket frames for DLP and prompt injection.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_ws_connections_total` | counter | `result` | Total WebSocket connections. `result` is `completed` or `blocked`. |
| `pipelock_ws_duration_seconds` | histogram | (none) | WebSocket connection lifetime. Buckets: 1s to 3600s. |
| `pipelock_ws_bytes_total` | counter | `direction` | Bytes transferred. `direction` is `client_to_server` or `server_to_client`. |
| `pipelock_ws_active_connections` | gauge | (none) | Currently open WebSocket connections. |
| `pipelock_ws_frames_total` | counter | `type` | Frames by type (e.g. `text`, `binary`). |
| `pipelock_ws_scan_hits_total` | counter | `scanner` | WebSocket frame scan detections by scanner. |
| `pipelock_forward_ws_redirect_hint_total` | counter | (none) | CONNECT requests to known WebSocket API hosts (potential upgrade candidates). |

## Build Information

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_info` | gauge | `version` | Build information. Always 1. The `version` label identifies the running release (e.g. `2.2.0`). |
| `pipelock_kill_switch_active` | gauge | `source` | Whether each kill switch source is active (1) or inactive (0). `source` is `config`, `api`, `signal`, or `sentinel`. Reported fresh on every scrape via a custom collector; the value is never stale. |

## Security Event Metrics

These counters track enforcement actions. In a healthy deployment, all of
these should be zero or very low. Any sustained increase warrants
investigation.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_kill_switch_denials_total` | counter | `transport`, `endpoint` | Requests denied by the kill switch. |
| `pipelock_chain_detections_total` | counter | `pattern`, `severity`, `action` | Tool call chain pattern detections. |

## Session Profiling Metrics

Pipelock tracks per-session behavioral profiles. Sessions that deviate
from established patterns trigger anomalies and escalation events. Adaptive
enforcement can upgrade later requests based on that session state, so these
metrics are both observability and enforcement context.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_session_anomalies_total` | counter | `type` | Behavioral anomalies by type. |
| `pipelock_session_escalations_total` | counter | `from`, `to` | Escalation events by session enforcement level transition (e.g. `elevated` → `high`, `high` → `critical`). These transitions feed adaptive enforcement decisions on later requests. |
| `pipelock_sessions_active` | gauge | (none) | Currently tracked sessions. |
| `pipelock_sessions_evicted_total` | counter | (none) | Sessions evicted by TTL or capacity limit. |
| `pipelock_adaptive_sessions_current` | gauge | `level` | Currently escalated sessions by enforcement level. |
| `pipelock_session_auto_deescalation_total` | counter | `from`, `to` | Autonomous time-based session de-escalations. |

## Adaptive Enforcement Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_adaptive_upgrades_total` | counter | `from_action`, `to_action`, `level` | Requests where adaptive enforcement upgraded the action (e.g. warn to block). |

## Cross-Request Detection Metrics

Cross-request detection tracks secrets split across multiple requests
using entropy budgets and fragment reassembly. These metrics indicate
active exfiltration attempts.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_cross_request_entropy_exceeded_total` | counter | (none) | Entropy budget exceeded events. |
| `pipelock_cross_request_dlp_match_total` | counter | (none) | Fragment reassembly DLP match events. |
| `pipelock_cross_request_fragment_buffer_bytes` | gauge | (none) | Total fragment buffer memory across all sessions. |

## Airlock Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_airlock_sessions` | gauge | `tier` | Current sessions in each airlock tier. |
| `pipelock_airlock_transitions_total` | counter | `from`, `to`, `trigger` | Airlock tier transitions. |
| `pipelock_airlock_denials_total` | counter | `tier`, `transport`, `action_class` | Requests denied by airlock enforcement. `action_class` is the transport-provided action label such as `read`, `GET`, `POST`, or `CONNECT`. |
| `pipelock_airlock_drain_completed_total` | counter | (none) | Sessions that completed drain cleanly. |
| `pipelock_airlock_drain_timeout_total` | counter | (none) | Sessions whose drain timed out before in-flight work completed. |

## Request Policy Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_request_policy_decisions_total` | counter | `rule`, `action` | `request_policy` rule matches by rule name and action. `action` values are `block`, `warn`, `shadow_block`, or `shadow_warn`. Shadow matches (would-have-blocked traffic in observe mode) are labeled `shadow_<action>` so operators can distinguish enforced blocks from shadow-mode observations. Cardinality is bounded because rule names are validated to a fixed character set at config load. |

## Browser Shield Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_shield_rewrites_total` | counter | `category`, `transport` | Browser shield rewrites by category and transport. |
| `pipelock_shield_bytes_stripped_total` | counter | `category` | Bytes stripped by browser shield. |
| `pipelock_shield_shims_injected_total` | counter | `transport` | Shim injections by transport. |
| `pipelock_shield_skipped_total` | counter | `reason` | Shield skips by reason. |
| `pipelock_shield_oversize_scan_head_total` | counter | `transport` | Oversized shieldable responses handled with `oversize_action: scan_head`. |
| `pipelock_shield_latency_seconds` | histogram | `transport` | Browser shield latency. |

## Address Protection Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_address_findings_total` | counter | `chain`, `verdict` | Address poisoning findings by blockchain and verdict. |

## File Sentry Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_file_sentry_findings_total` | counter | `pattern`, `severity`, `agent` | Secrets detected in agent-written files. `agent` is `true` when the write was attributed to the agent process tree, `false` otherwise. |

## Scan API Metrics

The Scan API (`/api/v1/scan`) is an evaluation-plane endpoint for external
integrations. Disabled by default; set `scan_api.listen` to enable.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_scan_api_requests_total` | counter | `kind`, `decision`, `status_code` | Total scan API requests. |
| `pipelock_scan_api_duration_seconds` | histogram | `kind` | Scan API latency. Default Prometheus buckets. |
| `pipelock_scan_api_findings_total` | counter | `kind`, `scanner`, `severity` | Scan API findings by scanner and severity. |
| `pipelock_scan_api_errors_total` | counter | `kind`, `error_code` | Scan API errors by kind and error code. |
| `pipelock_scan_api_inflight_requests` | gauge | (none) | Current number of in-flight scan API requests. |

## Reverse Proxy Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_reverse_proxy_requests_total` | counter | `method`, `status` | Total reverse proxy requests by method and status. |
| `pipelock_reverse_proxy_scan_blocked_total` | counter | `direction`, `reason` | Reverse proxy requests blocked by scanning. `direction` is `request` (DLP on inbound body) or `response` (injection on response). |

## Mediation Envelope Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_envelope_verify_total` | counter | `result` | Inbound mediation envelope verification attempts. `result` is `disabled` (verification off), `verified` (valid envelope), `missing` (required envelope absent), or `failed` (present but invalid). |

## Signed Receipt Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_receipt_emit_failures_total` | counter | `reason` | Signed action-receipt emission failures. A non-zero rate means receipts are not being recorded; check the flight-recorder signing key and chain state. `reason` values are `chain_init`, `sign`, `hash`, `marshal`, `record`, `sealed`, or `unknown`. |

## Capture System Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_capture_dropped_total` | counter | (none) | Capture entries dropped due to queue overflow. |
| `pipelock_capture_session_id_sanitized_total` | counter | `reason` | Capture entries whose unsafe or overlength logical session ID was replaced with a bounded hashed ID. `reason` is `unsafe_path`, `overlength`, or `unknown`. |
| `pipelock_capture_action_class_sanitized_total` | counter | `reason` | Capture entries whose `action_class` was corrected at ingestion. `reason` is `missing` (no action class supplied), `normalized` (whitespace/case correction applied), or `non_canonical` (value outside the closed action-class taxonomy, dropped). |

## Observation Pipeline Metrics (pipelock_learn_*)

The observation pipeline records agent actions for the learn-and-lock behavioral
contract system. These metrics use the `pipelock_learn_` prefix to keep alerting
on observation-pipeline health independent of core proxy alerts.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_learn_observation_events_total` | counter | `action_class` | Total observation events emitted to the recorder. `action_class` is one of: `read`, `derive`, `write`, `delegate`, `authorize`, `spend`, `commit`, `actuate`, or `unclassified`. Non-canonical values are silently dropped to prevent label cardinality drift. |
| `pipelock_learn_regulated_data_blocked_total` | counter | `reason` | Observation events whose data class resolved to regulated and were dropped before reaching the recorder. `reason` is `field_class_regulated`, `root_class_regulated`, or `explicit_block`. |
| `pipelock_learn_unclassified_actions_total` | counter | (none) | Subset of `pipelock_learn_observation_events_total` where `action_class=unclassified`. A non-zero rate on side-effecting or high-authority paths indicates contracts that require classification review. |
| `pipelock_learn_unclassified_rate` | gauge | (none) | Sliding-window unclassified-event ratio. `0.0` = all events classified; `1.0` = none classified. Updated by the observation pipeline's pre-flight calculator. |
| `pipelock_learn_inference_classify_total` | counter | `outcome` | Inference classifications produced by the contract-compile engine. `outcome` is `never_confirmed`, `brittle`, or `stable`. |
| `pipelock_learn_inference_floor_failures_total` | counter | `floor` | Floor failures that caused an inference classification to fall back to `never_confirmed`. `floor` is `sessions`, `events`, or `windows`. Use this to identify which data-volume floor is the bottleneck on a given deployment. |
| `pipelock_learn_capture_records_total` | counter | (none) | Capture records durably written by the learn-and-lock capture writer. |
| `pipelock_learn_capture_dropped_total` | counter | (none) | Capture records dropped before durable write. Distinct from `pipelock_capture_dropped_total`, which tracks queue overflow in the general capture system. |

## Conductor Metrics (enterprise build, `pipelock_conductor_*`)

These metrics are only registered in the enterprise build
(`-tags enterprise`). They are absent from the standard binary. Each metric
name appears once in `/metrics` output regardless of how many followers are
enrolled; the per-follower audit transport emits into the same time series via
labels.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_conductor_audit_queue_pending` | gauge | (none) | Current pending audit batches in the durable queue awaiting first delivery. |
| `pipelock_conductor_audit_queue_inflight` | gauge | (none) | Current claimed audit batches awaiting ack, retry, or dead-letter. |
| `pipelock_conductor_audit_queue_dead` | gauge | (none) | Current dead-lettered audit batches (delivery attempts exhausted). |
| `pipelock_conductor_audit_deliveries_total` | counter | `outcome`, `reason` | Total audit batch delivery outcomes. `outcome` is `ok`, `retry`, or `dead`. |
| `pipelock_conductor_server_requests_total` | counter | `route`, `method`, `status` | Total Conductor server HTTP requests by route, method, and HTTP status code. |
| `pipelock_conductor_server_request_duration_seconds` | histogram | `route`, `method` | Conductor server HTTP request duration by route and method. Default Prometheus buckets. |
| `pipelock_conductor_server_audit_ingest_total` | counter | `outcome`, `reason` | Total Conductor server audit ingest outcomes. |
| `pipelock_conductor_server_audit_queries_total` | counter | `outcome`, `reason` | Total Conductor server audit query outcomes. |

## Counter Initialization

Prometheus `CounterVec` metrics only appear in `/metrics` output after
their first increment. If you see a metric missing from a fresh instance,
it means that event type hasn't occurred yet, not that the metric is
broken. For example, `pipelock_requests_total` won't appear if all traffic
is HTTPS (CONNECT tunnels).

## Observability Export

### Prometheus and JSON stats

The `/metrics` endpoint serves all registered Prometheus metrics. A JSON
summary is available at `/stats` on the same port:

```bash
curl http://localhost:8888/stats | jq .
```

```json
{
  "uptime_seconds": 3600.5,
  "requests": {
    "total": 42,
    "allowed": 40,
    "blocked": 2,
    "block_rate": 0.0476
  },
  "tunnels": 1523,
  "websockets": 0,
  "top_blocked_domains": [
    {"name": "evil.com", "count": 2}
  ],
  "top_scanners": [
    {"name": "dlp", "count": 2}
  ],
  "sessions": {
    "active": 3,
    "anomalies": 0,
    "escalations": 0,
    "top_anomalies": []
  },
  "agents": {
    "claude-code": {"allowed": 35, "blocked": 1, "tunnels": 1200},
    "cursor": {"allowed": 5, "blocked": 1, "tunnels": 323}
  }
}
```

The `agents` field is omitted when no agent-scoped traffic has been recorded.

### OTLP export

The `emit.otlp` configuration sends audit events as **OTLP log records** to
an OpenTelemetry-compatible collector. The endpoint is `/v1/logs` (not
`/v1/traces`). Pipelock does not currently emit distributed traces; all OTLP
export is log-based. Events are structured as `LogRecord` bodies with
`pipelock.instance` and event-specific key-value attributes.

See the [SIEM Integration Guide](guides/siem-integration.md) for collector
configuration and the OTLP attribute schema.

### SIEM / webhook events and signing

Audit events emitted via webhook, syslog, and OTLP are **not
individually signed**. They are structured log records and are not
cryptographically authenticated at the transport layer.

Signed attestation is a separate feature: the flight recorder emits
Ed25519-signed, hash-chained **action receipts** stored as JSONL on disk.
Action receipts and SIEM events record the same enforcement decisions but
serve different purposes — receipts provide tamper-evident proof for
auditors and compliance workflows; SIEM events are for real-time alerting
and analysis. See [receipt-verification.md](guides/receipt-verification.md)
for receipt verification, and [flight-recorder.md](guides/flight-recorder.md)
for the chain model.

## Grafana Dashboard

An importable Grafana dashboard is included at
[`configs/grafana-dashboard.json`](../configs/grafana-dashboard.json).
Import it via **Dashboards → Import → Upload JSON file** in Grafana.

The bundled dashboard covers core traffic, TLS interception, security
event, WebSocket, adaptive enforcement, and Scan API panels. Newer families
(airlock, browser shield, observation pipeline, conductor) are registered
in Prometheus; operators can add panels for them using the metric names
in this document.

## Alert Rules

Example Prometheus alert rules are available at
[`examples/prometheus/pipelock-alerts.yaml`](../examples/prometheus/pipelock-alerts.yaml).
See the [SIEM Integration Guide](guides/siem-integration.md) for
Alertmanager routing and automated response patterns.

## Go Runtime Metrics

The standard Go runtime and process collectors are also registered on the
same Prometheus registry. These expose `go_memstats_heap_alloc_bytes`,
`go_goroutines`, `process_resident_memory_bytes`, and related metrics —
useful for capacity planning and for comparing against RSS in benchmarks.
