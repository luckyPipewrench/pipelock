# Metrics Reference

Pipelock exposes Prometheus metrics at `/metrics` on the proxy listen port
(default 8888). All metric names are prefixed with `pipelock_`.

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
| `pipelock_requests_total` | counter | `result` | Total HTTP requests. `result` is `allowed` or `blocked`. |
| `pipelock_request_duration_seconds` | histogram | (none) | HTTP request latency. Buckets: 10ms to 10s. |
| `pipelock_scanner_hits_total` | counter | `scanner` | Blocks by scanner type (e.g. `dlp`, `prompt_injection`, `domain`). |

## CONNECT Tunnel Metrics

In forward-proxy mode, HTTPS traffic uses CONNECT tunnels, which are opaque TCP
pipes that pipelock cannot inspect beyond the hostname. These are the primary
traffic metrics for forward-proxy deployments.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_tunnels_total` | counter | `result` | Total CONNECT tunnels. `result` is `completed` or `blocked`. |
| `pipelock_tunnel_duration_seconds` | histogram | (none) | Tunnel lifetime. Buckets: 1s to 300s. |
| `pipelock_tunnel_bytes_total` | counter | (none) | Total bytes transferred through all tunnels. |
| `pipelock_active_tunnels` | gauge | (none) | Currently open CONNECT tunnels. |
| `pipelock_sni_total` | counter | `category` | SNI verification results. `category` is `match`, `mismatch`, `not_tls`, `no_extension`, `malformed_tls`, or `timeout`. |

## TLS Interception Metrics

When `tls_interception.enabled` is true, pipelock performs TLS MITM on
CONNECT tunnels and records additional metrics for interception outcomes,
handshake latency, and per-request/response blocking.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_tls_intercept_total` | counter | `outcome` | Total TLS-intercepted CONNECT tunnels. `outcome` is `intercepted` or `handshake_error`. |
| `pipelock_tls_handshake_duration_seconds` | histogram | `side` | TLS handshake latency. `side` is `client` or `upstream`. Buckets: 1ms to 500ms. |
| `pipelock_tls_request_blocked_total` | counter | `reason` | Requests blocked inside intercepted tunnels. `reason` is `authority_mismatch`, `body_dlp`, or `header_dlp`. |
| `pipelock_tls_response_blocked_total` | counter | `reason` | Responses blocked inside intercepted tunnels. `reason` is `compressed`, `read_error`, `oversized`, or `injection`. |
| `pipelock_tls_cert_cache_size` | gauge | (none) | Current number of cached forged leaf certificates. |

## Request Scanning Metrics

Request body and header scanning detects secrets in POST/PUT/PATCH bodies,
form data, multipart uploads, and HTTP headers on forward-proxy traffic.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_body_dlp_hits_total` | counter | `action` | Request body DLP detections. `action` is `warn` or `block`. |
| `pipelock_header_dlp_hits_total` | counter | `action` | Request header DLP detections. `action` is `warn` or `block`. |

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
| `pipelock_info` | gauge | `version` | Build information. Always 1. The `version` label identifies the running release (e.g. `2.1.0`). |
| `pipelock_kill_switch_active` | gauge | `source` | Whether each kill switch source is active (1) or inactive (0). `source` is `config`, `api`, `signal`, or `sentinel`. Reported fresh on every scrape. |

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
from established patterns trigger anomalies and escalation events. In v1,
escalation is observability-only (scoring and event emission); it does not
automatically change enforcement behavior (warn vs block).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_session_anomalies_total` | counter | `type` | Behavioral anomalies by type. |
| `pipelock_session_escalations_total` | counter | `from`, `to` | Escalation events by level transition (e.g. `warn` → `block`). In v1, these are observability events, not enforcement changes. |
| `pipelock_sessions_active` | gauge | (none) | Currently tracked sessions. |
| `pipelock_sessions_evicted_total` | counter | (none) | Sessions evicted by TTL or capacity limit. |
| `pipelock_adaptive_sessions_current` | gauge | `level` | Currently escalated sessions by enforcement level. |
| `pipelock_session_auto_deescalation_total` | counter | `from`, `to` | Autonomous time-based session de-escalations. |

## Cross-Request Detection Metrics

Cross-request detection tracks secrets split across multiple requests
using entropy budgets and fragment reassembly. These metrics indicate
active exfiltration attempts.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_cross_request_entropy_exceeded_total` | counter | (none) | Entropy budget exceeded events. |
| `pipelock_cross_request_dlp_match_total` | counter | (none) | Fragment reassembly DLP match events. |
| `pipelock_cross_request_fragment_buffer_bytes` | gauge | (none) | Total fragment buffer memory across all sessions. |

## Scan API Metrics

The Scan API (`/scan`) is an evaluation-plane endpoint for external
integrations. Disabled by default; set `scan_api.listen` to enable.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_scan_api_requests_total` | counter | `kind`, `decision`, `status_code` | Total scan API requests. |
| `pipelock_scan_api_duration_seconds` | histogram | `kind` | Scan API latency. Default Prometheus buckets. |
| `pipelock_scan_api_findings_total` | counter | `kind`, `scanner`, `severity` | Scan API findings by scanner and severity. |
| `pipelock_scan_api_errors_total` | counter | `kind`, `error_code` | Scan API errors by kind and error code. |
| `pipelock_scan_api_inflight_requests` | gauge | (none) | Current number of in-flight scan API requests. |

## Address Protection Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_address_findings_total` | counter | `chain`, `verdict` | Address poisoning findings by blockchain and verdict. |

## File Sentry Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_file_sentry_findings_total` | counter | `pattern`, `severity`, `agent` | Secrets detected in agent-written files. |

## Adaptive Enforcement Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_adaptive_upgrades_total` | counter | `from_action`, `to_action`, `level` | Requests where adaptive enforcement upgraded the action (e.g. warn to block). |

## Reverse Proxy Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_reverse_proxy_requests_total` | counter | `method`, `status` | Total reverse proxy requests by method and status. |
| `pipelock_reverse_proxy_scan_blocked_total` | counter | `direction`, `reason` | Reverse proxy requests blocked by scanning. |

## Capture System Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_capture_dropped_total` | counter | (none) | Capture entries dropped due to queue overflow. |

## Counter Initialization

Prometheus `CounterVec` metrics only appear in `/metrics` output after
their first increment. If you see a metric missing from a fresh instance,
it means that event type hasn't occurred yet, not that the metric is
broken. For example, `pipelock_requests_total` won't appear if all traffic
is HTTPS (CONNECT tunnels).

## JSON Stats Endpoint

Pipelock also exposes a JSON summary at `/stats` on the same port. This
provides a human-readable snapshot without needing Prometheus:

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

The `agents` field is omitted when no agent-scoped traffic has been recorded. Fresh deployments or single-profile setups without agent configuration will not include this key.

## Grafana Dashboard

An importable Grafana dashboard is included at
[`configs/grafana-dashboard.json`](../configs/grafana-dashboard.json).
Import it via **Dashboards → Import → Upload JSON file** in Grafana.

The dashboard covers all 45 metric families across ten sections: fleet
overview, agent status table, traffic, connection details, TLS interception,
security events, WebSocket proxy, cross-request detection, adaptive
enforcement, and Scan API.

## Alert Rules

Example Prometheus alert rules are available at
[`examples/prometheus/pipelock-alerts.yaml`](../examples/prometheus/pipelock-alerts.yaml).
See the [SIEM Integration Guide](guides/siem-integration.md) for
Alertmanager routing and automated response patterns.
