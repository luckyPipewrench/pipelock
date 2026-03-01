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

All HTTPS traffic from AI agents uses CONNECT tunnels, which are opaque TCP pipes
that pipelock cannot inspect. These are the primary traffic metrics for
most deployments.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_tunnels_total` | counter | `result` | Total CONNECT tunnels. `result` is `completed` or `blocked`. |
| `pipelock_tunnel_duration_seconds` | histogram | (none) | Tunnel lifetime. Buckets: 1s to 300s. |
| `pipelock_tunnel_bytes_total` | counter | (none) | Total bytes transferred through all tunnels. |
| `pipelock_active_tunnels` | gauge | (none) | Currently open CONNECT tunnels. |

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
from established patterns trigger anomalies; sustained anomalies cause
enforcement escalation.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `pipelock_session_anomalies_total` | counter | `type` | Behavioral anomalies by type. |
| `pipelock_session_escalations_total` | counter | `from`, `to` | Enforcement escalations by transition (e.g. `warn` → `block`). |
| `pipelock_sessions_active` | gauge | (none) | Currently tracked sessions. |
| `pipelock_sessions_evicted_total` | counter | (none) | Sessions evicted by TTL or capacity limit. |

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
  }
}
```

## Grafana Dashboard

An importable Grafana dashboard is included at
[`configs/grafana-dashboard.json`](../configs/grafana-dashboard.json).
Import it via **Dashboards → Import → Upload JSON file** in Grafana.

The dashboard covers all 20 metric families across six sections: fleet
overview, agent status table, traffic, connection details, security events,
and WebSocket proxy.

## Alert Rules

Example Prometheus alert rules are available at
[`examples/prometheus/pipelock-alerts.yaml`](../examples/prometheus/pipelock-alerts.yaml).
See the [SIEM Integration Guide](guides/siem-integration.md) for
Alertmanager routing and automated response patterns.
