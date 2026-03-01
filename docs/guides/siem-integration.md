# SIEM Integration Guide

Pipelock pushes structured security events to external systems via webhook
(HTTP POST) and syslog (RFC 5424) sinks. This guide covers the event schema,
forwarding setup for common SIEM platforms, detection rule examples, and
automated kill switch response.

## Event Schema

Both sinks emit the same JSON envelope:

```json
{
  "severity": "warn",
  "type": "blocked",
  "timestamp": "2026-02-25T12:34:56.789Z",
  "pipelock_instance": "prod-node-1",
  "fields": {
    "method": "GET",
    "url": "https://attacker.com/steal?key=AKIA...",
    "scanner": "dlp",
    "reason": "AWS access key pattern detected",
    "client_ip": "10.0.0.50",
    "request_id": "req-abc-123"
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `severity` | string | `info`, `warn`, or `critical`. Hardcoded per event type. |
| `type` | string | Event type identifier (see tables below) |
| `timestamp` | string | RFC 3339, nanosecond precision, UTC. Trailing zeros are trimmed. Use ISO 8601 parsing, not fixed-width extraction. |
| `pipelock_instance` | string | Hostname, `emit.instance_id` config override, or `"pipelock"` fallback |
| `fields` | object | Event-specific key-value pairs (vary by type) |

## Event Types

Only security events (critical and warn) are pushed to webhook and syslog.
Info-level events go to local logs only, with one exception noted below.

### Critical (requires immediate response)

| Type | Description | Key Fields |
|------|-------------|------------|
| `kill_switch_deny` | All traffic denied by emergency kill switch | `transport`, `endpoint`, `source`, `deny_message`, `client_ip` |
| `adaptive_escalation`* | Session escalated to block level | `session`, `from`, `to`, `client_ip`, `request_id`, `score` |

\* Critical when `to` is `block`. Otherwise warn.

### Warn (suspicious activity)

| Type | Description | Key Fields |
|------|-------------|------------|
| `blocked` | Request blocked by scanner pipeline | `method`, `url`, `scanner`, `reason`, `client_ip`, `request_id` |
| `anomaly` | Behavioral anomaly detected | `method`, `url`, `reason`, `client_ip`, `request_id`, `score` |
| `session_anomaly` | Session-level anomaly | `session`, `anomaly_type`, `detail`, `client_ip`, `request_id`, `score` |
| `mcp_unknown_tool` | Unregistered MCP tool call attempted | `tool`, `action` |
| `ws_blocked` | WebSocket frame blocked | `target`, `direction`, `scanner`, `reason`, `client_ip`, `request_id` |
| `response_scan` | Prompt injection detected in response | `url`, `client_ip`, `request_id`, `action`, `match_count`, `patterns` |
| `ws_scan` | Prompt injection in WebSocket frame | `target`, `direction`, `client_ip`, `request_id`, `action`, `match_count`, `patterns` |
| `adaptive_escalation`* | Session escalated (not to block) | `session`, `from`, `to`, `client_ip`, `request_id`, `score` |
| `error` | Internal error during request processing | `method`, `url`, `client_ip`, `request_id`, `error` |

### Info (local logs only)

These go to stderr/file but **not** to webhook or syslog. If you need
visibility into allowed traffic, use Prometheus metrics or ship local logs
via a log collector (Promtail, Filebeat, Fluentd).

| Type | Description | Key Fields |
|------|-------------|------------|
| `allowed` | Request allowed | `method`, `url`, `client_ip`, `request_id`, `status_code`, `size_bytes`, `duration_ms` |
| `tunnel_open` | CONNECT tunnel established | `target`, `client_ip`, `request_id` |
| `tunnel_close` | CONNECT tunnel closed | `target`, `client_ip`, `request_id`, `total_bytes`, `duration_ms` |
| `ws_open` | WebSocket connection opened | `target`, `client_ip`, `request_id`, `agent` |
| `ws_close` | WebSocket connection closed | `target`, `client_ip`, `request_id`, `agent`, `client_to_server_bytes`, `server_to_client_bytes`, `text_frames`, `binary_frames`, `duration_ms` |
| `config_reload` | Config file reloaded (also emitted) | `status`, `detail` |
| `redirect` | HTTP redirect followed | `original_url`, `redirect_url`, `client_ip`, `request_id`, `hop` |
| `forward_http` | Forward proxy request completed | `method`, `url`, `client_ip`, `request_id`, `status_code`, `size_bytes`, `duration_ms` |

> **Note:** Chain detection events (`chain_detection`) are tracked via
> Prometheus metrics (`pipelock_chain_detections_total`) but are not currently
> emitted to webhook or syslog. Use the Alertmanager rules below to alert on
> chain detection patterns.

## Pipelock Configuration

Add an `emit` block to your pipelock config to enable one or both sinks:

```yaml
emit:
  instance_id: "pipelock-prod-1"      # optional, defaults to hostname

  webhook:
    url: "https://siem.example.com/api/events"
    min_severity: "warn"              # info, warn, or critical
    auth_token: "your-bearer-token"   # optional Authorization header
    timeout_seconds: 5
    queue_size: 64                    # async buffer capacity

  syslog:
    address: "udp://syslog.example.com:514"
    min_severity: "warn"
    facility: "local0"                # local0-local7, auth, daemon, etc.
    tag: "pipelock"
```

**Severity filtering:** Events below `min_severity` are silently dropped before
reaching the sink. Set to `warn` for all security events (recommended), or
`critical` for emergency alerts only. Setting `info` adds `config_reload`
events. All other info-level events are local-only and never sent to sinks.

**`min_severity` defaults to `warn`** when omitted. Valid values are `info`,
`warn`, and `critical`. Invalid values fail config validation.

**You can't change event severity:** it's hardcoded per event type. What you
control is the emission *threshold* (`min_severity`). This is intentional: it
prevents misconfiguration from silently hiding critical events.

## Forwarding Patterns

### Webhook to Splunk HEC

```yaml
emit:
  webhook:
    url: "https://splunk.example.com:8088/services/collector/event"
    auth_token: "your-splunk-hec-token"
    min_severity: "warn"
```

Splunk HEC expects `Authorization: Splunk <token>`, but pipelock sends
`Authorization: Bearer <token>`. You have two options:

**Option A (preferred):** Put n8n or a reverse proxy in front of HEC to
rewrite the auth header from `Bearer` to `Splunk`.

**Option B:** Use Splunk's raw endpoint with the token in the URL. Be aware
this exposes the token in access logs, proxy logs, and URL fields, so only
use this behind TLS with restricted network access.

```yaml
emit:
  webhook:
    url: "https://splunk.example.com:8088/services/collector/raw"
    # For Splunk HEC auth, append your HEC credential as a query param
    min_severity: "warn"
```

### Webhook to n8n

The simplest path if you're self-hosting. n8n accepts raw JSON webhooks
with no auth transformation needed:

```yaml
emit:
  webhook:
    url: "https://n8n.example.com/webhook/pipelock-events"
    min_severity: "warn"
```

In n8n, create a Webhook node that receives POST requests. From there, route
to any destination: Slack, PagerDuty, Grafana OnCall, a database, or trigger
the kill switch API for automated response.

### Webhook to Microsoft Sentinel

Use an Azure Logic App or Function App as the webhook receiver, then ingest
into a custom Log Analytics table:

```yaml
emit:
  webhook:
    url: "https://your-logic-app.azurewebsites.net/api/pipelock"
    auth_token: "function-key-here"
    min_severity: "warn"
```

### Syslog to rsyslog / syslog-ng

```yaml
emit:
  syslog:
    address: "udp://syslog.example.com:514"
    facility: "local0"
    tag: "pipelock"
    min_severity: "warn"
```

On the receiver, filter by program name:

```conf
# rsyslog
if $programname == 'pipelock' then /var/log/pipelock.log
& stop

# syslog-ng
filter f_pipelock { program("pipelock"); };
destination d_pipelock { file("/var/log/pipelock.log"); };
log { source(s_network); filter(f_pipelock); destination(d_pipelock); };
```

### Syslog to Elasticsearch (via Logstash)

```conf
# logstash.conf
input {
  syslog {
    port => 514
    type => "pipelock"
  }
}

filter {
  if [type] == "pipelock" {
    json {
      source => "message"
      target => "pipelock"
    }
    date {
      match => [ "[pipelock][timestamp]", "ISO8601" ]
    }
    mutate {
      add_field => {
        "event.severity" => "%{[pipelock][severity]}"
        "event.type" => "%{[pipelock][type]}"
        "event.instance" => "%{[pipelock][pipelock_instance]}"
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["https://es.example.com:9200"]
    index => "pipelock-%{+YYYY.MM.dd}"
  }
}
```

## Detection Rules

### Splunk (SPL)

All blocked requests in the last hour:

```spl
index=pipelock severity="warn" type="blocked"
| stats count by fields.scanner, fields.reason
| sort -count
```

DLP exfiltration attempts:

```spl
index=pipelock type="blocked" fields.scanner="dlp"
| table _time, fields.client_ip, fields.url, fields.reason
```

Kill switch activations:

```spl
index=pipelock severity="critical" type="kill_switch_deny"
| stats count by fields.source, fields.deny_message
```

High anomaly scores (behavioral profiling):

```spl
index=pipelock type IN ("anomaly", "session_anomaly") fields.score>0.7
| timechart span=5m count by type
```

Adaptive escalation to block (agent misbehaving):

```spl
index=pipelock type="adaptive_escalation" fields.to="block"
| table _time, fields.session, fields.from, fields.to, fields.score
```

### Microsoft Sentinel (KQL)

All blocked requests in the last hour:

```kql
PipelockEvents_CL
| where severity_s == "warn" and type_s == "blocked"
| summarize count() by fields_scanner_s, fields_reason_s
| sort by count_ desc
```

DLP exfiltration attempts:

```kql
PipelockEvents_CL
| where type_s == "blocked" and fields_scanner_s == "dlp"
| project TimeGenerated, fields_client_ip_s, fields_url_s, fields_reason_s
```

Kill switch activations:

```kql
PipelockEvents_CL
| where severity_s == "critical" and type_s == "kill_switch_deny"
| summarize count() by fields_source_s, fields_deny_message_s
```

Anomaly score trending:

```kql
PipelockEvents_CL
| where type_s in ("anomaly", "session_anomaly")
| where todouble(fields_score_s) > 0.7
| summarize count() by bin(TimeGenerated, 5m), type_s
| render timechart
```

### Elasticsearch (EQL / KQL)

Blocked requests (Kibana KQL):

```kql
pipelock.severity: "warn" AND pipelock.type: "blocked"
```

DLP exfiltration:

```kql
pipelock.type: "blocked" AND pipelock.fields.scanner: "dlp"
```

Kill switch events:

```kql
pipelock.severity: "critical" AND pipelock.type: "kill_switch_deny"
```

EQL sequence: blocked request followed by kill switch within 60 seconds:

```eql
sequence by pipelock.pipelock_instance with maxspan=60s
  [any where pipelock.type == "blocked"]
  [any where pipelock.type == "kill_switch_deny"]
```

### Grafana (LogQL / Loki)

Blocked requests rate:

```logql
sum(rate({job="pipelock"} | json | type="blocked" [5m])) by (fields_scanner)
```

> **Note:** After `| json`, nested field names depend on your Loki version's
> JSON flattening behavior. Fields like `fields.scanner` typically become
> `fields_scanner`. Verify field names in your Loki Explorer.

Critical events:

```logql
{job="pipelock"} | json | severity="critical"
```

Kill switch deny events:

```logql
{job="pipelock"} | json | type="kill_switch_deny"
```

## Automated Response: Closing the Loop

Detection without response is just logging. The real value comes from wiring
pipelock's webhook output into an automation platform that can POST back to
the kill switch API and shut the agent down.

```text
Agent violates policy
  → Pipelock blocks request + emits webhook event
    → SIEM/n8n receives event
      → Automation POSTs to kill switch API
        → Pipelock denies ALL subsequent traffic
          → Alert sent to operator
```

### Kill Switch API

The examples below use port 9090. Replace with whatever you set in
`kill_switch.api_listen`. If `api_listen` is not set, the API lives on the
main proxy port (default 8888).

**Toggle:**

```bash
# Activate kill switch
curl -X POST http://pipelock:9090/api/v1/killswitch \
  -H "Authorization: Bearer $KILL_SWITCH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"active": true}'

# Response (message field only present when configured in kill_switch.message)
{"active": true, "source": "api"}

# With a custom message configured:
{"active": true, "source": "api", "message": "Emergency shutdown by SOC"}
```

**Query status:**

```bash
curl http://pipelock:9090/api/v1/killswitch/status \
  -H "Authorization: Bearer $KILL_SWITCH_TOKEN"

# Response
{
  "active": true,
  "sources": {
    "config": false,
    "api": true,
    "signal": false,
    "sentinel": false
  }
}
```

The kill switch uses OR logic across four independent sources (config, API,
SIGUSR1 signal, sentinel file). If *any* source is active, all traffic is
denied. Deactivating one doesn't affect the others.

**Rate limiting:** `POST /api/v1/killswitch` is limited to 10 requests per
60-second window. Exceeding it returns `429` with a `Retry-After: 60` header.
`GET` status requests are not rate-limited.

**Port isolation:** When `kill_switch.api_listen` is set, the API runs on a
dedicated port that isn't exposed to the agent. This matters. Without it, a
compromised agent could call the API to deactivate its own kill switch.

### n8n Workflow Example

1. **Webhook node:** receives pipelock events at `/webhook/pipelock-events`
2. **Switch node:** route by `severity`:
   - `critical` → kill switch + PagerDuty
   - `warn` with `type == "blocked"` and `fields.scanner == "dlp"` → kill switch + Slack
   - `warn` with `type == "blocked"` → Slack only
   - other → log to database
3. **HTTP Request node:** POST to kill switch API:
   - URL: `http://pipelock-api:9090/api/v1/killswitch`
   - Auth: Bearer token
   - Body: `{"active": true}`
4. **Slack node:** post alert to `#security-alerts` channel
5. **Postgres node:** archive all events for compliance

### Alertmanager Integration

Pipelock exposes Prometheus metrics at `/metrics`. If you already run
Alertmanager, you can alert on counters directly, which is useful for events like
chain detection that aren't emitted to webhook/syslog.

A complete set of alert rules covering traffic anomalies, security events,
session profiling, and operational health is available at
[`examples/prometheus/pipelock-alerts.yaml`](../../examples/prometheus/pipelock-alerts.yaml).
Here are the three most important rules to start with:

```yaml
groups:
  - name: pipelock
    rules:
      - alert: PipelockKillSwitchActive
        expr: increase(pipelock_kill_switch_denials_total[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Kill switch denying traffic on {{ $labels.instance }}"

      - alert: PipelockChainDetection
        expr: increase(pipelock_chain_detections_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Chain attack detected on {{ $labels.instance }}"

      - alert: PipelockDown
        expr: up{job=~".*pipelock.*"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Pipelock instance {{ $labels.instance }} is down"
```

## Operational Notes

**Queue overflow.** If the webhook queue fills up (slow SIEM, network blip),
new events are dropped and `"emit: webhook queue full, event dropped"` is
logged to stderr. If you see these regularly, bump `queue_size` in the config.

**Syslog is synchronous.** Each event blocks until delivered or fails. Use UDP
for fire-and-forget, TCP if you need guaranteed delivery. Syslog is not
available on Windows.

**Multiple instances.** Set `emit.instance_id` when running more than one
pipelock instance so you can tell events apart in your SIEM. Defaults to the
OS hostname.

**Local logs vs emission.** `logging.include_allowed` and
`logging.include_blocked` only affect local log output (stderr/file). Webhook
and syslog emission is independent: security events (blocked, anomaly, error,
etc.) are always sent if they meet the severity threshold. Info-level
operational events (allowed, tunnel, WebSocket, redirect, forward) are
local-only regardless of `min_severity`.

**Auth header.** Pipelock sends `Authorization: Bearer <token>`. If your SIEM
expects a different scheme (Splunk HEC wants `Splunk <token>`), put a reverse
proxy in front or use the SIEM's raw ingestion endpoint.

## Testing Your Setup

Trigger a known block to verify events flow end-to-end:

```bash
# Send a request containing a fake AWS key. Pipelock will block and emit the event.
FAKE_KEY="AKIA""IOSFODNN7EXAMPLE"
curl -x http://localhost:8888 "https://example.com/?key=${FAKE_KEY}"
```

You should see a `blocked` event in your SIEM within a few seconds. If not,
check:

1. Is `emit.webhook.url` (or `emit.syslog.address`) reachable from the
   pipelock host?
2. Is `min_severity` set low enough? A `blocked` event is severity `warn`.
3. Check pipelock's stderr for sink errors (`emit: webhook send error: ...`).
