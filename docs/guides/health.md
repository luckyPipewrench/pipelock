# Health Endpoint and Wedge-Detection Watchdog

The `/health` endpoint reports whether pipelock's main HTTP server is responsive AND whether its internal subsystems are healthy. External supervisors — Kubernetes liveness/readiness probes, KiloClaw's controller, generic process supervisors — poll `/health` to decide when to restart pipelock or route traffic away from it.

Before v2.4, `/health` returned 200 as long as the HTTP handler itself responded. A scanner deadlock, config-reload race, or dead session-manager goroutine would not surface here: the process looked healthy from outside while customer traffic failed inside. v2.4 introduces an internal wedge-detection watchdog that flips `/health` to **503 Service Unavailable** when any tracked subsystem is unhealthy.

## Response Shape

```http
GET /health
```

Healthy response (HTTP 200):

```json
{
  "status": "healthy",
  "version": "v2.4.0",
  "mode": "balanced",
  "uptime_seconds": 1234.56,
  "dlp_patterns": 78,
  "response_scan_enabled": true,
  "git_protection_enabled": false,
  "rate_limit_enabled": true,
  "forward_proxy_enabled": true,
  "websocket_proxy_enabled": false,
  "request_body_scan_enabled": true,
  "tls_interception_enabled": false,
  "kill_switch_active": false,
  "subsystems": {
    "scanner": true,
    "config": true,
    "session": true,
    "killswitch": true,
    "watchdog": true
  }
}
```

Unhealthy response (HTTP 503):

```json
{
  "status": "unhealthy",
  "version": "v2.4.0",
  ...
  "subsystems": {
    "scanner": false,
    "config": true,
    "session": true,
    "killswitch": true,
    "watchdog": true
  }
}
```

The top-level fields (`version`, `mode`, `uptime_seconds`, the feature-enabled booleans, `kill_switch_active`) keep their pre-v2.4 shape so existing consumers parse cleanly. The new field is `subsystems` — a map of subsystem name to liveness boolean. When the watchdog is disabled the `subsystems` field is omitted entirely (legacy shape).

`status` is `"healthy"` (HTTP 200) when every value in `subsystems` is `true`; `"unhealthy"` (HTTP 503) otherwise.

## The Subsystems

| Name | Healthy when | Notes |
|------|--------------|-------|
| `scanner` | The scanner pointer and config pointer are both non-nil AND either the scanner heartbeat is fresh or a synthetic probe completes within `interval/2` | The probe scans a fail-fast scheme URL through the live scanner; it's the only subsystem that uses an active probe |
| `config` | The atomic config pointer is non-nil | Hot reload swaps the pointer atomically; a nil pointer means a reload race left the proxy unable to read config |
| `session` | Session profiling is disabled, OR the session-manager pointer is non-nil | Sessions are optional (`session_profiling.enabled`); a missing manager when expected is unhealthy |
| `killswitch` | The kill switch is disabled in config, OR the kill-switch controller is wired | The controller is independent of `kill_switch_active`: `active` reports whether traffic is currently denied; `subsystems.killswitch` reports whether the kill-switch state machine itself is reachable |
| `watchdog` | Watchdog goroutine has bumped its self-heartbeat within the staleness threshold | If the goroutine dies, `/health` flips to 503 even when other subsystems look fine |

## Detection Strategy

The watchdog uses **hybrid passive + active** detection.

- **Passive scanner heartbeats** are the cheap normal-path signal. Each `Scan()` completion bumps an `atomic.Int64` timestamp. One atomic store per scan; effectively free at scan-rate.
- **Bounded synthetic probe** runs only when the scanner heartbeat is stale. The watchdog asks the live scanner to scan a fail-fast scheme URL (`ftp://wedge-probe.invalid/`) under an `interval/2` deadline. A timeout means scanner is wedged. On success, the heartbeat is refreshed so subsequent `/health` calls don't re-pay the probe cost until the heartbeat ages out again.
- **Structural presence checks** cover config, session, and kill switch state. Optional subsystems report healthy when disabled; enabled subsystems report unhealthy if their live pointer/controller is missing.

Idle systems do not flag false positives. If no traffic has reached the scanner for several intervals — common in dev or low-volume agents — the heartbeat ages out, the probe runs, the scanner answers immediately, the heartbeat re-seeds, and `/health` stays 200. The probe path only surfaces a wedge when the scanner cannot complete a trivial scan within `interval/2`.

The watchdog goroutine itself is intentionally minimal: a ticker that stores `time.Now()` into one atomic on each tick. If it dies (panic, runtime crash), its self-heartbeat goes stale and `/health` flips to 503 even when every other subsystem looks fine.

## Configuration

```yaml
health_watchdog:
  enabled: true            # default: true
  interval_seconds: 2      # default: 2; staleness threshold = 3 × interval
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Turn the watchdog off to restore pre-v2.4 `/health` behavior (no `subsystems` map, always 200). Operators rarely want this off. |
| `interval_seconds` | `2` | Self-beat tick rate. The staleness threshold (when the watchdog declares a heartbeat stale) is derived as 3 × interval, so the default 2s gives a 6s window. |

If `health_watchdog` is omitted entirely from the YAML, the section defaults to `enabled: true, interval_seconds: 2` (fail-open for the watchdog: an operator who omits the section still gets wedge protection). YAML `null`/blank for the section or for `enabled` is treated as omitted.

**Hot reload note.** Watchdog settings are immutable across hot reload in v2.4 — restarting pipelock is required to change the interval. The settings are purely operational and do not affect the canonical policy hash, so toggling them does not rotate `ph` for downstream verifiers.

## Polling Contract for External Watchdogs

Pipelock's wedge-detection design assumes an **external supervisor** to act on the 503 signal. A wedged process cannot reliably restart itself; the watchdog provides the diagnostic, the supervisor performs the action.

Recommended polling pattern:

```yaml
# Kubernetes liveness/readiness probe
livenessProbe:
  httpGet:
    path: /health
    port: 8888
  periodSeconds: 5            # ≥ interval_seconds
  failureThreshold: 3         # restart after ~15s of consecutive 503s
  timeoutSeconds: 2
```

The `failureThreshold` × `periodSeconds` budget should be larger than the staleness threshold (3 × `interval_seconds`) so transient probe blips don't trigger restarts.

Supervisors that are not Kubernetes (KiloClaw controller, systemd, custom watchdogs) should follow the same pattern: poll every N seconds, restart after K consecutive failures, where N ≥ `interval_seconds` and N × K > 3 × `interval_seconds`.

## Disabling the Watchdog

```yaml
health_watchdog:
  enabled: false
```

The `/health` endpoint returns the pre-v2.4 shape: status always `"healthy"`, no `subsystems` map, HTTP 200 regardless of internal state. Use only when an external system already provides equivalent liveness signal and you want to silence pipelock's view.

## Relationship to `kill_switch_active`

`kill_switch_active` (top-level field) reports whether the kill switch is currently denying traffic. It is a *policy* signal — operators can flip it on/off through any of four sources (config, API, signal, sentinel file).

`subsystems.killswitch` (under the watchdog map) reports whether the kill-switch *state machine* is reachable from the proxy. A pipelock that cannot read its kill switch is wedged; one that reads it and reports "active" is fine.

External watchdogs interested in "should this instance receive traffic?" check both: `status == "healthy"` AND `kill_switch_active == false`. The first answers "is pipelock alive?", the second answers "is pipelock currently allowing traffic?".
