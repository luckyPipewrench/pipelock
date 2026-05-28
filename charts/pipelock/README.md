# Pipelock Helm chart

Pipelock is an agent firewall: a network proxy that sits between AI agents and the internet and scans every HTTP, WebSocket, and MCP message for credential leaks, prompt injection, SSRF, and tool poisoning. This chart deploys Pipelock as a Kubernetes Deployment with a Service, optional PodMonitor for Prometheus, optional NetworkPolicy, and optional PodDisruptionBudget.

## TL;DR

```bash
helm install pipelock ./charts/pipelock
```

Pipelock runs as a non-root container with a read-only root filesystem, drops all Linux capabilities, and binds the standard Pipelock proxy on port 8888.

## Values

The chart is configured by passing values to `helm install -f values.yaml`. The most commonly used values are listed below. See [`values.yaml`](values.yaml) for the full set.

### Image

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/luckypipewrench/pipelock` | Image repository |
| `image.tag` | `""` | Tag used when `image.digest` is empty. Falls through to `.Chart.AppVersion` if also empty. |
| `image.digest` | v2.5.0 multi-arch manifest digest | When set, the chart renders `repository@digest` for pinning |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |

### Ports

| Key | Default | Description |
|---|---|---|
| `service.port` | `8888` | Main proxy port (HTTP, MCP, fetch, WebSocket) |
| `service.mcpPort` | `8889` | MCP HTTP listener port. Only opened when `mcp.enabled=true` and `mcp.upstream` is set. |
| `service.metricsPort` | `9091` | Prometheus metrics |
| `service.adminPort` | `9090` | Authenticated admin API (`pipelock adaptive`, `pipelock session`). Only opened when `adminApi.enabled=true`. |

### Health probes

Liveness and readiness probes hit `/health`, which v2.5 backs with a subsystem watchdog. The endpoint returns 503 when scanner, config, kill switch, session, or watchdog liveness fails — Kubernetes will restart the pod automatically.

| Key | Default | Description |
|---|---|---|
| `livenessProbe.httpGet.path` | `/health` | Probe path |
| `livenessProbe.periodSeconds` | `30` | Probe interval |
| `livenessProbe.failureThreshold` | `3` | Failures before restart |
| `readinessProbe.httpGet.path` | `/health` | Probe path |
| `readinessProbe.periodSeconds` | `10` | Probe interval |
| `readinessProbe.failureThreshold` | `2` | Failures before pod is marked unready |

### License (Pro / Enterprise)

Community installs do not need a license. Pro features (per-agent profiles, CIDR matching, budgets) require a signed token.

| Key | Default | Description |
|---|---|---|
| `license.enabled` | `false` | Mount the license token from a Secret |
| `license.existingSecret` | `""` | Name of the Kubernetes Secret holding the token |
| `license.secretKey` | `license.token` | Key within the Secret |
| `license.mountPath` | `/etc/pipelock/license` | Where the Secret is mounted in the pod |

When enabled, the chart sets `PIPELOCK_LICENSE_KEY` from the same Secret and renders `license_file` to the mounted Secret path.

### Sentry

| Key | Default | Description |
|---|---|---|
| `sentry.enabled` | `false` | Set `SENTRY_DSN` env from a Secret |
| `sentry.dsnSecretRef.name` | `""` | Secret name |
| `sentry.dsnSecretRef.key` | `dsn` | Key within the Secret |

### Admin API

| Key | Default | Description |
|---|---|---|
| `adminApi.enabled` | `false` | Open the admin port for `pipelock adaptive` / `pipelock session` |
| `adminApi.tokenSecretRef.name` | `""` | Secret holding the bearer token. Required for authentication. |
| `adminApi.tokenSecretRef.key` | `token` | Key within the Secret |

When enabled, the chart sets `kill_switch.api_listen` in the generated pipelock.yaml and sources the bearer token from `PIPELOCK_KILLSWITCH_API_TOKEN`.

### MCP sidecar

| Key | Default | Description |
|---|---|---|
| `mcp.enabled` | `false` | Run as MCP HTTP listener bridging to `mcp.upstream` |
| `mcp.upstream` | `""` | Upstream MCP server URL |
| `mcp.listen` | `0.0.0.0:8889` | Listen address inside the pod |

### Network policy

| Key | Default | Description |
|---|---|---|
| `networkPolicy.enabled` | `false` | Apply a default-deny NetworkPolicy with explicit egress for DNS, 80, and 443 |

### High availability

| Key | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Number of replicas |
| `podDisruptionBudget.enabled` | `false` | Apply a PodDisruptionBudget |
| `podDisruptionBudget.minAvailable` | `1` | Minimum replicas available during voluntary disruption |
| `topologySpreadConstraints` | `[]` | Spread replicas across zones / hosts |
| `priorityClassName` | `""` | PriorityClass for the pod |

### Pipelock configuration

The `.Values.pipelock` block is rendered into a ConfigMap as `pipelock.yaml` and mounted at `/etc/pipelock/pipelock.yaml`. Any v2.5 config section can be set under this key. See the [Pipelock learn guide](https://pipelab.org/learn/) for the full schema and [`values.yaml`](values.yaml) comments for common v2.5 sections.

The chart automatically templates these into the config and they should not be set in `.Values.pipelock`:

- `fetch_proxy.listen` (from `service.port`)
- `metrics_listen` (from `service.metricsPort`)
- `kill_switch.api_listen` (from `service.adminPort` when `adminApi.enabled`)
- `license_file` (from `license.existingSecret`)

## Examples

See [`examples/`](examples/) for ready-to-use values configurations:

- `values-pro.yaml` — Licensed per-agent profile example with optional admin API and Sentry Secret wiring
- `values-mcp-sidecar.yaml` — MCP HTTP listener bridging to an upstream MCP server
- `values-ha.yaml` — 3 replicas, PodDisruptionBudget, topology spread, NetworkPolicy

## See also

- [Pipelock docs](https://pipelab.org/learn/)
- [Audit Packet schema](https://github.com/luckyPipewrench/pipelock/tree/main/sdk/audit-packet)
- [pipelock-verifier CLI](https://github.com/luckyPipewrench/pipelock/tree/main/cmd/pipelock-verifier)
