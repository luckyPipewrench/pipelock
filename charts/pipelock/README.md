# Pipelock Helm chart

Pipelock is an agent firewall: a network proxy that sits between AI agents and the internet and scans every HTTP, WebSocket, and MCP message for credential leaks, prompt injection, SSRF, and tool poisoning. This chart deploys the proxy by default and also supports Enterprise Conductor, standalone fleet-sink, and Conductor follower topologies.

## TL;DR

```bash
helm install pipelock ./charts/pipelock
```

Pipelock runs as a non-root container with a read-only root filesystem, drops all Linux capabilities, and binds the standard Pipelock proxy on port 8888.

Enterprise examples:

```bash
helm install pipelock-conductor ./charts/pipelock -f charts/pipelock/examples/values-enterprise-conductor.yaml
helm install pipelock-follower ./charts/pipelock -f charts/pipelock/examples/values-enterprise-follower.yaml
helm install pipelock-fleet-sink ./charts/pipelock -f charts/pipelock/examples/values-enterprise-devfleet.yaml
```

## Values

The chart is configured by passing values to `helm install -f values.yaml`. The most commonly used values are listed below. See [`values.yaml`](values.yaml) for the full set.

### Image

| Key | Default | Description |
|---|---|---|
| `image.repository` | `ghcr.io/luckypipewrench/pipelock` | Image repository |
| `image.tag` | `""` | Tag used when `image.digest` is empty. Falls through to `.Chart.AppVersion` if also empty. |
| `image.digest` | `""` | Optional multi-arch manifest digest. When set, the chart renders `repository@digest` for pinning |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |

> **Upgrading from chart 0.2.0:** the default `image.digest` was cleared, so the chart now follows `.Chart.AppVersion` by default instead of a pinned digest. Set `image.digest` explicitly in your values if you need an immutable image reference.

### Ports

| Key | Default | Description |
|---|---|---|
| `service.port` | `8888` | Main proxy port (HTTP, MCP, fetch, WebSocket) |
| `service.mcpPort` | `8889` | MCP HTTP listener port. Only opened when `mcp.enabled=true` and `mcp.upstream` is set. |
| `service.metricsPort` | `9091` | Prometheus metrics |
| `service.adminPort` | `9090` | Authenticated admin API (`pipelock adaptive`, `pipelock session`). Only opened when `adminApi.enabled=true`. |

### Deployment mode

| Key | Default | Description |
|---|---|---|
| `mode` | `proxy` | Topology to render: `proxy`, `conductor`, or `fleetSink` |
| `conductorFollower.enabled` | `false` | Enables follower-side Conductor polling/audit wiring while staying in `mode: proxy` |

The default `proxy` mode runs `pipelock run`. `conductor` mode runs the verified Enterprise entrypoint `pipelock conductor serve` with separate follower mTLS and probe Services. `fleetSink` mode runs the standalone `pipelock fleet-sink` server; it is intentionally separate because the binary exposes independent listener, storage, auth, and mTLS flags.

### Health probes

Liveness and readiness probes hit `/health`, backed by the subsystem watchdog. The endpoint returns 503 when scanner, config, kill switch, session, or watchdog liveness fails — Kubernetes will restart the pod automatically.

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

Enterprise server modes use the license Secret as `PIPELOCK_LICENSE_KEY` because the current server commands do not accept a license-file flag. Conductor publisher, auditor, admin, reader, TLS, mTLS, trust roster, and CRL inputs are mounted as Secret files and never templated as plaintext values.

### Enterprise Conductor

| Key | Default | Description |
|---|---|---|
| `conductor.service.port` | `8895` | Follower mTLS API listener |
| `conductor.service.probePort` | `9092` | Plain HTTP health/readiness/metrics probe listener |
| `conductor.tls.serverSecretRef.name` | `""` | Existing TLS Secret with `tls.crt` and `tls.key` |
| `conductor.tls.clientCASecretRef.name` | `""` | Existing Secret with the follower client CA bundle |
| `conductor.tokens.publisher.secretRef.name` | `""` | Existing Secret for publisher bearer token file |
| `conductor.tokens.auditor.secretRef.name` | `""` | Existing Secret for auditor bearer token file |
| `conductor.tokens.admin.secretRef.name` | `""` | Existing Secret for admin bearer token file |
| `conductor.persistence.size` | `20Gi` | PVC size for policy and audit state |

### Enterprise follower

| Key | Default | Description |
|---|---|---|
| `conductorFollower.conductorURL` | `""` | HTTPS URL of the Conductor follower API |
| `conductorFollower.serverCASecretRef.name` | `""` | Existing Secret containing the Conductor server CA |
| `conductorFollower.clientSecretRef.name` | `""` | Existing Kubernetes TLS Secret for follower mTLS client identity; must contain `tls.crt` and `tls.key`, mounted at `client_cert_path` and `client_key_path` |
| `conductorFollower.trustRosterSecretRef.name` | `""` | Existing Secret containing the signed trust roster |
| `conductorFollower.persistence.bundleCache.enabled` | `false` | PVC for signed policy bundle cache |
| `conductorFollower.persistence.auditQueue.enabled` | `false` | PVC for durable audit queue |

### Fleet sink

| Key | Default | Description |
|---|---|---|
| `fleetSink.service.port` | `8894` | Audit sink listener |
| `fleetSink.service.probePort` | `9093` | Plain HTTP health probe listener |
| `fleetSink.tls.serverSecretRef.name` | `""` | Existing TLS Secret with `tls.crt` and `tls.key` |
| `fleetSink.tls.clientCASecretRef.name` | `""` | Existing Secret with follower client CA bundle |
| `fleetSink.readerToken.secretRef.name` | `""` | Existing Secret for audit query reader token file |
| `fleetSink.persistence.size` | `20Gi` | PVC size for audit store |

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
| `networkPolicy.preset` | `dev` | Preset: `dev`, `restricted`, or `airgapped` |
| `networkPolicy.ingress` | `[]` | Full Kubernetes ingress rules override |
| `networkPolicy.egress` | `[]` | Full Kubernetes egress rules override |

Enterprise modes require `networkPolicy.enabled=true`. Use `networkPolicy.ingress` and `networkPolicy.egress` to name the allowed namespaces and pod selectors for followers, operators, DNS, KMS/HSM signing, and other deployment-local dependencies. The chart makes complete mediation deployable, but mediation completeness remains deployment-enforced: agents must not have a path around their local Pipelock follower.

`podMonitor.enabled` is supported for proxy and Conductor modes. The standalone fleet-sink server exposes `/health` but not a Prometheus metrics endpoint, so the chart rejects `podMonitor.enabled=true` in `mode: fleetSink`.

### High availability

| Key | Default | Description |
|---|---|---|
| `replicaCount` | `1` | Number of replicas |
| `podDisruptionBudget.enabled` | `false` | Apply a PodDisruptionBudget |
| `podDisruptionBudget.minAvailable` | `1` | Minimum replicas available during voluntary disruption |
| `topologySpreadConstraints` | `[]` | Spread replicas across zones / hosts |
| `priorityClassName` | `""` | PriorityClass for the pod |

### Pipelock configuration

The `.Values.pipelock` block is rendered into a ConfigMap as `pipelock.yaml` and mounted at `/etc/pipelock/pipelock.yaml` in `mode: proxy`. Any supported config section can be set under this key. See the [Pipelock learn guide](https://pipelab.org/learn/) for the full schema and [`values.yaml`](values.yaml) comments for common sections.

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
- `values-enterprise-conductor.yaml` — Conductor control plane with separate follower and probe Services
- `values-enterprise-follower.yaml` — Follower proxy with Conductor mTLS, trust roster, bundle cache, and durable audit queue
- `values-enterprise-devfleet.yaml` — Standalone fleet-sink development deployment

## See also

- [Pipelock docs](https://pipelab.org/learn/)
- [Audit Packet schema](https://github.com/luckyPipewrench/pipelock/tree/main/sdk/audit-packet)
- [pipelock-verifier CLI](https://github.com/luckyPipewrench/pipelock/tree/main/cmd/pipelock-verifier)
