# pipelock init sidecar

Generate an enforced pipelock companion proxy for a Kubernetes workload.

## Synopsis

```bash
pipelock init sidecar --inject-spec <manifest>
  [--emit patch|kustomize|helm-values]
  [--output <path>]
  [--dry-run]
  [--force]
  [--image <ref>]
  [--preset strict|balanced|audit]
  [--skip-canary]
  [--skip-verify]
  [--json]
  [--agent-identity <name>]
```

## Description

`pipelock init sidecar` reads a Kubernetes workload manifest (Deployment, StatefulSet, Job, or CronJob), patches the workload to use a companion pipelock proxy Service, and emits the extra Kubernetes resources needed to enforce that topology.

The generated bundle includes:

- The patched agent workload with `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` pointing at the companion Service
- A pipelock ConfigMap with forward proxy mode enabled
- A companion pipelock Deployment with two replicas, anti-affinity, and production-oriented resource defaults
- A companion pipelock Service
- An agent NetworkPolicy that limits agent pod egress to DNS plus the pipelock proxy
- A proxy NetworkPolicy that allows agent ingress and standard web egress for the pipelock proxy pods
- A PodDisruptionBudget that keeps at least one proxy replica available during voluntary disruptions

This is not same-pod sidecar injection. The enforcement boundary comes from pod-scoped NetworkPolicies plus a separate pipelock proxy workload, not from trusting application containers to honor proxy environment variables on their own.

The command runs 7 phases: detect, generate, preview, emit, verify, canary, and summary.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--inject-spec` | (required) | Path to the Kubernetes workload manifest |
| `--emit` | `patch` | Output format: `patch`, `kustomize`, or `helm-values` |
| `--output`, `-o` | stdout for `patch`; directory required for `kustomize` and `helm-values` | Output path. **`patch` expects a file path** (multi-doc YAML stream). **`kustomize` and `helm-values` expect a directory path** (multi-file bundle: overlay, resources, values.yaml, README). Passing a `.yaml` file path to a bundle format creates a directory with that name. |
| `--dry-run` | false | Show the generated topology without writing files or running canary |
| `--force` | false | Overwrite existing output files |
| `--image` | `ghcr.io/luckypipewrench/pipelock:<version>` | Companion proxy image (tag or digest ref) |
| `--preset` | `balanced` | Config preset: `strict`, `balanced`, `audit` |
| `--skip-canary` | false | Skip the canary detection test |
| `--skip-verify` | false | Skip static topology verification |
| `--json` | false | Machine-readable JSON output (`--output` required unless `--dry-run`) |
| `--agent-identity` | `<kind>/<name>` | Default agent identity for attribution |

## Supported Workload Kinds

| Kind | Pod spec location |
|------|-------------------|
| Deployment | `spec.template.spec` |
| StatefulSet | `spec.template.spec` |
| Job | `spec.template.spec` |
| CronJob | `spec.jobTemplate.spec.template.spec` |

## Output Formats

### patch (default)

Writes the full enforced topology as multi-document YAML:

1. Patched agent workload
2. Pipelock ConfigMap
3. Pipelock Deployment
4. Pipelock Service
5. Agent NetworkPolicy
6. Pipelock NetworkPolicy
7. Pipelock PodDisruptionBudget

```bash
pipelock init sidecar --inject-spec deployment.yaml --output enforced.yaml
kubectl apply -f enforced.yaml
```

### kustomize

Writes a standalone directory with the emitted resources and `kustomization.yaml`.

Generated files:

- `agent-workload.yaml`
- `pipelock-configmap.yaml`
- `pipelock-deployment.yaml`
- `pipelock-service.yaml`
- `agent-networkpolicy.yaml`
- `pipelock-networkpolicy.yaml`
- `pipelock-pdb.yaml`
- `kustomization.yaml`

```bash
pipelock init sidecar --inject-spec deployment.yaml --emit kustomize --output ./pipelock-overlay
kubectl apply -k ./pipelock-overlay
```

### helm-values

Writes a Helm bundle directory for the pipelock chart plus the agent workload and NetworkPolicies that stay outside the chart.

Generated files:

- `values.yaml`
- `agent-workload.yaml`
- `agent-networkpolicy.yaml`
- `pipelock-networkpolicy.yaml`
- `pipelock-pdb.yaml`
- `README.txt`

```bash
pipelock init sidecar --inject-spec deployment.yaml --emit helm-values --output ./pipelock-bundle
helm upgrade --install my-agent-pipelock pipelock/pipelock -f ./pipelock-bundle/values.yaml
kubectl rollout status deployment/my-agent-pipelock
kubectl apply -f ./pipelock-bundle/pipelock-networkpolicy.yaml \
  -f ./pipelock-bundle/pipelock-pdb.yaml
kubectl apply -f ./pipelock-bundle/agent-networkpolicy.yaml
kubectl apply -f ./pipelock-bundle/agent-workload.yaml
```

## Examples

### Deployment (dry run)

```bash
pipelock init sidecar --inject-spec deployment.yaml --dry-run
```

### StatefulSet with strict preset

```bash
pipelock init sidecar --inject-spec statefulset.yaml --preset strict --output enforced.yaml
```

### Job with custom agent identity

```bash
pipelock init sidecar --inject-spec job.yaml --agent-identity ci-team/nightly-scan
```

### CronJob with kustomize output

```bash
pipelock init sidecar --inject-spec cronjob.yaml --emit kustomize --output ./overlay
```

### Machine-readable output

```bash
pipelock init sidecar --inject-spec deployment.yaml --dry-run --json
```

## Agent Identity

Requests are attributed to a default agent identity derived from the workload:

- `deployment/my-agent` for a Deployment named `my-agent`
- `statefulset/my-db` for a StatefulSet named `my-db`

Override with `--agent-identity`. The identity is written into the generated pipelock config as `default_agent_identity` and appears in audit logs, receipts, and metrics instead of `anonymous`.

The generated companion config also sets `bind_default_agent_identity: true`, which makes the deployment single-workload and operator-bound: caller-supplied `X-Pipelock-Agent` headers and `?agent=` query parameters are ignored.

Companion-mode precedence: context override (unused in this topology) > `default_agent_identity` config > `anonymous`.

## Verification

The verify phase is static. It confirms the generated topology has the expected companion resources and boundary settings:

- forward proxy mode enabled
- cluster-reachable proxy listeners
- agent NetworkPolicy allows DNS plus the pipelock proxy port only
- proxy NetworkPolicy allows agent ingress and standard web egress

The canary phase runs locally against the generated config to confirm DLP blocks a synthetic secret. It validates generated policy coverage, not the live cluster deployment.

## NetworkPolicy Semantics

The enforcement claim for this command depends on Kubernetes NetworkPolicy egress enforcement being active in your cluster. If your CNI does not enforce egress policies, the generated manifests still configure the companion proxy correctly, but the cluster will not provide the intended direct-egress boundary.

For existing workloads, roll the companion proxy out first and wait for ready endpoints before patching the agent workload. The Helm bundle output includes that order explicitly to avoid a fail-closed brownout while the proxy Deployment is still starting.

Within a cluster that enforces egress NetworkPolicies, the agent pods are limited to:

- DNS
- The pipelock companion Service on port `8888`

Direct `80/443` web egress is reserved for the pipelock companion pods, not the agent workload.

DNS egress is intentionally left unrestricted at the NetworkPolicy layer for cluster portability. This command does not block DNS tunneling by policy alone.

## Idempotency

Running `pipelock init sidecar` against a manifest already managed by this command is safe. The workload annotations preserve the generated proxy identity, the command reports the manifest as already patched, and verification can still be rerun against the derived topology.
