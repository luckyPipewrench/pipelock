# pipelock init sidecar

Inject a pipelock sidecar proxy into a Kubernetes workload manifest.

## Synopsis

```
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

Reads a Kubernetes workload manifest (Deployment, StatefulSet, Job, or CronJob), detects the pod spec, and generates a sidecar injection patch that routes all container egress through pipelock.

The patched manifest includes:

- A `pipelock` sidecar container with health probes, resource limits, and a read-only security context
- `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment variables on existing containers
- A shared `pipelock-config` volume backed by a ConfigMap
- A pod-scoped `NetworkPolicy` that allows DNS and standard web egress for the injected sidecar

The command runs 7 phases: detect, generate, preview, emit, verify, canary, and summary.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--inject-spec` | (required) | Path to the Kubernetes workload manifest |
| `--emit` | `patch` | Output format: `patch`, `kustomize`, or `helm-values` |
| `--output`, `-o` | stdout | Output path (file or directory for kustomize) |
| `--dry-run` | false | Show diff without writing files or running canary |
| `--force` | false | Overwrite existing output files |
| `--image` | `ghcr.io/luckypipewrench/pipelock:<version>` | Sidecar container image (tag or digest ref) |
| `--preset` | `balanced` | Config preset: `strict`, `balanced`, `audit` |
| `--skip-canary` | false | Skip the canary detection test |
| `--skip-verify` | false | Skip post-apply sidecar verification |
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

Writes the full patched manifest as multi-document YAML: the workload, a ConfigMap, and a NetworkPolicy.

```bash
pipelock init sidecar --inject-spec deployment.yaml --output patched.yaml
kubectl apply -f patched.yaml
```

### kustomize

Writes a standalone directory containing the original workload manifest, the sidecar patch, ConfigMap, NetworkPolicy, and `kustomization.yaml`.

```bash
pipelock init sidecar --inject-spec deployment.yaml --emit kustomize --output ./pipelock-overlay
kubectl apply -k ./pipelock-overlay
```

### helm-values

Writes a `values.yaml` fragment targeting the pipelock Helm chart.

```bash
pipelock init sidecar --inject-spec deployment.yaml --emit helm-values --output values-pipelock.yaml
helm upgrade --install pipelock pipelock/pipelock -f values-pipelock.yaml
```

## Examples

### Deployment (dry run)

```bash
pipelock init sidecar --inject-spec deployment.yaml --dry-run
```

### StatefulSet with strict preset

```bash
pipelock init sidecar --inject-spec statefulset.yaml --preset strict --output patched.yaml
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

In sidecar mode, requests are attributed to a default agent identity derived from the workload:

- `deployment/my-agent` for a Deployment named `my-agent`
- `statefulset/my-db` for a StatefulSet named `my-db`

Override with `--agent-identity`. The identity is written to the generated ConfigMap as `default_agent_identity` and appears in audit logs, receipts, and metrics instead of `anonymous`.

Resolution precedence: `X-Pipelock-Agent` header > `?agent=` query param > `default_agent_identity` config > `anonymous`.

## NetworkPolicy Semantics

The generated `NetworkPolicy` is pod-scoped because Kubernetes policies apply to pods, not individual containers. That means it cannot enforce "app container may only talk to the sidecar" inside the same pod. Instead, the generated policy keeps sidecar mode functional by allowing DNS plus standard web egress for the selected workload pods.

## Idempotency

Running `pipelock init sidecar` against a manifest that already has a `pipelock` sidecar container produces no changes. The command detects the existing container and reports "already patched".
