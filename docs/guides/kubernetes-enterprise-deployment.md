<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Kubernetes Enterprise Deployment: Conductor Fleet

Deploy a [Conductor](conductor.md)-managed Pipelock fleet on Kubernetes with the
[Helm chart](../../charts/pipelock/README.md). One chart renders all three
topologies via `mode`: the Conductor control plane, follower proxies, and an
optional standalone fleet-sink. This guide is the narrative around the chart's
[example values files](../../charts/pipelock/examples/); the chart README holds
the full key reference.

Everything here is Enterprise-tier: the server commands verify a license
granting the `fleet` feature and fail closed without it. See
[`pipelock license`](../cli/license.md).

## Topology

```text
agent workloads ──egress──▶ followers (mode: proxy, conductorFollower.enabled)
                                 │  mTLS :8895
                                 ▼
                            Conductor (mode: conductor)
                            policy bundles · audit sink · remote kill
```

- **Conductor** runs in its own namespace (for example `pipelock-control`) with
  a PVC for policy and audit state.
- **Followers** are ordinary Pipelock proxies (`mode: proxy`) that agents
  egress through; `conductorFollower.enabled: true` adds the Conductor polling,
  remote-kill, and audit-batch wiring. Followers enforce locally and keep
  enforcing if Conductor is unreachable.
- **Fleet-sink** (`mode: fleetSink`) is optional: the standalone audit-ingest
  server, for operators who collect evidence separately from the control plane.

## What you provision out of band

The chart references **existing Secrets only** — it never templates key
material as plaintext values. Create these with your secret manager before
installing:

| Secret | Used by | Contents |
|---|---|---|
| Enterprise license token (+ optional signed CRL) | all modes | `license.token`, `license.crl` |
| Conductor server TLS | Conductor | `tls.crt` / `tls.key` |
| Follower client CA bundle | Conductor | CA that signed follower client certs |
| Follower client certs | each follower | Kubernetes TLS Secret; the certificate carries the follower's SPIFFE URI SAN, which **is** its fleet identity |
| Conductor server CA | followers | CA to verify Conductor's server cert |
| Signed trust roster | followers | `trust-roster.json` plus its root fingerprint pin |
| Trusted audit / control public keys | Conductor | follower audit signing keys (org-bound) and purpose-scoped emergency control keys |
| Operator bearer tokens | Conductor / sink | publisher, auditor, admin, reader tokens (file-mounted, never flags) |
| Follower recorder signing key | each follower | Ed25519 key for signed evidence (`pipelock keygen recorder`) |

For a working local reference of all of this material end to end, run
[`pipelock conductor bootstrap`](conductor.md#trying-it-locally-pipelock-conductor-bootstrap)
on a workstation — it generates a complete dev fleet (CA, SPIFFE certs, roster,
keys, tokens, license) and proves the round trip. Bootstrap is for evaluation,
not production.

## Install Conductor

```bash
helm install pipelock-conductor ./charts/pipelock \
  -f charts/pipelock/examples/values-enterprise-conductor.yaml
```

The example pins `mode: conductor`, wires the TLS/token/trust-key Secrets,
sizes the state PVC, and ships a restricted NetworkPolicy that admits only
labeled followers (port 8895) and operators (probe port 9092). Enterprise
modes **require** `networkPolicy.enabled: true`; name your real namespaces and
pod selectors in `networkPolicy.ingress`/`egress`.

The follower API listener is TLS 1.3 with mandatory client certificates.
Health, readiness, and Prometheus metrics live on the separate plain-HTTP
probe listener.

## Install followers

```bash
helm install pipelock-follower ./charts/pipelock \
  -f charts/pipelock/examples/values-enterprise-follower.yaml
```

The example stays in `mode: proxy` and enables `conductorFollower` with the
Conductor URL, org/fleet/instance identity, trust-roster pin, mTLS Secrets, and
PVCs for the bundle cache and durable audit queue. Two requirements that are
easy to miss:

- **A follower must produce signed evidence.** Config validation rejects
  `conductor.enabled: true` unless the flight recorder is enabled with
  `sign_checkpoints: true` and a `signing_key_path`. The example mounts the
  recorder key Secret via `extraVolumes`/`extraVolumeMounts` and points
  `pipelock.flight_recorder.signing_key_path` at it.
- **The audit queue is single-writer.** Pipelock takes an advisory lock scoped
  to one host and local filesystem — not a distributed lock. Use ReadWriteOnce
  storage and one queue per pod when running multiple follower replicas.

Point agent workloads at the follower Service as their egress proxy
(`HTTPS_PROXY`), exactly as with a standalone Pipelock; see the
[deployment recipes](deployment-recipes.md) for the agent-side wiring.

## Optional: standalone fleet-sink

```bash
helm install pipelock-fleet-sink ./charts/pipelock \
  -f charts/pipelock/examples/values-enterprise-devfleet.yaml
```

`mode: fleetSink` runs `pipelock fleet-sink` with its own listener, storage
PVC, auth, and mTLS flags. A non-loopback bind requires either a client CA or
a reader token. The sink exposes `/health` but no Prometheus metrics endpoint,
so the chart rejects `podMonitor.enabled: true` in this mode.

## Verify the fleet

- Pods: liveness and readiness probes hit `/health`, backed by the subsystem
  watchdog — a wedged scanner, config, or kill switch turns the pod unready
  and gets it restarted.
- Enforcement: run [`pipelock verify-install`](../cli/verify-install.md) and
  [`pipelock doctor`](../cli/doctor.md) from an agent workload to prove
  scanning is wired and the topology is enforceable.
- Evidence: follower evidence and the sink's escrow verify **offline** with
  [`pipelock verify-receipt`](receipt-verification.md) against pinned keys —
  no trust in Conductor, the follower, or the storage layer required. The
  [Conductor operator runbook](conductor-operator-runbook.md) walks signing a
  batch and verifying it offline.

## Binary-enforced vs deployment-provided

Pipelock enforces the license gate, mTLS client-certificate verification,
signature/skew/fork checks, fail-closed config validation, and the emergency
validity-window caps. You provide and protect the PKI, the Secrets, the
NetworkPolicies, and — critically — the guarantee that agent workloads have no
egress path around their follower. The chart makes complete mediation
deployable; mediation completeness remains deployment-enforced.

## See also

- [Conductor guide](conductor.md) — architecture, planes, licensing, flags
- [Conductor operator runbook](conductor-operator-runbook.md) — hands-on local walkthrough
- [Helm chart README](../../charts/pipelock/README.md) — full values reference
- [Configuration reference: Conductor follower](../configuration.md#conductor-follower-v27-enterprise)
- [Tier-gating audit matrix](../security/tier-gating-audit-matrix.md)
