<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Enterprise Readiness

Pipelock can run inside an organization's own boundary: enforcement, evidence,
keys, policy, and audit storage do not require a Pipelab-hosted control plane.
This page gives security reviewers and platform teams a practical map of the
shipped enterprise surfaces and the responsibilities that remain with the
deployment.

It is a technical readiness guide, not a certification, uptime commitment,
support contract, or data-processing agreement.

## What Ships

| Area | Shipped surface | Start here |
|---|---|---|
| Boundary enforcement | HTTP, WebSocket, MCP, A2A, sandbox, host containment, Kubernetes topology, kill switch | [Deployment recipes](guides/deployment-recipes.md), [transport modes](guides/transport-modes.md) |
| Fleet control | Signed policy distribution, mTLS follower enrollment, remote kill, rollback, dry-run, replay, drift and applied-state reporting | [Conductor](guides/conductor.md), [production runbook](guides/conductor-production-runbook.md) |
| Identity and access | Dashboard token, OIDC, or mTLS authentication; bounded read permissions and separate raw-evidence elevation | [Dashboard](cli/dashboard.md) |
| Verifiable evidence | Signed action receipts, EvidenceReceipt v2, hash chains, checkpoints, coverage certificates, Audit Packets, offline verifiers | [Receipt verification](guides/receipt-verification.md), [security assurance](security-assurance.md) |
| Key lifecycle | Purpose-bound signing keys, trusted rosters, rotation, revocation, recovery, and trust-key inspection | [Key rotation](security/key-rotation-runbook.md), [keys CLI](cli/keys.md) |
| Audit integration | JSON logs, durable Enterprise forwarding, webhook, syslog, CEF, OTLP, Prometheus, Grafana | [SIEM integration](guides/siem-integration.md), [metrics](metrics.md) |
| Operations | Health/readiness probes, support bundle, backup/restore, retention controls, legal-hold metadata, incident and fleet views | [Support bundle](cli/support.md), [Conductor backup/restore](guides/conductor-backup-restore.md) |
| Software supply chain | Signed releases, checksums, provenance attestations, SBOMs, vulnerability scanning, reproducible OSS build check | [Install verification](cli/verify-install.md), [reproducible builds](reproducible-builds.md) |

## Evaluation Path

An evaluation should prove behavior on the buyer's intended topology, not only
show a dashboard:

1. Run `pipelock demo --receipts-dir ./out` and verify one receipt with the
   generated public key.
2. Run `pipelock check`, `pipelock doctor`, and `pipelock audit score` against
   the candidate configuration.
3. Use `pipelock contain verify` or the Kubernetes deployment proof appropriate
   to the topology to show whether direct egress is actually blocked.
4. Exercise the exact HTTP, WebSocket, MCP, A2A, and TLS visibility paths the
   deployment will claim.
5. Run `pipelock conductor bootstrap` in an isolated evaluation environment to
   prove enrollment, signed audit ingest, query, and offline verification.
6. Restore a Conductor backup on the buyer's storage class before agreeing to an
   RTO or RPO.
7. Export a secret-redacted `pipelock support bundle`, review it manually, and
   confirm the organization's support-data handling process.

The [security assessment mapping](compliance/assess-mapping.md) connects
deployment evidence to common frameworks without claiming certification.

## Deployment Review

| Question | Required enterprise decision |
|---|---|
| Which process or network control prevents direct agent egress? | Select and test host containment, separate users, container controls, NetworkPolicy, or an equivalent boundary. |
| Which transports expose payload content? | Decide where TLS interception is permitted and document CONNECT passthrough as metadata-only. |
| Who controls signing and trust keys? | Define creation, storage, rotation, revocation, recovery, and relying-party distribution. |
| Which identity provider protects the dashboard? | Configure OIDC or mTLS role mapping; reserve raw-evidence permission for a narrower group. |
| How are Conductor write operations authorized? | Protect deployment PKI and publisher/admin role tokens; dashboard OIDC does not automatically govern Conductor mutation APIs. |
| Where is evidence stored and for how long? | Set retention, legal hold, storage encryption, backup encryption, deletion, and access policy. |
| Which events must reach the SIEM? | Choose sinks, alert thresholds, queue/drop monitoring, and an outage procedure. |
| What is the availability target? | Prove replica, storage, failover, restore, and upgrade behavior on the intended platform before committing to an SLO. |
| What leaves the customer's environment? | Pipelock can run locally; any hosted service or support exchange needs its own approved data-flow and privacy terms. |

## Current Boundaries

These are explicit boundaries, not hidden footnotes:

- Complete mediation is a deployment property. Installing the binary beside an
  unrestricted process does not block that process from opening another socket.
- The dashboard supports OIDC, but Conductor's mutating operator APIs currently
  use deployment mTLS plus file-backed role tokens rather than SCIM-managed
  workforce identity.
- Local Conductor and fleet-sink evidence uses filesystem and SQLite storage.
  Pipelock does not provide universal application-layer encryption at rest; use
  encrypted volumes, restricted service identities, and protected backups.
- Retention controls prune the configured store. Organization-wide retention,
  deletion, litigation hold, and privacy policy remain operator responsibilities.
- The repository does not promise multi-region high availability, a fleet-size
  ceiling, RTO, RPO, or support response outside a separate proved deployment
  and commercial commitment.
- Signed receipts prove integrity and signer binding for supplied records, not
  completeness against the key holder or traffic outside the mediated boundary.

## Review Material

- [Security assurance case](security-assurance.md)
- [Product and Conductor threat model](security/agent-firewall-conductor-threat-model.md)
- [Evidence hard limits](evidence/hard-limits.md)
- [Current unsupported paths](security/current-unsupported-paths.md)
- [Vulnerability policy](../SECURITY.md)
- [Tier-gating audit matrix](security/tier-gating-audit-matrix.md)
- [Compliance mappings](compliance/)

Security questionnaires should cite the shipped control and its verification
path, then mark deployment-dependent controls as deployment-dependent. Claims
about certification, support, pricing, legal terms, data processing, fleet
scale, or availability require separate owner-approved evidence.
