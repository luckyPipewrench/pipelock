<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Agent Firewall And Conductor Threat Model

## Assets

- Agent secrets and workspace data
- Pipelock policy configuration and rule bundles
- Conductor policy bundles, stream heads, rollback authorizations, and remote
  kill messages
- Follower enrollment records and audit-signing public keys
- Signed receipts, audit batches, and fleet reports
- Operator signing keys, TLS keys, and license tokens

## Trust Boundaries

| Boundary | Enforced by Pipelock? | Notes |
|---|---:|---|
| Agent traffic routed through Pipelock | Yes | URL, body, header, WebSocket, and MCP scanning apply to mediated traffic. |
| Direct agent egress around Pipelock | Deployment-dependent | Use OS/container/network controls to prevent bypass. |
| Follower to Conductor identity | Yes plus deployment PKI | Conductor derives follower identity from mTLS SPIFFE URI SANs. |
| Operator to Conductor API | Yes | mTLS plus bearer token role checks. |
| Policy/emergency message authenticity | Yes | Ed25519 signatures and purpose-bound keys. |
| Signing-key custody | Deployment-dependent | Store operator keys in KMS/HSM/Secrets outside the Conductor storage backup. |

## Primary Threats And Controls

| Threat | Control |
|---|---|
| Credential exfiltration through mediated traffic | DLP, provider-key detection, env leak scanning, body/header/MCP input scanning. |
| Prompt injection in fetched/tool content | Response scanning and MCP tool/result scanning. |
| SSRF to metadata/private networks | URL scanner SSRF layer after DLP/blocklist pre-resolution checks. |
| Malicious or stale policy bundle | Signed bundle verification, payload hash, lineage checks, and not-before skew bounded by `MessageNotBeforeSkew`. |
| Fleet-wide emergency-control forgery | Purpose-bound Ed25519 threshold keys for remote kill and rollback. |
| Revoked follower evidence accepted after decommission | Enrollment-store audit-key resolver; `conductor follower remove` deletes the active enrollment so future evidence fails signature-key resolution. |
| Rollback of license revocation state | Signed CRL generation high-water and monotonic recovery path. |
| Conductor storage loss | Offline backup/restore of storage state plus separate secret/KMS restore for private keys. |

## Residual Deployment Responsibilities

- Block direct egress around Pipelock.
- Protect TLS private keys, operator signing keys, license tokens, and backup
  destinations.
- Run Conductor backup from a stopped service or crash-consistent volume
  snapshot.
- Rotate and revoke operator credentials through the deployment's PKI/KMS
  process.
- Prove fleet scale and restore behavior on the target platform before quoting
  production RTO/RPO.
