<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Enterprise Sale Gap Checklist

This is a technical readiness checklist for an Enterprise buyer conversation.
It is not a contract, price sheet, or legal commitment.

## Technical Artifacts

| Artifact | Status | Owner action |
|---|---|---|
| Product threat model | Drafted in `docs/security/agent-firewall-conductor-threat-model.md` | Review for buyer-specific claims before sharing. |
| Offline-verifiable evidence explainer | Drafted in `docs/security/demonstration-over-attestation.md` | Pair with a live verifier demo. |
| Vulnerability disclosure policy | Present in `SECURITY.md` | Owner should confirm SLA language is acceptable for public commitments. |
| Conductor production runbook | Present in `docs/guides/conductor-production-runbook.md` | Run against the buyer topology before calling it proven. |
| Backup/restore runbook | Present in `docs/guides/conductor-backup-restore.md` | Run on the target storage class before quoting an RTO/RPO. |
| Tier-gating audit matrix | Present in `docs/security/tier-gating-audit-matrix.md` | Keep current when new paid surfaces ship. |

## DRAFT-FOR-OWNER Business Items

| Item | Draft stance | Owner decision needed |
|---|---|---|
| Support tiers | DRAFT: define named tiers with response targets, channels, and escalation path. | Pick actual tier names and staffing coverage. |
| SLA targets | DRAFT: do not promise uptime or response windows beyond `SECURITY.md` without operational capacity. | Legal/business approval. |
| License terms | DRAFT: point to the applicable commercial agreement; do not encode legal terms in docs. | Counsel-approved contract. |
| Pricing | DRAFT: custom Enterprise pricing, not committed in repo docs. | Owner-approved quote process. |
| Security questionnaire | DRAFT: answer from shipped controls and evidence only; mark deployment-dependent controls as deployment-dependent. | Buyer-specific review. |
| Data processing | DRAFT: Pipelock can run locally; any hosted/support data flow needs a separate data-processing statement. | Counsel/privacy review. |

## Do Not Promise Without Proof

- Fleet scale above the latest load proof.
- RTO/RPO before running restore on the buyer's storage class.
- Complete egress mediation unless the deployment blocks direct egress around
  Pipelock.
- Legal, compliance, or pricing commitments not approved by the owner.
