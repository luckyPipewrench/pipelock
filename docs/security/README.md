# Pipelock security documents

This directory holds policy and threat-model documents that integrators and procurement reviewers ask for as standalone files. Each document is independent prose and can be read on its own.

| Document | Purpose |
|---|---|
| [current-unsupported-paths.md](current-unsupported-paths.md) | Egress paths the current binary does not intercept. Integrator action required for each. |
| [browser-shield-production-readiness.md](browser-shield-production-readiness.md) | Browser Shield boundary, receipt behavior, adaptive signal, and anti-bot non-goals. |
| [key-rotation-runbook.md](key-rotation-runbook.md) | Operational procedure for rotating Ed25519 signing keys without breaking the live-lock roster. |
| [provider-key-dlp-coverage.md](provider-key-dlp-coverage.md) | Built-in AI provider-key DLP coverage, exclusions, and the custom provider-key configuration path. |
| [coordinated-disclosure.md](coordinated-disclosure.md) | Vulnerability disclosure policy, response SLA, embargo handling, and CVE process. |
| [per-deployment-ca-threat-model.md](per-deployment-ca-threat-model.md) | Threat model for the per-deployment TLS interception CA, including snapshot-restoration and root-compromise blast radius. |
| [audit-packet-threat-model.md](audit-packet-threat-model.md) | Threat model for the Audit Packet evidence bundle. What a verified packet proves, what it does not prove, and the trust assumptions a relying party should pin before treating a `valid` verdict as provenance. |

These documents describe what the current binary enforces today. Behaviour planned for later versions is tracked in the project roadmap and is out of scope here.

## See also

- [SECURITY.md](../../SECURITY.md): reporting channel and supported versions
- [CHARTER.md](../../CHARTER.md): project governance, disclosure SLA source
- [README.md](../../README.md): supported transports and scanner layers
