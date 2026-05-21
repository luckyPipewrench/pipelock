# Assess Mapping: Pipelock vs Industry & Regulatory Frameworks

This document maps Pipelock's runtime security controls to the frameworks the `pipelock assess` command produces evidence against. It is intended for procurement, audit, and buyer-side review.

**Scope.** Pipelock is an open-source agent firewall. It mediates HTTP, WebSocket, MCP, and tool-execution traffic at the deployment boundary. It does not cover model training, organizational policy, workforce administration, or contractual instruments (BAAs, DPIAs). Where a control depends on those, the mapping says so.

**Disclaimer.** This document maps Pipelock's features against framework requirements for informational purposes. It does not constitute legal advice or guarantee regulatory compliance. Each organization must evaluate its own obligations with qualified counsel.

**Evidence source.** Run `pipelock assess` against your deployment to produce a signed, scored evidence bundle. The bundle's compliance annex reports the same control mappings documented here. The status of each control (`covered` / `partial` / `not_covered`) reflects what Pipelock as a product supports, not whether the specific feature is enabled in your `pipelock.yaml`; the surrounding `Config Posture` section grades the per-deployment configuration separately. Per-control runtime gating (downgrading a control's status when its underlying feature is disabled) is tracked as a follow-up.

## Framework set

`pipelock assess` produces evidence for these seven frameworks, in the order they render in the report:

| # | Framework | Purpose | Detailed mapping |
|---|-----------|---------|------------------|
| 1 | OWASP MCP Top 10 | MCP-specific attack patterns and mitigations | [owasp-mcp-top10.md](owasp-mcp-top10.md) |
| 2 | OWASP Agentic Top 10 | Agent-level attack patterns and mitigations | (mapping in source: `internal/report/compliance/owasp_agentic.go`) |
| 3 | MITRE ATLAS | Adversarial ML attack technique taxonomy | (mapping in source: `internal/report/compliance/atlas.go`) |
| 4 | EU AI Act | EU regulatory requirements for high-risk AI systems | [eu-ai-act-mapping.md](eu-ai-act-mapping.md) |
| 5 | NIST AI RMF | NIST AI Risk Management Framework 1.0 + GenAI Profile | (mapping in source: `internal/report/compliance/nist_ai_rmf.go`) |
| 6 | HIPAA Security Rule | 45 CFR 164 technical + administrative safeguards | (mapping in source: `internal/report/compliance/hipaa.go`) |
| 7 | SOC 2 Trust Services Criteria | AICPA TSC for security, availability, confidentiality, integrity, privacy | (mapping in source: `internal/report/compliance/soc2.go`) |

Mappings ship inside the binary. A `pipelock assess` run produces both a summary count per framework (`N/M covered`) and a per-control annex with the specific Pipelock features that supply the evidence.

## What "covered" means here

Each control in each framework maps to one of three statuses:

- **covered.** The Pipelock feature directly implements the requirement with binary-enforced behavior. The evidence appears in the proxy's audit log and (when enabled) the flight recorder.
- **partial.** The Pipelock feature contributes to the requirement but does not satisfy it alone. Other controls (deployment, policy, third-party tooling) are required to complete the safeguard.
- **not_covered.** The control is organizational, contractual, or outside the network/tool-execution boundary. The mapping documents the limitation rather than claim implicit coverage.

Statuses are static per framework version, set in the source mapping files. Per-deployment runtime coverage (whether the feature is actually enabled) is computed at `assess` time and surfaces in the bundle's compliance annex.

## NIST AI RMF (added 2026-05)

The mapping covers five core functions (Govern, Map, Measure, Manage) plus a Generative AI overlay derived from NIST AI 600-1 (Data Privacy, Information Integrity, Provenance, Harmful Bias).

- **Covered:** Measure, Manage, GenAI Data Privacy, GenAI Information Integrity
- **Partial:** Govern, Map, GenAI Provenance
- **Not covered:** GenAI Harmful Bias (belongs upstream of network mediation)

The Govern and Map functions are partial by design: Pipelock supplies the operational artifacts (audit emissions, signed attestations, discovery output) that a risk-management program records against AI RMF outcomes, but the governance roles, RACI, and policy-approval workflow live with the operator.

## HIPAA Security Rule (added 2026-05)

The mapping covers the Technical Safeguards (164.312) that Pipelock can mediate plus selected Administrative Safeguards (164.308) it touches through evidence emission.

- **Covered:** Access Control (164.312(a)), Audit Controls (164.312(b)), Integrity (164.312(c)), Transmission Security (164.312(e)), ePHI Disclosure Prevention
- **Partial:** Person or Entity Authentication (164.312(d)), Contingency Plan (164.308(a)(7))
- **Not covered:** Business Associate Agreement, Workforce Security (164.308(a)(3))

The not-covered entries are intentional: BAA execution and workforce procedures are organizational instruments, not network controls. A buyer should treat them as honest scope, not unfilled stubs.

## Procurement use

For procurement and security questionnaires:

1. Run `pipelock assess init --config pipelock.yaml`, then `assess run` and `assess finalize --attestation --badge` against the deployment under review.
2. Share the produced `assessment.json` (paid tier) or `summary.json` (free tier) along with this document.
3. The bundle's `compliance` array reports per-framework `covered / partial / not_covered` counts for the runtime, which can be pasted directly into the response.
4. The detached attestation (`attestation.json` + `.sig`) supplies cryptographic provenance for the report, signed with the operator's Ed25519 key. Verify with `pipelock assess verify-attestation`.

## Limitations to disclose

When sharing an assessment bundle as evidence:

- Pipelock attests its own mediation, not the model's training data lineage. Upstream model provenance is out of scope for every framework above.
- The `pipelock assess` evidence bundle is signed at finalize time. The manifest itself is unsigned at `assess run` time; under threat models where `assess run` and `assess finalize` run under different principals, sign the run directory out of band between the two steps.
- Free-tier summaries redact MCP server names. The signed paid-tier assessment includes full server identity for the operator's own consumption; redact before sharing externally when sharing operator-private infrastructure detail is undesirable.

## Updating mappings

Mappings are versioned per framework via `MappingVersion`. Increment when a control's status or feature list changes. Backward-compatible additions (a new control) keep the same `MappingVersion`; status downgrades or feature removals require a bump.

To add a framework: create `internal/report/compliance/<framework>.go` returning a `Framework` value, append it to `Catalog()` in `coverage.go` in topical order, add structural-invariant tests, and document the framework in this file.
