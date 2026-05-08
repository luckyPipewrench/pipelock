# Pipelock Governance Charter

Status: v0
Maintainer of record: Joshua Waldrep / The Waldrep Family LLC

Pipelock is an open-source agent firewall for Verifiable Egress Control: control agent egress, produce mediator-signed action receipts, and let relying parties verify evidence from outside the agent trust boundary.

This charter is a public operating promise. It is not a transfer of ownership, copyright, trademark, or governance to a foundation. Pipelock remains founder-led. The goal is predictable stewardship, not committee theater.

## License Promise

The Pipelock core remains Apache License 2.0. Detection, prevention, local evidence, receipt emission, receipt verification, and conformance primitives stay open. Everything already free stays free.

Current repo licenses:

- `pipelock`: Apache 2.0 for core; Elastic License 2.0 only for enterprise-tagged paid code.
- `pipelock-rules`: Apache 2.0. Rules are operational security content with fixtures, citations, signing, and provenance, so Apache keeps contribution terms consistent.
- `agent-egress-bench`: Apache 2.0. The corpus includes schemas, runners, fixtures, and code, so Apache is simpler than splitting case data under a separate license.
- `pipelock-agent-egress-action`: Apache 2.0.

A future Apache license version may be considered through the RFC process below. Relicensing the core to a non-Apache license is outside normal maintainer authority and will not happen without a public proposal, at least 90 days of comment, and explicit written consent from affected copyright holders where required.

The paid product line is evidence operations and support: org coordination, hosted verification uptime, managed key rotation, central search, signed org bundles, auditor workflows. Detection and enforcement stay open and stay free.

## Maintainers

Pipelock uses three trust levels:

- Contributor: submits issues, docs, rules, tests, cases, or code.
- Reviewer: has a track record of useful reviews or case validation.
- Committer: can merge in one or more repos.

Auxiliary repos include `pipelock-rules`, `agent-egress-bench`, and `pipelock-agent-egress-action`. Core means the `pipelock` repo.

Auxiliary commit access may be granted by the maintainer of record after sustained contribution, usually including at least 3 merged PRs, 30 days in the community, and clean handling of review feedback.

Core commit access requires stronger evidence: at least 5 meaningful merged PRs, at least 90 days of visible participation, demonstrated security review judgment, and approval by Josh plus one existing core committer once a second core committer exists. Until then, Josh remains the only core committer.

Core commit access may be revoked only by Josh for security risk, inactivity, repeated policy violation, or loss of trust. Auxiliary access may be revoked by Josh or, once an auxiliary repo has at least 3 committers, by a two-of-three maintainer decision. A revoked committer may appeal once after a 30-day cooldown.

## Security Response

Report security issues through GitHub Security Advisories at:
https://github.com/luckyPipewrench/pipelock/security/advisories/new

Do not open public issues for vulnerabilities.

Target response times:

| Severity | ACK target | Patch or mitigation target |
|---|---:|---:|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 3 business days | 30 days |
| Low | 5 business days | 90 days |

Critical and High issues may be pre-disclosed under embargo to material relying parties when they are actively exposed and need time to patch. Embargoed notice is limited to what operators need to reduce risk. Public disclosure happens after a fix, mitigation, or coordinated disclosure deadline.

CVE reservation should be used when the issue affects released versions, has meaningful user impact, and benefits from ecosystem-wide tracking.

## Conformance Suite

The conformance corpus exists to make receipts and egress-control behavior verifiable outside Pipelock.

Anyone may propose cases by PR. Maintainers may accept cases that are deterministic, tool-neutral, documented, and tied to a clear expected verdict or verification property.

Maintainers may reject cases that are non-deterministic, duplicate an existing case without adding coverage, require private infrastructure, encode Pipelock-specific implementation details instead of public behavior, or create unsafe payloads that cannot be safely distributed.

The corpus is versioned with semantic versions:

- Major: expected verdicts or schemas change in a breaking way.
- Minor: new cases or optional fields are added.
- Patch: fixture corrections, typo fixes, metadata cleanup.

Accepted and rejected cases should be logged publicly through PR history, labels, or a maintained decision log. Breaking changes require an RFC issue, at least 14 days of public comment, and a documented maintainer decision.

## Trademark

The Pipelock name and marks identify the original project and product.

Allowed without written permission:

- "Protected by Pipelock"
- "Supports Pipelock"
- "Works with Pipelock"
- "Verifies Pipelock action receipts"
- "Uses Pipelock-compatible receipt verification" when describing factual interoperability without implying endorsement

Requires written permission:

- "Pipelock-Compatible" as a certification claim
- Product names that start with "Pipelock"
- Logos, badges, or marketing that imply endorsement
- Hosted services using Pipelock as the product name

Forks should not use the Pipelock name as their project or product name. Acceptable attribution is: "Forked from Pipelock" or "Based on Pipelock," with a distinct project name.

## Decisions

Routine implementation decisions are made by maintainers in PRs.

Receipt-format breaking changes require:

1. Public RFC issue
2. 14-day public comment period
3. Maintainer decision with rationale
4. Migration notes before release

Security-disclosure decisions may remain private until disclosure. Product strategy, pricing, customer discussions, and acquisition discussions may remain private. Public technical contracts should be decided in public unless doing so would expose users.

## Code of Conduct

Pipelock follows the Contributor Covenant. Reports may be sent to security@pipelab.org or another published maintainer contact.

Good-faith security reports, disagreement, and criticism are protected. Retaliation against reporters, contributors, or reviewers is not acceptable.
