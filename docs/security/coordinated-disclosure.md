# Coordinated disclosure policy

Pipelock accepts security vulnerability reports through coordinated disclosure. This document gives the reporting channel, the response SLA, the embargo policy, and the CVE handling procedure. The SLA numbers are the same as those in [SECURITY.md](../../SECURITY.md); this document exists so that procurement reviewers can cite a standalone policy.

## Reporting channel

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories/new). Public GitHub issues are out of scope. A vulnerability filed publicly is moved to a private advisory on receipt and the original issue is closed.

The reporting channel is monitored by the project maintainer. Reports are acknowledged on the response SLA below from the time the report is complete.

## Required content of a report

A complete report contains the description of the vulnerability, the steps to reproduce, the impact assessment, the affected versions, and an optional suggested mitigation. Incomplete reports get a single triage round where the maintainer asks for what is missing; the SLA timer pauses until the report is complete.

A reproduction step that requires only what the maintainer can run locally is preferred. If the reproduction requires special infrastructure or specific upstream state, include enough detail that the maintainer can stand up the same environment.

## Response SLA

Timing is measured from the receipt of a complete report.

| Severity | ACK target | Patch or mitigation target |
|---|---:|---:|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 3 business days | 30 days |
| Low | 5 business days | 90 days |

Severity is set by the maintainer based on the impact assessment in the report and the exploitability of the issue against shipped Pipelock versions. The maintainer may revise the severity during triage and informs the reporter when that happens.

## Embargo policy

Critical and High issues may be pre-disclosed under embargo to material relying parties when those parties are actively exposed and need time to patch. Embargoed notice is limited to what operators need to reduce risk: affected versions, available mitigation, and the ETA on the fixed release. Embargo participants are not identified publicly. The reporter is informed of the embargo decision and may request not to be cited in the embargoed notice.

Embargo windows default to the patch SLA for the assigned severity. Extensions beyond the default require the reporter's agreement.

## CVE handling

The maintainer requests CVE reservation through the GitHub Security Advisory automation when the issue affects released versions, has meaningful user impact, and benefits from ecosystem-wide tracking. The CVE is published with the advisory at the end of the embargo window.

The reporter is credited in the published advisory unless they request otherwise. Credit takes the form the reporter prefers: name, handle, organisation, or anonymous.

## Public disclosure timing

Public disclosure happens after one of: a fix has shipped in a released Pipelock version, a documented mitigation is available that an operator can apply without the fix, or the coordinated disclosure deadline has elapsed.

The coordinated disclosure deadline is ninety days from the initial complete report. The deadline can be extended when the reporter agrees and there is active progress on the fix. The deadline can be shortened when there is evidence of active exploitation.

## What is in scope

Reports for the following are accepted under this policy:

- Bypass of URL scanning, including blocklist, DLP, and entropy layers
- SSRF in the fetch proxy or any of the wrapped transports
- Bypass of MCP response scanning and prompt injection evasion
- Ed25519 signature forgery or verification bypass
- Integrity monitoring bypass, including undetected modification of monitored files
- Audit log injection or tampering
- Config parsing vulnerabilities, including bypass of validation, panics on operator input, and incorrect default handling
- Privilege escalation in network restriction mode
- Any issue that could lead to credential exfiltration

## What is out of scope

Reports for the following are not accepted under this policy:

- Theoretical attacks without a working proof of concept
- Self-XSS or self-impact issues that do not cross a privilege boundary
- Denial of service through expected-load patterns rather than amplification
- Social engineering against project maintainers or contributors
- Vulnerabilities in third-party dependencies, which should be reported upstream first; report the impact on Pipelock separately so the project can ship a bumped version

## Reporter recognition

Reporters are credited in the published advisory and in [SECURITY.md](../../SECURITY.md) when the issue ships in a release. A separate hall-of-fame document is on the roadmap; until it exists, the published advisory is the canonical credit.

## See also

- [SECURITY.md](../../SECURITY.md): reporting channel and supported versions
- [CHARTER.md](../../CHARTER.md): governance and the source of the response SLA
- [current-unsupported-paths.md](current-unsupported-paths.md): egress paths that are not in scope for vulnerability reports
