# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Pipelock, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please use **[GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories/new)** to report vulnerabilities privately.

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Response Timeline

| Severity | ACK target | Patch or mitigation target |
|---|---:|---:|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 3 business days | 30 days |
| Low | 5 business days | 90 days |

Critical and High issues may be pre-disclosed under embargo to material relying parties when they are actively exposed and need time to patch. Embargoed notice is limited to what operators need to reduce risk. Public disclosure happens after a fix, mitigation, or coordinated disclosure deadline. CVE reservation is used when the issue affects released versions, has meaningful user impact, and benefits from ecosystem-wide tracking. Full governance is documented in [CHARTER.md](CHARTER.md).

## Scope

The following are in scope:
- Bypass of URL scanning (blocklist, DLP, entropy)
- SSRF vulnerabilities in the fetch proxy
- Bypass of MCP response scanning (prompt injection evasion)
- Ed25519 signature forgery or verification bypass
- Integrity monitoring bypass (undetected file modification)
- Audit log injection or tampering
- Config parsing vulnerabilities
- Privilege escalation in network restriction mode
- Any issue that could lead to credential exfiltration

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
| 0.x     | No        |

## Security Design

Pipelock's security model is documented in the README. Key design decisions:

1. **Opt-in MITM only:** TLS interception is disabled by default and requires explicit CA setup (`pipelock tls init`). Without it, security comes from capability separation, not inspection.
2. **Defense in depth:** Multiple scanner layers (blocklist, DLP, entropy) each catch different attack vectors.
3. **Honest claims:** We document what each mode prevents vs. detects. See the security matrix in the README.
