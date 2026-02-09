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

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 1 week
- **Fix and disclosure:** Coordinated with reporter, typically within 30 days

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
| 0.x     | Yes       |

## Security Design

Pipelock's security model is documented in the README. Key design decisions:

1. **No MITM** — We don't decrypt HTTPS traffic. Security comes from capability separation, not inspection.
2. **Defense in depth** — Multiple scanner layers (blocklist, DLP, entropy) each catch different attack vectors.
3. **Honest claims** — We document what each mode prevents vs. detects. See the security matrix in the README.
