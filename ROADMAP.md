# Roadmap

High-level direction for Pipelock development. Priorities shift based on customer feedback, enterprise requirements, and the evolving AI agent security landscape.

## Shipped (v2.0)

Core capabilities available today:

**Traffic Inspection**
- 11-layer scanner pipeline across HTTP, HTTPS, WebSocket, and MCP
- Forward proxy (CONNECT/HTTPS_PROXY), fetch proxy, reverse proxy, and Scan API modes
- Optional TLS interception with full body, header, and response scanning
- Generic HTTP reverse proxy with bidirectional body scanning

**Data Loss Prevention**
- 46 credential and secret patterns with encoding-aware matching (base64, hex, URL, Unicode)
- Environment variable leak detection
- BIP-39 seed phrase detection with checksum validation
- Blockchain address poisoning protection (ETH, BTC, SOL, BNB)

**Prompt Injection Defense**
- 6-pass normalization pipeline covering zero-width characters, homoglyphs, leetspeak, and encoded payloads
- 19 response scanning patterns including state manipulation and control flow hijacking
- Full-schema tool poisoning detection (recursive inputSchema scanning)

**MCP Security**
- Bidirectional scanning for stdio, Streamable HTTP, and HTTP reverse proxy
- Tool description poisoning detection with rug-pull drift tracking
- Pre-execution tool policy engine with redirect action (17 built-in rules)
- Tool call chain detection (10 built-in attack patterns)
- Session binding and behavioral profiling

**Process Sandbox**
- Linux: Landlock filesystem restriction + seccomp syscall filtering + network namespace isolation
- macOS: sandbox-exec with dynamically generated SBPL profiles
- Per-agent profiles with strict mode, diagnostics, and preflight checks

**Operational Controls**
- OR-composed kill switch (config, signal, sentinel file, remote API)
- Structured audit logging with MITRE ATT&CK technique IDs
- Webhook, syslog, OTLP, and Prometheus emission (40 metric families)
- Grafana dashboard for fleet monitoring
- HTML/JSON audit reports with Ed25519 signing
- Config security scoring (`pipelock audit score`)
- Attack simulation (`pipelock simulate`)

**Developer Experience**
- IDE integration for Claude Code, Cursor, VS Code, and JetBrains/Junie
- Preset configs for common agent frameworks
- `pipelock diagnose` for config and sandbox validation
- `pipelock audit` for project security assessment
- Git diff scanning for pre-commit secret detection
- Community rule bundles (signed YAML detection patterns)

**Supply Chain**
- Single static binary (~18 MB), 17 direct dependencies
- Cosign-signed releases, CycloneDX SBOM, SLSA v1.0 provenance
- OpenSSF Best Practices Silver, published OWASP and NIST 800-53 coverage mappings

## Near-Term

- Cross-request exfiltration detection (multi-turn data staging and low-and-slow patterns)
- Expanded DLP coverage for financial instruments and regulated data
- Agent process management (launch, monitor, enforce capability separation)
- Enhanced reporting and compliance evidence generation

## Medium-Term

- Multi-agent policy coordination and inter-agent traffic controls
- Redirect-instead-of-block (steer agents to safe alternatives)
- Profile-then-lock policy generation (learned allowlists from observed behavior)
- Kubernetes sidecar Helm chart
- Centralized policy management for multi-team deployments

## Long-Term

- Fleet-wide dashboard and management plane
- Compliance report generation mapped to NIST AI RMF, EU AI Act, and SOC 2
- Advanced behavioral analytics and anomaly detection

## Out of Scope

These are explicitly not goals:

- Model training or fine-tuning security
- Data governance or dataset management
- Full-lifecycle AI management platforms
- Replacing network firewalls or endpoint protection
- Container runtime management (Docker, K8s orchestration)

## Feedback

Feature requests and use case discussions are welcome in [GitHub Issues](https://github.com/luckyPipewrench/pipelock/issues).
