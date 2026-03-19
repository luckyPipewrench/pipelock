# Roadmap

High-level direction for Pipelock development. Priorities shift based on customer feedback, enterprise requirements, and the evolving AI agent security landscape.

## Shipped (v1.x)

Core capabilities available today:

**Traffic Inspection**
- 11-layer scanner pipeline across HTTP, HTTPS, WebSocket, and MCP
- Forward proxy (CONNECT/HTTPS_PROXY), fetch proxy, and Scan API modes
- Optional TLS interception with full body, header, and response scanning

**Data Loss Prevention**
- 44 credential and secret patterns with encoding-aware matching (base64, hex, URL, Unicode)
- Environment variable leak detection
- BIP-39 seed phrase detection with checksum validation
- Blockchain address poisoning protection (ETH, BTC, SOL, BNB)

**Prompt Injection Defense**
- 6-pass normalization pipeline covering zero-width characters, homoglyphs, leetspeak, and encoded payloads
- Response scanning on fetched content and MCP tool results

**MCP Security**
- Bidirectional scanning for stdio, Streamable HTTP, and HTTP reverse proxy
- Tool description poisoning detection with rug-pull drift tracking
- Pre-execution tool policy engine (17 built-in rules)
- Tool call chain detection (10 built-in attack patterns)
- Session binding and behavioral profiling

**Operational Controls**
- OR-composed kill switch (config, signal, sentinel file, remote API)
- Structured audit logging with MITRE ATT&CK technique IDs
- Webhook, syslog, and Prometheus emission (38 metric families)
- Grafana dashboard for fleet monitoring
- HTML/JSON audit reports with Ed25519 signing

**Developer Experience**
- IDE integration for Claude Code, Cursor, and VS Code
- Preset configs for common agent frameworks
- `pipelock diagnose` for config validation
- `pipelock audit` for project security assessment
- Git diff scanning for pre-commit secret detection
- Community rule bundles (signed YAML detection patterns)

**Supply Chain**
- Single static binary (~12 MB), 12 direct dependencies
- Cosign-signed releases, CycloneDX SBOM, SLSA v1.0 provenance
- OpenSSF Best Practices Silver, published OWASP coverage mappings

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

Pipelock is an application-layer agent firewall. These are explicitly not goals:

- Model training or fine-tuning security
- Data governance or dataset management
- Full-lifecycle AI management platforms
- Replacing network firewalls or endpoint protection
- Full sandbox or container runtime isolation

## Feedback

Feature requests and use case discussions are welcome in [GitHub Issues](https://github.com/luckyPipewrench/pipelock/issues).
