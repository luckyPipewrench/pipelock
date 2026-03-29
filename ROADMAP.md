# Roadmap

High-level direction for Pipelock development. Priorities shift based on customer feedback, enterprise requirements, and the evolving AI agent security landscape.

## Shipped (v2.1)

New capabilities added since v2.0:

**Evidence and Compliance**
- Flight recorder: hash-chained, tamper-evident JSONL evidence log with Ed25519 signed checkpoints and X25519 encrypted raw escrow
- Agent Bill of Materials (AgBOM): CycloneDX 1.6 runtime inventory with declared vs observed views
- Session manifest and signed decision records: per-verdict Ed25519 signing with unified session substrate
- Compliance evidence: OWASP MCP Top 10, OWASP Agentic Top 10, MITRE ATLAS, EU AI Act, SOC 2 coverage mappings
- Trust attestation: Ed25519-signed assessment results with SVG badge generation

**Detection and Prevention**
- Canary tokens: synthetic secrets for irrefutable compromise detection with zero false positives
- A2A protocol scanning: Agent Card drift detection, session smuggling, field-level content inspection
- MCP binary integrity: pre-spawn SHA-256 hash verification with shebang and versioned interpreter parsing
- Denial-of-wallet detection: loop detection, retry storm detection, fan-out tracking
- Scanner hardening: improved encoded payload coverage and cross-transport DLP
- Response scanning exempt_domains: per-domain exemption from injection scanning

**Assessment and Simulation**
- `pipelock assess`: four-stage self-serve security assessment with HTML report, secret redaction, and remediation guidance
- `pipelock simulate`: expanded to 54+ attack scenarios (up from 24) across 6 categories

**Operational**
- Session admin API: GET/POST endpoints for adaptive enforcement recovery, identity-family scoping
- MCP redirect handlers: built-in fetch-proxy and quarantine-write profiles
- Autonomous block_all recovery for adaptive enforcement
- Trusted domains for forward proxy SSRF exemption
- SecureIQLab Docker Compose test harness

**Developer Experience**
- CLI split into 10 focused subpackages (from monolithic 91-file package)
- MCPProxyOpts pattern for cleaner internal APIs
- Shared escalation recording and signal classification helpers

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

## Shipped (v2.1)

- Cross-request exfiltration detection: entropy budgets, fragment reassembly, multi-turn data staging
- Financial DLP: blockchain address poisoning protection (ETH, BTC, SOL, BNB) and BIP-39 seed phrase detection
- Agent process management: `pipelock run` with sandbox enforcement (Landlock, seccomp, macOS sandbox-exec)
- Security assessment reports: `pipelock assess` with HTML/JSON output, Ed25519 signing, and config scoring
- Tool policy redirect: steer matched tool calls to audited handler programs instead of blocking
- Profile-then-lock: learned tool baselines from observed behavior, session binding enforcement
- Behavioral analytics: session profiling, adaptive enforcement escalation, cross-request entropy anomaly detection
- A2A protocol scanning: Agent Card validation, agent-to-agent header and body scanning

## Near-Term

- Kubernetes sidecar Helm chart for simplified deployment
- Multi-agent policy coordination and inter-agent traffic controls
- Expanded compliance evidence generation (NIST AI RMF, EU AI Act mapping)

## Medium-Term

- Centralized policy management for multi-team deployments
- Fleet-wide dashboard and management plane
- SOC 2 and regulatory compliance report generation

## Out of Scope

These are explicitly not goals:

- Model training or fine-tuning security
- Data governance or dataset management
- Full-lifecycle AI management platforms
- Replacing network firewalls or endpoint protection
- Container runtime management (Docker, K8s orchestration)

## Feedback

Feature requests and use case discussions are welcome in [GitHub Issues](https://github.com/luckyPipewrench/pipelock/issues).
