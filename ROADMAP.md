# Roadmap

High-level direction for Pipelock development. Priorities may shift based on community feedback and the evolving AI agent security landscape.

## Current (v0.2.x)

Shipped capabilities:

- HTTP fetch proxy with 9-layer scanner pipeline
- MCP stdio proxy with bidirectional scanning
- DLP detection (15+ credential patterns, entropy analysis, encoding-aware)
- Prompt injection detection (20+ pattern categories, Unicode-aware)
- Tool description poisoning detection with rug-pull tracking
- Pre-execution tool call policy engine
- Human-in-the-loop terminal approvals
- File integrity monitoring (SHA-256 manifests)
- Ed25519 signing and verification
- Git diff scanning for leaked secrets
- Structured JSON audit logging with Prometheus metrics
- Preset configs for common agent frameworks
- MCP Streamable HTTP transport support
- Known secret file scanning (`secrets_file` config)

## Near-Term

- Agent process management (launch, monitor, enforce capability separation)
- Expanded DLP pattern library
- Configuration improvements and validation tooling

## Medium-Term

- Inter-agent communication security (lateral movement prevention)
- Multi-agent policy coordination
- Enhanced observability and telemetry integration
- Additional MCP transport backends

## Long-Term

- Enterprise deployment patterns (multi-tenant, centralized policy)
- Ecosystem integrations with agent orchestration frameworks
- Community-driven scanner rule sharing

## Out of Scope

Pipelock is a runtime security layer. These are explicitly not goals:

- Model training or fine-tuning security
- Data governance or dataset management
- Full-lifecycle AI management platforms
- Replacing network firewalls or endpoint protection

## Feedback

Feature requests and use case discussions are welcome in [GitHub Issues](https://github.com/luckyPipewrench/pipelock/issues).
