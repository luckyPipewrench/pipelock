# Roadmap

High-level direction for Pipelock development. Priorities may shift based on community feedback and the evolving AI agent security landscape.

## Current (v0.2.x)

Shipped capabilities:

- HTTP fetch proxy with 9-layer scanner pipeline
- MCP stdio proxy with bidirectional scanning
- MCP Streamable HTTP transport (`--upstream` mode)
- DLP detection (15+ credential patterns, entropy analysis, encoding-aware)
- Prompt injection detection (20+ pattern categories, Unicode-aware)
- Tool description poisoning detection with rug-pull tracking
- Pre-execution tool call policy engine (9 default rules)
- Human-in-the-loop terminal approvals
- File integrity monitoring (SHA-256 manifests)
- Ed25519 signing and verification
- Git diff scanning for leaked secrets
- Structured JSON audit logging with Prometheus metrics
- Preset configs for common agent frameworks
- Known secret file scanning (`secrets_file` config)
- Scanner validation command (`pipelock test`)
- Framework integration guides (Claude Code, OpenAI, Google ADK, AutoGen, CrewAI, LangGraph)
- OpenSSF Best Practices Silver badge, SLSA provenance, CycloneDX SBOM

## Near-Term

- "Agent Firewall" positioning (documentation refresh)
- Codebase refactoring (MCP package modularization)
- Unified HTTP+MCP mode (single process for both proxy types)
- GitHub Action v2 (MCP scanning, SARIF output)
- Docker compose-for-agents example

## Medium-Term

- Inter-agent communication security (lateral movement prevention)
- Multi-agent policy coordination
- Redirect-instead-of-block (steer agents to safe alternatives)
- Policy generation ("profile-then-lock" learned allowlists)
- K8s sidecar Helm chart

## Long-Term

- Enterprise deployment patterns (multi-tenant, centralized policy)
- Community-driven scanner rule sharing
- Web dashboard and fleet management
- Compliance report generation (NIST AI RMF evidence from audit logs)

## Out of Scope

Pipelock is a runtime security layer. These are explicitly not goals:

- Model training or fine-tuning security
- Data governance or dataset management
- Full-lifecycle AI management platforms
- Replacing network firewalls or endpoint protection
- Full sandbox/container runtime
- Custom policy DSL

## Feedback

Feature requests and use case discussions are welcome in [GitHub Issues](https://github.com/luckyPipewrench/pipelock/issues).
