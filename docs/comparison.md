# Comparison: Pipelock vs Other Agent Security Tools

An honest matrix anchored on enforcement and evidence provenance, with a feature-level appendix below.

## Enforcement and Evidence Provenance (May 2026)

The 2026 agent-security field splits along three independent axes: where the decision is computed, where it is enforced, and what evidence artifact the system emits. The matrix below locates current peers on those axes. The narrative after the table covers the nuance, and the per-feature appendix further down preserves the earlier comparison against AIP / agentsh / srt for continuity.

| Tool / category | `decision_location` | `enforcement_location` | `evidence_profile` | HTTP+WS egress content scanning | MCP coverage | A2A coverage | Direct-egress boundary | Best fit |
|---|---|---|---|---|---|---|---|---|
| **Pipelock** | `network_mediator` | `http_proxy` + `mcp_proxy` + optional `kernel_boundary` | `mediator_signed_receipt` — Ed25519, hash-chained, offline-verifiable, standalone CLI + Go/TS/Rust verifiers | DLP, injection, SSRF, encoding evasion, shell obfuscation, WebSocket DLP | Bidirectional: input + tool + chain + drift | Yes (message + Agent Card) | Yes when containment or deployment egress boundary is configured | Agent-agnostic boundary enforcement with offline-verifiable mediation evidence |
| **Microsoft Agent Governance Toolkit** | `in_runtime` | `tool_adapter` + `agent_framework` | `runtime_log` / telemetry | No wire-level HTTP+WS content inspection; egress control depends on framework policy and surrounding infra | MCPGateway and framework-level policy surfaces | Partial (framework-dependent) | In-process policy; direct-egress boundary depends on deployment infra | In-process governance for AGT-instrumented agents on supported frameworks |
| **CAPSEM** (google/capsem) | `network_mediator` (host MITM) | `http_proxy` + `mcp_proxy` (VM-host) | `runtime_log` (SQLite, full-body capture) | Yes — TLS terminated and body capture available; native DLP policy scope is implementation-specific | MCP gateway with allow/block/ask/rewrite | Unknown | Yes within supported VM-host topology | VM-isolated coding agents on a developer laptop |
| **Signet** (Prismer-AI) | `external_service` (sidecar) | `mcp_proxy` | signed enforcement evidence (Ed25519; uses "logs vs evidence" framing) | No | MCP-stdio channel | No | Partial (single mediated transport) | Signed enforcement evidence for MCP-stdio |
| **AgentMint** | `in_runtime` (Python SDK) | `tool_adapter` | `runtime_signed_receipt` (Ed25519, AERF spec, hash-chained, 230-line Go verifier) | No | Partial (tool calls) | No | In-process | Compliance-evidence for in-process agent actions in regulated industries |
| **Cupcake** (eqtylab/cupcake) | `in_runtime` | `agent_framework` + `tool_adapter` | `runtime_log` + evaluation traces (no cryptographic signing in docs) | No | Partial via integrations | No | In-process | OPA-Rego policy enforcement for Claude Code / Cursor / Factory AI / OpenCode |
| **Invariant / Snyk `mcp-scan`** | `external_service` / scanner | `mcp_proxy` or pre-connect scan (mode-dependent) | `runtime_log` / JSON output | No | MCP tool-definition scan plus runtime MCP policy where deployed | No | Partial (MCP only) | MCP-specific scanning and policy guardrails |
| **Trail of Bits `mcp-context-protector`** | `external_service` (wrapper) | `mcp_proxy` | `runtime_log` / quarantine artifact | No | Drift (TOFU pinning) + tool-description scanning | No | Partial | Drift + tool-description pinning for MCP servers |
| **Docker `mcp-gateway`** | `external_service` | `mcp_proxy` | `runtime_log` | No general HTTP+WS content inspection | MCP server gateway / lifecycle surface | No | Partial (MCP only) | Docker-native MCP server management and gatewaying |
| **Sandbox / allowlist cluster** (srt, agentsh, Coder Agent Firewall-style tools) | `external_service` (proxy / sandbox / kernel) | `http_proxy` / `container_boundary` / `kernel_boundary` (per tool) | `runtime_log` | Usually no content inspection; allowlist / sandbox focus | Usually no | No | Yes (per architecture) | Domain / CIDR allowlisting and process containment for agent network access |

**Why three location fields, not one.** A Guardian's *decision* (where the allow/deny/modify is computed) is logically independent from its *enforcement* (where the decision is applied) and from its *evidence profile* (what the receipt cryptographically proves). Conflating them lets a tool claim provenance properties it cannot deliver. The matrix lists each axis separately so the receipt's strength is auditable in the same units Pipelock intends to propose for Agent Control Standard verdicts.

**The cooperative-vs-non-cooperative distinction.** As Pipelock's maintainer told *Help Net Security* in May 2026:

> "Most agent-security tools still need the agent to cooperate."
>
> — Joshua Waldrep, [Help Net Security, May 4 2026](https://www.helpnetsecurity.com/2026/05/04/pipelock-open-source-ai-agent-firewall/)

The article's point was that SDKs, decorators, middleware, and wrapper APIs only work while the agent keeps calling them. The provenance matrix makes that distinction precise. In-process SDKs (Cupcake, AgentMint, AGT) make decisions and emit artifacts *while the agent cooperates*; sidecar / network-mediator / kernel-boundary tools (Pipelock, CAPSEM, Signet) emit stronger evidence for mediated traffic from outside the agent process. Both have their place. The receipt's `decision_location` and `enforcement_location` fields tell you which you're looking at.

**Boundary honesty.** Pipelock receipts prove what Pipelock mediated. Traffic outside Pipelock's control point — direct egress in deployments without containment, processes Pipelock did not intercept — does not appear in receipts and is not bound by them. See the [Audit Packet threat model](security/audit-packet-threat-model.md) for the explicit limits.

## Feature Appendix (legacy matrix)

The matrix below compares Pipelock to earlier-generation tools (AIP, agentsh, srt) on a feature-level basis. The provenance matrix above is the load-bearing comparison for current peers; this appendix is retained for historical reference and continuity.

| Feature | Pipelock | AIP | agentsh | srt |
|---------|----------|-----|---------|-----|
| **Layer** | Application firewall + process containment (HTTP + MCP + WebSocket + Landlock + seccomp + netns) | MCP proxy | Kernel (seccomp/eBPF/FUSE) | OS sandbox |
| **Language** | Go | Go | Go | TypeScript |
| **Binary** | Single, ~22MB | Single | Single + kernel modules | npm package |
| **Domain allowlist** | Yes | Yes (MCP-level) | Yes (LLM proxy) | Yes |
| **DLP (secret detection)** | Regex + entropy + env scan + BIP-39 seed phrases | Regex (per-argument) | Regex (LLM proxy) | No |
| **Crypto secret detection** | Yes (BIP-39, WIF, xprv, ETH hex) | No | No | No |
| **SSRF protection** | Yes (DNS pinning) | No | N/A (kernel-level) | N/A |
| **Prompt injection detection** | Yes (response scanning on fetched content + MCP results) | No | No | No |
| **File integrity monitoring** | SHA256 manifests | No | Workspace checkpoints | Filesystem restrictions |
| **Ed25519 signing** | Yes | No | No | No |
| **WebSocket proxy** | Yes (frame scanning + fragment reassembly) | No | No | No |
| **MCP scanning** | Yes (bidirectional + tool poisoning) | Yes (native proxy) | No | No |
| **HITL approvals** | Yes (terminal y/N/s) | Yes (OS dialogs) | No | No |
| **Entropy analysis** | Shannon entropy on URLs | No | No | No |
| **Rate limiting** | Per-domain sliding window | No | No | No |
| **Audit logging** | Structured JSON (zerolog) | JSONL | Session logs | No |
| **Prometheus metrics** | Yes | No | No | No |
| **Multi-agent support** | Agent ID header + per-agent logs | Per-agent config | Per-session | No |
| **Network isolation** | Yes (network namespaces in sandbox mode, deployment-enforced otherwise) | No | Kernel-level | sandbox-exec / bubblewrap |
| **Syscall filtering** | Yes (seccomp BPF in sandbox mode) | No | Yes (seccomp) | Yes (sandbox-exec) |
| **Filesystem sandboxing** | Yes (Landlock LSM in sandbox mode) | No | Yes (FUSE) | Yes (bubblewrap) |
| **Config format** | YAML + presets | YAML (agent.yaml) | CLI flags | Code |
| **Hot-reload** | Yes (fsnotify + SIGHUP) | No | No | No |
| **CI/CD friendly** | Yes (exit codes, JSON output) | Yes | Limited | Yes |
| **Testing depth** | Thousands of tests, 88%+ coverage, private adversarial suite | Public unit tests | Public unit tests | Public unit tests |
| **Independent verifier SDKs** | First-party Go, TypeScript, Rust verifiers + standalone `pipelock-verifier` CLI + Python companion. Auditors verify signed receipts without running the firewall. | Not applicable | Not applicable | Not applicable |
| **Host containment lifecycle** | `pipelock contain install / verify / rollback / add-tool / grant-workspace / revoke-workspace / ca-refresh` — 3-UID kernel-enforced separation with nftables owner-match, workspace ACL lifecycle, and TOFU binary-integrity pinning | No | Kernel-level, no install lifecycle | OS sandbox per session |
| **Cross-org federation** | Inbound mediation-envelope verification, strict-default SPIFFE actors, RFC 9421 well-known signing-key directory, replay-protected nonce cache, operator trust CLI | No | No | No |

## When to Use What

### Use mcp-scan / Snyk agent-scan when:
- You want a **quick static audit** of MCP server tool definitions before connecting
- You need to **detect known-malicious tool descriptions** in a registry
- You want **MCP-specific policy checks** and JSON output around MCP server/tool risk

### Use Docker MCP Gateway when:
- You're already in the **Docker ecosystem** and want native MCP server management
- You want a **Docker-native gateway** and lifecycle surface for MCP servers
- You want MCP server management more than cross-transport content inspection

### Use Pipelock when:
- You need to **prevent credential exfiltration** from AI agents with API keys
- You want **content inspection** (DLP, injection detection) on what agents fetch
- You need **audit logging** of all agent network activity
- You want a **single binary** with no dependencies or kernel modules
- You're running agents in **CI/CD** and need machine-readable output
- You want **workspace integrity monitoring** to detect file tampering

### Use AIP when:
- You prefer **native OS dialog HITL** (Pipelock uses terminal prompts, AIP uses OS-level dialogs)
- You're focused specifically on **MCP server security** (AIP is an MCP-native proxy)
- You want **per-argument regex validation** on MCP tool calls (AIP validates argument schemas; Pipelock scans argument content for DLP/injection patterns)

### Use agentsh when:
- You need **eBPF-based enforcement** and "steering" to redirect denied operations to safe alternatives
- You're comfortable with kernel modules and more complex setup
- You want redirect-based control (SIGKILL to SIGTERM) rather than block/scan-based control

### Use srt when:
- You're using **Claude Code** specifically (srt is built into it)
- You need **OS-level process sandboxing** (sandbox-exec on macOS, bubblewrap on Linux)
- You want domain-level allow/deny **without content inspection**
- You don't need DLP, audit logging, or injection detection

### Pipelock vs mcp-scan
mcp-scan focuses on MCP-specific auditing and policy checks around server/tool risk. Pipelock scans mediated traffic with pattern matching, Unicode normalization, entropy analysis, and covers HTTP and WebSocket traffic in addition to MCP. They're complementary: mcp-scan for MCP-specific auditing and guardrails, Pipelock for deep content inspection across cross-transport agent egress.

### Pipelock vs Docker MCP Gateway
Docker MCP Gateway aggregates MCP servers and provides Docker-native MCP lifecycle and gatewaying. Pipelock provides deep content inspection (48 DLP patterns, BIP-39 seed phrase detection, 29 injection detection patterns, entropy analysis, tool poisoning, and request-body prompt-injection hard-blocking) across more than MCP. They're complementary: Gateway handles Docker-native routing and lifecycle, while Pipelock handles content inspection and signed mediation evidence.

## Using Tools Together

These tools operate at different layers and complement each other well.

### Pipelock + srt
srt provides the OS sandbox (process isolation, filesystem restrictions). Pipelock provides content inspection (DLP, injection detection, audit logging). Use srt to prevent the agent from bypassing Pipelock, and Pipelock to inspect what passes through.

### Pipelock + agentsh
agentsh provides kernel-level enforcement (the agent literally cannot make unauthorized syscalls). Pipelock provides the content inspection layer (scanning what the agent fetches and detecting secrets in URLs). agentsh ensures the agent uses Pipelock; Pipelock ensures the content is safe.

## Architecture Comparison

```
┌─────────────────────────────────────────────────────────┐
│  Layer 4: Application                                    │
│  ┌──────────┐  ┌──────────┐                              │
│  │ Pipelock │  │   AIP    │   Agent firewall: DLP,       │
│  │          │  │          │   injection, scanning        │
│  └──────────┘  └──────────┘                              │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Shell / Process                                │
│  ┌──────────┐                                            │
│  │ agentsh  │   Syscall interception, FUSE,              │
│  │          │   process steering                         │
│  └──────────┘                                            │
├─────────────────────────────────────────────────────────┤
│  Layer 2: OS Sandbox                                     │
│  ┌──────────┐                                            │
│  │   srt    │   sandbox-exec, bubblewrap,                │
│  │          │   binary allow/deny                        │
│  └──────────┘                                            │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Container / VM                                 │
│  Docker, Firecracker, gVisor                             │
└─────────────────────────────────────────────────────────┘
```

Defense in depth: use tools at multiple layers. A compromised agent must bypass all layers to exfiltrate data.

## Links

- [Pipelock](https://github.com/luckyPipewrench/pipelock)
- [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [CAPSEM](https://github.com/google/capsem)
- [Signet](https://github.com/Prismer-AI/signet)
- [AgentMint](https://agent-mint.dev/)
- [Cupcake](https://github.com/eqtylab/cupcake)
- [mcp-scan / Snyk agent-scan](https://github.com/snyk/agent-scan)
- [Trail of Bits mcp-context-protector](https://github.com/trailofbits/mcp-context-protector)
- [Docker MCP Gateway](https://github.com/docker/mcp-gateway)
- [Coder Agent Firewall](https://coder.com/blog/agent-firewall)
- [AIP](https://github.com/ArangoGutierrez/agent-identity-protocol)
- [agentsh](https://github.com/canyonroad/agentsh)
- [srt](https://github.com/anthropic-experimental/sandbox-runtime)
- [Help Net Security: Pipelock feature](https://www.helpnetsecurity.com/2026/05/04/pipelock-open-source-ai-agent-firewall/)
- [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
