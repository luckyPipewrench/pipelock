# Comparison: Pipelock vs Other Agent Security Tools

An honest feature matrix and guidance on when to use what.

## Feature Matrix

| Feature | Pipelock | AIP | agentsh | srt |
|---------|----------|-----|---------|-----|
| **Layer** | Application firewall (HTTP + MCP) | MCP proxy | Kernel (seccomp/eBPF/FUSE) | OS sandbox |
| **Language** | Go | Go | Go | TypeScript |
| **Binary** | Single, ~12MB | Single | Single + kernel modules | npm package |
| **Domain allowlist** | Yes | Yes (MCP-level) | Yes (LLM proxy) | Yes |
| **DLP (secret detection)** | Regex + entropy + env scan | Regex (per-argument) | Regex (LLM proxy) | No |
| **SSRF protection** | Yes (DNS pinning) | No | N/A (kernel-level) | N/A |
| **Prompt injection detection** | Bidirectional (response + request scanning) | No | No | No |
| **File integrity monitoring** | SHA256 manifests | No | Workspace checkpoints | Filesystem restrictions |
| **Ed25519 signing** | Yes | No | No | No |
| **MCP scanning** | Yes (bidirectional + tool poisoning) | Yes (native proxy) | No | No |
| **HITL approvals** | Yes (terminal y/N/s) | Yes (OS dialogs) | No | No |
| **Entropy analysis** | Shannon entropy on URLs | No | No | No |
| **Rate limiting** | Per-domain sliding window | No | No | No |
| **Audit logging** | Structured JSON (zerolog) | JSONL | Session logs | No |
| **Prometheus metrics** | Yes | No | No | No |
| **Multi-agent support** | Agent ID header + per-agent logs | Per-agent config | Per-session | No |
| **Network isolation** | Docker Compose generation | No | Kernel-level | sandbox-exec / bubblewrap |
| **Syscall filtering** | No | No | Yes (seccomp) | Yes (sandbox-exec) |
| **Filesystem sandboxing** | No | No | Yes (FUSE) | Yes (bubblewrap) |
| **Config format** | YAML + presets | YAML (agent.yaml) | CLI flags | Code |
| **Hot-reload** | Yes (fsnotify + SIGHUP) | No | No | No |
| **CI/CD friendly** | Yes (exit codes, JSON output) | Yes | Limited | Yes |

## When to Use What

### Use mcp-scan / Snyk agent-scan when:
- You want a **quick static audit** of MCP server tool definitions before connecting
- You need to **detect known-malicious tool descriptions** in a registry
- You want **runtime MCP traffic monitoring** with PII/secrets guardrails (proxy mode)

### Use Docker MCP Gateway when:
- You're already in the **Docker ecosystem** and want native MCP server management
- You need the **interceptor framework** (programmable middleware for MCP requests)
- Basic secret scanning is sufficient and you want **Docker-native deployment**

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
- You need **kernel-level enforcement** (seccomp, eBPF) — agent literally cannot bypass
- You want **"steering"** — redirect denied operations to safe alternatives (e.g., SIGKILL to SIGTERM)
- You need **filesystem sandboxing** via FUSE
- You're comfortable with kernel modules and more complex setup

### Use srt when:
- You're using **Claude Code** specifically (srt is built into it)
- You need **OS-level process sandboxing** (sandbox-exec on macOS, bubblewrap on Linux)
- You want domain-level allow/deny **without content inspection**
- You don't need DLP, audit logging, or injection detection

### Pipelock vs mcp-scan
mcp-scan has two modes: static scanning detects tool poisoning via hash comparison ("has this tool changed?"), while proxy mode monitors MCP traffic with PII/secrets guardrails. Pipelock scans bidirectionally with pattern matching, Unicode normalization, entropy analysis, and covers HTTP fetch traffic in addition to MCP. They're complementary: mcp-scan for MCP-specific auditing and guardrails, Pipelock for deep content inspection across both HTTP and MCP.

### Pipelock vs Docker MCP Gateway
Docker MCP Gateway aggregates MCP servers and provides basic secret scanning. Pipelock provides deep content inspection (15+ DLP patterns, injection detection, entropy analysis, tool poisoning). They're complementary — Pipelock could run as a Gateway interceptor for content inspection while Gateway handles routing and Docker-native lifecycle management.

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
- [mcp-scan / Snyk agent-scan](https://github.com/snyk/agent-scan)
- [Docker MCP Gateway](https://github.com/docker/mcp-gateway)
- [AIP](https://github.com/ArangoGutierrez/agent-identity-protocol)
- [agentsh](https://github.com/canyonroad/agentsh)
- [srt](https://github.com/anthropic-experimental/sandbox-runtime)
- [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
