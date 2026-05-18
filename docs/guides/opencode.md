# Using Pipelock with OpenCode

OpenCode is sst's coding agent — a terminal-first agent with native MCP server support, deep IDE adapters, and a Plans-and-Tasks workflow. Pipelock wraps OpenCode's MCP traffic and scans HTTP egress that is routed through the proxy before it leaves the machine.

## Why OpenCode Needs an Agent Firewall

OpenCode runs long sessions across multiple repos, calls many MCP tools, and frequently fetches remote context (docs, READMEs, issues). That makes it a high-value injection target and a high-value secret-exfil target. Pipelock closes both:

| Workflow | What OpenCode accesses | What could go wrong |
|---|---|---|
| Codebase navigation | Source code, secrets in test fixtures | Secrets routed through tool arguments to an attacker server |
| Plan execution | Filesystem writes, shell commands | Tool chain that smuggles persistence steps |
| Web research | Documentation, GitHub issues, blog posts | Prompt injection in fetched content rewriting the agent's plan |
| Multi-repo refactor | Cross-project filesystem access | Reading `.env` from one repo and exfiltrating via the other |
| MCP servers (third-party) | Whatever surfaces the server exposes | Tool poisoning, rug-pull, chain attacks |

## Quick Start

```bash
# 1. Install pipelock
brew install luckyPipewrench/tap/pipelock

# 2. Wrap every OpenCode MCP server with pipelock in one shot
pipelock opencode install

# 3. Restart OpenCode so it picks up the wrapped MCP entries
```

`pipelock opencode install` discovers OpenCode's MCP server entries, rewrites each one to launch through `pipelock mcp proxy`, and is idempotent — re-running it on an already-installed setup is a no-op. After adding or removing an MCP server in OpenCode's configuration, re-run the installer to wrap any new entries.

## What Gets Scanned

| Direction | What | Scanning |
|---|---|---|
| OpenCode → MCP server | Tool call arguments | DLP (secrets, credentials, env-leak), input injection patterns, tool-policy rules |
| MCP server → OpenCode | Tool results, error responses | Response injection patterns with 6-pass normalisation |
| Tool definitions | `tools/list` responses | Poisoned descriptions, schema injection, rug-pull drift |
| Tool sequences | Multi-call patterns | Chain detection (recon-then-exfil, etc.) |
| Session inventory | First-seen tool set | Inventory pinning across the session |

## Forward Proxy Mode for HTTP

For shell-executed HTTP (curl, wget, fetch), run pipelock as a forward proxy:

```bash
pipelock run --config configs/balanced.yaml &
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NO_PROXY=127.0.0.1,localhost
```

This adds DLP / SSRF / response-injection scanning to outbound HTTP requests from OpenCode tool calls that honor the proxy settings. Use containment or another network boundary for tools that ignore proxy environment variables or open raw sockets directly.

## Choosing a Config

| Preset | Action | Best for |
|---|---|---|
| `balanced.yaml` | warn | Getting started, tuning phase |
| `claude-code.yaml` | block | Unattended OpenCode sessions on production code |
| `strict.yaml` | block | High-security repos |
| `hostile-model.yaml` | block | If you're running an uncensored model |

Start in `balanced.yaml` to surface false positives in audit mode. Promote to a blocking preset once a workload is clean.

## Containment for Local Multi-User Hosts

If you run OpenCode on a shared host, layer the [`pipelock contain`](../contain-cli.md) lifecycle on top of MCP wrapping. `pipelock contain install` splits the host into `operator` / `pipelock-proxy` / `pipelock-agent` users and uses nftables owner-match to force the contained agent user through Pipelock on loopback, including tools that try raw sockets. The two layers compose: MCP wrapping covers JSON-RPC scanning; containment covers the underlying egress path.

## Troubleshooting

### `pipelock opencode install` says no servers found

OpenCode reads MCP servers from its configuration file. Run `opencode mcp list` to confirm at least one server is registered, then re-run the installer.

### A tool call hangs

Bridge-style MCP servers (those that stdio in but call out over HTTPS to a SaaS) need network egress. If you've enabled `sandbox.enabled: true` on the wrap, the proxy will isolate the MCP server in a network namespace and the upstream call will fail. Set `sandbox: false` on bridge servers via the install flag.

### Receipts and audit trail

Enable the flight recorder for tamper-evident evidence:

```yaml
flight_recorder:
  enabled: true
  dir: /var/lib/pipelock/opencode-evidence
  sign_checkpoints: true
  redact: true
```

Verify receipts after the fact with the standalone `pipelock-verifier` CLI, or any of the language-portable verifier packages. See [receipt-verification.md](receipt-verification.md).

## See also

- [Claude Code guide](claude-code.md) — same MCP-wrap pattern, different IDE
- [Codex guide](codex.md) — coding agent integration
- [Cline guide](cline.md) — VS Code coding agent integration
- [Host Containment](../contain-cli.md) — kernel-enforced 3-UID isolation
- [Receipt verification](receipt-verification.md) — independent audit of agent activity
