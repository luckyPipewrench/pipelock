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
# 1. Install pipelock (requires Go 1.25+)
git clone --branch v3.5.0 --depth 1 https://github.com/luckyPipewrench/pipelock.git
make -C pipelock install
# or (macOS): brew install luckyPipewrench/tap/pipelock

# 2. Generate a config, then preview the wrapper changes
pipelock generate config --preset balanced -o pipelock.yaml
pipelock opencode install --config "$PWD/pipelock.yaml" --dry-run

# 3. Apply the same change and restart OpenCode
pipelock opencode install --config "$PWD/pipelock.yaml"
```

`pipelock opencode install` reads `OPENCODE_CONFIG` when set, otherwise
`~/.config/opencode/opencode.json` (or its JSONC variant), rewrites each MCP
server to launch through `pipelock mcp proxy`, and is idempotent. Pass
`--path` to target another config. After adding or removing an MCP server in
OpenCode's configuration, re-run the installer to wrap new entries.

After restarting OpenCode, use `opencode mcp list` and a harmless tool action
to confirm the server connects. A rewritten config does not by itself prove an
MCP connection.

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
pipelock generate config --preset balanced > pipelock.yaml
pipelock run --config pipelock.yaml &
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NO_PROXY=127.0.0.1,localhost
```

This adds DLP / SSRF / response-injection scanning to outbound HTTP requests from OpenCode tool calls that honor the proxy settings. Use containment or another network boundary for tools that ignore proxy environment variables or open raw sockets directly.

## Choosing a Config

| Preset | Action | Best for |
|---|---|---|
| `balanced` | warn | Getting started, tuning phase |
| `claude-code` | block | Unattended OpenCode sessions on production code |
| `strict` | block | High-security repos |
| `hostile-model` | block | If you're running an uncensored model |

Start in `balanced` to surface false positives in audit mode. Promote to a blocking preset once a workload is clean.

## Containment for Local Multi-User Hosts

If you run OpenCode on a shared host, layer the [`pipelock contain`](../contain-cli.md) lifecycle on top of MCP wrapping. `pipelock contain install` splits the host into `operator` / `pipelock-proxy` / `pipelock-agent` users and uses nftables owner-match to force the contained agent user through Pipelock on loopback, including tools that try raw sockets. The two layers compose: MCP wrapping covers JSON-RPC scanning; containment covers the underlying egress path.

## Troubleshooting

### `pipelock opencode install` says no servers found

OpenCode reads MCP servers from its configuration file. Run `opencode mcp list` to confirm at least one server is registered, then re-run the installer.

### A tool call hangs

Bridge-style MCP servers (those that stdio in but call out over HTTPS to a SaaS)
need network egress. `pipelock opencode install` has no per-install sandbox
flag. Configure sandbox behavior in the Pipelock config used by the wrapper,
then preview and re-run the install with `--config`.

### Previewing or removing the wrapper

```bash
# Inspect the change without writing files.
pipelock opencode install --config "$PWD/pipelock.yaml" --dry-run

# Restore only entries previously wrapped by Pipelock.
pipelock opencode remove --path /path/to/opencode.json --dry-run
pipelock opencode remove --path /path/to/opencode.json
```

Install and remove create a one-version `.bak` backup before a real change.
Removal restores wrapped entries from their `_pipelock` metadata and leaves
other entries alone. If removal warns about an invalid entry or header-sidecar
cleanup, inspect `opencode mcp list` after restarting before changing the
backup. A backup is not a substitute for checking the active client config.

### Receipts and audit trail

Enable the flight recorder for tamper-evident evidence:

```yaml
flight_recorder:
  enabled: true
  dir: /var/lib/pipelock/opencode-evidence
  sign_checkpoints: true
  signing_key_path: /etc/pipelock/keys/flight-recorder-signing.key   # `pipelock init` writes this next to your config
  redact: true
```

Verify receipts after the fact with the standalone `pipelock-verifier` CLI, or any of the language-portable verifier packages. See [receipt-verification.md](receipt-verification.md).

## See also

- [Claude Code guide](claude-code.md) — same MCP-wrap pattern, different IDE
- [Codex guide](codex.md) — coding agent integration
- [Cline guide](cline.md) — VS Code coding agent integration
- [Host Containment](../contain-cli.md) — kernel-observed 3-UID host containment
- [Receipt verification](receipt-verification.md) — independent audit of agent activity
