# Using Pipelock with Cline

Cline is an open-source coding agent that runs natively in VS Code with first-class MCP server support. Like every other agent surface Pipelock wraps, Cline talks to MCP servers and to upstream LLM APIs. Pipelock scans wrapped MCP traffic in both directions and scans HTTP traffic that is routed through the proxy.

## Why Cline Needs an Agent Firewall

Cline tasks frequently involve:

| Workflow | What Cline accesses | What could go wrong |
|---|---|---|
| Multi-file edits | Source code, secrets in committed history | Secrets leaked through tool arguments |
| Browsing docs / fetching context | URLs, README files, GitHub issues | Prompt injection in fetched content steering the agent into exfiltration |
| MCP tool execution | Filesystem, databases, network APIs | Tool poisoning, rug-pull updates, chain attacks |
| Cline's checkpoint state | Conversation history, intermediate plans | An injected instruction surviving across resume |

Pipelock sits inline. It scans MCP `tools/call` arguments outbound for DLP, scans tool responses inbound for prompt injection, scans tool definitions for poisoned descriptions, and emits signed action receipts so an operator can prove what happened.

## Quick Start

```bash
# 1. Install pipelock
brew install luckyPipewrench/tap/pipelock

# 2. Wrap every Cline MCP server with pipelock in one shot
pipelock cline install

# 3. Reload VS Code so Cline picks up the wrapped configuration
```

`pipelock cline install` discovers Cline's MCP server configuration, rewrites each entry to launch through `pipelock mcp proxy`, and is idempotent — re-running it on an already-installed setup is a no-op. Add or remove an MCP server in Cline's settings as usual, then re-run `pipelock cline install` to wrap any new entries.

## What Gets Scanned

| Direction | What | Scanning |
|---|---|---|
| Cline → MCP server | Tool call arguments (`tools/call` `params.arguments`) | DLP (secrets, credentials, env-leak), input injection patterns, tool-policy allow/deny/redirect rules |
| MCP server → Cline | Tool results, error messages | Response injection patterns with 6-pass normalisation (zero-width, homoglyphs, leetspeak, base64-wrapped) |
| Tool definitions | `tools/list` responses | Poisoned descriptions, schema injection, rug-pull drift across sessions |
| Tool sequences | Multi-call patterns | Chain detection (recon-then-exfil, persist-then-callback, etc.) |
| Session inventory | First-seen tool set | Inventory pinning so a malicious mid-session server can't add new tools silently |

## Forward Proxy Mode for HTTP Calls

For outbound HTTP that Cline executes through tool calls (`curl`, `wget`, etc.), run pipelock as a forward proxy and point the agent shell at it:

```bash
pipelock run --config configs/balanced.yaml &
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NO_PROXY=127.0.0.1,localhost
```

Combined with MCP wrapping, this covers Cline MCP traffic and HTTP clients that honor the proxy settings. Use `pipelock contain`, sandboxing, or another network boundary for tools that ignore proxy environment variables or open raw sockets directly.

## Choosing a Config

| Preset | Action | Best for |
|---|---|---|
| `balanced.yaml` | warn | Getting started, tuning phase |
| `claude-code.yaml` | block | Unattended Cline sessions on regulated codebases |
| `strict.yaml` | block | High-security repos, third-party plugin work |
| `hostile-model.yaml` | block | If running an uncensored or jailbroken model under Cline |

Start with `balanced.yaml` to see what gets flagged. Switch to `claude-code.yaml` or `strict.yaml` once you've verified no false positives in your workflow.

## Action Receipts

Every scanning decision is logged and signed. For Cline workflows that touch production source code, enable the flight recorder so each tool call produces a verifiable receipt:

```yaml
flight_recorder:
  enabled: true
  dir: /var/lib/pipelock/cline-evidence
  sign_checkpoints: true
  redact: true
```

The receipts can be verified after the fact with the standalone `pipelock-verifier` CLI or the TypeScript / Rust / Go verifier packages. See [receipt-verification.md](receipt-verification.md).

## Troubleshooting

### Cline says a tool was denied

Pipelock denies tool calls whose arguments trip DLP, response scanning, tool-policy rules, or chain detection. Check the pipelock stderr or the flight-recorder JSONL for the corresponding action receipt — it carries the `Layer`, `Pattern`, and `Severity` of the firing scanner.

### `pipelock cline install` reports "no MCP servers found"

Make sure you have at least one MCP server registered in Cline before running the installer. The installer discovers the existing configuration; it does not add new MCP servers.

### Re-running after a Cline upgrade

If Cline moves the MCP config to a new location, re-run `pipelock cline install` after the upgrade. The installer is idempotent, so it's safe to run as part of routine maintenance.

## See also

- [Claude Code guide](claude-code.md) — same MCP-wrap pattern, different IDE
- [Codex guide](codex.md) — coding agent integration
- [OpenCode guide](opencode.md) — sst's coding agent integration
- [Receipt verification](receipt-verification.md) — independent audit of what each tool call did
