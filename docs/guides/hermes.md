# Using Pipelock with Hermes

[Hermes](https://hermes-agent.nousresearch.com) (Nous Research) is a Python agent with a rich in-process hook API and roughly seventy built-in tools — `terminal`, `browser`, `web_extract`, file read/write, image generation, and MCP servers among them. Unlike an IDE that only speaks MCP, most of Hermes' egress never touches an MCP server, so Pipelock offers two integration modes with deliberately different coverage.

## Why Hermes Needs an Agent Firewall

| Workflow | What Hermes accesses | What could go wrong |
|---|---|---|
| `terminal` / `execute_code` | Shell, network, filesystem | Direct exfiltration that never passes through MCP |
| `web_extract` / `browser` | Arbitrary URLs and page content | Prompt injection in fetched content steering later tool calls |
| MCP tool execution | Databases, APIs, remote services | Tool poisoning, rug-pull updates, chain attacks |
| Cross-session memory | `MEMORY.md`, session DB | An injected instruction surviving across resume |

## Two Install Modes

| Mode | Command | What it wires | Coverage |
|---|---|---|---|
| **full** (default) | `pipelock hermes install --mode full` | Python plugin (`pre_tool_call`, `transform_tool_result`, `pre_gateway_dispatch`, session lifecycle), enabled in `plugins.enabled`, **plus** proxy env names injected into the terminal backend | Plugin-visible tool surfaces; terminal network egress still requires the proxy env values to be set and honored |
| **mcp-only** | `pipelock hermes install --mode mcp-only` | Rewrites `mcp_servers` to route each server through `pipelock mcp proxy` | **Partial** — MCP server traffic only |

`--mode full` is the default because the plugin sees every tool's structured arguments before execution and every result before it returns, so Pipelock scans surfaces a network proxy never sees: a terminal command's arguments, a file write's contents, a tool result before the model reads it. The plugin's load → enable → fire → block path is proven end-to-end against a live Hermes by the `make hermes-e2e` integration test (it installs a pinned Hermes, drives Hermes' own plugin manager, and asserts a secret-bearing tool call is blocked through the real binary). The one cooperative arm is terminal egress: Pipelock sees terminal network traffic only when the proxy env **values** are also set in Hermes' environment and the backend honors them (see below).

`--mode mcp-only` is the lighter opt-in: it wraps every declared MCP server with no Python plugin and no terminal env changes. It is honestly labeled partial coverage — it does not touch the terminal, file, browser, or gateway surfaces. Choose it when you only want MCP traffic wrapped, or when a network-level pipelock deployment (forward proxy + sandbox) already covers the rest of the agent's egress.

## Quick Start

```bash
# 1. Install pipelock
brew install luckyPipewrench/tap/pipelock

# 2. Full coverage (default): plugin-visible tool surfaces + terminal env passthrough
pipelock hermes install --mode full --pipelock-config ~/.config/pipelock/pipelock.yaml

# 2b. OR lighter MCP-only coverage: wrap mcp_servers, no plugin
pipelock hermes install --mode mcp-only --pipelock-config ~/.config/pipelock/pipelock.yaml

# 3. Confirm what was wired
pipelock hermes verify
```

Both modes are idempotent — re-running wraps only new entries and never duplicates work — and back up `~/.hermes/config.yaml` to a timestamped `.bak` before any change.

### Terminal coverage is cooperative

`--mode full` adds Pipelock's proxy environment **names** (`HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, …) to the terminal backend's `env_passthrough`. For terminal traffic to actually route through Pipelock you must also set those env **values** in Hermes' own environment and the backend must honor them. This is cooperative proxying, not binary-enforced network isolation; pair it with `pipelock contain`, a sandbox, or a network policy where you need a hard boundary.

## MCP-Only Mode: Auth-Header Preservation

When `--mode mcp-only` wraps a remote (`url`) MCP server that carries auth `headers`, the credential is **not** placed on the wrapped command line — process arguments are world-visible via `/proc/<pid>/cmdline`. Instead the header lines are written to an operator-private `0600` sidecar under `~/.config/pipelock/wrap-headers/` and referenced through `--header-file`:

```yaml
# before
mcp_servers:
  remote:
    url: https://mcp.example.com
    headers:
      Authorization: "Bearer sk-…"

# after `pipelock hermes install --mode mcp-only`
mcp_servers:
  remote:
    command: /usr/local/bin/pipelock
    args: [mcp, proxy, --config, …, --header-file, ~/.config/pipelock/wrap-headers/<hash>.headers, --upstream, https://mcp.example.com]
    _pipelock: { … }   # original entry, restored by rollback
```

The original headers are retained in the `_pipelock` metadata so `rollback` restores the entry faithfully — the same file-level exposure as the source `headers:` block. The sidecar's job is to prevent the *new* argv exposure that wrapping would otherwise introduce.

## What Gets Scanned

| Direction | full | mcp-only | Scanning |
|---|---|---|---|
| Any tool call args (`terminal`, `write_file`, `web_extract`, …) | ✅ | — | DLP, input injection, tool-policy rules |
| Any tool result | ✅ | — | Response injection (6-pass normalisation), redaction |
| Hermes → MCP server | ✅ | ✅ | DLP + injection on `tools/call` arguments |
| MCP server → Hermes | ✅ | ✅ | Response injection, tool-poisoning, chain detection |
| Gateway dispatch | ✅ | — | `pre_gateway_dispatch` skip/rewrite/allow |

The **full** column reflects what the plugin scans once enabled; the plugin path is proven end-to-end against a live Hermes by `make hermes-e2e`. The **mcp-only** column is the lighter opt-in path for MCP traffic only.

## Verify and Roll Back

```bash
pipelock hermes verify            # human-readable coverage report
pipelock hermes verify --json     # machine-readable

pipelock hermes rollback          # surgical: unwrap mcp_servers, strip proxy env, remove plugin
pipelock hermes rollback --restore-backup ~/.hermes/config.yaml.bak.<ts>   # explicit recovery
```

`verify` reports coverage honestly, and counts the plugin as ready only when it will actually load and fire under Hermes: the plugin files are present, the `plugin.yaml` manifest exists (Hermes skips manifest-less plugin directories), the plugin is enabled in `plugins.enabled` (standalone plugins are opt-in), the hook binary is resolvable, and the config sidecar is sane. File presence alone is **not** coverage. `full` means a ready plugin **and** the proxy env names are present; `partial` means some coverage (a ready plugin, env, or wrapped MCP servers) but not all surfaces; `none` means nothing is wired. `verify` annotates a `full` result to note that terminal egress is cooperative (it routes through Pipelock only when the proxy env values are set in Hermes' environment); the plugin hook path itself is proven by `make hermes-e2e`. It also reports how many MCP servers are declared versus wrapped. Rollback is surgical by default and undoes both modes — it unwraps any wrapped `mcp_servers` (deleting their header sidecars), strips the proxy env names, and removes the plugin from `plugins.enabled` — so you do not have to remember which mode you installed.

## Choosing a Config

| Preset | Action | Best for |
|---|---|---|
| `balanced.yaml` | warn | Getting started, tuning phase |
| `strict.yaml` | block | High-security workflows |
| `hostile-model.yaml` | block | Running an uncensored or jailbroken model |

Start with `balanced.yaml` to see what gets flagged, then move to a blocking preset once you have verified no false positives.

## See also

- [Cline guide](cline.md) — the same MCP-wrap pattern for an MCP-native IDE
- [OpenClaw guide](openclaw.md) — agent framework integration
- [Receipt verification](receipt-verification.md) — independent audit of what each tool call did
