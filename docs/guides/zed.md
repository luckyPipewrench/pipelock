# Securing Zed with Pipelock

Zed is a high-performance code editor with first-class MCP support through
its `context_servers` block in `settings.json`. Zed agents that talk to MCP
servers see source code, secrets in files you open, tool results, and the
contents of remote services they call. Pipelock sits between Zed and those
surfaces, scanning outbound tool calls and inbound responses before anything
reaches the model or your filesystem.

## Why Zed Needs an Agent Firewall

Zed's agent workflows touch high-value targets:

| Workflow | What Zed accesses | What could go wrong |
|----------|--------------------|--------------------|
| Code review / refactor | Source code, diffs, repo files | Secrets in files leaked through MCP arguments |
| Agent panel / Claude integration | Files, terminals, project context | Prompt injection in fetched docs or repo READMEs |
| MCP filesystem / fetch tools | Local files, URLs, external APIs | Tool poisoning, rug-pull attacks, credential exfil |
| Project search | Workspace files | Sensitive data echoed back into the model |

Zed itself does not inspect the content crossing the MCP boundary. Pipelock
adds that layer: DLP on tool arguments, injection scanning on tool results,
poisoning detection on tool descriptions, and policy enforcement on tool
sequences.

## Quick Start

```bash
# 1. Install pipelock
brew install luckyPipewrench/tap/pipelock

# 2. Wrap every Zed MCP context_server (default discovery; no args needed)
pipelock zed install

# 3. Restart Zed so the wrapped servers spawn through pipelock
```

The installer rewrites every `context_servers.<name>` entry in your Zed
`settings.json` so that the spawned command is pipelock instead of the
original MCP server. The original command, args, and env block are stashed
in a `_pipelock` metadata field, which `pipelock zed remove` uses to restore
the file later.

## What `pipelock zed install` Wraps

Default discovery scans every standard Zed `settings.json` location:

| Path | Channel |
|------|---------|
| `<cwd>/.zed/settings.json` | Project-local |
| `$XDG_CONFIG_HOME/zed/settings.json` (or `~/.config/zed/settings.json`) | Native stable |
| `$XDG_CONFIG_HOME/zed-preview/settings.json` | Native Preview |
| `~/.var/app/dev.zed.Zed/config/zed/settings.json` | Flatpak stable |
| `~/.var/app/dev.zed.Zed.Preview/config/zed-preview/settings.json` | Flatpak Preview |

Each file that exists is wrapped independently with its own `.bak` backup.
If you want to operate on a single explicit file, pass `--path`:

```bash
pipelock zed install --path ~/some/custom/settings.json
```

If none of the default paths exist, install prints every probed path so you
can see why nothing was wrapped and pick the right `--path` value.

## The Wrap, Inside

A native Zed stdio MCP server like this:

```json
"context_servers": {
  "filesystem": {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
  }
}
```

becomes:

```json
"context_servers": {
  "filesystem": {
    "type": "stdio",
    "command": "pipelock",
    "args": [
      "mcp", "proxy",
      "--config", "/home/you/.config/pipelock/pipelock.yaml",
      "--",
      "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
    ],
    "_pipelock": {
      "original_command": "npx",
      "original_args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "original_type": "stdio",
      "type_omitted": true,
      "args_present": true
    }
  }
}
```

Remote (URL-based) `context_servers` are rewritten the same way, with
pipelock spawned as a stdio-to-HTTP bridge via `--upstream`:

```json
"context_servers": {
  "remote": {
    "command": "pipelock",
    "args": ["mcp", "proxy", "--config", "...", "--upstream", "https://api.example.com/mcp"]
  }
}
```

Credential-bearing `headers` blocks (e.g. `Authorization: Bearer ...`) land
in a 0o600 header-sidecar file referenced via `--header-file`, so header
values never appear in `/proc/<pid>/cmdline`.

## What Gets Scanned

| Direction | What | Scanning |
|-----------|------|----------|
| Zed → MCP server | Tool call arguments | DLP (secrets, credentials, env vars), injection patterns |
| MCP server → Zed | Tool results, descriptions | Prompt injection (default response patterns, 6-pass normalization) |
| Tool definitions | `tools/list` responses | Poisoned descriptions, schema injection, rug-pull detection |
| Tool sequences | Multi-call patterns | Chain detection (read-then-exfil, persist-then-callback) |

## End-to-End: a Real DLP Block

With install in place and the filesystem MCP server configured, an attempted
`write_file` call carrying an AWS-style key gets blocked at the MCP input
boundary:

```text
$ # tools/call write_file with content "AKIAIOSFODNN7EXAMPLE"
pipelock: proxying MCP server [npx -y @modelcontextprotocol/server-filesystem /tmp]
          (response=warn, input=block, tools=block, policy=warn)
pipelock: input line 3: blocked tools/call request (AWS Access ID)

{"jsonrpc":"2.0","id":2,"error":{"code":-32001,
  "message":"pipelock: request blocked by MCP input scanning"}}

$ ls /tmp/mcp-leak.txt
ls: cannot access '/tmp/mcp-leak.txt': No such file or directory
```

The credential never reaches the filesystem MCP server and the file is
never written. The block is at the protocol layer, not just a model-side
refusal.

## Round-Trip Behavior with Zed Settings Saves

Zed re-saves `settings.json` when you change settings through the UI
(theme, font size, agent panel changes). The `_pipelock` metadata block
survives that re-save because Zed preserves unknown top-level fields and
unknown server keys. Verified live against Zed 1.2.6: install, change the
UI theme, exit, and the `_pipelock` block is still intact and the wrap
still spawns.

## Discovering Wrap Status

`pipelock discover` reports MCP servers across every IDE it knows about,
including all four Zed channels:

```bash
$ pipelock discover
zed                  1 server,  1 protected
zed-preview          1 server,  0 protected   <-- channel missed during install
zed-flatpak          0 servers
zed-preview-flatpak  0 servers
```

Use `pipelock discover --json` for a machine-readable report.

## Removing the Wrap

```bash
pipelock zed remove           # restores every wrapped file
pipelock zed remove --path .. # single explicit file
```

Restores the original server entries from the `_pipelock` metadata field
and strips that field. Non-wrapped entries and non-server top-level fields
(theme, ui_font_size, agent settings, etc.) are left untouched.

## Choosing a Config

| Preset | Action | Best For |
|--------|--------|----------|
| `balanced.yaml` | warn | Getting started, tuning phase |
| `claude-code.yaml` | block | Unattended Zed agent sessions |
| `strict.yaml` | block | High-security repos, sensitive code |
| `hostile-model.yaml` | block | Local / uncensored models routed through Zed |

Start with `balanced.yaml` to surface false positives without breaking your
workflow. Switch to `claude-code.yaml` or `strict.yaml` once you've tuned
the pattern set.

## Limitations

- Project-local discovery scans `<cwd>/.zed/settings.json`, so run install
  from the project directory if you want the project-local config wrapped.
- The installer only touches `context_servers`. Zed's separate
  `agent_servers` block (e.g. the `claude-acp` agent integration) is not an
  MCP surface and is left alone.
- Re-running install after Zed has written its own additions
  (`agent.default_model`, etc.) is safe: wrapped entries are skipped
  (idempotent), and Zed's other additions are preserved.

## Evidence and Audit Trail

Every scanning decision is logged. For Zed sessions that touch sensitive
repos, enable the flight recorder:

```yaml
flight_recorder:
  enabled: true
  dir: /tmp/pipelock-zed-evidence
  sign_checkpoints: true
  redact: true
```

The recorder produces a hash-chained JSONL evidence log with signed
checkpoints and DLP-redacted content. Hand it to your security team as
proof of what each Zed session did and did not access.
