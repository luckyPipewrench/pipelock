# Using Pipelock with JetBrains IDEs

Pipelock wraps Junie MCP server configurations through its MCP proxy, scanning
all tool calls and responses bidirectionally. Works with IntelliJ IDEA, PyCharm,
WebStorm, GoLand, and any JetBrains IDE that uses Junie.

## Quick Start

```bash
# 1. Install pipelock (requires Go 1.26+)
git clone --branch v3.6.0 --depth 1 https://github.com/luckyPipewrench/pipelock.git
make -C pipelock install
# or (macOS): brew install luckyPipewrench/tap/pipelock

# 2. Wrap all Junie MCP servers (user-level)
pipelock jetbrains install

# 3. Restart your JetBrains IDE

# 4. Verify protection
pipelock discover
```

## What Gets Scanned

Once installed, pipelock sits between your JetBrains IDE and every MCP server:

```text
JetBrains IDE  <-->  pipelock mcp proxy  <-->  MCP Server
  (Junie)            (scan both directions)     (subprocess)
```

All scanning layers apply: DLP pattern matching, prompt injection detection,
tool poisoning checks, chain detection, and session binding.

## Install Options

```bash
# User-level (default, visible to pipelock discover)
pipelock jetbrains install

# Project-level (current directory only)
pipelock jetbrains install --project

# Preview changes without writing
pipelock jetbrains install --dry-run

# Use a specific pipelock config
pipelock jetbrains install --config ~/.config/pipelock/pipelock.yaml
```

During install, Pipelock validates the selected config and writes the resolved
absolute path into each wrapped MCP server. Without `--config`, it uses the
standard config discovery order and prints the source it embedded.

Re-running after upgrading Pipelock also recovers and re-wraps an older Pipelock-authored entry using the current binary's invocation shape; an entry it cannot safely normalize is refused with a message identifying the file and entry, and nothing is changed.

## Remove

```bash
# Restore original configs
pipelock jetbrains remove

# Preview what would be restored
pipelock jetbrains remove --dry-run
```

## How It Works

The `jetbrains install` command reads `~/.junie/mcp/mcp.json` (or
`.junie/mcp/mcp.json` with `--project`), wraps each MCP server entry through
`pipelock mcp proxy`, and writes the modified config back. Original server
configurations are stored in a `_pipelock` metadata field for clean removal.

**Stdio servers** get their command wrapped:
```json
// Before
{"command": "node", "args": ["server.js"]}

// After
{"command": "/usr/local/bin/pipelock", "args": ["mcp", "proxy", "--", "node", "server.js"]}
```

**Environment variables:** If your MCP server config has an `env` block, pipelock adds `--env KEY` flags so the child process receives allowed values. The proxy refuses code-loading and other blocked names at startup. See [child environment restrictions](sandbox.md#child-environment-restrictions) before passing runtime settings; ordinary credentials can still pass through.

**HTTP/SSE servers** without custom headers are converted to stdio with
`--upstream`. Servers with authentication headers (e.g., `Authorization`) are
skipped with a warning, because the JetBrains installer does not move header
values into a protected file. Wrap such a server by hand instead: put one
`Header-Name: value` per line in a file with mode `0600` and run
`pipelock mcp proxy --upstream <url> --header-file <path>`.

## Limitations

- **Header passthrough:** the installer cannot wrap HTTP/SSE servers that send
  custom headers. Wrap them by hand with `pipelock mcp proxy --header-file`, as
  above, or use a server that reads its credentials from the environment.
- **Project-local configs** are not visible to `pipelock discover`. The default
  user-level install (omit `--project`) is visible to discover.
- **IDE restart required** after install or remove. Junie reads MCP config at
  startup.
