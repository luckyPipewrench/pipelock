# Using Pipelock with JetBrains IDEs

Pipelock wraps Junie MCP server configurations through its MCP proxy, scanning
all tool calls and responses bidirectionally. Works with IntelliJ IDEA, PyCharm,
WebStorm, GoLand, and any JetBrains IDE that uses Junie.

## Quick Start

```bash
# 1. Install pipelock
brew install luckyPipewrench/tap/pipelock
# or: go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest

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

**Environment variables** are passed through automatically. If your MCP server
config has an `env` block, pipelock adds `--env KEY` flags so the child process
receives them.

**HTTP/SSE servers** without custom headers are converted to stdio with
`--upstream`. Servers with authentication headers (e.g., `Authorization`) are
skipped with a warning since header passthrough is not yet supported for the
MCP proxy upstream path.

## Limitations

- **Header passthrough:** HTTP/SSE servers with custom headers cannot be wrapped.
  Use environment variable-based authentication instead.
- **Project-local configs** are not visible to `pipelock discover`. The default
  user-level install (omit `--project`) is visible to discover.
- **IDE restart required** after install or remove. Junie reads MCP config at
  startup.
