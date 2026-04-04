# Securing OpenAI Codex with Pipelock

Codex is the coding agent you hand a real repository. It can review PRs,
trace large codebases, research dependencies, and operate MCP tools. That
means it sees secrets, calls tools, and follows links in untrusted content.

Pipelock sits between Codex and those surfaces, scanning outbound requests,
inbound content, and tool traffic before anything reaches the model or
leaves your machine.

## Why Codex Needs an Agent Firewall

Codex workflows touch high-value targets:

| Workflow | What Codex accesses | What could go wrong |
|----------|--------------------|--------------------|
| PR review | Source code, diffs, commit messages | Secrets in diffs exfiltrated via tool calls |
| Large codebase tracing | Full repo access, dependency trees | Prompt injection in docs, READMEs, or issue templates |
| Web research | URLs, documentation pages, API docs | Injected instructions in fetched content |
| MCP tool use | External tools, databases, APIs | Tool poisoning, rug-pull attacks, data exfiltration via arguments |
| Shell commands | System access within sandbox | Shell obfuscation, persistence attempts |

Codex has its own sandbox (bubblewrap on Linux, Seatbelt on macOS) that
restricts filesystem and process access. Pipelock adds the layer Codex's
sandbox doesn't cover: **content inspection on egress and ingress.** A
sandboxed agent can still send credentials through an allowed HTTPS
connection.

## Quick Start

```bash
# 1. Install pipelock
brew install luckyPipewrench/tap/pipelock

# 2. Wrap an MCP server for Codex
codex mcp add my-server \
  -- pipelock mcp proxy --config configs/balanced.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp

# 3. Run an assessment before first use
pipelock assess init --config configs/balanced.yaml
pipelock assess run assessment-*/
pipelock assess finalize assessment-*/
```

## MCP Proxy Mode

Codex supports MCP servers via `codex mcp add`. Pipelock wraps any MCP
server as a stdio proxy with bidirectional scanning:

```text
Codex  <-->  pipelock mcp proxy  <-->  MCP Server
(agent)      (scan both ways)          (subprocess)
```

### Adding a Wrapped MCP Server

```bash
# Wrap a filesystem server
codex mcp add filesystem \
  -- pipelock mcp proxy --config configs/balanced.yaml \
  -- npx -y @modelcontextprotocol/server-filesystem ~/projects

# Wrap a database server
codex mcp add postgres \
  -- pipelock mcp proxy --config configs/balanced.yaml \
  -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost/mydb

# Wrap a remote MCP server (Streamable HTTP)
codex mcp add remote-tools \
  -- pipelock mcp proxy --config configs/balanced.yaml \
  --upstream http://localhost:8080/mcp
```

### Or Edit the Config Directly

Codex stores MCP server config in `~/.codex/config.toml`:

```toml
[mcp_servers.filesystem]
command = "pipelock"
args = [
  "mcp", "proxy",
  "--config", "/home/you/.config/pipelock/balanced.yaml",
  "--",
  "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"
]
```

### What Gets Scanned

| Direction | What | Scanning |
|-----------|------|----------|
| Codex → MCP server | Tool call arguments | DLP (secrets, credentials, env vars), injection patterns |
| MCP server → Codex | Tool results, descriptions | Prompt injection (19 patterns, 6-pass normalization) |
| Tool definitions | `tools/list` responses | Poisoned descriptions, schema injection, rug-pull detection |
| Tool sequences | Multi-call patterns | Chain detection (read-then-exfil, persist-then-callback) |

## Forward Proxy Mode

For outbound HTTP requests Codex makes through shell commands (curl, wget,
fetch), run pipelock as a forward proxy:

```bash
# Start the proxy
pipelock run --config configs/balanced.yaml &

# Set the proxy for Codex sessions
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
export NO_PROXY=127.0.0.1,localhost
```

This scans all outbound HTTP traffic for DLP, SSRF, and URL-based
exfiltration. Response content is scanned for prompt injection before
reaching the agent.

## Running an Assessment First

Before giving Codex access to a real repository, run an assessment.
Think of it as a background check before the agent starts work.

```bash
# Initialize an assessment session
pipelock assess init --config configs/balanced.yaml

# Run attack simulations
pipelock assess run assessment-*/

# Generate a signed report
pipelock assess finalize assessment-*/
```

The report returns a recommendation:
- **Approve**: config is solid, proceed
- **Approve with constraints**: tighten specific settings before production
- **Probation**: significant gaps found, monitor closely
- **Do not approve**: critical issues, do not use this config with real repos

Re-run after major changes: new model, new MCP tools, new repository,
updated config.

## Codex + Pipelock Sandbox

Both Codex and Pipelock have sandboxing. They work at different layers:

| Layer | Codex sandbox | Pipelock sandbox |
|-------|--------------|-----------------|
| Filesystem | bubblewrap/Seatbelt restricts paths | Landlock restricts paths + seccomp filters syscalls |
| Network | Sandbox mode controls network access | Network namespace isolates + proxy inspects traffic |
| Process | Restricted by sandbox policy | Seccomp + subreaper for descendant cleanup |

For maximum containment, use both:

```bash
# Codex sandbox + pipelock sandbox on MCP server
codex mcp add secure-filesystem \
  -- pipelock mcp proxy --config configs/strict.yaml --sandbox \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## Choosing a Config

| Preset | Action | Best For |
|--------|--------|----------|
| `balanced.yaml` | warn | Getting started, tuning phase |
| `claude-code.yaml` | block | Unattended Codex sessions (works for Codex too) |
| `strict.yaml` | block | High-security repos, sensitive code |
| `hostile-model.yaml` | block | If using uncensored models via Codex |

Start with `balanced.yaml` to see what gets flagged. Switch to
`claude-code.yaml` or `strict.yaml` once you've verified no false positives.

## Evidence and Audit Trail

Every scanning decision is logged. For Codex workflows that touch
sensitive repos, enable the flight recorder:

```yaml
flight_recorder:
  enabled: true
  dir: /tmp/pipelock-codex-evidence
  sign_checkpoints: true
  redact: true
```

This produces a hash-chained JSONL evidence log with signed checkpoints
and DLP-redacted content. Hand it to your security team as proof of what
the agent did and didn't access.

## Troubleshooting

### MCP server not starting under Codex

Verify the command works without Codex first:

```bash
# Test the MCP server directly
pipelock mcp proxy --config configs/balanced.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

# Then add to Codex
codex mcp add test-fs -- pipelock mcp proxy --config configs/balanced.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

### Environment variables not passing through

Codex passes environment variables via `codex mcp add --env` or the
`env_vars` field in `config.toml`. Make sure proxy variables are available:

```bash
codex mcp add my-server --env HTTPS_PROXY --env HTTP_PROXY \
  -- pipelock mcp proxy --config balanced.yaml -- your-server
```

Or pass specific env vars through pipelock:

```bash
codex mcp add my-server \
  -- pipelock mcp proxy --config balanced.yaml --env API_KEY \
  -- my-mcp-server
```

### Checking what Codex MCP servers are configured

```bash
codex mcp list
```

### False positives

If legitimate tool responses are blocked, start with `warn` mode:

```yaml
response_scanning:
  action: warn
```

Check pipelock stderr for detection logs, then adjust patterns.
