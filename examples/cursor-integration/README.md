# Cursor Integration Example

Runnable walkthrough for `pipelock cursor install`: register Pipelock as a
Cursor hook that scans shell commands, MCP tool calls, and file reads before
the agent runs them.

This example does **not** require Cursor to be running. The verify script
simulates the same JSON payloads Cursor sends to hooks on stdin.

## What This Demonstrates

| Surface | Hook event | Pipelock checks |
|---------|------------|-----------------|
| Terminal commands | `beforeShellExecution` | DLP secrets, destructive shell patterns |
| MCP tool calls | `beforeMCPExecution` | Secret leaks in tool arguments |
| File reads | `beforeReadFile` | Credential path access (`.ssh`, `.env`, etc.) |

Install writes three entries into `.cursor/hooks.json` (user-level:
`~/.cursor/hooks.json`, or project-level: `.cursor/hooks.json`).

## Prerequisites

- `pipelock` on `PATH`, or set `PIPELOCK_BIN` to your built binary
- Bash 3.2+ (macOS default is fine)
- Optional: Cursor IDE to use the hooks in a real session

Build from the repo root if needed:

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
```

## Quick Verify (no Cursor required)

From this directory:

```bash
./verify.sh
```

Exit code `0` means all checks passed. The script:

1. Confirms `pipelock` is available
2. Dry-runs `cursor install --project`
3. Installs hooks into a temporary `.cursor/hooks.json`
4. Feeds representative hook payloads to `pipelock cursor hook`
5. Confirms allow/deny decisions match expectations
6. Removes pipelock hooks cleanly

## Install for Real Use

### User-level (all Cursor projects)

```bash
pipelock cursor install --config pipelock.yaml
```

Writes to `~/.cursor/hooks.json`. Existing non-pipelock hooks are preserved.
A `.bak` backup is created before modification.

### Project-level (one repo, shareable via git)

```bash
cd your-project
pipelock cursor install --project --config /absolute/path/to/pipelock.yaml
```

Writes to `.cursor/hooks.json` in the current directory.

### Preview without writing

```bash
pipelock cursor install --dry-run --config pipelock.yaml
```

### Remove pipelock hooks only

```bash
pipelock cursor remove          # user-level
pipelock cursor remove --project  # project-level
```

## What Gets Installed

After install, `hooks.json` contains entries like:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "/path/to/pipelock cursor hook --config /path/to/pipelock.yaml",
        "timeout": 10
      }
    ],
    "beforeMCPExecution": [ ... ],
    "beforeReadFile": [ ... ]
  }
}
```

Cursor calls the command before each action. Pipelock reads JSON from stdin
and prints a single JSON line to stdout:

```json
{"permission":"allow"}
```

or

```json
{"permission":"deny","user_message":"..."}
```

The hook always exits `0`; `permission` is the authoritative decision.

## Manual Hook Tests

Simulate what Cursor sends:

```bash
# Allowed shell command
echo '{"hook_event_name":"beforeShellExecution","command":"ls -la","cwd":"/tmp"}' \
  | pipelock cursor hook

# Blocked: destructive delete
echo '{"hook_event_name":"beforeShellExecution","command":"rm -rf /","cwd":"/tmp"}' \
  | pipelock cursor hook

# Blocked: credential file read
echo '{"hook_event_name":"beforeReadFile","file_path":"/home/user/.ssh/id_rsa"}' \
  | pipelock cursor hook
```

Fixture files under `fixtures/` mirror these payloads for `verify.sh`.

## Config

`pipelock.yaml` in this directory is a minimal hook policy. For full Cursor
egress scanning (fetch proxy, MCP proxy, DLP on network traffic), also run:

```bash
pipelock run --config ../../configs/cursor.yaml --listen 127.0.0.1:8888
```

and route agent HTTP traffic through the proxy. Hooks and the network proxy
are complementary:

- **Hooks** scan actions before they execute inside Cursor
- **Proxy** scans outbound/inbound network and MCP transport traffic

See also `configs/cursor.yaml` and the main project README Cursor section
for additional integration notes.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Cursor does not call hooks | Restart Cursor after install; confirm `hooks.json` path |
| Hook times out | Default timeout is 10s; check `pipelock` path in `hooks.json` |
| Everything denied | Run `pipelock cursor hook` manually with a clean payload |
| Wrong config loaded | Re-run install with `--config` and an absolute path |

## Security Note

Fixture payloads include synthetic attack patterns for testing. They are
detector harness inputs, not weapons.

## Contributing

Improvements welcome: clearer fixtures, additional hook scenarios, or CI
wiring for `./verify.sh`. Open a PR against `main`.
