# OpenCode Integration Example

Runnable walkthrough for `pipelock opencode install`: wrap OpenCode MCP servers
so every tool call runs through `pipelock mcp proxy`.

OpenCode is MCP-native (not hook-based). This example does **not** require the
OpenCode IDE — `verify.sh` uses a temp `opencode.json` and `--path`.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Dry-run install | Shows wrap plan without writing |
| Local MCP wrap | `command` becomes `[pipelock, mcp, proxy, …]` |
| Remote MCP wrap | Remote URL becomes `--upstream` + header sidecar |
| Idempotence | Second install leaves config unchanged |
| Remove | Restores original entries from `_pipelock` metadata |

## Prerequisites

- `pipelock` on `PATH`, or set `PIPELOCK_BIN`
- Bash 3.2+, Python 3

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
```

## Quick Verify

From the repository root:

```bash
./examples/opencode-integration/verify.sh
```

Or from this directory: `./verify.sh` (with `PIPELOCK_BIN` set if needed).

## Manual Try

```bash
"$PIPELOCK_BIN" opencode install --path /path/to/opencode.json \
  --config examples/opencode-integration/pipelock.yaml --dry-run

"$PIPELOCK_BIN" opencode install --path /path/to/opencode.json \
  --config examples/opencode-integration/pipelock.yaml
```

If `pipelock` is already on your `PATH`, you can use `pipelock` instead of `"$PIPELOCK_BIN"`.

Restart OpenCode after install, then use `opencode mcp list` and a harmless
tool action to confirm the server connects. The changed config alone is not a
connection result.

```bash
"$PIPELOCK_BIN" opencode remove --path /path/to/opencode.json --dry-run
"$PIPELOCK_BIN" opencode remove --path /path/to/opencode.json
```

Install and remove create a one-version `.bak` backup before a real change.
Removal restores only Pipelock-wrapped entries from `_pipelock` metadata. If it
warns about an entry or header-sidecar cleanup, restart OpenCode and inspect the
MCP list before using the backup.

## Config Notes

Pass `--config` so the wrapped proxy embeds a real Pipelock config. Without it,
install warns and MCP scanning defaults may leave layers off.

See `../../docs/guides/opencode.md`.

## Contributing

Improvements welcome: OAuth-skip case, live decoy MCP round-trip, or CI wiring.
Open a PR against `main`.
