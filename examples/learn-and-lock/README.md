# Learn and Lock Example

Runnable walkthrough for Pipelock **MCP behavioral baseline**: observe tool
calls in learn mode, auto-lock the profile, then prove a learned call still
passes while a novel tool is denied.

This is **learned behavior**, not a static denylist (`examples/mcp-tool-policy/`)
and not the full v2.4 contract pipeline in `docs/guides/learn-and-lock.md`.

Fully offline: stdio decoy MCP server under `pipelock mcp proxy`.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Learn | One `echo` sample under `learning_window: 1` (stdio sample-per-exit) |
| Lock | `auto_ratify` writes a locked profile under `profile_dir` |
| Learned still allowed | Post-lock `echo` reaches the decoy (not deny-all) |
| Novel denied | Same session `run_shell` hits baseline deviation (`-32001`) |
| Not tool policy | Deny must not look like `mcp_tool_policy` (`-32002`) |

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
./examples/learn-and-lock/verify.sh
```

Or from this directory: `./verify.sh` (with `PIPELOCK_BIN` set if needed).

## Manual Try

```bash
"$PIPELOCK_BIN" mcp proxy --config examples/learn-and-lock/pipelock.yaml -- \
  python3 examples/learn-and-lock/baseline_decoy_server.py
```

Drive JSON-RPC `tools/call` for `echo` once and exit the proxy (stdio records a
sample on exit; this example uses `learning_window: 1` so that sample
auto-locks). Restart and call `echo` (allow) then `run_shell` (deny) in the same
session. Production operators can also use `pipelock baseline show` / `ratify`
against `pipelock run` with the admin API instead of `auto_ratify`.

If `pipelock` is already on your `PATH`, you can use `pipelock` instead of `"$PIPELOCK_BIN"`.

## Config Notes

| Example | Mechanism |
|---------|-----------|
| `mcp-tool-policy` | Static operator denylist (`mcp_tool_policy.rules`) |
| `tool-poisoning-honeypot` | Manifest / response scanning |
| **`learn-and-lock`** | **Observed-behavior baseline** (`behavioral_baseline`) |

`auto_ratify: true` is for this offline harness: stdio `mcp proxy` does not
expose `/api/v1/baseline/*`. Prefer explicit `pipelock baseline ratify` in
production.

See `../../docs/cli/baseline.md` and `../../docs/guides/learn-and-lock.md`
(contract path).

## Contributing

Improvements welcome: admin-API ratify path, or `tool_calls` dimension case.
Open a PR against `main`.
