# Pi Integration Example

Runnable walkthrough for `pipelock pi install`: set Pi's global `httpProxy`
to a named Pipelock listener.

This example does **not** require a Gemini API key. `verify.sh` uses
`PI_CODING_AGENT_DIR` and never writes `~/.pi/agent/settings.json`.

## What This Demonstrates

| Check | What it proves |
|---|---|
| Dry-run install | Shows the `httpProxy` change without writing |
| Install | Writes only `httpProxy` and keeps other settings |
| Idempotence | Second install reports the proxy is already set |
| Override directory | `PI_CODING_AGENT_DIR` receives the change |
| Remove | Restores the previous proxy value, or deletes a newly created settings file |

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
./examples/pi-integration/verify.sh
```

Or from this directory: `./verify.sh` (with `PIPELOCK_BIN` set if needed).

## Manual Try

```bash
export PI_CODING_AGENT_DIR="$PWD/tmp-pi-agent"
"$PIPELOCK_BIN" pi install --config examples/pi-integration/pipelock.yaml \
  --profile pi --proxy http://127.0.0.1:18991 --dry-run

"$PIPELOCK_BIN" pi install --config examples/pi-integration/pipelock.yaml \
  --profile pi --proxy http://127.0.0.1:18991
```

If `pipelock` is already on your `PATH`, you can use `pipelock` instead of `"$PIPELOCK_BIN"`.

Start Pipelock with that config so the named listener is bound, then start Pi.
Pi's default provider is Google Gemini (`GEMINI_API_KEY`, or `google` in Pi's auth file).
Restart Pi after install. The changed settings file alone is not a live Gemini request.

```bash
"$PIPELOCK_BIN" pi remove --dry-run
"$PIPELOCK_BIN" pi remove
```

See `../../docs/guides/pi.md`.
