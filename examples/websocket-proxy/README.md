# WebSocket Proxy Example

Runnable walkthrough for Pipelock's WebSocket proxy (`/ws?url=...`): bidirectional
frame scanning with DLP on client and server text frames.

This example does **not** require external network access. A local echo server
and pipelock proxy both bind on `127.0.0.1`.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Health endpoint | `websocket_proxy_enabled: true` |
| Clean text frame | Message echoes through `ws://PROXY/ws?url=ws://ECHO` |
| DLP on client frame | Secret-shaped text closes the connection |
| Binary frames | Rejected when `allow_binary_frames: false` |

## Prerequisites

- `pipelock` on `PATH`, or set `PIPELOCK_BIN` to your built binary
- Go 1.25+ (to run the small echo/probe helpers)
- Bash 3.2+ and `curl`
- Python 3

Build from the repo root if needed:

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
```

## Quick Verify

From this directory:

```bash
./verify.sh
```

Exit code `0` means all checks passed. The script:

1. Validates `pipelock.yaml`
2. Starts a local WebSocket echo server (`ws_echo.go`)
3. Starts `pipelock run` with WebSocket proxy enabled
4. Sends a clean message and expects an echo
5. Sends a runtime-generated secret and expects the proxy to close the connection
6. Sends a binary frame and expects rejection

## Manual Try

Terminal 1 — echo backend:

```bash
cd /path/to/pipelock
go run examples/websocket-proxy/ws_echo.go
```

Terminal 2 — pipelock (update listen port if needed):

```bash
pipelock run --config examples/websocket-proxy/pipelock.yaml --listen 127.0.0.1:8888
```

Terminal 3 — probe through the proxy (use addresses printed by the echo server):

```bash
go run examples/websocket-proxy/ws_probe.go \
  -proxy 127.0.0.1:8888 \
  -backend 127.0.0.1:ECHO_PORT \
  -message "hello" \
  -expect echo
```

Agent connection URL shape:

```text
ws://127.0.0.1:8888/ws?url=wss://stream.api.vendor.example/events
```

See `../../docs/guides/transport-modes.md` for the full transport matrix.

## Config Notes

`pipelock.yaml` enables `websocket_proxy` with text-frame scanning and binary
frames disabled. `ssrf.ip_allowlist` includes loopback so the verify harness can
target the local echo server.

`verify.sh` copies config into a temp file and assigns a free proxy port.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `go run` fails | Run from repo root; module deps must resolve |
| Proxy not healthy | Check `pipelock.log` from verify temp dir or run in foreground |
| Echo mismatch | Confirm echo server address matches `-backend` flag |
| Immediate close on connect | Check SSRF allowlist and target URL host |

## Security Note

The verify harness generates ephemeral secret-shaped strings at runtime for DLP
testing. They are detector inputs, not real credentials.

## Contributing

Improvements welcome: additional frame cases, CI wiring, or compressed-frame
regression coverage. Open a PR against `main`.
