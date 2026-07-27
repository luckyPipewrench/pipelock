# SSE Streaming Scan Example

Runnable walkthrough for Pipelock **response_scanning.sse_streaming** on the
**reverse proxy**: clean `text/event-stream` events flush through; a prompt-
injection event terminates the stream so later events never reach the client.

Distinct from buffered `/fetch` response scanning (which is not the SSE
inline path) and from A2A-specific streaming.

Fully offline: local Python SSE upstream + `pipelock run`.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Clean SSE | Both benign events reach the client |
| Injection truncate | After injection, `"never reached"` is absent |

## Prerequisites

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
```

## Quick Verify

```bash
./examples/sse-streaming-scan/verify.sh
```

## Manual Try

```bash
# Terminal 1 — upstream
python3 examples/sse-streaming-scan/sse_upstream.py 7899

# Terminal 2 — rewrite listen/upstream ports in a temp config, then:
"$PIPELOCK_BIN" run --config /path/to/rewritten-pipelock.yaml

# Terminal 3 — client
curl -N http://127.0.0.1:8890/clean
curl -N http://127.0.0.1:8890/inject
```

## Config Notes

See `../../docs/guides/sse-streaming.md`. Defaults already enable SSE
streaming scan; this example makes `action: block` explicit on reverse_proxy.

## Contributing

Improvements welcome: cross-event split injection, or gzip fail-closed demo.
Open a PR against `main`.
