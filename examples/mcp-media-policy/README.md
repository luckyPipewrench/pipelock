# MCP Media Policy Example

Runnable walkthrough for Pipelock **media_policy** on MCP tool results: JPEG
EXIF metadata is stripped, while audio and video responses are blocked by
default.

Distinct from `mcp-tool-policy` (static tool denylist), `tool-poisoning-honeypot`
(manifest poison), and `tool-response-injection` (prompt injection in text).

Fully offline: stdio decoy under `pipelock mcp proxy`.

## What This Demonstrates

| Check | What it proves |
|-------|----------------|
| Text allowed | Plain text tool result reaches the client |
| JPEG EXIF stripped | Image forwards; synthetic EXIF marker removed |
| Audio blocked | `audio` content → JSON-RPC `-32002` media policy |
| Video blocked | `video` content → JSON-RPC `-32002` media policy |

## Prerequisites

```bash
make build
export PIPELOCK_BIN="$PWD/pipelock"
```

## Quick Verify

```bash
./examples/mcp-media-policy/verify.sh
```

## Manual Try

```bash
"$PIPELOCK_BIN" mcp proxy --config examples/mcp-media-policy/pipelock.yaml -- \
  python3 examples/mcp-media-policy/media_decoy_server.py
```

## Config Notes

See `../../docs/guides/media-policy.md`. Audio/video strip is the default;
this example only makes the posture explicit.

## Contributing

Improvements welcome: oversized image case, or sniffed MIME from
`application/octet-stream`. Open a PR against `main`.
