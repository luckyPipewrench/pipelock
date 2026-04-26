# SSE Streaming and Inline Response Scanning

Pipelock streams Server-Sent Event (SSE) responses inline while scanning
each event for DLP patterns, prompt injection, and other response-layer
threats. Clean events flush immediately so token-by-token LLM chat UX is
preserved; a detection terminates the stream fail-closed.

Before v2.3.0, only A2A streams received inline scanning. Generic
`text/event-stream` responses (OpenAI chat completions, Anthropic
messages, Kilo Gateway, any MCP HTTP/SSE server) were buffered before
scanning, which broke streaming UX and capped response size at 1 MB in
the reverse proxy. v2.3.0 generalizes the streaming scan path to every
`text/event-stream` response across the forward proxy, TLS interception,
and reverse proxy.

## What gets scanned

Each SSE event is parsed per the WHATWG Server-Sent Events spec. Scanning
runs on the canonical event text, which includes the `data:` payload
plus the `event:`, `id:`, and `retry:` metadata fields:

- DLP patterns (same set used for non-streaming response scanning)
- Prompt injection detectors (jailbreak phrases, instruction override,
  credential solicitation, memory persistence, covert action directives,
  CJK instruction overrides)
- Response-address protection and CEE taint propagation when enabled

Unknown fields and lines without a `:` delimiter are ignored by the
parser rather than terminating the stream, matching the WHATWG SSE
spec's forgiving parse rules.

Comment lines (`:` prefix) and keepalives are **dropped** before the
event is forwarded to the client. They are protocol metadata that the
spec specifically excludes from event delivery, so they are never
exposed to client code. The scanner neither inspects them nor re-emits
them. This is consistent with the WHATWG spec and intentional so an
upstream cannot smuggle bytes through comments.

## What is rejected fail-closed

- Compressed SSE streams. Any `Content-Encoding` other than `identity`
  is blocked with a receipt before any bytes are forwarded. This
  prevents scanner bypass by requesting gzip/br/deflate SSE.
- Events exceeding the configured per-event byte ceiling are treated as
  a finding and terminate the stream.
- Invalid UTF-8 in an event's `data:` payload terminates the stream
  (cannot be safely scanned as text).

## Configuration

SSE streaming scanning lives under `response_scanning.sse_streaming`:

```yaml
response_scanning:
  sse_streaming:
    enabled: true            # default true
    action: block            # block | warn, default block
    max_event_bytes: 65536   # 64 KiB per event, default 65536
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable generic SSE streaming scan. When disabled, `text/event-stream` responses stream through with flushing but are not body-scanned (CONNECT-level visibility preserved). |
| `action` | `block` | `block` terminates the stream on a finding and emits a block receipt. `warn` logs the anomaly and forwards the event. |
| `max_event_bytes` | `65536` | Per-event byte ceiling. Exceeding this is treated as a finding. LLM token events are typically small; 64 KiB is a conservative default for most streaming providers. Raise it if a provider emits larger single events (batched deltas, full response chunks). |

## Transport coverage

| Transport | Before v2.3.0 | From v2.3.0 |
|-----------|---------------|-------------|
| Forward proxy + TLS interception | A2A-only streaming; generic SSE buffered | All `text/event-stream` streamed and scanned |
| TLS-intercepted CONNECT | A2A-only streaming; generic SSE buffered | All `text/event-stream` streamed and scanned |
| Reverse proxy | No streaming path; all responses buffered at 1 MB | All `text/event-stream` streamed and scanned; non-SSE responses continue to use the buffered path |
| A2A | Already streamed with field-aware walker + cross-event rolling-tail detection | Unchanged |

## Known limitations

- **Cross-event injection detection applies only to A2A.** Generic SSE
  streaming scans each event in isolation. An attacker who splits a
  single injection payload across sequential SSE events can evade the
  current detector. A2A's rolling-tail detector covers this case for
  the A2A protocol. Generalizing cross-event detection to any SSE
  stream is tracked as a follow-up.
- **Per-account proxy overrides in clients can bypass pipelock.** If an
  upstream client sets its own proxy (not through `HTTPS_PROXY`), it
  may route around pipelock entirely. Configure clients to honor the
  system proxy env vars.
- **SSE comment lines are not scanned.** Generic SSE scanning inspects the
  `data:` payload plus `event:`, `id:`, and `retry:` metadata fields. Comment
  lines are protocol keep-alives and are not exposed to clients as event data.

## See also

- [Response scanning configuration](../configuration.md#response-scanning)
- [Mediation envelope](./mediation-envelope.md) (signed proof of each
  scanning decision, including SSE stream terminations)
- [Receipt transports](./receipt-transports.md)
