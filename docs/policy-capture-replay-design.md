# Policy Capture and Replay Design

**Status:** Approved
**Version:** 0.1.0
**Date:** 2026-03-28

This document defines `pipelock policy capture` and `pipelock policy replay`.
The goal is to capture live policy verdicts from the proxy and MCP paths, replay
them against a candidate config, and produce a diff report without changing live
verdict behavior.

## Goals

- Capture every verdict site that can affect a policy diff.
- Keep capture fire-and-forget. Capture must never block, slow, or change the
  proxy verdict path.
- Preserve exact scanner input when replay fidelity is needed.
- Reuse the existing recorder for hash chaining, signing, rotation, and retention.
- Make stateful surfaces explicit instead of pretending they are independent.
- Produce HTML and JSON diff reports suitable for enterprise review.

## Non-Goals

- No SSRF replay in v1.
- No live network or DNS resolution during replay.
- No attempt to reconstruct stateful surfaces from a single isolated record.
- No new policy language or enforcement semantics.

## Architecture

Capture uses a small observer interface that the proxy and MCP code call at the
existing verdict sites. The observer must be non-blocking and must never alter
the result of the live request.

```go
type CaptureObserver interface {
    ObserveURLVerdict(context.Context, *URLVerdictRecord)
    ObserveResponseVerdict(context.Context, *ResponseVerdictRecord)
    ObserveDLPVerdict(context.Context, *DLPVerdictRecord)
    ObserveCEEVerdict(context.Context, *CEERecord)
    ObserveToolPolicyVerdict(context.Context, *ToolPolicyRecord)
    ObserveToolScanVerdict(context.Context, *ToolScanRecord)
    Close() error
}
```

Each method is fire-and-forget. The implementation writes records to a bounded
queue, and a single worker goroutine serializes them to disk.

The on-disk evidence format uses the existing recorder envelope:

- `recorder.Entry` provides `v`, `seq`, `ts`, `session_id`, `trace_id`,
  `transport`, `summary`, `prev_hash`, `hash`, and optional `raw_ref`.
- The capture summary lives in `Entry.Detail`.
- A separate encrypted payload sidecar stores the exact payload for replay
  fidelity when the inline summary would otherwise exceed the JSONL line cap.

The session also writes a manifest using the existing `internal/manifest`
package. The manifest stores session-level provenance such as session ID,
transport, start time, agent identity, config hash, active features, and tool
inventory.

## Capture Surfaces

`surface` is the semantic family. `subsurface` is the precise hook site. `kind`
belongs to individual findings, not the record root.

| Surface | Subsurface examples | Observer method | Replay class | Notes |
|---------|---------------------|-----------------|--------------|-------|
| `url` | `fetch_url`, `forward_url`, `reverse_url`, `connect_url`, `websocket_url` | `ObserveURLVerdict` | stateful-session | URL-layer scanner verdicts from the 11-layer pipeline; rate limit and data budget are session state |
| `response` | `response_fetch`, `response_reverse`, `response_intercept`, `response_ws_frame`, `response_mcp`, `response_redirect_output` | `ObserveResponseVerdict` | stateless | Response injection scanning on transformed text |
| `dlp` | `dlp_fetch_header`, `dlp_forward`, `dlp_reverse_request`, `dlp_intercept`, `dlp_ws_headers`, `dlp_ws_frame`, `dlp_mcp_input` | `ObserveDLPVerdict` | stateless | Includes DLP and address-protection findings on text input |
| `cee` | `cee_forward`, `cee_intercept`, `cee_ws`, `cee_mcp` | `ObserveCEEVerdict` | stateful-session | Cross-request exfiltration depends on session history |
| `tool_policy` | `mcp_tool_policy` | `ObserveToolPolicyVerdict` | stateless | Pre-execution allow/deny/redirect on tool calls |
| `tool_scan` | `mcp_tools_list` | `ObserveToolScanVerdict` | stateful-session | Tool poisoning, drift, and baseline capture depend on prior tools/list state |

Additional stateful controls must be captured even if they do not get their own
observer method. Chain detection and session binding findings are recorded
through `ObserveToolPolicyVerdict` with the appropriate finding `kind` values.

- URL rate limiting
- URL data budget
- MCP chain detection (via `ObserveToolPolicyVerdict`, kind `chain_detection`)
- MCP session binding (via `ObserveToolPolicyVerdict`, kind `session_binding`)
- Any adaptive escalation or HITL override that changes effective action

These are recorded for evidence and reporting, but v1 does not pretend they are
independent per-record replays.
The replay engine must process the session stream in order so these controls see
the same history that live traffic saw.
The redirect handler's output text is captured as `response_redirect_output`
and replayed as a standard response scan. The handler invocation itself is
evidence-only.

## Record Model

The capture schema is versioned separately from the recorder envelope.
`recorder.Entry.Version` protects the JSONL envelope. `capture_schema_version`
protects the capture payload.

The inline JSONL record must stay bounded. Exact payloads are stored in a
separate encrypted payload sidecar when needed for replay fidelity.

```go
type CaptureSummary struct {
    CaptureSchemaVersion int       `json:"capture_schema_version"`
    Surface              string    `json:"surface"`
    Subsurface           string    `json:"subsurface"`
    BatchIndex           *int      `json:"batch_index,omitempty"`

    ConfigHash   string `json:"config_hash"`
    BuildVersion string `json:"build_version"`
    BuildSHA     string `json:"build_sha"`
    Agent        string `json:"agent,omitempty"`
    Profile      string `json:"profile,omitempty"`

    PayloadRef        string `json:"payload_ref,omitempty"`
    PayloadSHA256     string `json:"payload_sha256,omitempty"`
    PayloadBytes      int    `json:"payload_bytes,omitempty"`
    PayloadComplete   bool   `json:"payload_complete"`
    TransformKind     string `json:"transform_kind"`
    WirePayloadBytes  int    `json:"wire_payload_bytes,omitempty"`
    WirePayloadSample string `json:"wire_payload_sample,omitempty"`
    ScannerBytes      int    `json:"scanner_bytes,omitempty"`
    ScannerSample     string `json:"scanner_sample,omitempty"`

    Request CaptureRequest `json:"request"`

    RawFindings       []Finding `json:"raw_findings"`
    EffectiveFindings []Finding `json:"effective_findings"`
    EffectiveAction   string    `json:"effective_action"`
    Outcome           string    `json:"outcome"`
    SkipReason        string    `json:"skip_reason,omitempty"`
}

type CaptureRequest struct {
    Method     string              `json:"method"`
    URL        string              `json:"url"`
    Headers    map[string][]string  `json:"headers,omitempty"`
    BodySample string              `json:"body_sample,omitempty"`
    ToolName   string              `json:"tool_name,omitempty"`
    MCPMethod  string              `json:"mcp_method,omitempty"`
}

type Finding struct {
    Kind     string `json:"kind"`
    Action   string `json:"action,omitempty"`
    Severity string `json:"severity,omitempty"`

    PatternName string `json:"pattern_name,omitempty"`
    Encoded     string `json:"encoded,omitempty"`
    MatchText   string `json:"match_text,omitempty"`

    Chain       string   `json:"chain,omitempty"`
    Verdict     string   `json:"addr_verdict,omitempty"`
    ToolName    string   `json:"tool_name,omitempty"`
    DriftType   string   `json:"drift_type,omitempty"`
    PoisonSignal string  `json:"poison_signal,omitempty"`
    PolicyRule  string   `json:"policy_rule,omitempty"`
    RedirectTo  string   `json:"redirect_to,omitempty"`
    ToolSequence []string `json:"tool_sequence,omitempty"`
}
```

### Record Rules

- The recorder envelope owns `session_id`, `seq`, `ts`, `trace_id`, `transport`,
  `prev_hash`, and `hash`.
- `CaptureSummary` must not duplicate `session_id` or `seq`.
- `Agent` and `Profile` are session-level context on `CaptureSummary` only.
  `CaptureRequest` stays request-specific.
- `trace_id` is the canonical request correlation key.
- `BaseAction` is intentionally not a single record-level field. Mixed findings
  can carry different configured actions, so `action` belongs on each finding.
- `PayloadComplete` is required. If it is `false`, replay may still produce a
  useful diff, but it is not exact.
- `PayloadRef` metadata describes the encrypted sidecar object. `WirePayload*`
  and `Scanner*` fields describe the captured plaintext lengths and samples.
- `TransformKind` is versioned and must be preserved verbatim for replay.

### Transform Kinds

Examples of valid `transform_kind` values:

- `raw`
- `readability`
- `hidden_html`
- `header_value`
- `joined_fields`
- `cee_window`
- `websocket_frame`
- `tools_list_description`
- `tools_list_sibling_fields`
- `mcp_batch_element`
- `redirect_output`

The list can grow, but replay must treat unknown values as a version mismatch
unless a fallback is explicitly defined.

## Payload Handling

The JSONL entry stores the bounded summary. `PayloadRef` points to an encrypted
sidecar that stores the exact `scanner_input` used at capture time and, when
different, the raw `wire_payload` plus transform metadata.

- The summary stores hashes, sizes, and short samples for operator context.
- The summary remains useful even if the sidecar write fails.
- The report uses the summary by default and only consults the sidecar when the
  operator has the decryption key and asks for exact replay.
- If the sidecar write fails, write the summary with `PayloadComplete: false`,
  leave `PayloadRef` empty, and log the sidecar error. Do not discard the
  summary entry.

This design avoids the recorder scanner line cap and keeps the capture file
readable even for large bodies, WebSocket frames, and MCP batches.

## Persistence and Backpressure

Capture writer behavior:

- Use a bounded channel.
- Never block the proxy verdict path.
- Drop on overflow.
- Increment `pipelock_capture_dropped_total`.
- Emit a `capture_drop` sentinel entry every 100 drops and on flush.

Recorder behavior:

- Use hash-chained JSONL.
- Keep checkpoint signing optional.
- Keep retention and file rotation aligned with recorder semantics.
- Prefer entry-count rotation, not a separate size-based capture policy.

Capture sidecar behavior:

- Use the same session directory as the recorder output.
- Use authenticated encryption for exact payloads.
- Delete sidecars with their owning session files when retention expires.

If the payload sidecar fails, keep the summary entry, set `PayloadComplete:
false`, and log the error. The record remains useful in summary-only mode even
though exact replay is unavailable.

## Replay Engine

Replay consumes the session directory, loads the manifest if present, and then
replays the JSONL stream in order.

### V1 replay scope

Replay processes records in session order. That is required for:

- `url`
- URL rate limiting
- URL data budget
- `tool_scan`

That keeps the most common diffs honest. CEE, chain detection, and session
binding are evidence-only in v1 and should be labeled as such in the report.

Replay uses the exact `scanner_input` from the payload sidecar when available.
It does not re-derive hidden HTML, readability text, or joined fields from the
wire payload during replay. That keeps replay deterministic across library
changes.

### Replay fidelity matrix

| Surface | With payload sidecar | Without escrow key | Notes |
|---------|----------------------|--------------------|-------|
| `url` | full verdict compare | full verdict compare | session order reconstructs rate limit and data budget state |
| `tool_policy` | full verdict compare | full verdict compare | tool name and args are sufficient |
| `response` | full verdict compare | summary-only, no verdict comparison | exact scanner input required |
| `dlp` | full verdict compare | summary-only, no verdict comparison | exact scanner input required |
| `address_protection` (dlp finding kind) | full verdict compare | summary-only, no verdict comparison | exact scanner input required |
| `tool_scan` | full verdict compare | summary-only, no verdict comparison | exact tools/list payload required |
| `response_redirect_output` | full verdict compare | summary-only, no verdict comparison | redirect handler execution is not replayed; its output scan is |
| `cee` | evidence-only v1 | evidence-only v1 | deferred to v2 state machine |
| `chain_detection` | evidence-only v1 | evidence-only v1 | deferred to v2 state machine |
| `session_binding` | evidence-only v1 | evidence-only v1 | deferred to v2 state machine |
| `adaptive_escalation` / `hitl` | evidence-only v1 | evidence-only v1 | effective-action overrides are recorded, not replayed |

### Non-replayable in v1

- SSRF.

The candidate replay config must set `cfg.Internal = nil` just like the
assessment path. DNS resolution is not deterministic enough for a capture/replay
report to claim exact parity.

### Replay rules

- No network I/O.
- No DNS resolution.
- No randomness.
- No live HITL prompts.
- Candidate config hash is part of the report header.
- Original config hash is part of each capture summary so mid-session reloads are
  visible.

## Diff Report

The report should ship as HTML and JSON.

### Summary block

- Total records seen
- Records replayed
- New blocks
- New allows
- Unchanged verdicts
- Stateful-only records
- Non-replayable records
- Dropped capture records
- Original config hash
- Candidate config hash

### Per-record table

Default view shows only changed verdicts.

| Timestamp | Surface | Subsurface | Transport | Request or tool | Original action | Candidate action | Changed findings |
|-----------|---------|------------|-----------|-----------------|-----------------|------------------|------------------|

Rows should expand to show:

- the bounded inline summary
- the exact payload sidecar status
- raw findings
- effective findings
- a replay status badge

### Display rules

- Red means a new block.
- Yellow means a new allow.
- Green means unchanged.
- Gray means stateful-only or non-replayable.

The report must not print full raw payloads by default. Exact payload inspection
requires explicit operator opt-in and access to the decryption key.

## CLI

The `policy` group should live under the root command, alongside `assess`,
`audit`, and `canary`.

### Capture

```bash
pipelock policy capture --output ./sessions/ --duration 1h \
    [--sign] [--redact] [--raw-escrow] \
    [--escrow-public-key KEY] [--checkpoint-interval 100] \
    [--retention-days 30] [--max-entries-per-file 10000]
```

### Replay

```bash
pipelock policy replay --config candidate.yaml --sessions ./sessions/ \
    --report diff.html [--report-json diff.json] \
    [--escrow-private-key KEY]
```

### CLI rules

- Do not add `--max-size`. Recorder rotation is entry-count based.
- `--escrow-private-key` is required only when exact payload replay is needed.
- If the key is absent, replay can still generate a useful report, but exact
  body-level fidelity is not guaranteed.

## Operational Guarantees

- Capture never changes allow/block behavior.
- Replay never calls out to the network.
- All incomplete evidence must be explicit in the report.
- All record formats are versioned.
- Payload fidelity and stateful replay are separated on purpose.

## Versioning

The capture payload and the replay report both need explicit versioning.

- `recorder.Entry.Version` protects the envelope.
- `capture_schema_version` protects the capture payload.
- The report JSON needs its own version field so downstream tools can consume it
  safely.

If any of those versions change, replay must fail closed with a clear error.
