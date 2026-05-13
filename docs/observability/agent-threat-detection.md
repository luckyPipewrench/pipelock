# Agent Threat Detection (OTel `agent.threat.detection.*`)

> **Status:** Draft. Off by default until the OTel SIG accepts the convention. Enable via `emit.otlp.agent_threat_detection_emit: true`.
>
> **Tracks:** [`open-telemetry/semantic-conventions-genai#132`](https://github.com/open-telemetry/semantic-conventions-genai/issues/132)

Pipelock emits OTLP log records for every scanner decision. When `agent_threat_detection_emit` is on, those records additionally carry attributes proposed by the OTel `agent.threat.detection.*` semantic convention so external collectors can correlate runtime threat-detection events without parsing Pipelock-specific field names.

The convention itself is unstable. Pipelock will track the convention as it evolves; attribute names here are mirror images of what the proposal currently shapes.

## Attribute mapping

Each scanner-decision OTLP log record gains five attributes:

| Convention attribute | Pipelock source | Notes |
|---|---|---|
| `agent.threat.detection.rule_id` | `emit.Event.Fields["pattern"]` (DLP / response-scan / MCP) or `scanner` layer name (entropy, SSRF, blocklist) | Stable identifier of the matched rule, scoped by `ruleset`. Pipelock falls back to the scanner label when no pattern name exists (e.g. SSRF, entropy). |
| `agent.threat.detection.ruleset` | `pipelock-rules@<bundle-version>` if the matched pattern carries a non-empty `BundleVersion`; otherwise `pipelock-core@<binary-version>` | Two namespaces are honoured deliberately. See the **Ruleset namespace** section below. |
| `agent.threat.detection.severity` | `emit.Event.Severity` (`info` / `warn` / `critical`), mapped to convention `low` / `medium` / `high` / `critical` | Mapping table in the **Severity mapping** section. |
| `agent.threat.detection.action` | `emit.Event.Fields["action"]` normalised by `mapConventionAction` (`internal/emit/otlp_agent_threat.go`) | Only `allow` / `block` / `warn` / `ask` are emitted. `strip` / `forward` / `redirect` events are suppressed from this convention until the OTel proposal grows a vocabulary for them. |
| `agent.threat.detection.correlation_id` | `emit.Event.Fields["request_id"]` (opaque per-request identifier) | Opaque, producer-defined. **Not** the receipt SHA-256. Suppressed when `request_id` is absent. See **correlation_id semantics** below. |

The original Pipelock attribute set on the log record (`pipelock.instance`, `transport`, `layer`, etc.) is preserved unchanged. Consumers can opt in to either vocabulary; the two coexist on the same record.

## Per-detection event shape

Pipelock already emits one `emit.Event` per scanner decision. One decision = one OTLP log record = one set of `agent.threat.detection.*` attributes. Multiple detections on the same agent operation produce multiple records, joined externally by `correlation_id` plus the upstream agent's own trace context.

This satisfies the convention's "span events or log records, one event per detection" requirement without adding span emission.

## Ruleset namespace

Two namespaces are populated based on whether the detection came from a bundle-loaded rule or from a built-in scanner:

* `pipelock-rules@<bundle-version>` — for detections matched by a pattern loaded from a `pipelock-rules` bundle (DLP, response-scan, MCP tool poisoning, etc., when the pattern carries `BundleVersion`).
* `pipelock-core@<binary-version>` — for detections produced by built-in scanner logic that does not derive from a loaded rule (SSRF, entropy, blocklist, scheme, URL length, kill switch).

The `<binary-version>` value comes from `cliutil.Version` (the ldflag-injected build version). The `<bundle-version>` value comes from the matched pattern's `BundleVersion` field, set by `internal/rules/loader.go` at parse time.

Splitting the ruleset string by source is deliberate. Hardcoding everything to `pipelock-rules@<version>` would be strategically clean but technically dishonest if the underlying detection lives in core scanner code. Demonstrating both reinforces the public namespace-neutrality argument in the OTel discussion.

**Provenance integrity:** a bundle-origin rule identifier (`primary_rule_id`) without an accompanying `bundle_version` is treated as malformed and is NOT promoted to the `pipelock-core@<v>` namespace. Mislabeling a bundle-origin detection under the core namespace would weaken forensic trust in the audit stream. When `bundle_version` is missing, the mapper falls through to the `pattern` / `scanner` paths instead; if those are also empty, the convention attribute set is suppressed entirely.

## `correlation_id` semantics

`correlation_id` is the Pipelock `request_id` — the opaque per-request identifier already attached to every audit event and used as the join key in receipts. It is opaque and producer-defined. When the underlying event has no `request_id`, the `correlation_id` attribute is omitted rather than filled with a placeholder.

Three reasons it is **not** the receipt SHA-256:

1. **Temporal ordering.** The log record emits when the decision is made; the receipt is signed slightly later. Using the SHA-256 would require synchronously waiting for the signature, which would block the emit path. The `request_id` exists at decision time.
2. **Unconsented linkability.** A content-addressed hash exposed in log attributes lets any downstream system join receipts across organisations without the producer's consent. An opaque ID can be rotated, scoped, or withheld.
3. **Convention scope.** The OTel proposal explicitly leaves the external record format unstandardised. Pipelock's signed audit packet contains the SHA-256 hash chain internally; consumers verifying receipts join via `request_id`, then verify the receipt's hash chain separately.

If a deployment wants the hash form, a future option `correlation_id_format: sha256` can be added; the on-the-wire value would be prefixed `sha256:<hex>` for unambiguous parsing. Pipelock's `ActionRecord.ActionID` is intentionally not exposed in v0 — exposing it would couple the OTel attribute set to receipt internals that Pipelock may wish to evolve.

## Severity mapping

| Pipelock `emit.Severity` | Convention `severity` |
|---|---|
| `info` | `low` |
| `warn` | `medium` |
| `critical` | `high` |

The convention's fourth level (`critical`) is reserved for events that combine `critical` Pipelock severity with a `block` verdict on a sensitive transport (currently MCP tool calls and forward-proxy CONNECT to a flagged destination). Promotion is opt-in via the mapping table and not enabled in the v0 implementation.

## Action mapping

The convention's `action` enum is `allow | block | warn | ask`. Pipelock's internal verdict surface is wider. The mapper applies these rules:

| Pipelock verdict | Convention `action` | Emitted? |
|---|---|---|
| `block` | `block` | yes |
| `allow` | `allow` | yes, only when a detection actually matched (the record exists because something fired) |
| `warn` | `warn` | yes |
| `ask` | `ask` | yes |
| `strip` | — | suppressed (no convention vocabulary yet) |
| `forward` | — | suppressed (no convention vocabulary yet) |
| `redirect` | — | suppressed (no convention vocabulary yet) |

Suppression here means the `agent.threat.detection.*` attribute set is not appended; the underlying Pipelock log record still emits with its native fields. When the convention grows the vocabulary, suppression cases will be promoted.

`ask` is defined as the enforcement decision at detection time. The downstream human approval (yes/no) resolving to allow/block is a separate event with its own ActionID. The convention is intentionally silent on the chain.

## Transport parity

The mapper runs in `OTLPSink.eventToLogRecord`. Every transport that produces a scanner decision converges through the audit logger and `emit.Emitter` before reaching the sink, so a single insertion point covers all six surfaces:

| Transport | Event source | Covered |
|---|---|---|
| HTTP fetch (`/fetch?url=`) | `internal/proxy/proxy.go:handleFetch` | yes |
| Forward CONNECT | `internal/proxy/forward.go:handleConnect` | yes |
| Forward absolute-URI | `internal/proxy/forward.go` | yes |
| WebSocket (`/ws?url=`) | `internal/proxy/websocket.go` | yes |
| MCP stdio | `internal/mcp/scan.go` → audit logger | yes |
| MCP HTTP/SSE | `internal/proxy/proxy.go:handleMCPProxy` | yes |

The implementation does not add transport-specific code paths. Adding a new transport later does not require touching the mapper.

## Configuration

```yaml
emit:
  otlp:
    endpoint: "http://collector:4318"
    agent_threat_detection_emit: true  # default: false
```

The flag defaults to `false` because the convention is unstable. Operators who explicitly opt in accept that attribute names may change in subsequent Pipelock releases. The flag is documented in the schema with a stability warning.

## Configuration state matrix

Per the project's security-sensitive boolean discipline, the flag is validated in six states:

| State | Behaviour |
|---|---|
| field omitted from YAML | default `false`, no attrs emitted |
| explicit `false` | no attrs emitted |
| explicit `true` | attrs emitted on qualifying records |
| YAML `null` / blank | parses as `false` |
| hot reload `true` → `false` | next record carries no attrs |
| hot reload `false` → `true` | next qualifying record carries attrs |

## Golden sample

A sample OTLP log record, with both Pipelock-native fields and the convention attributes populated, is checked into `internal/emit/testdata/otlp_agent_threat_sample.json`. The sample is suitable for attaching to the eventual OTEP and is regenerated by the test suite.

## Out of scope

* Span emission (Pipelock does not produce OTel spans today).
* Convention attributes outside the five listed (`rule_id`, `ruleset`, `severity`, `action`, `correlation_id`).
* Joining to external evidence stores beyond `correlation_id` exposure.
* Translating the OTel attribute set back into Pipelock internal fields on ingest.

## Multi-rule determinism

A single scanner decision can match multiple bundle rules at once. The mapper emits one OTLP record per decision (per the per-detection-event model above), so a "primary" rule has to be chosen for the convention's single-valued `rule_id` and `ruleset` attributes. The full hit list stays in the Pipelock-native `bundle_rules` slice for downstream consumers that want to enumerate.

The primary hit is selected by **lexicographic sort on `RuleID`**, NOT by slice order. Pipelock's scanner emits hits in pattern-iteration order, which is stable in practice but not documented as part of any contract. Pinning the primary choice to a content-addressed criterion means the externally visible `agent.threat.detection.rule_id` stays stable across runs even if scanner iteration order changes upstream. See `selectPrimaryBundleHit` in `internal/audit/logger.go`.

## Open questions

1. Should `pipelock-core@<binary-version>` use the full version including pre-release suffix (e.g. `pipelock-core@v2.5.0-dev`) or the major.minor only (`pipelock-core@v2.5`)? Current implementation uses the full string.
2. When the OTel proposal grows a `strip` / `redirect` vocabulary, should existing operators see attribute emission appear for events that were previously silent? Likely yes, documented in the relevant release notes.

## Severity mapping rationale

Pipelock's pre-existing severity vocabulary is 3-level (`info`, `warn`, `critical`). The convention is 4-level (`low`, `medium`, `high`, `critical`). The mapping treats Pipelock's `info` as convention `low`, `warn` as `medium`, and `critical` as `high`. The convention's `critical` tier is reserved for future promotion logic; the absence of a native `low` baseline is not a problem because `info`-severity allow events are already routed through as `low`.
