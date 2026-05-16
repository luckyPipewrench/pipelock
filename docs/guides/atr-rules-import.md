# Importing Agent Threat Rules (ATR) into Pipelock

This guide documents the optional `atrimport` adapter at
`internal/rules/atrimport/`. It loads YAML rules from the external
Agent Threat Rules (ATR) project and converts the regex-based subset
into Pipelock pattern types.

ATR is an MIT-licensed community-maintained detection standard for AI
agent threats. Upstream: https://github.com/Agent-Threat-Rule/agent-threat-rules.

The adapter is read-only and does not touch the signed bundle pipeline.
Operators who do not call `atrimport.LoadDir` will see no behaviour
change.

## Scope and limits

The adapter intentionally imports only the subset of ATR that maps
cleanly onto Pipelock's existing pattern types:

- Rules with `detection_tier: pattern` (regex-based).
- Conditions with `operator: regex`.
- Single-condition rules, or multi-condition rules with
  `condition: any` (logical OR).

Rules that fall outside that subset are recorded in
`Result.Skipped` with a per-rule reason, including:

- `detection_tier: behavioral` and other non-pattern tiers.
- `condition: all` with multiple conditions (requires boolean
  composition that the scanner does not model today).
- Experimental or draft rules, unless the operator opts in via
  `Options.IncludeExperimental`.
- Rules with no regex condition at all.

Two further safety caps are hard-coded:

- A 1 MiB per-file size limit.
- A 2000-rule import ceiling per call.

## Usage

```go
import "github.com/luckyPipewrench/pipelock/internal/rules/atrimport"

res, err := atrimport.LoadDir("/path/to/atr/rules", atrimport.Options{
    MinSeverity: "high",
    ScanTargets: []string{"mcp", "llm"},
})
if err != nil {
    return err
}
// res.DLP and res.Injection can be appended to the corresponding
// config.DLP.Patterns and response-scan pattern slices.
// res.Skipped enumerates everything that was not imported.
```

Every imported pattern carries `Bundle = "atr"` and
`BundleVersion = <rule-id>` so audit events and metrics can attribute
matches back to the ATR source rather than Pipelock's standard tier.

## Why this is not a signed bundle

Pipelock's signed bundle format (`internal/rules`) carries
provenance, freshness, and tier-key binding guarantees. ATR is an
external standard with its own release cadence. Wrapping ATR into the
signed bundle format would conflate two different trust roots. The
adapter keeps them separate: operators opt in explicitly, and any
non-regex ATR rule is surfaced to them rather than silently dropped.
