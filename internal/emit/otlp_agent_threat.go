// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// Attribute keys proposed by the unstable OTel `agent.threat.detection.*`
// semantic convention. Tracks open-telemetry/semantic-conventions-genai#132.
// See docs/observability/agent-threat-detection.md.
const (
	attrAgentThreatRuleID        = "agent.threat.detection.rule_id"
	attrAgentThreatRuleset       = "agent.threat.detection.ruleset"
	attrAgentThreatSeverity      = "agent.threat.detection.severity"
	attrAgentThreatAction        = "agent.threat.detection.action"
	attrAgentThreatCorrelationID = "agent.threat.detection.correlation_id"
)

// Convention action vocabulary. Pipelock's wider verdict surface
// (strip/forward/redirect) is suppressed until the convention grows
// the missing terms.
const (
	conventionActionAllow = "allow"
	conventionActionBlock = "block"
	conventionActionWarn  = "warn"
	conventionActionAsk   = "ask"
)

// Convention severity vocabulary. Pipelock's 3-level internal severity
// maps onto low|medium|high; the convention's `critical` tier is reserved
// for future promotion logic and is not emitted in v0.
const (
	conventionSeverityLow    = "low"
	conventionSeverityMedium = "medium"
	conventionSeverityHigh   = "high"
)

// Ruleset namespace prefixes. The suffix is filled at emit time from
// either the loaded bundle's version (bundle-sourced detections) or the
// Pipelock binary version (core scanner detections).
const (
	rulesetNamespaceCorePrefix   = "pipelock-core@"
	rulesetNamespaceBundlePrefix = "pipelock-rules@"
)

// Pipelock-native emit field keys consulted by the mapper. Mirrored
// constants keep the linter happy and document the contract between the
// audit logger and this file.
const (
	fieldAction         = "action"
	fieldPattern        = "pattern"
	fieldScanner        = "scanner"
	fieldRequestID      = "request_id"
	fieldPrimaryRuleID  = "primary_rule_id"
	fieldBundleVersion  = "bundle_version"
	eventTypeBlocked    = "blocked"
	eventTypeWSBlocked  = "ws_blocked"
	verdictAllowed      = "allowed" // Pipelock historically uses both "allow" and "allowed"
	verdictAllowed2     = "allow"
	verdictBlockedShort = "block"
	verdictBlocked2     = "blocked"
	verdictWarn         = "warn"
	verdictAsk          = "ask"
)

// agentThreatDetectionAttrs maps a scanner-decision emit.Event to the
// proposed `agent.threat.detection.*` OTel attribute set. Returns nil
// when the event is not a scanner decision or its verdict is outside
// the convention's vocabulary.
//
// binaryVersion is used as the suffix for `pipelock-core@<v>` when the
// matched rule did not come from a loaded bundle. Callers should pass
// the build-time-injected Pipelock version (cliutil.Version).
func agentThreatDetectionAttrs(event Event, binaryVersion string) []*commonpb.KeyValue {
	action, ok := mapConventionAction(event)
	if !ok {
		return nil
	}

	ruleID, ruleset := resolveConventionRule(event.Fields, binaryVersion)
	if ruleID == "" {
		// No identifiable rule; suppress rather than emit a placeholder.
		return nil
	}

	attrs := []*commonpb.KeyValue{
		stringKV(attrAgentThreatRuleID, ruleID),
		stringKV(attrAgentThreatRuleset, ruleset),
		stringKV(attrAgentThreatSeverity, mapConventionSeverity(event.Severity)),
		stringKV(attrAgentThreatAction, action),
	}
	if requestID, _ := event.Fields[fieldRequestID].(string); requestID != "" {
		attrs = append(attrs, stringKV(attrAgentThreatCorrelationID, requestID))
	}
	return attrs
}

// mapConventionAction normalises a Pipelock verdict string to the
// convention's allow|block|warn|ask vocabulary. The Pipelock audit
// logger uses both "allow"/"allowed" and "block"/"blocked" in different
// call sites, so both forms are accepted.
//
// Generic blocked events predate the action field: LogBlocked and LogWSBlocked
// carry the scanner label and reason but not an explicit action. For those
// event types, the event type itself is the enforcement decision. To guard
// against future code reusing the "blocked" / "ws_blocked" type names for
// non-enforcement events (lifecycle, error fan-out, etc.), the legacy
// fallback ALSO requires a non-empty `scanner` field; LogBlocked and
// LogWSBlocked both populate it unconditionally, so this is a strict
// tightening with no operational impact on existing call sites.
//
// Returns ok=false for verdicts outside the convention's vocabulary
// (strip, forward, redirect, unknown) or for records that do not represent
// an enforcement decision.
func mapConventionAction(event Event) (string, bool) {
	s, ok := event.Fields[fieldAction].(string)
	if !ok {
		switch event.Type {
		case eventTypeBlocked, eventTypeWSBlocked:
			// Defense in depth: require a scanner identifier so a
			// lifecycle event accidentally tagged "blocked" cannot be
			// promoted to a convention block decision.
			if sc, scOK := event.Fields[fieldScanner].(string); scOK && sc != "" {
				return conventionActionBlock, true
			}
			return "", false
		default:
			return "", false
		}
	}
	switch s {
	case verdictBlockedShort, verdictBlocked2:
		return conventionActionBlock, true
	case verdictAllowed2, verdictAllowed:
		return conventionActionAllow, true
	case verdictWarn:
		return conventionActionWarn, true
	case verdictAsk:
		return conventionActionAsk, true
	default:
		return "", false
	}
}

// mapConventionSeverity maps Pipelock's 3-level severity to the
// convention's low|medium|high scale. The convention's `critical` tier
// is reserved for future promotion logic and is not emitted in v0.
func mapConventionSeverity(sev Severity) string {
	switch sev {
	case SeverityCritical:
		return conventionSeverityHigh
	case SeverityWarn:
		return conventionSeverityMedium
	default:
		return conventionSeverityLow
	}
}

// resolveConventionRule chooses the rule_id and ruleset attributes for
// a given event using these precedence rules:
//
//  1. primary_rule_id AND non-empty bundle_version (set together by the
//     audit logger when a bundle rule matched) → pipelock-rules@<bundle-version>.
//  2. pattern (single matched pattern name) → pipelock-core@<binary-version>.
//  3. scanner (scanner label like "ssrf", "entropy") → pipelock-core@<binary-version>.
//  4. empty pair → caller suppresses.
//
// Provenance integrity: a primary_rule_id without a bundle_version
// scalar is treated as malformed, NOT promoted to the core namespace.
// Emitting a bundle-origin rule ID under pipelock-core@<v> would
// mislabel detection source and weaken forensic trust in the audit
// stream. When bundle_version is absent, the function falls through to
// the pattern / scanner paths instead.
//
// Cases 2 and 3 use pipelock-core@<v> because the detection logic itself
// is part of the Pipelock binary, even though a specific pattern matched.
// A future refinement may differentiate core-default DLP patterns (built
// into the binary) from operator-supplied patterns (loaded from a config
// file but not a versioned bundle); v0 treats both as core.
func resolveConventionRule(fields map[string]any, binaryVersion string) (ruleID, ruleset string) {
	if primary, ok := fields[fieldPrimaryRuleID].(string); ok && primary != "" {
		if bv, bvOK := fields[fieldBundleVersion].(string); bvOK && bv != "" {
			return primary, rulesetNamespaceBundlePrefix + bv
		}
		// Bundle ID without bundle version: malformed. Fall through to
		// pattern/scanner rather than promote bundle-origin metadata to
		// the core namespace.
	}
	if p, ok := fields[fieldPattern].(string); ok && p != "" {
		return p, rulesetNamespaceCorePrefix + binaryVersion
	}
	if sc, ok := fields[fieldScanner].(string); ok && sc != "" {
		return sc, rulesetNamespaceCorePrefix + binaryVersion
	}
	return "", ""
}
