// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

const (
	testBinaryVersion        = "v2.5.0"
	testBundleVersion        = "1.2.3"
	testRuleIDDefault        = "test-rule-7"
	testPatternDefault       = "aws-access-key-id"
	testScannerDefault       = "ssrf"
	testRequestIDDefault     = "req-abc-123"
	testRuleIDFromBundle     = "example-bundle-rule-001"
	expectedCorePrefix       = "pipelock-core@"
	expectedBundlePrefix     = "pipelock-rules@"
	expectedCorrelationVal   = testRequestIDDefault
	conventionVerdictBlocked = "block"
	conventionVerdictAllowed = "allow"
)

// fieldsFor builds a minimal emit.Event.Fields map for the table tests.
// Callers override entries by post-mutation.
func fieldsFor(action string) map[string]any {
	return map[string]any{
		fieldAction:    action,
		fieldRequestID: testRequestIDDefault,
	}
}

func TestAgentThreatDetectionAttrs_ActionMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		raw      any
		want     string
		wantEmit bool
	}{
		{name: conventionVerdictBlocked, raw: conventionVerdictBlocked, want: conventionActionBlock, wantEmit: true},
		{name: "blocked-alias", raw: testEventBlocked, want: conventionActionBlock, wantEmit: true},
		{name: "allow", raw: "allow", want: conventionActionAllow, wantEmit: true},
		{name: "allowed-alias", raw: verdictAllowed, want: conventionActionAllow, wantEmit: true},
		{name: testSeverityWarn, raw: testSeverityWarn, want: conventionActionWarn, wantEmit: true},
		{name: conventionActionAsk, raw: conventionActionAsk, want: conventionActionAsk, wantEmit: true},
		{name: "strip-suppressed", raw: testActionStrip, wantEmit: false},
		{name: "forward-suppressed", raw: "forward", wantEmit: false},
		{name: "redirect-suppressed", raw: EventRedirect, wantEmit: false},
		{name: "unknown-suppressed", raw: "magic", wantEmit: false},
		{name: "non-string-suppressed", raw: 42, wantEmit: false},
		{name: "nil-suppressed", raw: nil, wantEmit: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			event := Event{Fields: map[string]any{fieldAction: tc.raw}}
			got, ok := mapConventionAction(event)
			if ok != tc.wantEmit {
				t.Fatalf("mapConventionAction(%v) ok=%v want=%v", tc.raw, ok, tc.wantEmit)
			}
			if ok && got != tc.want {
				t.Fatalf("mapConventionAction(%v)=%q want=%q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestAgentThreatDetectionAttrs_ActionMappingForLegacyBlockedEvents(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		eventType   string
		withScanner bool
		wantEmit    bool
	}{
		{name: "generic-blocked-with-scanner", eventType: eventTypeBlocked, withScanner: true, wantEmit: true},
		{name: "websocket-blocked-with-scanner", eventType: eventTypeWSBlocked, withScanner: true, wantEmit: true},
		{name: "anomaly-is-not-an-enforcement-action", eventType: EventAnomaly, withScanner: true, wantEmit: false},
		// Defense-in-depth: legacy fallback must require a scanner
		// identifier so future code reusing the testEventBlocked or EventWSBlocked
		// type for a lifecycle / error event cannot be promoted to a
		// convention block decision.
		{name: "blocked-without-scanner-suppresses", eventType: eventTypeBlocked, withScanner: false, wantEmit: false},
		{name: "ws-blocked-without-scanner-suppresses", eventType: eventTypeWSBlocked, withScanner: false, wantEmit: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fields := map[string]any{}
			if tc.withScanner {
				fields[fieldScanner] = testScannerDefault
			}
			event := Event{Type: tc.eventType, Fields: fields}
			got, ok := mapConventionAction(event)
			if ok != tc.wantEmit {
				t.Fatalf("mapConventionAction(type=%s scanner=%v) ok=%v want=%v",
					tc.eventType, tc.withScanner, ok, tc.wantEmit)
			}
			if ok && got != conventionActionBlock {
				t.Fatalf("mapConventionAction(%s)=%q want=%q", tc.eventType, got, conventionActionBlock)
			}
		})
	}
}

func TestAgentThreatDetectionAttrs_SeverityMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   Severity
		want string
	}{
		{name: "info-to-low", in: SeverityInfo, want: conventionSeverityLow},
		{name: "warn-to-medium", in: SeverityWarn, want: conventionSeverityMedium},
		{name: "critical-to-high", in: SeverityCritical, want: conventionSeverityHigh},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := mapConventionSeverity(tc.in); got != tc.want {
				t.Fatalf("mapConventionSeverity(%v)=%q want=%q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAgentThreatDetectionAttrs_RulesetResolution(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		fields      map[string]any
		wantRuleID  string
		wantRuleset string
	}{
		{
			name: "bundle-rule-hit",
			fields: map[string]any{
				fieldPrimaryRuleID: testRuleIDFromBundle,
				fieldBundleVersion: testBundleVersion,
			},
			wantRuleID:  testRuleIDFromBundle,
			wantRuleset: expectedBundlePrefix + testBundleVersion,
		},
		{
			// Provenance integrity: bundle-origin rule ID without a
			// bundle_version scalar must NOT be promoted to the core
			// namespace. With no pattern/scanner to fall back on, the
			// caller suppresses the entire convention attribute set.
			name: "bundle-id-without-version-suppresses",
			fields: map[string]any{
				fieldPrimaryRuleID: testRuleIDFromBundle,
				// no fieldBundleVersion
			},
			wantRuleID:  "",
			wantRuleset: "",
		},
		{
			// Bundle ID without version, but a real scanner-side label
			// IS available: fall through to the scanner identifier
			// under the core namespace. The bundle metadata is dropped
			// rather than mislabeled.
			name: "bundle-id-without-version-falls-through-to-scanner",
			fields: map[string]any{
				fieldPrimaryRuleID: testRuleIDFromBundle,
				// no fieldBundleVersion
				fieldScanner: testScannerDefault,
			},
			wantRuleID:  testScannerDefault,
			wantRuleset: expectedCorePrefix + testBinaryVersion,
		},
		{
			name: "pattern-only-uses-core",
			fields: map[string]any{
				fieldPattern: testPatternDefault,
			},
			wantRuleID:  testPatternDefault,
			wantRuleset: expectedCorePrefix + testBinaryVersion,
		},
		{
			name: "scanner-label-only-uses-core",
			fields: map[string]any{
				fieldScanner: testScannerDefault,
			},
			wantRuleID:  testScannerDefault,
			wantRuleset: expectedCorePrefix + testBinaryVersion,
		},
		{
			name: "pattern-takes-precedence-over-scanner",
			fields: map[string]any{
				fieldPattern: testPatternDefault,
				fieldScanner: testScannerDefault,
			},
			wantRuleID:  testPatternDefault,
			wantRuleset: expectedCorePrefix + testBinaryVersion,
		},
		{
			name: "primary-rule-id-takes-precedence-over-pattern",
			fields: map[string]any{
				fieldPrimaryRuleID: testRuleIDDefault,
				fieldBundleVersion: testBundleVersion,
				fieldPattern:       testPatternDefault,
				fieldScanner:       testScannerDefault,
			},
			wantRuleID:  testRuleIDDefault,
			wantRuleset: expectedBundlePrefix + testBundleVersion,
		},
		{
			name:   "no-identifiable-rule-returns-empty",
			fields: map[string]any{
				// no rule identifiers
			},
			wantRuleID:  "",
			wantRuleset: "",
		},
		{
			name: "empty-pattern-string-falls-through",
			fields: map[string]any{
				fieldPattern: "",
				fieldScanner: testScannerDefault,
			},
			wantRuleID:  testScannerDefault,
			wantRuleset: expectedCorePrefix + testBinaryVersion,
		},
		{
			name: "non-string-rule-id-ignored",
			fields: map[string]any{
				fieldPrimaryRuleID: 42,
				fieldScanner:       testScannerDefault,
			},
			wantRuleID:  testScannerDefault,
			wantRuleset: expectedCorePrefix + testBinaryVersion,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotID, gotRS := resolveConventionRule(tc.fields, testBinaryVersion)
			if gotID != tc.wantRuleID || gotRS != tc.wantRuleset {
				t.Fatalf("resolveConventionRule got=(%q, %q) want=(%q, %q)",
					gotID, gotRS, tc.wantRuleID, tc.wantRuleset)
			}
		})
	}
}

func TestAgentThreatDetectionAttrs_FullEventMapping(t *testing.T) {
	t.Parallel()
	t.Run("bundle-rule-block", func(t *testing.T) {
		fields := fieldsFor(conventionVerdictBlocked)
		fields[fieldPrimaryRuleID] = testRuleIDFromBundle
		fields[fieldBundleVersion] = testBundleVersion
		event := Event{
			Severity:   SeverityCritical,
			Type:       testEventBlocked,
			Timestamp:  time.Now(),
			InstanceID: testInstanceName,
			Fields:     fields,
		}
		attrs := agentThreatDetectionAttrs(event, testBinaryVersion)
		want := map[string]string{
			attrAgentThreatRuleID:        testRuleIDFromBundle,
			attrAgentThreatRuleset:       expectedBundlePrefix + testBundleVersion,
			attrAgentThreatSeverity:      conventionSeverityHigh,
			attrAgentThreatAction:        conventionActionBlock,
			attrAgentThreatCorrelationID: expectedCorrelationVal,
		}
		assertAttrs(t, attrs, want)
	})

	t.Run("core-scanner-warn-no-request-id", func(t *testing.T) {
		event := Event{
			Severity:  SeverityWarn,
			Type:      EventResponseScan,
			Timestamp: time.Now(),
			Fields: map[string]any{
				fieldAction:  testSeverityWarn,
				fieldScanner: testScannerDefault,
				// no request_id — correlation_id should be omitted
			},
		}
		attrs := agentThreatDetectionAttrs(event, testBinaryVersion)
		want := map[string]string{
			attrAgentThreatRuleID:   testScannerDefault,
			attrAgentThreatRuleset:  expectedCorePrefix + testBinaryVersion,
			attrAgentThreatSeverity: conventionSeverityMedium,
			attrAgentThreatAction:   conventionActionWarn,
		}
		assertAttrs(t, attrs, want)
		if hasKey(attrs, attrAgentThreatCorrelationID) {
			t.Fatalf("correlation_id present despite missing request_id")
		}
	})

	t.Run("suppressed-strip-verdict", func(t *testing.T) {
		event := Event{
			Severity: SeverityInfo,
			Fields: map[string]any{
				fieldAction:  testActionStrip,
				fieldScanner: testScannerDefault,
			},
		}
		if got := agentThreatDetectionAttrs(event, testBinaryVersion); got != nil {
			t.Fatalf("strip should suppress; got %d attrs", len(got))
		}
	})

	t.Run("suppressed-no-rule-identifier", func(t *testing.T) {
		event := Event{
			Severity: SeverityWarn,
			Fields: map[string]any{
				fieldAction: conventionVerdictBlocked,
				// no pattern/scanner/primary_rule_id
			},
		}
		if got := agentThreatDetectionAttrs(event, testBinaryVersion); got != nil {
			t.Fatalf("missing rule identifier should suppress; got %d attrs", len(got))
		}
	})

	t.Run("ask-verdict-allow-action", func(t *testing.T) {
		event := Event{
			Severity: SeverityWarn,
			Fields: map[string]any{
				fieldAction:        conventionActionAsk,
				fieldPrimaryRuleID: testRuleIDDefault,
				fieldBundleVersion: testBundleVersion,
				fieldRequestID:     testRequestIDDefault,
			},
		}
		attrs := agentThreatDetectionAttrs(event, testBinaryVersion)
		want := map[string]string{
			attrAgentThreatRuleID:        testRuleIDDefault,
			attrAgentThreatRuleset:       expectedBundlePrefix + testBundleVersion,
			attrAgentThreatSeverity:      conventionSeverityMedium,
			attrAgentThreatAction:        conventionActionAsk,
			attrAgentThreatCorrelationID: expectedCorrelationVal,
		}
		assertAttrs(t, attrs, want)
	})

	t.Run("generic-blocked-event-infers-block-action", func(t *testing.T) {
		event := Event{
			Severity: SeverityCritical,
			Type:     eventTypeBlocked,
			Fields: map[string]any{
				fieldScanner:   testScannerDefault,
				fieldRequestID: testRequestIDDefault,
			},
		}
		attrs := agentThreatDetectionAttrs(event, testBinaryVersion)
		want := map[string]string{
			attrAgentThreatRuleID:        testScannerDefault,
			attrAgentThreatRuleset:       expectedCorePrefix + testBinaryVersion,
			attrAgentThreatSeverity:      conventionSeverityHigh,
			attrAgentThreatAction:        conventionActionBlock,
			attrAgentThreatCorrelationID: expectedCorrelationVal,
		}
		assertAttrs(t, attrs, want)
	})

	t.Run("websocket-blocked-event-infers-block-action", func(t *testing.T) {
		event := Event{
			Severity: SeverityCritical,
			Type:     eventTypeWSBlocked,
			Fields: map[string]any{
				fieldScanner:   testScannerDefault,
				fieldRequestID: testRequestIDDefault,
			},
		}
		attrs := agentThreatDetectionAttrs(event, testBinaryVersion)
		want := map[string]string{
			attrAgentThreatRuleID:        testScannerDefault,
			attrAgentThreatRuleset:       expectedCorePrefix + testBinaryVersion,
			attrAgentThreatSeverity:      conventionSeverityHigh,
			attrAgentThreatAction:        conventionActionBlock,
			attrAgentThreatCorrelationID: expectedCorrelationVal,
		}
		assertAttrs(t, attrs, want)
	})
}

func TestOTLPSink_AgentThreatDetectionToggle(t *testing.T) {
	t.Parallel()
	sink := &OTLPSink{version: testBinaryVersion}
	event := Event{
		Severity:   SeverityWarn,
		Type:       EventResponseScan,
		Timestamp:  time.Now(),
		InstanceID: testInstanceName,
		Fields: map[string]any{
			fieldAction:    conventionVerdictAllowed,
			fieldPattern:   testPatternDefault,
			fieldRequestID: testRequestIDDefault,
		},
	}

	t.Run("disabled-by-default", func(t *testing.T) {
		record := sink.eventToLogRecord(event)
		if hasKey(record.Attributes, attrAgentThreatRuleID) {
			t.Fatalf("convention attrs leaked through when flag off")
		}
	})

	t.Run("enabled-appends-attrs", func(t *testing.T) {
		s := &OTLPSink{version: testBinaryVersion}
		s.EnableAgentThreatDetection()
		record := s.eventToLogRecord(event)
		if !hasKey(record.Attributes, attrAgentThreatRuleID) {
			t.Fatalf("convention attrs missing after EnableAgentThreatDetection")
		}
		if !hasKey(record.Attributes, attrAgentThreatCorrelationID) {
			t.Fatalf("correlation_id missing despite request_id in event")
		}
	})

	t.Run("enabled-but-suppressed-action-emits-no-attrs", func(t *testing.T) {
		s := &OTLPSink{version: testBinaryVersion}
		s.EnableAgentThreatDetection()
		stripEvent := event
		stripEvent.Fields = map[string]any{
			fieldAction:  testActionStrip,
			fieldPattern: testPatternDefault,
		}
		record := s.eventToLogRecord(stripEvent)
		if hasKey(record.Attributes, attrAgentThreatRuleID) {
			t.Fatalf("strip verdict should suppress convention attrs even with flag on")
		}
	})
}

// TestAgentThreatDetectionAttrs_GoldenSample writes a representative OTLP
// LogRecord (with both Pipelock-native fields and the convention attrs)
// to testdata/otlp_agent_threat_sample.json. Suitable for attaching to
// the OTEP discussion as a reference artifact.
func TestAgentThreatDetectionAttrs_GoldenSample(t *testing.T) {
	t.Parallel()
	s := &OTLPSink{version: testBinaryVersion}
	s.EnableAgentThreatDetection()
	const fixedTimestamp = "2026-05-13T15:00:00Z"
	ts, err := time.Parse(time.RFC3339, fixedTimestamp)
	if err != nil {
		t.Fatalf("parse fixed timestamp: %v", err)
	}
	event := Event{
		Severity:   SeverityCritical,
		Type:       testEventBlocked,
		Timestamp:  ts,
		InstanceID: "pipelock-sample",
		Fields: map[string]any{
			fieldAction:        conventionVerdictBlocked,
			fieldPattern:       testPatternDefault,
			fieldPrimaryRuleID: testRuleIDFromBundle,
			fieldBundleVersion: testBundleVersion,
			fieldRequestID:     testRequestIDDefault,
			"transport":        "forward",
			"layer":            "dlp",
		},
	}
	record := s.eventToLogRecord(event)

	// Encode the attribute set into a deterministic JSON map keyed by
	// attribute name so the golden file is stable. The protobuf record
	// itself orders attributes by Go map iteration, which is non-deterministic.
	attrMap := make(map[string]string, len(record.Attributes))
	for _, kv := range record.Attributes {
		if v, ok := kv.Value.Value.(*commonpb.AnyValue_StringValue); ok {
			attrMap[kv.Key] = v.StringValue
		}
	}

	type sample struct {
		Timestamp      string            `json:"timestamp"`
		SeverityNumber int32             `json:"severity_number"`
		SeverityText   string            `json:"severity_text"`
		BodyType       string            `json:"body_type"`
		Attributes     map[string]string `json:"attributes"`
	}
	out := sample{
		Timestamp:      fixedTimestamp,
		SeverityNumber: int32(record.SeverityNumber),
		SeverityText:   record.SeverityText,
		BodyType:       event.Type,
		Attributes:     attrMap,
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	dir := filepath.Join("testdata")
	if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
		t.Fatalf("mkdir testdata: %v", mkErr)
	}
	path := filepath.Join(dir, "otlp_agent_threat_sample.json")
	if writeErr := os.WriteFile(path, append(data, '\n'), 0o600); writeErr != nil {
		t.Fatalf("write sample: %v", writeErr)
	}

	// Sanity: the convention attrs must all be present in the sample.
	for _, key := range []string{
		attrAgentThreatRuleID,
		attrAgentThreatRuleset,
		attrAgentThreatSeverity,
		attrAgentThreatAction,
		attrAgentThreatCorrelationID,
	} {
		if _, ok := attrMap[key]; !ok {
			t.Fatalf("golden sample missing %q", key)
		}
	}
	// And the matched ruleset must be the bundle namespace.
	if got := attrMap[attrAgentThreatRuleset]; got != expectedBundlePrefix+testBundleVersion {
		t.Fatalf("golden ruleset=%q want=%q", got, expectedBundlePrefix+testBundleVersion)
	}
}

func TestBundleRulesField_PopulatesScalarFields(t *testing.T) {
	// This test lives in the emit package because that is where the
	// emit-side contract is consumed; the audit package owns the writer
	// side. We exercise the contract end-to-end by constructing an Event
	// that mirrors what the audit logger produces, then mapping it.
	t.Parallel()
	event := Event{
		Severity: SeverityWarn,
		Fields: map[string]any{
			fieldAction:        conventionVerdictBlocked,
			fieldPrimaryRuleID: testRuleIDFromBundle,
			fieldBundleVersion: testBundleVersion,
			fieldRequestID:     testRequestIDDefault,
		},
	}
	attrs := agentThreatDetectionAttrs(event, testBinaryVersion)
	wantRuleset := expectedBundlePrefix + testBundleVersion
	if got := lookup(attrs, attrAgentThreatRuleset); got != wantRuleset {
		t.Fatalf("ruleset=%q want=%q", got, wantRuleset)
	}
}

// assertAttrs verifies that attrs contains every (key, value) pair in
// want and no others. Order is not checked.
func assertAttrs(t *testing.T, attrs []*commonpb.KeyValue, want map[string]string) {
	t.Helper()
	got := make(map[string]string, len(attrs))
	for _, kv := range attrs {
		if v, ok := kv.Value.Value.(*commonpb.AnyValue_StringValue); ok {
			got[kv.Key] = v.StringValue
		}
	}
	if len(got) != len(want) {
		t.Fatalf("attr count got=%d want=%d (got=%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if gv, ok := got[k]; !ok || gv != v {
			t.Fatalf("attr %q got=%q want=%q", k, gv, v)
		}
	}
}

// hasKey reports whether attrs contains an attribute with the given key.
func hasKey(attrs []*commonpb.KeyValue, key string) bool {
	for _, kv := range attrs {
		if kv.Key == key {
			return true
		}
	}
	return false
}

// lookup returns the string value of the attribute with the given key, or "".
func lookup(attrs []*commonpb.KeyValue, key string) string {
	for _, kv := range attrs {
		if kv.Key == key {
			if v, ok := kv.Value.Value.(*commonpb.AnyValue_StringValue); ok {
				return v.StringValue
			}
		}
	}
	return ""
}
