// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestFormatOCSFEventDetectionFinding(t *testing.T) {
	ts := time.Date(2026, 7, 5, 12, 34, 56, 789000000, time.UTC)
	event := Event{
		Severity:   SeverityWarn,
		Type:       EventBodyDLP,
		Timestamp:  ts,
		InstanceID: testInstanceName,
		Fields: map[string]any{
			"action":     conventionActionBlock,
			"agent":      "agent-a",
			"client_ip":  "203.0.113.10",
			"method":     "POST",
			"pattern":    "api-key",
			"request_id": "req-123",
			"scanner":    "dlp",
			"url":        "https://api.vendor.example/v1/chat?mode=sync",
			fieldReason:  "secret detected",
		},
	}

	got := parseOCSFEvent(t, FormatOCSFEvent(event, "1.2.3"))
	assertNumber(t, got, "class_uid", 2004)
	assertString(t, got, "class_name", "Detection Finding")
	assertNumber(t, got, "category_uid", 2)
	assertString(t, got, "category_name", "Findings")
	assertNumber(t, got, "activity_id", 1)
	assertString(t, got, "activity_name", "Create")
	assertNumber(t, got, "type_uid", 200401)
	assertString(t, got, "type_name", "Detection Finding: Create")
	assertNumber(t, got, "severity_id", 3)
	assertString(t, got, "severity", "Medium")
	assertNumber(t, got, "time", float64(ts.UnixMilli()))
	assertString(t, got, "status", "New")
	assertNumber(t, got, "status_id", 1)
	assertString(t, got, "message", "body_dlp: secret detected")
	assertString(t, got, "action", "block")
	assertNumber(t, got, "action_id", 2)
	assertString(t, got, "status_detail", "secret detected")

	metadata := assertMap(t, got, "metadata")
	assertString(t, metadata, "version", ocsfSchemaVersion)
	product := assertMap(t, metadata, "product")
	assertString(t, product, "vendor_name", "Pipelock")
	assertString(t, product, "name", "Pipelock")
	assertString(t, product, "version", "1.2.3")

	findingInfo := assertMap(t, got, "finding_info")
	assertString(t, findingInfo, "title", "body_dlp: secret detected")
	assertString(t, findingInfo, "desc", "secret detected")
	assertNumber(t, findingInfo, "created_time", float64(ts.UnixMilli()))
	if uid := stringValue(t, findingInfo, "uid"); uid == "" {
		t.Fatal("finding_info.uid is empty")
	}

	actor := assertMap(t, got, "actor")
	user := assertMap(t, actor, "user")
	assertString(t, user, "name", "agent-a")
	src := assertMap(t, got, "src_endpoint")
	assertString(t, src, "ip", "203.0.113.10")
	dst := assertMap(t, got, "dst_endpoint")
	assertString(t, dst, "hostname", "api.vendor.example")
	eventURL := assertMap(t, got, "url")
	assertString(t, eventURL, "url_string", "https://api.vendor.example/v1/chat?mode=sync")
	assertString(t, eventURL, "hostname", "api.vendor.example")
	assertString(t, eventURL, "path", "/v1/chat")
	assertString(t, eventURL, "query_string", "mode=sync")
	req := assertMap(t, got, "http_request")
	assertString(t, req, "http_method", "POST")
	assertString(t, req, "uid", "req-123")

	unmapped := assertMap(t, got, "unmapped")
	pipelock := assertMap(t, unmapped, "pipelock")
	assertString(t, pipelock, "event_type", EventBodyDLP)
	assertString(t, pipelock, "severity", "warn")
	assertString(t, pipelock, "instance_id", testInstanceName)
	assertString(t, pipelock, "decision_type", EventBodyDLP)
	fields := assertMap(t, pipelock, "fields")
	assertString(t, fields, "scanner", "dlp")
	assertString(t, fields, "pattern", "api-key")
}

func TestFormatOCSFEventSeverityMapping(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		wantID   float64
		wantName string
	}{
		{name: "info", severity: SeverityInfo, wantID: 1, wantName: "Informational"},
		{name: "warn", severity: SeverityWarn, wantID: 3, wantName: "Medium"},
		{name: "critical", severity: SeverityCritical, wantID: 5, wantName: "Critical"},
		{name: "unknown", severity: Severity(99), wantID: 0, wantName: "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOCSFEvent(t, FormatOCSFEvent(Event{
				Severity:  tt.severity,
				Type:      EventResponseScan,
				Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
				Fields:    map[string]any{},
			}, "dev"))
			assertNumber(t, got, "severity_id", tt.wantID)
			assertString(t, got, "severity", tt.wantName)
		})
	}
}

func TestFormatOCSFEventDoesNotHTMLEscape(t *testing.T) {
	event := Event{
		Severity:  SeverityCritical,
		Type:      EventBlocked,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields: map[string]any{
			fieldReason: "<script>&blocked",
			"url":       "https://api.vendor.example/path?q=<token>&mode=test",
		},
	}

	line := FormatOCSFEvent(event, "dev")
	if strings.Contains(line, `\u003c`) || strings.Contains(line, `\u003e`) || strings.Contains(line, `\u0026`) {
		t.Fatalf("OCSF line HTML-escaped characters:\n%s", line)
	}
	got := parseOCSFEvent(t, line)
	assertString(t, got, "message", "blocked: <script>&blocked")
}

func TestFormatOCSFEventEscapesControlsAndIsDeterministic(t *testing.T) {
	event := Event{
		Severity:   SeverityWarn,
		Type:       EventBlocked,
		Timestamp:  time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		InstanceID: testInstanceName,
		Fields: map[string]any{
			fieldReason:   "quoted \" value\nnext line\x01",
			"unsupported": map[int]string{1: "one"},
			"z":           "last",
			"a":           "first",
		},
	}

	first := FormatOCSFEvent(event, "dev")
	second := FormatOCSFEvent(event, "dev")
	if first != second {
		t.Fatalf("OCSF output is not deterministic:\nfirst:  %s\nsecond: %s", first, second)
	}

	got := parseOCSFEvent(t, first)
	assertString(t, got, "message", "blocked: quoted \" value\nnext line\x01")
	fields := assertMap(t, assertMap(t, assertMap(t, got, "unmapped"), "pipelock"), "fields")
	assertString(t, fields, "unsupported", "[unsupported]")
}

func TestFormatOCSFEventHandlesUnmarshalableFields(t *testing.T) {
	line := FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventError,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields: map[string]any{
			"bad": make(chan int),
		},
	}, "dev")
	got := parseOCSFEvent(t, line)
	fields := assertMap(t, assertMap(t, assertMap(t, got, "unmapped"), "pipelock"), "fields")
	if _, ok := fields["bad"].(string); !ok {
		t.Fatalf("unmarshalable field was not rendered as string: %#v", fields["bad"])
	}
}

func TestFormatOCSFEventHandlesCyclicFields(t *testing.T) {
	fields := map[string]any{}
	fields["self"] = fields

	line := FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventError,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields:    fields,
	}, "dev")
	got := parseOCSFEvent(t, line)
	pipelock := assertMap(t, assertMap(t, got, "unmapped"), "pipelock")
	if _, ok := pipelock["fields"].(map[string]any); !ok {
		t.Fatalf("cyclic fields were not preserved as a JSON object: %#v", pipelock["fields"])
	}
}

func TestFormatOCSFEventHandlesNonFiniteNumbers(t *testing.T) {
	line := FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventError,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields: map[string]any{
			"nan":      math.NaN(),
			"positive": math.Inf(1),
			"negative": float32(math.Inf(-1)),
		},
	}, "dev")
	got := parseOCSFEvent(t, line)
	assertNumber(t, got, "class_uid", ocsfClassUIDDetectionFinding)
	assertString(t, got, "message", EventError)

	fields := assertMap(t, assertMap(t, assertMap(t, got, "unmapped"), "pipelock"), "fields")
	assertString(t, fields, "nan", "NaN")
	assertString(t, fields, "positive", "+Inf")
	assertString(t, fields, "negative", "-Inf")
}

func parseOCSFEvent(t *testing.T, line string) map[string]any {
	t.Helper()
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("OCSF line is not compact single-line JSON: %q", line)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("OCSF line is not valid JSON: %v\n%s", err, line)
	}
	return out
}

func assertMap(t *testing.T, values map[string]any, key string) map[string]any {
	t.Helper()
	got, ok := values[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, values[key])
	}
	return got
}

func assertString(t *testing.T, values map[string]any, key, want string) {
	t.Helper()
	if got := stringValue(t, values, key); got != want {
		t.Fatalf("%s = %q, want %q", key, got, want)
	}
}

func stringValue(t *testing.T, values map[string]any, key string) string {
	t.Helper()
	got, ok := values[key].(string)
	if !ok {
		t.Fatalf("%s = %#v, want string", key, values[key])
	}
	return got
}

func assertNumber(t *testing.T, values map[string]any, key string, want float64) {
	t.Helper()
	got, ok := values[key].(float64)
	if !ok {
		t.Fatalf("%s = %#v, want number", key, values[key])
	}
	if got != want {
		t.Fatalf("%s = %v, want %v", key, got, want)
	}
}

func TestFormatOCSFEventMinimalEventOmitsOptionalFields(t *testing.T) {
	line := FormatOCSFEvent(Event{
		Severity:  SeverityInfo,
		Type:      EventError,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
	}, "dev")
	got := parseOCSFEvent(t, line)
	assertNumber(t, got, "class_uid", ocsfClassUIDDetectionFinding)
	for _, key := range []string{"actor", "url", "http_request", "src_endpoint", "dst_endpoint"} {
		if _, present := got[key]; present {
			t.Fatalf("optional field %q should be omitted for a fieldless event: %#v", key, got[key])
		}
	}
}

func TestOCSFActionID(t *testing.T) {
	tests := map[string]int{
		conventionActionAllow: 1,
		eventActionForward:    1,
		EventRedirect:         1,
		conventionActionBlock: 2,
		eventActionStrip:      2,
		conventionActionWarn:  99,
		conventionActionAsk:   99,
		eventActionDefer:      99,
		"":                    0,
		"something-else":      0,
	}
	for action, want := range tests {
		if got := ocsfActionID(action); got != want {
			t.Fatalf("ocsfActionID(%q) = %d, want %d", action, got, want)
		}
	}
}

type ocsfStringerFixture struct{}

func (ocsfStringerFixture) String() string { return "stringer-value" }

func TestOCSFJSONValueDepthTypes(t *testing.T) {
	if got := ocsfJSONValueDepth("x", 17); got != "[truncated]" {
		t.Fatalf("depth guard = %#v, want [truncated]", got)
	}
	if got := ocsfJSONValue(nil); got != nil {
		t.Fatalf("nil = %#v, want nil", got)
	}
	if got := ocsfJSONValue(ocsfStringerFixture{}); got != "stringer-value" {
		t.Fatalf("stringer = %#v, want stringer-value", got)
	}
	if got, ok := ocsfJSONValue([]string{"a", "b"}).([]string); !ok || len(got) != 2 {
		t.Fatalf("[]string = %#v, want 2-element []string", got)
	}
	if got, ok := ocsfJSONValue([]any{1, "b"}).([]any); !ok || len(got) != 2 {
		t.Fatalf("[]any = %#v, want 2-element []any", got)
	}
	if got, ok := ocsfJSONValue(map[string]any{"k": "v"}).(map[string]any); !ok || got["k"] != "v" {
		t.Fatalf("map[string]any = %#v", got)
	}
	if got, ok := ocsfJSONValue(map[string]string{"k": "v"}).(map[string]any); !ok || got["k"] != "v" {
		t.Fatalf("map[string]string = %#v", got)
	}
	if got, ok := ocsfJSONValue([3]int{1, 2, 3}).([]any); !ok || len(got) != 3 {
		t.Fatalf("reflect array = %#v, want 3-element []any", got)
	}
	if got := ocsfJSONValue(map[int]string{1: "a"}); got != "[unsupported]" {
		t.Fatalf("non-string-key map = %#v, want [unsupported]", got)
	}
	if got, ok := ocsfJSONValue(map[string]int{"n": 7}).(map[string]any); !ok || got["n"].(int) != 7 {
		t.Fatalf("reflect string-key map = %#v", got)
	}
}

func TestFallbackOCSFEventEmitsValidFindingWithErrorMarker(t *testing.T) {
	record := ocsfDetectionFinding{
		ClassUID:    ocsfClassUIDDetectionFinding,
		Message:     "blocked: ssrf",
		StatusID:    ocsfStatusIDNew,
		FindingInfo: ocsfFindingInfo{Title: "blocked: ssrf"},
		Actor:       &ocsfActor{User: ocsfUser{Name: "agent-a"}},
		URL:         &ocsfURL{URLString: "http://host.vendor.example/"},
		Unmapped: map[string]any{
			"pipelock": map[string]any{"event_type": "blocked"},
		},
	}
	line := fallbackOCSFEvent(record, errors.New("boom"))
	got := parseOCSFEvent(t, line)
	assertNumber(t, got, "class_uid", ocsfClassUIDDetectionFinding)
	if msg := stringValue(t, got, "message"); !strings.HasPrefix(msg, "ocsf_format_error: ") {
		t.Fatalf("message = %q, want ocsf_format_error prefix", msg)
	}
	assertString(t, got, "status_detail", "boom")
	pipelock := assertMap(t, assertMap(t, got, "unmapped"), "pipelock")
	assertString(t, pipelock, "event_type", "blocked")
	assertString(t, pipelock, "ocsf_format_error", "boom")
	for _, key := range []string{"actor", "url", "http_request", "src_endpoint", "dst_endpoint"} {
		if _, present := got[key]; present {
			t.Fatalf("fallback should strip typed field %q: %#v", key, got[key])
		}
	}
}

func TestFormatOCSFEventBranchCoverage(t *testing.T) {
	// Empty deviceVersion default, explicit URL port, finite float field, and an
	// event whose action resolves to none (action_id 0, which clears the label).
	got := parseOCSFEvent(t, FormatOCSFEvent(Event{
		Severity:  SeverityInfo,
		Type:      "synthetic_note_event", // no known action mapping -> action_id 0
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields: map[string]any{
			"url":   "https://api.vendor.example:8443/v1?x=1",
			"score": float64(1.5),
			"ratio": float32(0.25),
		},
	}, ""))
	product := assertMap(t, assertMap(t, got, "metadata"), "product")
	assertString(t, product, "version", "unknown")
	if _, present := got["action"]; present {
		t.Fatalf("unknown action should be cleared, got %#v", got["action"])
	}
	assertNumber(t, assertMap(t, got, "url"), "port", 8443)
	fields := assertMap(t, assertMap(t, assertMap(t, got, "unmapped"), "pipelock"), "fields")
	assertNumber(t, fields, "score", 1.5)
	assertNumber(t, fields, "ratio", 0.25)
}

func TestFormatOCSFEventHostnameTargetAndUnparseableURL(t *testing.T) {
	// dst_endpoint hostname branch: a target with no URL field.
	got := parseOCSFEvent(t, FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventBlocked,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields:    map[string]any{"target": "backend.vendor.example"},
	}, "dev"))
	assertString(t, assertMap(t, got, "dst_endpoint"), "hostname", "backend.vendor.example")

	// url.Parse error branch: a control character makes net/url reject the URL,
	// so only the raw url_string is carried.
	got2 := parseOCSFEvent(t, FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventBlocked,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields:    map[string]any{"url": "http://bad\x7fhost/path"},
	}, "dev"))
	assertString(t, assertMap(t, got2, "url"), "url_string", "http://bad\x7fhost/path")
}

func TestFormatOCSFEventBoundsHostileFields(t *testing.T) {
	// Deeply nested fields are truncated at the depth bound so a malformed or
	// hostile event cannot drive unbounded recursion on the audit path.
	deep := any("leaf")
	for i := 0; i < 40; i++ {
		deep = map[string]any{"next": deep}
	}
	line := FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventBlocked,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields:    map[string]any{"deep": deep},
	}, "dev")
	got := parseOCSFEvent(t, line) // valid JSON => the walk stayed bounded
	assertNumber(t, got, "class_uid", ocsfClassUIDDetectionFinding)
	if !strings.Contains(line, "[truncated]") {
		t.Fatalf("deeply nested field was not truncated: %s", line)
	}

	// A wide shared-reference structure is bounded by the node budget rather
	// than expanding to branching^depth nodes.
	shared := map[string]any{"k": "v"}
	tree := any(shared)
	for i := 0; i < 20; i++ {
		tree = map[string]any{"a": tree, "b": tree, "c": tree}
	}
	wideLine := FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventBlocked,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields:    map[string]any{"tree": tree},
	}, "dev")
	if _ = parseOCSFEvent(t, wideLine); !strings.Contains(wideLine, "[truncated]") {
		t.Fatalf("wide structure was not bounded by the node budget")
	}
}

func TestFormatOCSFEventTruncatesOversizedStringField(t *testing.T) {
	huge := strings.Repeat("A", ocsfMaxStringBytes+500)
	line := FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventBlocked,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields:    map[string]any{"blob": huge},
	}, "dev")
	got := parseOCSFEvent(t, line)
	fields := assertMap(t, assertMap(t, assertMap(t, got, "unmapped"), "pipelock"), "fields")
	blob := stringValue(t, fields, "blob")
	if len(blob) >= len(huge) {
		t.Fatalf("oversized field not truncated: got %d bytes", len(blob))
	}
	if !strings.HasSuffix(blob, "...[truncated]") {
		t.Fatalf("truncated field missing marker: %q", blob[len(blob)-20:])
	}
}

func TestOCSFTruncateStringRuneSafe(t *testing.T) {
	// A string whose byte cap lands mid-rune must not emit a split (U+FFFD) rune.
	s := strings.Repeat("A", ocsfMaxStringBytes-1) + strings.Repeat("€", 8)
	line := FormatOCSFEvent(Event{
		Severity:  SeverityWarn,
		Type:      EventBlocked,
		Timestamp: time.Date(2026, 7, 5, 1, 2, 3, 0, time.UTC),
		Fields:    map[string]any{"blob": s},
	}, "dev")
	got := parseOCSFEvent(t, line)
	fields := assertMap(t, assertMap(t, assertMap(t, got, "unmapped"), "pipelock"), "fields")
	blob := stringValue(t, fields, "blob")
	if !utf8.ValidString(blob) {
		t.Fatalf("truncated field is not valid UTF-8")
	}
	if strings.ContainsRune(blob, '�') {
		t.Fatalf("truncated field split a rune (contains U+FFFD)")
	}
	if !strings.HasSuffix(blob, "...[truncated]") {
		t.Fatalf("missing truncation marker: %q", blob[max(0, len(blob)-20):])
	}
}
