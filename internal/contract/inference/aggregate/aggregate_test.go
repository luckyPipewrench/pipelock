// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aggregate

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/ingest"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestAggregate_CounterCorrectness(t *testing.T) {
	base := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	events := entries(
		entry(base, "s1", "GET", "https://API.Example.com/v1/users", "read", "allow", 10, 100),
		entry(base.Add(time.Minute), "s2", "POST", "https://api.example.com/v1/users", "write", "block", 20, 200),
		entry(base.Add(2*time.Minute), "s3", "GET", "https://other.example.com/v1/repos", "read", "allow", 5, 50),
	)

	got, err := Aggregate(events, AggregateConfig{})
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	if got.TotalEvents != 3 {
		t.Fatalf("TotalEvents = %d, want 3", got.TotalEvents)
	}
	if got.SessionCount != 3 {
		t.Fatalf("SessionCount = %d, want 3", got.SessionCount)
	}

	assertRule(t, got, "host=api.example.com", RuleCounts{
		Observed:      2,
		Opportunities: 3,
		Sessions:      2,
		Windows:       1,
	})
	assertRule(t, got, "host=api.example.com;path=/v1/users", RuleCounts{
		Observed:      2,
		Opportunities: 2,
		Sessions:      2,
		Windows:       1,
	})
	assertRule(t, got, "host=api.example.com;path=/v1/users;method=GET", RuleCounts{
		Observed:      1,
		Opportunities: 2,
		Sessions:      1,
		Windows:       1,
	})
	assertRule(t, got, "host=api.example.com;path=/v1/users;method=POST;action=block", RuleCounts{
		Observed:      1,
		Opportunities: 1,
		Sessions:      1,
		Windows:       1,
	})

	bucket := got.Budgets["host=api.example.com;path=/v1/users;method=GET"]
	if !reflect.DeepEqual(bucket.PayloadBytes, []float64{10}) {
		t.Fatalf("GET payload samples = %v, want [10]", bucket.PayloadBytes)
	}
	if budget := bucket.PayloadBudget(); budget.SampleCount != 1 || budget.Max != 10 {
		t.Fatalf("PayloadBudget() = %+v, want sample_count=1 max=10", budget)
	}
	if budget := bucket.ScannerBudget(); budget.SampleCount != 1 || budget.Max != 100 {
		t.Fatalf("ScannerBudget() = %+v, want sample_count=1 max=100", budget)
	}
}

func TestAggregate_WindowBoundaryStartsNewWindow(t *testing.T) {
	start := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	events := entries(
		entry(start.Add(time.Hour-time.Nanosecond), "s1", "GET", "https://example.com/v1/users", "read", "allow", 10, 100),
		entry(start.Add(time.Hour), "s1", "GET", "https://example.com/v1/users", "read", "allow", 20, 200),
	)

	got, err := Aggregate(events, AggregateConfig{WindowDuration: time.Hour})
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	if !got.WindowStart.Equal(start) {
		t.Fatalf("WindowStart = %s, want %s", got.WindowStart, start)
	}
	if want := start.Add(2 * time.Hour); !got.WindowEnd.Equal(want) {
		t.Fatalf("WindowEnd = %s, want %s", got.WindowEnd, want)
	}

	bucket := got.Budgets["host=example.com;path=/v1/users;method=GET"]
	want := []CountSample{
		{Start: start, Count: 1},
		{Start: start.Add(time.Hour), Count: 1},
	}
	if !reflect.DeepEqual(bucket.PerWindowCounts, want) {
		t.Fatalf("PerWindowCounts = %+v, want %+v", bucket.PerWindowCounts, want)
	}

	rule := got.Rules["host=example.com;path=/v1/users;method=GET"]
	if rule.Windows != 2 {
		t.Fatalf("method rule Windows = %d, want 2", rule.Windows)
	}
}

func TestAggregate_PerHostPathFamilyIsolation(t *testing.T) {
	base := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	events := entries(
		entry(base, "s1", "GET", "https://a.example.com/v1/users", "read", "allow", 10, 100),
		entry(base.Add(time.Minute), "s2", "GET", "https://b.example.com/v1/users", "read", "allow", 20, 200),
		entry(base.Add(2*time.Minute), "s3", "GET", "https://b.example.com/v1/users", "read", "allow", 30, 300),
	)

	got, err := Aggregate(events, AggregateConfig{})
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	aFamilies := got.PathFamilies("a.example.com")
	if len(aFamilies) != 1 || aFamilies[0].Pattern != "/v1/users" || aFamilies[0].EventCount != 1 {
		t.Fatalf("a.example.com families = %+v, want one /v1/users count 1", aFamilies)
	}
	if missing := got.PathFamilies("missing.example.com"); len(missing) != 0 {
		t.Fatalf("missing host families = %+v, want empty", missing)
	}

	bFamilies := got.PathFamilies("b.example.com")
	if len(bFamilies) != 1 || bFamilies[0].Pattern != "/v1/users" || bFamilies[0].EventCount != 2 {
		t.Fatalf("b.example.com families = %+v, want one /v1/users count 2", bFamilies)
	}
}

func TestAggregate_SortedAccessors(t *testing.T) {
	base := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	events := entries(
		entry(base, "s1", "GET", "https://z.example.com/z", "write", "allow", 1, 10),
		entry(base, "s2", "POST", "https://a.example.com/a", "read", "block", 1, 10),
	)

	got, err := Aggregate(events, AggregateConfig{})
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	if want := []string{"a.example.com", "z.example.com"}; !reflect.DeepEqual(got.HostKeys(), want) {
		t.Fatalf("HostKeys() = %v, want %v", got.HostKeys(), want)
	}
	if want := []string{"read", "write"}; !reflect.DeepEqual(got.ActionClasses(), want) {
		t.Fatalf("ActionClasses() = %v, want %v", got.ActionClasses(), want)
	}
	if keys := got.RuleKeys(); !sortStringsAlready(keys) {
		t.Fatalf("RuleKeys() not sorted: %v", keys)
	}
	if keys := got.BudgetKeys(); !sortStringsAlready(keys) {
		t.Fatalf("BudgetKeys() not sorted: %v", keys)
	}
}

func TestAggregate_RuleKeysEscapeDelimiters(t *testing.T) {
	base := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	events := entries(
		entry(base, "s1", "GET", "https://example.com/v1/users;id=1", "read", "allow", 1, 10),
	)

	got, err := Aggregate(events, AggregateConfig{})
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	key := pathRuleKey("example.com", "/v1/users;id=1")
	if _, ok := got.Rules[key]; !ok {
		t.Fatalf("missing escaped path rule %q; keys=%v", key, got.RuleKeys())
	}
	if !strings.Contains(key, "%3B") || !strings.Contains(key, "%3D") {
		t.Fatalf("path key = %q, want escaped delimiters", key)
	}
}

func TestAggregate_ActionClassDebtHistogram(t *testing.T) {
	base := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	events := entries(
		entry(base, "s1", "GET", "https://example.com/read", "read", "allow", 1, 10),
		entry(base, "s2", "GET", "https://example.com/empty", "", "allow", 1, 10),
		entry(base, "s3", "GET", "https://example.com/upper", "WRITE", "allow", 1, 10),
	)

	got, err := Aggregate(events, AggregateConfig{})
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	want := map[string]int{
		"read":                  1,
		"write":                 1,
		ActionClassUnclassified: 1,
	}
	if !reflect.DeepEqual(got.ActionClassHistogram, want) {
		t.Fatalf("ActionClassHistogram = %#v, want %#v", got.ActionClassHistogram, want)
	}
}

func TestAggregate_SkipsMalformedAndNonHTTP(t *testing.T) {
	base := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	events := entries(
		ingest.Entry{Recorder: recorder.Entry{Type: capture.EntryTypeCaptureDrop, Detail: capture.CaptureDropDetail{Count: 3}}},
		ingest.Entry{Recorder: recorder.Entry{Type: capture.EntryTypeCaptureDrop, Detail: func() {}}},
		ingest.Entry{Recorder: recorder.Entry{Timestamp: base}},
		ingest.Entry{Recorder: recorder.Entry{Timestamp: base, Type: capture.EntryTypeCapture}},
		entry(base, "s1", "GET", "ftp://example.com/v1/users", "read", "allow", 10, 100),
		entry(base, "s1", "GET", "://bad", "read", "allow", 10, 100),
		entry(base, "s1", "GET", "https://user@example.com/v1/users", "read", "allow", 10, 100),
		entry(base, "s1", "GET", "https://example.com/v1%2Fusers", "read", "allow", 10, 100),
		entry(base, "s1", "", "https://example.com/v1/users", "read", "allow", -10, -100),
	)

	got, err := Aggregate(events, AggregateConfig{})
	if err != nil {
		t.Fatalf("Aggregate() error = %v", err)
	}

	if got.TotalEvents != 1 {
		t.Fatalf("TotalEvents = %d, want 1", got.TotalEvents)
	}
	if got.DroppedEvents != 3 {
		t.Fatalf("DroppedEvents = %d, want 3", got.DroppedEvents)
	}
	if got.MalformedEvents != 6 {
		t.Fatalf("MalformedEvents = %d, want 6", got.MalformedEvents)
	}

	bucket := got.Budgets["host=example.com;path=/v1/users;method=UNKNOWN"]
	if !reflect.DeepEqual(bucket.PayloadBytes, []float64{0}) {
		t.Fatalf("UNKNOWN payload samples = %v, want [0]", bucket.PayloadBytes)
	}
}

func TestAggregate_ConfigValidationAndDefault(t *testing.T) {
	got := AggregateConfig{}.Resolved()
	if got.WindowDuration != time.Hour {
		t.Fatalf("Resolved().WindowDuration = %s, want 1h", got.WindowDuration)
	}

	_, err := Aggregate(entries(), AggregateConfig{WindowDuration: -time.Second})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Aggregate() error = %v, want ErrInvalidConfig", err)
	}
}

func entries(in ...ingest.Entry) <-chan ingest.Entry {
	ch := make(chan ingest.Entry, len(in))
	for _, event := range in {
		ch <- event
	}
	close(ch)
	return ch
}

func entry(t time.Time, sessionID, method, rawURL, actionClass, effectiveAction string, payloadBytes, scannerBytes int) ingest.Entry {
	summary := &capture.CaptureSummary{
		ActionClass:     actionClass,
		PayloadBytes:    payloadBytes,
		ScannerBytes:    scannerBytes,
		EffectiveAction: effectiveAction,
		Request: capture.CaptureRequest{
			Method: method,
			URL:    rawURL,
		},
	}
	return ingest.Entry{
		Recorder: recorder.Entry{
			Timestamp: t,
			SessionID: sessionID,
			Type:      capture.EntryTypeCapture,
		},
		Capture: summary,
	}
}

func assertRule(t *testing.T, got Aggregates, key string, want RuleCounts) {
	t.Helper()

	rule, ok := got.Rules[key]
	if !ok {
		t.Fatalf("missing rule %q; keys=%v", key, got.RuleKeys())
	}
	if rule != want {
		t.Fatalf("rule %q = %+v, want %+v", key, rule, want)
	}
}

func sortStringsAlready(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			return false
		}
	}
	return true
}
