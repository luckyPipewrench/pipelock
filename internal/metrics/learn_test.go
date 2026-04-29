// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// expectedLearnMetricNames is the canonical set of fully-qualified metric
// names that registerLearnMetrics must publish. Used by the registration
// test to guard against silent renames or dropped registrations.
var expectedLearnMetricNames = []string{
	"pipelock_learn_observation_events_total",
	"pipelock_learn_regulated_data_blocked_total",
	"pipelock_learn_unclassified_actions_total",
	"pipelock_learn_unclassified_rate",
	"pipelock_learn_inference_classify_total",
	"pipelock_learn_inference_floor_failures_total",
}

func TestRegisterLearnMetrics_RegistersAllFour(t *testing.T) {
	t.Parallel()
	m := New()

	// Touch the CounterVec metrics so Gather() emits them. CounterVec/
	// GaugeVec are lazy: descriptors are registered at New() time, but
	// no MetricFamily appears in Gather output until at least one
	// labeled child is observed. The new inference helpers enforce a
	// closed allowlist on their labels (cardinality protection), so we
	// touch them with canonical values rather than a synthetic probe;
	// the pre-existing helpers retain the probe label because their
	// behavior is out of scope for this PR.
	m.RecordObservationEvent("registration_probe")
	m.RecordRegulatedDataBlocked("registration_probe")
	m.RecordInferenceClassification(OutcomeStable)
	m.RecordInferenceFloorFailure(FloorSessions)

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("registry.Gather: %v", err)
	}

	got := make(map[string]bool, len(families))
	for _, fam := range families {
		got[fam.GetName()] = true
	}

	for _, want := range expectedLearnMetricNames {
		if !got[want] {
			t.Errorf("expected metric %q in registry, not found", want)
		}
	}
}

func TestRecordObservationEvent_IncrementsByActionClass(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordObservationEvent("read")
	m.RecordObservationEvent("read")
	m.RecordObservationEvent("read")
	m.RecordObservationEvent("write")

	if got := testutil.ToFloat64(m.learnObservationEvents.WithLabelValues("read")); got != 3 {
		t.Errorf("read counter = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.learnObservationEvents.WithLabelValues("write")); got != 1 {
		t.Errorf("write counter = %v, want 1", got)
	}
}

func TestRecordObservationEvent_UnclassifiedAlsoBumpsUnclassifiedTotal(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordObservationEvent("unclassified")

	if got := testutil.ToFloat64(m.learnObservationEvents.WithLabelValues("unclassified")); got != 1 {
		t.Errorf("unclassified label counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.learnUnclassifiedActions); got != 1 {
		t.Errorf("unclassified total = %v, want 1", got)
	}

	// A non-unclassified increment must not bump the unclassified total.
	m.RecordObservationEvent("read")
	if got := testutil.ToFloat64(m.learnUnclassifiedActions); got != 1 {
		t.Errorf("unclassified total after read = %v, want still 1", got)
	}
}

func TestRecordRegulatedDataBlocked_IncrementsByReason(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordRegulatedDataBlocked("field_class_regulated")
	m.RecordRegulatedDataBlocked("field_class_regulated")
	m.RecordRegulatedDataBlocked("root_class_regulated")

	if got := testutil.ToFloat64(m.learnRegulatedDataBlocked.WithLabelValues("field_class_regulated")); got != 2 {
		t.Errorf("field_class_regulated counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.learnRegulatedDataBlocked.WithLabelValues("root_class_regulated")); got != 1 {
		t.Errorf("root_class_regulated counter = %v, want 1", got)
	}
}

func TestSetUnclassifiedRate_PublishesGaugeValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rate float64
	}{
		{"zero", 0.0},
		{"five percent", 0.05},
		{"half", 0.5},
		{"one", 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			m.SetUnclassifiedRate(tt.rate)
			if got := testutil.ToFloat64(m.learnUnclassifiedRate); got != tt.rate {
				t.Errorf("unclassified rate = %v, want %v", got, tt.rate)
			}
		})
	}
}

func TestSetUnclassifiedRate_OverwritesPreviousValue(t *testing.T) {
	t.Parallel()
	m := New()

	m.SetUnclassifiedRate(0.5)
	m.SetUnclassifiedRate(0.05)

	if got := testutil.ToFloat64(m.learnUnclassifiedRate); got != 0.05 {
		t.Errorf("unclassified rate after overwrite = %v, want 0.05", got)
	}
}

func TestRecordObservationEvent_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordObservationEvent("read")         // no panic
	m.RecordObservationEvent("unclassified") // unclassified branch, also nil-safe
}

func TestRecordRegulatedDataBlocked_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordRegulatedDataBlocked("field_class_regulated") // no panic
}

func TestSetUnclassifiedRate_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.SetUnclassifiedRate(0.5) // no panic
}

// TestRecordInferenceClassification_IncrementsByOutcome confirms each
// canonical outcome label increments its own counter independently.
// The wire labels (never_confirmed, brittle, stable) must agree with
// inference.Confidence.String() so the metric is groupable in Grafana
// against the recorder's emitted values byte-for-byte.
func TestRecordInferenceClassification_IncrementsByOutcome(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordInferenceClassification("stable")
	m.RecordInferenceClassification("stable")
	m.RecordInferenceClassification("stable")
	m.RecordInferenceClassification("brittle")

	if got := testutil.ToFloat64(m.learnInferenceClassifications.WithLabelValues("stable")); got != 3 {
		t.Errorf("stable counter = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.learnInferenceClassifications.WithLabelValues("brittle")); got != 1 {
		t.Errorf("brittle counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.learnInferenceClassifications.WithLabelValues("never_confirmed")); got != 0 {
		t.Errorf("never_confirmed counter = %v, want 0 (untouched)", got)
	}
}

// TestRecordInferenceClassification_NilSafe matches the existing nil-safe
// pattern across the learn metrics. A nil *Metrics receiver is the legal
// "metrics disabled" sentinel — the helper must not panic.
func TestRecordInferenceClassification_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordInferenceClassification("stable") // no panic
}

// TestRecordInferenceFloorFailure_IncrementsByFloor confirms each canonical
// floor label increments its own counter independently. The wire labels
// (sessions, events, windows) match the YAML field-name suffixes the
// operator sees in pipelock.yaml so the diagnostic counter and the
// validator error message use the same vocabulary.
func TestRecordInferenceFloorFailure_IncrementsByFloor(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordInferenceFloorFailure("sessions")
	m.RecordInferenceFloorFailure("sessions")
	m.RecordInferenceFloorFailure("events")
	m.RecordInferenceFloorFailure("windows")
	m.RecordInferenceFloorFailure("windows")
	m.RecordInferenceFloorFailure("windows")

	if got := testutil.ToFloat64(m.learnInferenceFloorFailures.WithLabelValues("sessions")); got != 2 {
		t.Errorf("sessions counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.learnInferenceFloorFailures.WithLabelValues("events")); got != 1 {
		t.Errorf("events counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.learnInferenceFloorFailures.WithLabelValues("windows")); got != 3 {
		t.Errorf("windows counter = %v, want 3", got)
	}
}

// TestRecordInferenceFloorFailure_NilSafe matches the existing nil-safe
// pattern.
func TestRecordInferenceFloorFailure_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordInferenceFloorFailure("sessions") // no panic
}

// TestRecordInferenceClassification_DropsNonCanonical confirms the
// closed-allowlist contract: a label value outside {never_confirmed,
// brittle, stable} is dropped silently, never increments any series,
// and cannot expand cardinality. Catches future caller drift before it
// bakes into dashboards or alerts.
func TestRecordInferenceClassification_DropsNonCanonical(t *testing.T) {
	t.Parallel()
	m := New()

	// Cast a non-canonical literal through the typed parameter to
	// reach the default branch.
	m.RecordInferenceClassification(InferenceOutcome("malicious_label"))
	m.RecordInferenceClassification(InferenceOutcome(""))
	m.RecordInferenceClassification(InferenceOutcome("STABLE")) // case-sensitive

	if got := testutil.ToFloat64(m.learnInferenceClassifications.WithLabelValues("malicious_label")); got != 0 {
		t.Errorf("non-canonical label leaked into counter: got %v", got)
	}
	if got := testutil.ToFloat64(m.learnInferenceClassifications.WithLabelValues("STABLE")); got != 0 {
		t.Errorf("case-variant label leaked into counter: got %v", got)
	}
	// All canonical labels must remain at zero too: the helper dropped
	// every input above.
	for _, canonical := range []string{"never_confirmed", "brittle", "stable"} {
		if got := testutil.ToFloat64(m.learnInferenceClassifications.WithLabelValues(canonical)); got != 0 {
			t.Errorf("canonical %q counter = %v, want 0 after non-canonical-only inputs", canonical, got)
		}
	}
}

// TestRecordInferenceFloorFailure_DropsNonCanonical mirrors the
// classification drop test for the floor-failure counter.
func TestRecordInferenceFloorFailure_DropsNonCanonical(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordInferenceFloorFailure(FloorFailure("requests"))
	m.RecordInferenceFloorFailure(FloorFailure(""))
	m.RecordInferenceFloorFailure(FloorFailure("Sessions")) // case-sensitive

	if got := testutil.ToFloat64(m.learnInferenceFloorFailures.WithLabelValues("requests")); got != 0 {
		t.Errorf("non-canonical floor leaked into counter: got %v", got)
	}
	for _, canonical := range []string{"sessions", "events", "windows"} {
		if got := testutil.ToFloat64(m.learnInferenceFloorFailures.WithLabelValues(canonical)); got != 0 {
			t.Errorf("canonical %q counter = %v, want 0 after non-canonical-only inputs", canonical, got)
		}
	}
}

// TestInferenceOutcome_AlignsWithConfidenceString documents the
// cross-package wire-form contract: the metrics package's canonical
// outcome strings must equal inference.Confidence.String() byte-for-byte.
// We assert the literals here rather than importing inference (to avoid
// a layering edge); inference's TestConfidence_String is the symmetric
// guard on the other side.
func TestInferenceOutcome_AlignsWithConfidenceString(t *testing.T) {
	t.Parallel()
	cases := map[InferenceOutcome]string{
		OutcomeNeverConfirmed: "never_confirmed",
		OutcomeBrittle:        "brittle",
		OutcomeStable:         "stable",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("InferenceOutcome %q wire form = %q, want %q (must match inference.Confidence.String())", want, string(got), want)
		}
	}
}
