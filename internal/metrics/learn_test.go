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
}

func TestRegisterLearnMetrics_RegistersAllFour(t *testing.T) {
	t.Parallel()
	m := New()

	// Touch the CounterVec metrics with a synthetic label so Gather()
	// emits them. CounterVec/GaugeVec are lazy: descriptors are registered
	// at New() time, but no MetricFamily appears in Gather output until
	// at least one labeled child is observed. The non-Vec counter and
	// gauge appear immediately. We use a distinct test-only label value
	// for the Vec metrics so this touch can't be confused with real data.
	m.RecordObservationEvent("registration_probe")
	m.RecordRegulatedDataBlocked("registration_probe")

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
