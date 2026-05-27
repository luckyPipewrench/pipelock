// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordRequestPolicyDecision(t *testing.T) {
	t.Parallel()
	m := New()
	m.RecordRequestPolicyDecision("destructive-mutations", "block")
	m.RecordRequestPolicyDecision("destructive-mutations", "block")
	m.RecordRequestPolicyDecision("outbound-send", "warn")

	if got := testutil.ToFloat64(m.requestPolicyDecisions.WithLabelValues("destructive-mutations", "block")); got != 2 {
		t.Errorf("block count = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.requestPolicyDecisions.WithLabelValues("outbound-send", "warn")); got != 1 {
		t.Errorf("warn count = %v, want 1", got)
	}
}

func TestRecordRequestPolicyDecision_NilSafe(t *testing.T) {
	t.Parallel()
	var m *Metrics
	// Must not panic on a nil Metrics (matches the other Record* helpers).
	m.RecordRequestPolicyDecision("rule", "block")
}
