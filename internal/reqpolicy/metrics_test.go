// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMetricsRecord(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	m.Record(Decision{Action: config.ActionBlock, RuleName: "api-write"})
	m.Record(Decision{Action: config.ActionWarn, RuleName: "api-shadow", Shadow: true})
	m.Record(Decision{}) // no match: no-op

	if got := testutil.ToFloat64(m.Decisions.WithLabelValues("api-write", "block")); got != 1 {
		t.Errorf("block count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.Decisions.WithLabelValues("api-shadow", "shadow_warn")); got != 1 {
		t.Errorf("shadow_warn count = %v, want 1", got)
	}
}

func TestMetricsRecord_NilSafe(t *testing.T) {
	var m *Metrics
	// Must not panic on a nil receiver or an unmatched decision.
	m.Record(Decision{Action: config.ActionBlock, RuleName: "x"})
	live := NewMetrics(prometheus.NewRegistry())
	live.Record(Decision{})
}
