// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordEmitFailure_CanonicalReasons(t *testing.T) {
	m := New()
	m.RecordEmitFailure("chain_init")
	m.RecordEmitFailure("chain_init")
	m.RecordEmitFailure("record")

	if got := testutil.ToFloat64(m.receiptEmitFailures.WithLabelValues("chain_init")); got != 2 {
		t.Errorf("chain_init = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.receiptEmitFailures.WithLabelValues("record")); got != 1 {
		t.Errorf("record = %v, want 1", got)
	}
}

func TestRecordEmitFailure_NonCanonicalMappedToUnknown(t *testing.T) {
	m := New()
	m.RecordEmitFailure("arbitrary attacker controlled text")
	m.RecordEmitFailure("another one")

	if got := testutil.ToFloat64(m.receiptEmitFailures.WithLabelValues("unknown")); got != 2 {
		t.Errorf("unknown = %v, want 2 (non-canonical reasons collapsed)", got)
	}
}

func TestRecordEmitFailure_NilSafe(t *testing.T) {
	var m *Metrics
	m.RecordEmitFailure("chain_init") // must not panic
}
