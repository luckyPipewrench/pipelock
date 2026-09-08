// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The owner-mismatch counter is the only signal an operator gets that a
// fragment append was refused because a stream already held another identity's
// evidence. A nonzero value is an internal invariant failure rather than a
// tuning signal, so it stays separate from the capacity counter, which an
// operator IS expected to act on.
func TestRecordCrossRequestFragmentOwnerMismatch(t *testing.T) {
	t.Parallel()
	m := New()

	m.RecordCrossRequestFragmentOwnerMismatch()
	m.RecordCrossRequestFragmentOwnerMismatch()

	if got := testutil.ToFloat64(m.CrossRequestFragmentOwnerMismatch); got != 2 {
		t.Fatalf("owner mismatch counter = %v, want 2", got)
	}

	// A nil receiver must not panic: several call sites treat metrics as
	// optional, and a refused append must never become a crash.
	var nilMetrics *Metrics
	nilMetrics.RecordCrossRequestFragmentOwnerMismatch()
}

// The partition-fallback reason label is a closed set so an attacker-shaped
// value cannot grow the metric's cardinality.
func TestRecordCrossRequestJSONPartitionFallbackBoundsItsLabel(t *testing.T) {
	t.Parallel()
	m := New()

	for _, reason := range []string{"malformed", "incomplete", "unkeyed"} {
		m.RecordCrossRequestJSONPartitionFallback(reason)
		if got := testutil.ToFloat64(m.CrossRequestJSONPartitionFallback.WithLabelValues(reason)); got != 1 {
			t.Fatalf("%s counter = %v, want 1", reason, got)
		}
	}

	m.RecordCrossRequestJSONPartitionFallback("$(attacker-chosen)")
	if got := testutil.ToFloat64(m.CrossRequestJSONPartitionFallback.WithLabelValues("other")); got != 1 {
		t.Fatalf("unrecognized reason folded into = %v, want 1 under other", got)
	}

	// An empty reason means the body was fully partitioned, which is not a
	// fallback and must not be counted as one.
	m.RecordCrossRequestJSONPartitionFallback("")
	if got := testutil.ToFloat64(m.CrossRequestJSONPartitionFallback.WithLabelValues("")); got != 0 {
		t.Fatalf("empty reason counter = %v, want 0", got)
	}
}
