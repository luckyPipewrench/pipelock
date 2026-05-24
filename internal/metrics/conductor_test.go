// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/conductor/auditbatcher"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestConductorAuditMetrics(t *testing.T) {
	m := New()
	m.RecordConductorAuditQueue(auditbatcher.Stats{Pending: 2, Inflight: 1, Dead: 3})
	m.RecordConductorAuditDelivery("retry", "http_server_error")
	m.RecordConductorAuditDelivery("retry", "http_server_error")
	m.RecordConductorAuditDelivery("drop", "http_client_error")

	if got := testutil.ToFloat64(m.conductorAuditQueuePending); got != 2 {
		t.Fatalf("pending gauge = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.conductorAuditQueueInflight); got != 1 {
		t.Fatalf("inflight gauge = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.conductorAuditQueueDead); got != 3 {
		t.Fatalf("dead gauge = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.conductorAuditDeliveries.WithLabelValues("retry", "http_server_error")); got != 2 {
		t.Fatalf("retry counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.conductorAuditDeliveries.WithLabelValues("drop", "http_client_error")); got != 1 {
		t.Fatalf("drop counter = %v, want 1", got)
	}
}
