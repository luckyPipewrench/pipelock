//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package metrics

import (
	"net/http"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
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

func TestConductorServerMetrics(t *testing.T) {
	m := New()
	m.RecordConductorServerRequest("/readyz", http.MethodGet, 200, 25*time.Millisecond)
	m.RecordConductorServerAuditIngest("accepted", "ok")
	m.RecordConductorServerAuditIngest("rejected", "bad_request")
	m.RecordConductorServerAuditQuery("listed", "ok")

	if got := testutil.ToFloat64(m.conductorServerRequests.WithLabelValues("/readyz", http.MethodGet, "200")); got != 1 {
		t.Fatalf("server request counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.conductorServerAuditIngest.WithLabelValues("accepted", "ok")); got != 1 {
		t.Fatalf("audit ingest accepted counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.conductorServerAuditIngest.WithLabelValues("rejected", "bad_request")); got != 1 {
		t.Fatalf("audit ingest rejected counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.conductorServerAuditQueries.WithLabelValues("listed", "ok")); got != 1 {
		t.Fatalf("audit query counter = %v, want 1", got)
	}
}
