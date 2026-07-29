//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package metrics

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
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

func TestConductorEmergencyQuarantineMetric(t *testing.T) {
	m := New()
	m.RecordConductorEmergencyQuarantine("rollback", "signature_verification_failed")
	m.RecordConductorEmergencyQuarantine("rollback", "signature_verification_failed")
	m.RecordConductorEmergencyQuarantine("remote_kill", "nil_resolver")

	if got := testutil.ToFloat64(m.conductorEmergencyQuarantine.WithLabelValues("rollback", "signature_verification_failed")); got != 2 {
		t.Fatalf("rollback quarantine counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.conductorEmergencyQuarantine.WithLabelValues("remote_kill", "nil_resolver")); got != 1 {
		t.Fatalf("remote kill quarantine counter = %v, want 1", got)
	}

	var nilMetrics *Metrics
	nilMetrics.RecordConductorEmergencyQuarantine("rollback", "nil_resolver")
}

func TestConductorPolicyHashStatusMetricIsBounded(t *testing.T) {
	m := New()
	m.RecordConductorPolicyHashStatusCounts(map[conductor.PolicyHashStatus]int{
		conductor.PolicyHashCurrent:            4,
		conductor.PolicyHashKnownLegacy:        2,
		conductor.PolicyHashUnknownUnverified:  1,
		conductor.PolicyHashStatus("future-x"): 99,
	})

	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(`# HELP pipelock_conductor_policy_bundle_policy_hash_status_count Conductor policy bundles by policy hash status, counted when the store was loaded at startup. It is a snapshot and does not move as bundles are published; alert on unknown_unverified, which can only change across a restart.
# TYPE pipelock_conductor_policy_bundle_policy_hash_status_count gauge
pipelock_conductor_policy_bundle_policy_hash_status_count{status="current"} 4
pipelock_conductor_policy_bundle_policy_hash_status_count{status="known_legacy"} 2
pipelock_conductor_policy_bundle_policy_hash_status_count{status="unknown_unverified"} 1
`), "pipelock_conductor_policy_bundle_policy_hash_status_count"); err != nil {
		t.Fatalf("policy hash status metric = %v", err)
	}

	var nilMetrics *Metrics
	nilMetrics.RecordConductorPolicyHashStatusCounts(nil)
}
