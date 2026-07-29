//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package metrics

import (
	"strconv"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/prometheus/client_golang/prometheus"
)

var conductorPolicyHashStatuses = []conductor.PolicyHashStatus{
	conductor.PolicyHashCurrent,
	conductor.PolicyHashKnownLegacy,
	conductor.PolicyHashUnknownUnverified,
}

func (m *Metrics) registerConductorMetrics(reg *prometheus.Registry) {
	m.conductorAuditQueuePending = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "conductor_audit_queue_pending",
		Help:      "Current pending Conductor audit batches in the durable queue.",
	})
	m.conductorAuditQueueInflight = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "conductor_audit_queue_inflight",
		Help:      "Current claimed Conductor audit batches awaiting ack, retry, or drop.",
	})
	m.conductorAuditQueueDead = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "conductor_audit_queue_dead",
		Help:      "Current dead-lettered Conductor audit batches.",
	})
	m.conductorAuditDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "conductor_audit_deliveries_total",
		Help:      "Total Conductor audit batch delivery outcomes.",
	}, []string{"outcome", "reason"})
	m.conductorServerRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "conductor_server_requests_total",
		Help:      "Total Conductor server HTTP requests by route, method, and status code.",
	}, []string{"route", "method", "status"})
	m.conductorServerDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "conductor_server_request_duration_seconds",
		Help:      "Conductor server HTTP request duration by route and method.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"route", "method"})
	m.conductorServerAuditIngest = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "conductor_server_audit_ingest_total",
		Help:      "Total Conductor server audit ingest outcomes.",
	}, []string{"outcome", "reason"})
	m.conductorServerAuditQueries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "conductor_server_audit_queries_total",
		Help:      "Total Conductor server audit query outcomes.",
	}, []string{"outcome", "reason"})
	m.conductorEmergencyQuarantine = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "conductor_emergency_quarantine_total",
		Help:      "Total Conductor emergency-control records dropped at a leader read path because they failed signature verification against the trusted control keys.",
	}, []string{"control", "reason"})
	m.conductorPolicyHashStatuses = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "conductor_policy_bundle_policy_hash_status_count",
		Help: "Conductor policy bundles by policy hash status, counted when the store " +
			"was loaded at startup. It is a snapshot and does not move as bundles are " +
			"published; alert on unknown_unverified, which can only change across a restart.",
	}, []string{"status"})
	reg.MustRegister(
		m.conductorAuditQueuePending,
		m.conductorAuditQueueInflight,
		m.conductorAuditQueueDead,
		m.conductorAuditDeliveries,
		m.conductorServerRequests,
		m.conductorServerDuration,
		m.conductorServerAuditIngest,
		m.conductorServerAuditQueries,
		m.conductorEmergencyQuarantine,
		m.conductorPolicyHashStatuses,
	)
}

func (m *Metrics) RecordConductorAuditQueue(stats auditbatcher.Stats) {
	if m == nil {
		return
	}
	m.conductorAuditQueuePending.Set(float64(stats.Pending))
	m.conductorAuditQueueInflight.Set(float64(stats.Inflight))
	m.conductorAuditQueueDead.Set(float64(stats.Dead))
}

func (m *Metrics) RecordConductorAuditDelivery(outcome, reason string) {
	if m == nil {
		return
	}
	m.conductorAuditDeliveries.WithLabelValues(outcome, reason).Inc()
}

func (m *Metrics) RecordConductorServerRequest(route, method string, status int, duration time.Duration) {
	if m == nil {
		return
	}
	m.conductorServerRequests.WithLabelValues(route, method, strconv.Itoa(status)).Inc()
	m.conductorServerDuration.WithLabelValues(route, method).Observe(duration.Seconds())
}

func (m *Metrics) RecordConductorServerAuditIngest(outcome, reason string) {
	if m == nil {
		return
	}
	m.conductorServerAuditIngest.WithLabelValues(outcome, reason).Inc()
}

func (m *Metrics) RecordConductorServerAuditQuery(outcome, reason string) {
	if m == nil {
		return
	}
	m.conductorServerAuditQueries.WithLabelValues(outcome, reason).Inc()
}

// RecordConductorEmergencyQuarantine counts an emergency-control record dropped
// at a leader read path because it failed Ed25519 signature verification against
// the trusted control keys. control is "rollback" or "remote_kill"; reason
// classifies the failure (signature_verification_failed,
// untrusted_or_rotated_signer, or nil_resolver).
func (m *Metrics) RecordConductorEmergencyQuarantine(control, reason string) {
	if m == nil {
		return
	}
	m.conductorEmergencyQuarantine.WithLabelValues(control, reason).Inc()
}

// RecordConductorPolicyHashStatusCounts sets the bounded status gauge for
// policy bundles loaded from the Conductor store. It deliberately iterates the
// three known statuses instead of ranging over counts so a corrupt or future
// status string cannot create unbounded label cardinality.
func (m *Metrics) RecordConductorPolicyHashStatusCounts(counts map[conductor.PolicyHashStatus]int) {
	if m == nil {
		return
	}
	for _, status := range conductorPolicyHashStatuses {
		m.conductorPolicyHashStatuses.WithLabelValues(string(status)).Set(float64(counts[status]))
	}
}
