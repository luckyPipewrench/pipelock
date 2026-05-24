// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/luckyPipewrench/pipelock/internal/conductor/auditbatcher"
	"github.com/prometheus/client_golang/prometheus"
)

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
	reg.MustRegister(
		m.conductorAuditQueuePending,
		m.conductorAuditQueueInflight,
		m.conductorAuditQueueDead,
		m.conductorAuditDeliveries,
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
