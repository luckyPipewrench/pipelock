// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/prometheus/client_golang/prometheus"
)

type auditSinkCollector struct {
	mu       sync.RWMutex
	snapshot func() []emit.SinkHealth

	delivered        *prometheus.Desc
	failed           *prometheus.Desc
	dropped          *prometheus.Desc
	abandoned        *prometheus.Desc
	queueDepth       *prometheus.Desc
	queueCapacity    *prometheus.Desc
	degraded         *prometheus.Desc
	lastErrorPresent *prometheus.Desc
}

func newAuditSinkCollector() *auditSinkCollector {
	labels := []string{"sink"}
	return &auditSinkCollector{
		delivered: prometheus.NewDesc(
			"pipelock_audit_sink_delivered_total",
			"Audit events successfully delivered, cumulative per sink type over the process lifetime (survives sink reload).",
			labels, nil,
		),
		failed: prometheus.NewDesc(
			"pipelock_audit_sink_failed_total",
			"Audit event delivery failures recorded, cumulative per sink type over the process lifetime (survives sink reload).",
			labels, nil,
		),
		dropped: prometheus.NewDesc(
			"pipelock_audit_sink_dropped_total",
			"Audit events dropped before delivery, cumulative per sink type over the process lifetime (survives sink reload).",
			labels, nil,
		),
		abandoned: prometheus.NewDesc(
			"pipelock_audit_sink_abandoned_total",
			"Queued audit events abandoned during shutdown, cumulative per sink type over the process lifetime (survives sink reload).",
			labels, nil,
		),
		queueDepth: prometheus.NewDesc(
			"pipelock_audit_sink_queue_depth",
			"Current number of audit events queued for delivery.",
			labels, nil,
		),
		queueCapacity: prometheus.NewDesc(
			"pipelock_audit_sink_queue_capacity",
			"Configured audit event delivery queue capacity.",
			labels, nil,
		),
		degraded: prometheus.NewDesc(
			"pipelock_audit_sink_degraded",
			"Whether the audit sink has an unresolved delivery failure or drop (1 degraded, 0 healthy).",
			labels, nil,
		),
		lastErrorPresent: prometheus.NewDesc(
			"pipelock_audit_sink_last_error_present",
			"Whether the audit sink currently records a last error (1 present, 0 absent); error text is excluded to bound cardinality and prevent secret exposure.",
			labels, nil,
		),
	}
}

func (c *auditSinkCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.delivered
	ch <- c.failed
	ch <- c.dropped
	ch <- c.abandoned
	ch <- c.queueDepth
	ch <- c.queueCapacity
	ch <- c.degraded
	ch <- c.lastErrorPresent
}

func (c *auditSinkCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	snapshot := c.snapshot
	c.mu.RUnlock()
	if snapshot == nil {
		return
	}

	for _, health := range snapshot() {
		if !knownAuditSink(health.Sink) {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.delivered, prometheus.CounterValue, float64(health.Delivered), health.Sink)
		ch <- prometheus.MustNewConstMetric(c.failed, prometheus.CounterValue, float64(health.Failed), health.Sink)
		ch <- prometheus.MustNewConstMetric(c.dropped, prometheus.CounterValue, float64(health.Dropped), health.Sink)
		ch <- prometheus.MustNewConstMetric(c.abandoned, prometheus.CounterValue, float64(health.Abandoned), health.Sink)
		ch <- prometheus.MustNewConstMetric(c.queueDepth, prometheus.GaugeValue, float64(health.QueueLen), health.Sink)
		ch <- prometheus.MustNewConstMetric(c.queueCapacity, prometheus.GaugeValue, float64(health.QueueCap), health.Sink)
		ch <- prometheus.MustNewConstMetric(c.degraded, prometheus.GaugeValue, boolFloat(health.Degraded), health.Sink)
		ch <- prometheus.MustNewConstMetric(c.lastErrorPresent, prometheus.GaugeValue, boolFloat(health.LastErrorPresent), health.Sink)
	}
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

// knownAuditSink bounds the Prometheus "sink" label to the built-in sink
// identities so a hostile or unexpected SinkHealth.Sink value cannot inflate
// label cardinality.
func knownAuditSink(name string) bool {
	switch name {
	case emit.SinkWebhook, emit.SinkSyslog, emit.SinkOTLP:
		return true
	default:
		return false
	}
}

// SetAuditSinkHealthSnapshot connects the live emitter's pull-only health
// snapshot to Prometheus. The callback runs only during a scrape, never while
// an event is being emitted.
func (m *Metrics) SetAuditSinkHealthSnapshot(snapshot func() []emit.SinkHealth) {
	if m == nil || m.auditSinkCollector == nil {
		return
	}
	m.auditSinkCollector.mu.Lock()
	m.auditSinkCollector.snapshot = snapshot
	m.auditSinkCollector.mu.Unlock()
}
