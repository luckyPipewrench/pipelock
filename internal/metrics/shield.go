// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// registerShieldMetrics builds and registers the browser shield rewrite
// counters, bytes-stripped counter, shim injection counter, skip counter,
// rewrite-latency histogram, and the response-scan exemption counter.
// Handles are attached to m.
func (m *Metrics) registerShieldMetrics(reg *prometheus.Registry) {
	m.shieldRewrites = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "shield_rewrites_total",
		Help:      "Total browser shield rewrites by category and transport.",
	}, []string{"category", "transport"})

	m.shieldBytesStripped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "shield_bytes_stripped_total",
		Help:      "Total bytes stripped by browser shield by category.",
	}, []string{"category"})

	m.shieldShimsInjected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "shield_shims_injected_total",
		Help:      "Total shim script injections by transport.",
	}, []string{"transport"})

	m.shieldSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "shield_skipped_total",
		Help:      "Total shield processing skips by reason.",
	}, []string{"reason"})

	m.shieldLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "shield_latency_seconds",
		Help:      "Browser shield rewriting latency in seconds.",
		Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
	}, []string{"transport"})

	m.responseScanExemptTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "response_scan_exempt_total",
		Help:      "Total response scan exemption skips by reason and transport.",
	}, []string{"reason", "transport"})

	reg.MustRegister(
		m.shieldRewrites, m.shieldBytesStripped, m.shieldShimsInjected,
		m.shieldSkipped, m.shieldLatency,
		m.responseScanExemptTotal,
	)
}

// RecordShieldRewrite increments the shield rewrite counter.
func (m *Metrics) RecordShieldRewrite(category, transport string) {
	if m == nil {
		return
	}
	m.shieldRewrites.WithLabelValues(category, transport).Inc()
}

// RecordShieldBytesStripped increments the stripped bytes counter.
func (m *Metrics) RecordShieldBytesStripped(category string, n int) {
	if m == nil {
		return
	}
	m.shieldBytesStripped.WithLabelValues(category).Add(float64(n))
}

// RecordShieldShimInjected increments the shim injection counter.
func (m *Metrics) RecordShieldShimInjected(transport string) {
	if m == nil {
		return
	}
	m.shieldShimsInjected.WithLabelValues(transport).Inc()
}

// RecordShieldSkipped increments the shield skip counter.
func (m *Metrics) RecordShieldSkipped(reason string) {
	if m == nil {
		return
	}
	m.shieldSkipped.WithLabelValues(reason).Inc()
}

// RecordShieldLatency observes shield rewriting latency.
func (m *Metrics) RecordShieldLatency(transport string, d time.Duration) {
	if m == nil {
		return
	}
	m.shieldLatency.WithLabelValues(transport).Observe(d.Seconds())
}

// RecordResponseScanExempt increments the response scan exemption counter.
// reason: "exempt_domain" (config exempt_domains match) or "suppress" (config suppress match).
// transport: "fetch", "forward", "connect", "websocket", "reverse".
func (m *Metrics) RecordResponseScanExempt(reason, transport string) {
	if m == nil {
		return
	}
	m.responseScanExemptTotal.WithLabelValues(reason, transport).Inc()
}
