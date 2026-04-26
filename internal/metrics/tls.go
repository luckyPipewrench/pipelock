// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// registerTLSMetrics builds and registers the TLS interception counter,
// certificate cache gauge, handshake-duration histogram, and request/response
// blocked counters. Handles are attached to m.
func (m *Metrics) registerTLSMetrics(reg *prometheus.Registry) {
	m.tlsInterceptTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tls_intercept_total",
		Help:      "Total TLS-intercepted CONNECT tunnels by outcome.",
	}, []string{"outcome"})

	m.tlsCertCacheSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "tls_cert_cache_size",
		Help:      "Current number of cached TLS leaf certificates.",
	})

	m.tlsHandshakeDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "tls_handshake_duration_seconds",
		Help:      "TLS handshake latency in seconds.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
	}, []string{"side"})

	m.tlsRequestBlocked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tls_request_blocked_total",
		Help:      "Total TLS-intercepted requests blocked by reason.",
	}, []string{"reason"})

	m.tlsResponseBlocked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tls_response_blocked_total",
		Help:      "Total TLS-intercepted responses blocked by reason.",
	}, []string{"reason"})

	reg.MustRegister(
		m.tlsInterceptTotal, m.tlsCertCacheSize, m.tlsHandshakeDuration,
		m.tlsRequestBlocked, m.tlsResponseBlocked,
	)
}

// RecordTLSIntercept increments the TLS interception counter by outcome.
func (m *Metrics) RecordTLSIntercept(outcome string) {
	m.tlsInterceptTotal.WithLabelValues(outcome).Inc()
}

// SetTLSCertCacheSize sets the current TLS certificate cache size gauge.
func (m *Metrics) SetTLSCertCacheSize(n float64) {
	m.tlsCertCacheSize.Set(n)
}

// RecordTLSHandshake records a TLS handshake duration by side (client/upstream).
func (m *Metrics) RecordTLSHandshake(side string, d time.Duration) {
	m.tlsHandshakeDuration.WithLabelValues(side).Observe(d.Seconds())
}

// RecordTLSRequestBlocked increments the TLS request blocked counter by reason.
func (m *Metrics) RecordTLSRequestBlocked(reason string) {
	m.tlsRequestBlocked.WithLabelValues(reason).Inc()
}

// RecordTLSResponseBlocked increments the TLS response blocked counter by reason.
func (m *Metrics) RecordTLSResponseBlocked(reason string) {
	m.tlsResponseBlocked.WithLabelValues(reason).Inc()
}
