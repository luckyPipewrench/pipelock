// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// registerScanAPIMetrics builds and registers the Scan API request,
// duration, finding, error, and inflight metrics. Handles are attached to m.
func (m *Metrics) registerScanAPIMetrics(reg *prometheus.Registry) {
	m.ScanAPIRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_scan_api_requests_total",
		Help: "Total scan API requests by kind, decision, and status code.",
	}, []string{"kind", "decision", "status_code"})

	m.ScanAPIDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pipelock_scan_api_duration_seconds",
		Help:    "Scan API scan latency in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"kind"})

	m.ScanAPIFindings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_scan_api_findings_total",
		Help: "Total scan API findings by kind, scanner, and severity.",
	}, []string{"kind", "scanner", "severity"})

	m.ScanAPIErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_scan_api_errors_total",
		Help: "Total scan API errors by kind and error code.",
	}, []string{"kind", "error_code"})

	m.ScanAPIInflight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pipelock_scan_api_inflight_requests",
		Help: "Current number of in-flight scan API requests.",
	})

	reg.MustRegister(
		m.ScanAPIRequests, m.ScanAPIDuration, m.ScanAPIFindings,
		m.ScanAPIErrors, m.ScanAPIInflight,
	)
}

// RecordScanAPIRequest increments the Scan API request counter.
func (m *Metrics) RecordScanAPIRequest(kind, decision, statusCode string) {
	m.ScanAPIRequests.WithLabelValues(kind, decision, statusCode).Inc()
}

// ObserveScanAPIDuration records a Scan API scan duration.
func (m *Metrics) ObserveScanAPIDuration(kind string, d time.Duration) {
	m.ScanAPIDuration.WithLabelValues(kind).Observe(d.Seconds())
}

// RecordScanAPIFinding increments the Scan API finding counter.
func (m *Metrics) RecordScanAPIFinding(kind, scannerName, severity string) {
	m.ScanAPIFindings.WithLabelValues(kind, scannerName, severity).Inc()
}

// RecordScanAPIError increments the Scan API error counter.
func (m *Metrics) RecordScanAPIError(kind, errorCode string) {
	m.ScanAPIErrors.WithLabelValues(kind, errorCode).Inc()
}

// IncrScanAPIInflight increments the Scan API in-flight request gauge.
func (m *Metrics) IncrScanAPIInflight() {
	m.ScanAPIInflight.Inc()
}

// DecrScanAPIInflight decrements the Scan API in-flight request gauge.
func (m *Metrics) DecrScanAPIInflight() {
	m.ScanAPIInflight.Dec()
}
