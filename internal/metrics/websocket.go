// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// registerWSMetrics builds and registers the WebSocket counter, gauge, and
// histogram set, attaching the handles to m.
func (m *Metrics) registerWSMetrics(reg *prometheus.Registry) {
	m.wsConnectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "ws_connections_total",
		Help:      "Total WebSocket proxy connections by result.",
	}, []string{"result"})

	m.wsDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "ws_duration_seconds",
		Help:      "WebSocket connection duration in seconds.",
		Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	})

	m.wsBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "ws_bytes_total",
		Help:      "Total bytes transferred through WebSocket proxy.",
	}, []string{"direction"})

	m.activeWS = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "ws_active_connections",
		Help:      "Current number of active WebSocket proxy connections.",
	})

	m.wsFrames = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "ws_frames_total",
		Help:      "Total WebSocket frames by type.",
	}, []string{"type"})

	m.wsScanHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "ws_scan_hits_total",
		Help:      "Total WebSocket scan detections by scanner.",
	}, []string{"scanner"})

	m.wsRedirectHints = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "forward_ws_redirect_hint_total",
		Help:      "CONNECT requests to known WebSocket API hosts.",
	})

	reg.MustRegister(
		m.wsConnectionsTotal, m.wsDuration, m.wsBytes, m.activeWS,
		m.wsFrames, m.wsScanHits, m.wsRedirectHints,
	)
}

// RecordWSCompleted records a WebSocket connection that ended normally.
func (m *Metrics) RecordWSCompleted() {
	m.wsConnectionsTotal.WithLabelValues("completed").Inc()

	m.mu.Lock()
	m.wsConnectionCount++
	m.mu.Unlock()
}

// RecordWSBlocked records a WebSocket connection terminated by policy/DLP/injection.
func (m *Metrics) RecordWSBlocked() {
	m.wsConnectionsTotal.WithLabelValues("blocked").Inc()
}

// RecordWSStats records duration and byte counters for any WebSocket connection
// regardless of outcome (completed or blocked).
func (m *Metrics) RecordWSStats(duration time.Duration, clientToServer, serverToClient int64) {
	m.wsDuration.Observe(duration.Seconds())
	m.wsBytes.WithLabelValues("client_to_server").Add(float64(clientToServer))
	m.wsBytes.WithLabelValues("server_to_client").Add(float64(serverToClient))
}

// IncrActiveWS increments the active WebSocket connection gauge.
func (m *Metrics) IncrActiveWS() {
	m.activeWS.Inc()
}

// DecrActiveWS decrements the active WebSocket connection gauge.
func (m *Metrics) DecrActiveWS() {
	m.activeWS.Dec()
}

// RecordWSFrame records a WebSocket frame by type.
func (m *Metrics) RecordWSFrame(frameType string) {
	m.wsFrames.WithLabelValues(frameType).Inc()
}

// RecordWSScanHit records a WebSocket scan detection.
func (m *Metrics) RecordWSScanHit(scannerName string) {
	m.wsScanHits.WithLabelValues(scannerName).Inc()
}

// RecordWSRedirectHint records a CONNECT request to a known WebSocket API host.
func (m *Metrics) RecordWSRedirectHint() {
	m.wsRedirectHints.Inc()
}
