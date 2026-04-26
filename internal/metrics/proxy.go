// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// registerProxyMetrics builds and registers the proxy/tunnel/SNI/reverse-proxy
// counter and histogram set, attaching the handles to m.
func (m *Metrics) registerProxyMetrics(reg *prometheus.Registry) {
	m.requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "requests_total",
		Help:      "Total number of fetch proxy requests by result.",
	}, []string{"result", "agent"})

	m.scannerHits = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "scanner_hits_total",
		Help:      "Total blocks by scanner type.",
	}, []string{"scanner", "agent"})

	m.requestLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "request_duration_seconds",
		Help:      "Fetch request latency in seconds.",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	})

	m.tunnelsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tunnels_total",
		Help:      "Total CONNECT tunnels by result.",
	}, []string{"result", "agent"})

	m.tunnelDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "tunnel_duration_seconds",
		Help:      "CONNECT tunnel duration in seconds.",
		Buckets:   []float64{1, 5, 10, 30, 60, 120, 300},
	})

	m.tunnelBytes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tunnel_bytes_total",
		Help:      "Total bytes transferred through CONNECT tunnels.",
	})

	m.activeTunnels = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "active_tunnels",
		Help:      "Current number of active CONNECT tunnels.",
	})

	m.sniTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "sni_total",
		Help:      "Total SNI verification results by category.",
	}, []string{"category", "agent"})

	m.reverseProxyRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "reverse_proxy_requests_total",
		Help:      "Total reverse proxy requests by method and status.",
	}, []string{"method", "status"})

	m.reverseProxyScanBlocked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "reverse_proxy_scan_blocked_total",
		Help:      "Reverse proxy requests blocked by scanning.",
	}, []string{"direction", "reason"})

	reg.MustRegister(
		m.requestsTotal, m.scannerHits, m.requestLatency,
		m.tunnelsTotal, m.tunnelDuration, m.tunnelBytes, m.activeTunnels,
		m.sniTotal,
		m.reverseProxyRequests, m.reverseProxyScanBlocked,
	)
}

// RecordAllowed records a successful (allowed) request.
func (m *Metrics) RecordAllowed(duration time.Duration, agent string) {
	m.requestsTotal.WithLabelValues("allowed", agent).Inc()
	m.requestLatency.Observe(duration.Seconds())

	m.mu.Lock()
	m.allowedCount++
	m.agentCounter(agent).Allowed++
	m.mu.Unlock()
}

// RecordBlocked records a blocked request with domain and scanner info.
func (m *Metrics) RecordBlocked(domain, scannerName string, duration time.Duration, agent string) {
	m.requestsTotal.WithLabelValues("blocked", agent).Inc()
	m.scannerHits.WithLabelValues(scannerName, agent).Inc()
	m.requestLatency.Observe(duration.Seconds())

	m.mu.Lock()
	m.blockedCount++
	m.agentCounter(agent).Blocked++
	if len(m.topBlockedDomains) < maxTopEntries {
		m.topBlockedDomains[domain]++
	} else if _, exists := m.topBlockedDomains[domain]; exists {
		m.topBlockedDomains[domain]++
	}
	if len(m.topScannerHits) < maxTopEntries {
		m.topScannerHits[scannerName]++
	} else if _, exists := m.topScannerHits[scannerName]; exists {
		m.topScannerHits[scannerName]++
	}
	m.mu.Unlock()
}

// RecordTunnel records a completed CONNECT tunnel.
func (m *Metrics) RecordTunnel(duration time.Duration, totalBytes int64, agent string) {
	m.tunnelsTotal.WithLabelValues("completed", agent).Inc()
	m.tunnelDuration.Observe(duration.Seconds())
	m.tunnelBytes.Add(float64(totalBytes))

	m.mu.Lock()
	m.tunnelCount++
	m.agentCounter(agent).Tunnels++
	m.mu.Unlock()
}

// RecordTunnelBlocked records a blocked CONNECT tunnel attempt.
func (m *Metrics) RecordTunnelBlocked(agent string) {
	m.tunnelsTotal.WithLabelValues("blocked", agent).Inc()
}

// IncrActiveTunnels increments the active tunnel gauge.
func (m *Metrics) IncrActiveTunnels() {
	m.activeTunnels.Inc()
}

// DecrActiveTunnels decrements the active tunnel gauge.
func (m *Metrics) DecrActiveTunnels() {
	m.activeTunnels.Dec()
}

// RecordSNI increments the SNI verification counter for the given category.
func (m *Metrics) RecordSNI(category, agent string) {
	m.sniTotal.WithLabelValues(category, agent).Inc()
}

// RecordReverseProxyRequest increments the reverse proxy request counter.
// Method is normalized to a known set to prevent unbounded cardinality
// from arbitrary client-controlled HTTP methods.
func (m *Metrics) RecordReverseProxyRequest(method, status string) {
	if m == nil {
		return
	}
	m.reverseProxyRequests.WithLabelValues(normalizeHTTPMethod(method), status).Inc()
}

// RecordReverseProxyScanBlocked increments the reverse proxy scan blocked counter.
// direction is "request" (DLP on inbound body) or "response" (injection on response).
func (m *Metrics) RecordReverseProxyScanBlocked(direction, reason string) {
	if m == nil {
		return
	}
	m.reverseProxyScanBlocked.WithLabelValues(direction, reason).Inc()
}

// normalizeHTTPMethod maps HTTP methods to a bounded label set.
// Unknown methods are grouped as "OTHER" to prevent cardinality explosion.
func normalizeHTTPMethod(method string) string {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
		return method
	default:
		return "OTHER"
	}
}
