// Package metrics provides Prometheus instrumentation and a JSON stats endpoint
// for the Pipelock fetch proxy.
package metrics

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxTopEntries = 100

// Metrics collects Prometheus counters and histograms for the fetch proxy.
type Metrics struct {
	registry *prometheus.Registry

	requestsTotal  *prometheus.CounterVec
	scannerHits    *prometheus.CounterVec
	requestLatency prometheus.Histogram

	tunnelsTotal   *prometheus.CounterVec
	tunnelDuration prometheus.Histogram
	tunnelBytes    prometheus.Counter
	activeTunnels  prometheus.Gauge

	mu                sync.Mutex
	startTime         time.Time
	topBlockedDomains map[string]int64
	topScannerHits    map[string]int64
	allowedCount      int64
	blockedCount      int64
	tunnelCount       int64
}

// New creates a Metrics instance with its own Prometheus registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "requests_total",
		Help:      "Total number of fetch proxy requests by result.",
	}, []string{"result"})

	scannerHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "scanner_hits_total",
		Help:      "Total blocks by scanner type.",
	}, []string{"scanner"})

	requestLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "request_duration_seconds",
		Help:      "Fetch request latency in seconds.",
		Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	})

	tunnelsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tunnels_total",
		Help:      "Total CONNECT tunnels by result.",
	}, []string{"result"})

	tunnelDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "tunnel_duration_seconds",
		Help:      "CONNECT tunnel duration in seconds.",
		Buckets:   []float64{1, 5, 10, 30, 60, 120, 300},
	})

	tunnelBytes := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tunnel_bytes_total",
		Help:      "Total bytes transferred through CONNECT tunnels.",
	})

	activeTunnels := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "active_tunnels",
		Help:      "Current number of active CONNECT tunnels.",
	})

	reg.MustRegister(requestsTotal, scannerHits, requestLatency,
		tunnelsTotal, tunnelDuration, tunnelBytes, activeTunnels)

	return &Metrics{
		registry:          reg,
		requestsTotal:     requestsTotal,
		scannerHits:       scannerHits,
		requestLatency:    requestLatency,
		tunnelsTotal:      tunnelsTotal,
		tunnelDuration:    tunnelDuration,
		tunnelBytes:       tunnelBytes,
		activeTunnels:     activeTunnels,
		startTime:         time.Now(),
		topBlockedDomains: make(map[string]int64),
		topScannerHits:    make(map[string]int64),
	}
}

// RecordAllowed records a successful (allowed) request.
func (m *Metrics) RecordAllowed(duration time.Duration) {
	m.requestsTotal.WithLabelValues("allowed").Inc()
	m.requestLatency.Observe(duration.Seconds())

	m.mu.Lock()
	m.allowedCount++
	m.mu.Unlock()
}

// RecordBlocked records a blocked request with domain and scanner info.
func (m *Metrics) RecordBlocked(domain, scannerName string, duration time.Duration) {
	m.requestsTotal.WithLabelValues("blocked").Inc()
	m.scannerHits.WithLabelValues(scannerName).Inc()
	m.requestLatency.Observe(duration.Seconds())

	m.mu.Lock()
	m.blockedCount++
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
func (m *Metrics) RecordTunnel(duration time.Duration, totalBytes int64) {
	m.tunnelsTotal.WithLabelValues("completed").Inc()
	m.tunnelDuration.Observe(duration.Seconds())
	m.tunnelBytes.Add(float64(totalBytes))

	m.mu.Lock()
	m.tunnelCount++
	m.mu.Unlock()
}

// RecordTunnelBlocked records a blocked CONNECT tunnel attempt.
func (m *Metrics) RecordTunnelBlocked() {
	m.tunnelsTotal.WithLabelValues("blocked").Inc()
}

// IncrActiveTunnels increments the active tunnel gauge.
func (m *Metrics) IncrActiveTunnels() {
	m.activeTunnels.Inc()
}

// DecrActiveTunnels decrements the active tunnel gauge.
func (m *Metrics) DecrActiveTunnels() {
	m.activeTunnels.Dec()
}

// PrometheusHandler returns an HTTP handler that serves /metrics in Prometheus text format.
func (m *Metrics) PrometheusHandler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// StatsHandler returns an HTTP handler that serves a JSON stats summary.
func (m *Metrics) StatsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		total := m.allowedCount + m.blockedCount
		stats := statsResponse{
			UptimeSeconds: time.Since(m.startTime).Seconds(),
			Requests: requestStats{
				Total:   total,
				Allowed: m.allowedCount,
				Blocked: m.blockedCount,
			},
			Tunnels:           m.tunnelCount,
			TopBlockedDomains: topN(m.topBlockedDomains),
			TopScanners:       topN(m.topScannerHits),
		}
		if total > 0 {
			stats.Requests.BlockRate = float64(m.blockedCount) / float64(total)
		}
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	}
}

type statsResponse struct {
	UptimeSeconds     float64       `json:"uptime_seconds"`
	Requests          requestStats  `json:"requests"`
	Tunnels           int64         `json:"tunnels"`
	TopBlockedDomains []rankedEntry `json:"top_blocked_domains"`
	TopScanners       []rankedEntry `json:"top_scanners"`
}

type requestStats struct {
	Total     int64   `json:"total"`
	Allowed   int64   `json:"allowed"`
	Blocked   int64   `json:"blocked"`
	BlockRate float64 `json:"block_rate"`
}

type rankedEntry struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func topN(m map[string]int64) []rankedEntry {
	entries := make([]rankedEntry, 0, len(m))
	for name, count := range m {
		entries = append(entries, rankedEntry{Name: name, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	return entries
}
