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

	mu                sync.Mutex
	startTime         time.Time
	topBlockedDomains map[string]int64
	topScannerHits    map[string]int64
	allowedCount      int64
	blockedCount      int64
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

	reg.MustRegister(requestsTotal, scannerHits, requestLatency)

	return &Metrics{
		registry:          reg,
		requestsTotal:     requestsTotal,
		scannerHits:       scannerHits,
		requestLatency:    requestLatency,
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
