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

	wsConnectionsTotal *prometheus.CounterVec
	wsDuration         prometheus.Histogram
	wsBytes            *prometheus.CounterVec
	activeWS           prometheus.Gauge
	wsFrames           *prometheus.CounterVec
	wsScanHits         *prometheus.CounterVec
	wsRedirectHints    prometheus.Counter

	killSwitchDenials *prometheus.CounterVec

	sessionAnomalies   *prometheus.CounterVec
	sessionEscalations *prometheus.CounterVec
	sessionsActive     prometheus.Gauge
	sessionsEvicted    prometheus.Counter

	wsConnectionCount int64

	mu                sync.Mutex
	startTime         time.Time
	topBlockedDomains map[string]int64
	topScannerHits    map[string]int64
	allowedCount      int64
	blockedCount      int64
	tunnelCount       int64

	// Session profiling stats (for JSON /stats endpoint)
	sessionActiveCount     int64
	sessionAnomalyCount    int64
	sessionEscalationCount int64
	topAnomalyTypes        map[string]int64
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

	wsConnectionsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "ws_connections_total",
		Help:      "Total WebSocket proxy connections by result.",
	}, []string{"result"})

	wsDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "ws_duration_seconds",
		Help:      "WebSocket connection duration in seconds.",
		Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	})

	wsBytes := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "ws_bytes_total",
		Help:      "Total bytes transferred through WebSocket proxy.",
	}, []string{"direction"})

	activeWS := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "ws_active_connections",
		Help:      "Current number of active WebSocket proxy connections.",
	})

	wsFrames := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "ws_frames_total",
		Help:      "Total WebSocket frames by type.",
	}, []string{"type"})

	wsScanHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "ws_scan_hits_total",
		Help:      "Total WebSocket scan detections by scanner.",
	}, []string{"scanner"})

	wsRedirectHints := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "forward_ws_redirect_hint_total",
		Help:      "CONNECT requests to known WebSocket API hosts.",
	})

	killSwitchDenials := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "kill_switch_denials_total",
		Help:      "Total requests denied by the kill switch.",
	}, []string{"transport", "endpoint"})

	sessionAnomalies := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "session_anomalies_total",
		Help:      "Total session behavioral anomalies by type.",
	}, []string{"type"})

	sessionEscalations := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "session_escalations_total",
		Help:      "Total session enforcement escalations by transition.",
	}, []string{"from", "to"})

	sessionsActive := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "sessions_active",
		Help:      "Current number of active tracked sessions.",
	})

	sessionsEvicted := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "sessions_evicted_total",
		Help:      "Total sessions evicted by TTL or capacity.",
	})

	reg.MustRegister(requestsTotal, scannerHits, requestLatency,
		tunnelsTotal, tunnelDuration, tunnelBytes, activeTunnels,
		wsConnectionsTotal, wsDuration, wsBytes, activeWS, wsFrames, wsScanHits, wsRedirectHints,
		killSwitchDenials,
		sessionAnomalies, sessionEscalations, sessionsActive, sessionsEvicted)

	return &Metrics{
		registry:           reg,
		requestsTotal:      requestsTotal,
		scannerHits:        scannerHits,
		requestLatency:     requestLatency,
		tunnelsTotal:       tunnelsTotal,
		tunnelDuration:     tunnelDuration,
		tunnelBytes:        tunnelBytes,
		activeTunnels:      activeTunnels,
		wsConnectionsTotal: wsConnectionsTotal,
		wsDuration:         wsDuration,
		wsBytes:            wsBytes,
		activeWS:           activeWS,
		wsFrames:           wsFrames,
		wsScanHits:         wsScanHits,
		wsRedirectHints:    wsRedirectHints,
		killSwitchDenials:  killSwitchDenials,
		sessionAnomalies:   sessionAnomalies,
		sessionEscalations: sessionEscalations,
		sessionsActive:     sessionsActive,
		sessionsEvicted:    sessionsEvicted,
		startTime:          time.Now(),
		topBlockedDomains:  make(map[string]int64),
		topScannerHits:     make(map[string]int64),
		topAnomalyTypes:    make(map[string]int64),
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

// RecordKillSwitchDenial increments the kill switch denial counter.
func (m *Metrics) RecordKillSwitchDenial(transport, endpoint string) {
	m.killSwitchDenials.WithLabelValues(transport, endpoint).Inc()
}

// RecordSessionAnomaly increments the session anomaly counter by type.
func (m *Metrics) RecordSessionAnomaly(anomalyType string) {
	m.sessionAnomalies.WithLabelValues(anomalyType).Inc()

	m.mu.Lock()
	m.sessionAnomalyCount++
	if len(m.topAnomalyTypes) < maxTopEntries {
		m.topAnomalyTypes[anomalyType]++
	} else if _, exists := m.topAnomalyTypes[anomalyType]; exists {
		m.topAnomalyTypes[anomalyType]++
	}
	m.mu.Unlock()
}

// RecordSessionEscalation increments the session escalation counter by transition.
func (m *Metrics) RecordSessionEscalation(from, to string) {
	m.sessionEscalations.WithLabelValues(from, to).Inc()

	m.mu.Lock()
	m.sessionEscalationCount++
	m.mu.Unlock()
}

// SetSessionsActive sets the current number of active tracked sessions.
func (m *Metrics) SetSessionsActive(n float64) {
	m.sessionsActive.Set(n)

	m.mu.Lock()
	m.sessionActiveCount = int64(n)
	m.mu.Unlock()
}

// RecordSessionEvicted increments the evicted sessions counter.
func (m *Metrics) RecordSessionEvicted() {
	m.sessionsEvicted.Inc()
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
			WebSockets:        m.wsConnectionCount,
			TopBlockedDomains: topN(m.topBlockedDomains),
			TopScanners:       topN(m.topScannerHits),
			Sessions: sessionStats{
				Active:       m.sessionActiveCount,
				Anomalies:    m.sessionAnomalyCount,
				Escalations:  m.sessionEscalationCount,
				TopAnomalies: topN(m.topAnomalyTypes),
			},
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
	WebSockets        int64         `json:"websockets"`
	TopBlockedDomains []rankedEntry `json:"top_blocked_domains"`
	TopScanners       []rankedEntry `json:"top_scanners"`
	Sessions          sessionStats  `json:"sessions"`
}

type sessionStats struct {
	Active       int64         `json:"active"`
	Anomalies    int64         `json:"anomalies"`
	Escalations  int64         `json:"escalations"`
	TopAnomalies []rankedEntry `json:"top_anomalies"`
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
