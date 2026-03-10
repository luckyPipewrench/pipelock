// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

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

	chainDetections *prometheus.CounterVec

	sniTotal *prometheus.CounterVec

	bodyDLPHits   *prometheus.CounterVec
	headerDLPHits *prometheus.CounterVec

	sessionAnomalies   *prometheus.CounterVec
	sessionEscalations *prometheus.CounterVec
	sessionsActive     prometheus.Gauge
	sessionsEvicted    prometheus.Counter

	tlsInterceptTotal    *prometheus.CounterVec
	tlsCertCacheSize     prometheus.Gauge
	tlsHandshakeDuration *prometheus.HistogramVec
	tlsRequestBlocked    *prometheus.CounterVec
	tlsResponseBlocked   *prometheus.CounterVec

	// Cross-request exfiltration detection
	CrossRequestEntropyExceeded prometheus.Counter
	CrossRequestDLPMatch        prometheus.Counter
	CrossRequestEntropyAnomaly  prometheus.Counter
	CrossRequestFragmentBytes   prometheus.Gauge

	wsConnectionCount int64

	mu                sync.Mutex
	startTime         time.Time
	topBlockedDomains map[string]int64
	topScannerHits    map[string]int64
	allowedCount      int64
	blockedCount      int64
	tunnelCount       int64
	agentStats        map[string]*agentCounters // per-agent allowed/blocked/tunnel counts

	// Session profiling stats (for JSON /stats endpoint)
	sessionActiveCount     int64
	sessionAnomalyCount    int64
	sessionEscalationCount int64
	topAnomalyTypes        map[string]int64

	// Cross-request exfiltration stats callback (for JSON /stats endpoint).
	// Called on each /stats request to get live CEE state.
	CEEStatsFunc func() CEEStats
}

// agentCounters tracks per-agent request counts for the /stats endpoint.
// Cardinality is bounded because callers pass the resolved profile name
// (not the raw header value), which falls back to "_default" for unknown agents.
type agentCounters struct {
	Allowed int64
	Blocked int64
	Tunnels int64
}

// New creates a Metrics instance with its own Prometheus registry.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "requests_total",
		Help:      "Total number of fetch proxy requests by result.",
	}, []string{"result", "agent"})

	scannerHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "scanner_hits_total",
		Help:      "Total blocks by scanner type.",
	}, []string{"scanner", "agent"})

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
	}, []string{"result", "agent"})

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

	chainDetections := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "chain_detections_total",
		Help:      "Total tool call chain pattern detections.",
	}, []string{"pattern", "severity", "action"})

	sniTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "sni_total",
		Help:      "Total SNI verification results by category.",
	}, []string{"category", "agent"})

	bodyDLPHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "body_dlp_hits_total",
		Help:      "Total request body DLP scan detections by action.",
	}, []string{"action", "agent"})

	headerDLPHits := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "header_dlp_hits_total",
		Help:      "Total request header DLP scan detections by action.",
	}, []string{"action", "agent"})

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

	tlsInterceptTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tls_intercept_total",
		Help:      "Total TLS-intercepted CONNECT tunnels by outcome.",
	}, []string{"outcome"})

	tlsCertCacheSize := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "tls_cert_cache_size",
		Help:      "Current number of cached TLS leaf certificates.",
	})

	tlsHandshakeDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "tls_handshake_duration_seconds",
		Help:      "TLS handshake latency in seconds.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
	}, []string{"side"})

	tlsRequestBlocked := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tls_request_blocked_total",
		Help:      "Total TLS-intercepted requests blocked by reason.",
	}, []string{"reason"})

	tlsResponseBlocked := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "tls_response_blocked_total",
		Help:      "Total TLS-intercepted responses blocked by reason.",
	}, []string{"reason"})

	crossRequestEntropyExceeded := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pipelock_cross_request_entropy_exceeded_total",
		Help: "Entropy budget exceeded events",
	})
	crossRequestDLPMatch := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pipelock_cross_request_dlp_match_total",
		Help: "Fragment reassembly DLP match events",
	})
	crossRequestEntropyAnomaly := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "pipelock_cross_request_entropy_anomaly_total",
		Help: "Adaptive entropy rate signal events",
	})
	crossRequestFragmentBytes := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pipelock_cross_request_fragment_buffer_bytes",
		Help: "Total fragment buffer memory across all sessions",
	})

	reg.MustRegister(requestsTotal, scannerHits, requestLatency,
		tunnelsTotal, tunnelDuration, tunnelBytes, activeTunnels,
		wsConnectionsTotal, wsDuration, wsBytes, activeWS, wsFrames, wsScanHits, wsRedirectHints,
		killSwitchDenials, chainDetections, sniTotal,
		bodyDLPHits, headerDLPHits,
		sessionAnomalies, sessionEscalations, sessionsActive, sessionsEvicted,
		tlsInterceptTotal, tlsCertCacheSize, tlsHandshakeDuration, tlsRequestBlocked, tlsResponseBlocked,
		crossRequestEntropyExceeded, crossRequestDLPMatch, crossRequestEntropyAnomaly, crossRequestFragmentBytes)

	return &Metrics{
		registry:                    reg,
		requestsTotal:               requestsTotal,
		scannerHits:                 scannerHits,
		requestLatency:              requestLatency,
		tunnelsTotal:                tunnelsTotal,
		tunnelDuration:              tunnelDuration,
		tunnelBytes:                 tunnelBytes,
		activeTunnels:               activeTunnels,
		wsConnectionsTotal:          wsConnectionsTotal,
		wsDuration:                  wsDuration,
		wsBytes:                     wsBytes,
		activeWS:                    activeWS,
		wsFrames:                    wsFrames,
		wsScanHits:                  wsScanHits,
		wsRedirectHints:             wsRedirectHints,
		killSwitchDenials:           killSwitchDenials,
		chainDetections:             chainDetections,
		sniTotal:                    sniTotal,
		bodyDLPHits:                 bodyDLPHits,
		headerDLPHits:               headerDLPHits,
		sessionAnomalies:            sessionAnomalies,
		sessionEscalations:          sessionEscalations,
		sessionsActive:              sessionsActive,
		sessionsEvicted:             sessionsEvicted,
		tlsInterceptTotal:           tlsInterceptTotal,
		tlsCertCacheSize:            tlsCertCacheSize,
		tlsHandshakeDuration:        tlsHandshakeDuration,
		tlsRequestBlocked:           tlsRequestBlocked,
		tlsResponseBlocked:          tlsResponseBlocked,
		CrossRequestEntropyExceeded: crossRequestEntropyExceeded,
		CrossRequestDLPMatch:        crossRequestDLPMatch,
		CrossRequestEntropyAnomaly:  crossRequestEntropyAnomaly,
		CrossRequestFragmentBytes:   crossRequestFragmentBytes,
		startTime:                   time.Now(),
		topBlockedDomains:           make(map[string]int64),
		topScannerHits:              make(map[string]int64),
		topAnomalyTypes:             make(map[string]int64),
		agentStats:                  make(map[string]*agentCounters),
	}
}

// Registry returns the underlying Prometheus registry for test assertions.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// agentCounter returns the per-agent counters, creating them on first access.
// Must be called with m.mu held.
func (m *Metrics) agentCounter(agent string) *agentCounters {
	ac := m.agentStats[agent]
	if ac == nil {
		ac = &agentCounters{}
		m.agentStats[agent] = ac
	}
	return ac
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

// RecordChainDetection increments the chain detection counter.
func (m *Metrics) RecordChainDetection(pattern, severity, action string) {
	m.chainDetections.WithLabelValues(pattern, severity, action).Inc()
}

// RecordSNI increments the SNI verification counter for the given category.
func (m *Metrics) RecordSNI(category, agent string) {
	m.sniTotal.WithLabelValues(category, agent).Inc()
}

// RecordBodyDLP increments the request body DLP scan counter by action.
func (m *Metrics) RecordBodyDLP(action, agent string) {
	m.bodyDLPHits.WithLabelValues(action, agent).Inc()
}

// RecordHeaderDLP increments the request header DLP scan counter by action.
func (m *Metrics) RecordHeaderDLP(action, agent string) {
	m.headerDLPHits.WithLabelValues(action, agent).Inc()
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

// RecordCrossRequestEntropyExceeded increments the cross-request entropy exceeded counter.
func (m *Metrics) RecordCrossRequestEntropyExceeded() {
	if m != nil {
		m.CrossRequestEntropyExceeded.Inc()
	}
}

// RecordCrossRequestDLPMatch increments the cross-request fragment DLP match counter.
func (m *Metrics) RecordCrossRequestDLPMatch() {
	if m != nil {
		m.CrossRequestDLPMatch.Inc()
	}
}

// RecordCrossRequestEntropyAnomaly increments the cross-request entropy anomaly counter.
func (m *Metrics) RecordCrossRequestEntropyAnomaly() {
	if m != nil {
		m.CrossRequestEntropyAnomaly.Inc()
	}
}

// SetCrossRequestFragmentBytes sets the total fragment buffer memory gauge.
func (m *Metrics) SetCrossRequestFragmentBytes(bytes float64) {
	if m != nil {
		m.CrossRequestFragmentBytes.Set(bytes)
	}
}

// SetCEEStatsFunc registers a callback that returns live CEE state for the
// /stats endpoint. Called on each /stats request (not on every proxy request).
func (m *Metrics) SetCEEStatsFunc(fn func() CEEStats) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.CEEStatsFunc = fn
	m.mu.Unlock()
}

// RegisterKillSwitchState registers a custom collector that reports the
// current kill switch state as pipelock_kill_switch_active{source=...}
// gauges. The sourceFunc is called once per Prometheus scrape and should
// return the active/inactive state of each source (e.g. Controller.Sources).
func (m *Metrics) RegisterKillSwitchState(sourceFunc func() map[string]bool) {
	if sourceFunc == nil {
		return
	}
	m.registry.MustRegister(&killSwitchCollector{sourceFunc: sourceFunc})
}

// RegisterInfo registers a pipelock_info gauge with the given version label.
// This is a standard Prometheus info metric (always 1) that lets Grafana
// display which version each agent runs.
func (m *Metrics) RegisterInfo(version string) {
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   "pipelock",
		Name:        "info",
		Help:        "Pipelock build information.",
		ConstLabels: prometheus.Labels{"version": version},
	})
	info.Set(1)
	m.registry.MustRegister(info)
}

// killSwitchCollector implements prometheus.Collector to report kill switch
// source states on each scrape. This avoids stale gauge values: the state
// is read fresh from the Controller on every Prometheus scrape request.
type killSwitchCollector struct {
	sourceFunc func() map[string]bool
}

var killSwitchActiveDesc = prometheus.NewDesc(
	"pipelock_kill_switch_active",
	"Whether a kill switch source is currently active (1) or inactive (0).",
	[]string{"source"}, nil,
)

func (c *killSwitchCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- killSwitchActiveDesc
}

func (c *killSwitchCollector) Collect(ch chan<- prometheus.Metric) {
	for source, active := range c.sourceFunc() {
		val := 0.0
		if active {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(killSwitchActiveDesc, prometheus.GaugeValue, val, source)
	}
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
		ceeFunc := m.CEEStatsFunc
		if total > 0 {
			stats.Requests.BlockRate = float64(m.blockedCount) / float64(total)
		}
		if len(m.agentStats) > 0 {
			stats.Agents = make(map[string]agentStatsOut, len(m.agentStats))
			for name, ac := range m.agentStats {
				stats.Agents[name] = agentStatsOut{
					Allowed: ac.Allowed,
					Blocked: ac.Blocked,
					Tunnels: ac.Tunnels,
				}
			}
		}
		m.mu.Unlock()

		// Call CEE stats func outside the lock (it accesses proxy atomic pointers).
		if ceeFunc != nil {
			stats.CEE = ceeFunc()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	}
}

type statsResponse struct {
	UptimeSeconds     float64                  `json:"uptime_seconds"`
	Requests          requestStats             `json:"requests"`
	Tunnels           int64                    `json:"tunnels"`
	WebSockets        int64                    `json:"websockets"`
	TopBlockedDomains []rankedEntry            `json:"top_blocked_domains"`
	TopScanners       []rankedEntry            `json:"top_scanners"`
	Sessions          sessionStats             `json:"sessions"`
	CEE               CEEStats                 `json:"cross_request_detection"`
	Agents            map[string]agentStatsOut `json:"agents,omitempty"`
}

type CEEStats struct {
	EntropyTrackerActive bool `json:"entropy_tracker_active"`
	FragmentBufferActive bool `json:"fragment_buffer_active"`
	FragmentBufferBytes  int  `json:"fragment_buffer_bytes"`
}

type agentStatsOut struct {
	Allowed int64 `json:"allowed"`
	Blocked int64 `json:"blocked"`
	Tunnels int64 `json:"tunnels"`
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
