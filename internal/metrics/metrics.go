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
	CrossRequestFragmentBytes   prometheus.Gauge

	// Scan API metrics
	ScanAPIRequests *prometheus.CounterVec
	ScanAPIDuration *prometheus.HistogramVec
	ScanAPIFindings *prometheus.CounterVec
	ScanAPIErrors   *prometheus.CounterVec
	ScanAPIInflight prometheus.Gauge

	// Address protection: crypto address poisoning detection.
	AddressFindings *prometheus.CounterVec

	// File sentry: secret detection in agent-written files.
	FileSentryFindings *prometheus.CounterVec

	// Adaptive enforcement v2: action upgrades and escalated sessions.
	adaptiveUpgrades        *prometheus.CounterVec
	adaptiveSessionsCurrent *prometheus.GaugeVec

	// Auto-deescalation: autonomous time-based session recovery.
	sessionAutoDeescalations *prometheus.CounterVec

	// Reverse proxy: request counting and scan block tracking.
	reverseProxyRequests    *prometheus.CounterVec
	reverseProxyScanBlocked *prometheus.CounterVec

	// Capture system metrics.
	CaptureDropped prometheus.Counter

	// Airlock: graduated quarantine metrics.
	airlockSessions       *prometheus.GaugeVec   // tier label
	airlockTransitions    *prometheus.CounterVec // from, to, trigger labels
	airlockDenials        *prometheus.CounterVec // tier, transport, action_class labels
	airlockDrainCompleted prometheus.Counter
	airlockDrainTimeout   prometheus.Counter

	// Browser Shield: inline rewriting metrics.
	shieldRewrites      *prometheus.CounterVec   // category, transport labels
	shieldBytesStripped *prometheus.CounterVec   // category label
	shieldShimsInjected *prometheus.CounterVec   // transport label
	shieldSkipped       *prometheus.CounterVec   // reason label
	shieldLatency       *prometheus.HistogramVec // transport label

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
		Namespace: "pipelock",
		Name:      "cross_request_entropy_exceeded_total",
		Help:      "Entropy budget exceeded events.",
	})
	crossRequestDLPMatch := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "cross_request_dlp_match_total",
		Help:      "Fragment reassembly DLP match events.",
	})
	crossRequestFragmentBytes := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "cross_request_fragment_buffer_bytes",
		Help:      "Total fragment buffer memory across all sessions.",
	})

	scanAPIRequests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_scan_api_requests_total",
		Help: "Total scan API requests by kind, decision, and status code.",
	}, []string{"kind", "decision", "status_code"})
	scanAPIDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pipelock_scan_api_duration_seconds",
		Help:    "Scan API scan latency in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"kind"})
	scanAPIFindings := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_scan_api_findings_total",
		Help: "Total scan API findings by kind, scanner, and severity.",
	}, []string{"kind", "scanner", "severity"})
	scanAPIErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_scan_api_errors_total",
		Help: "Total scan API errors by kind and error code.",
	}, []string{"kind", "error_code"})
	scanAPIInflight := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pipelock_scan_api_inflight_requests",
		Help: "Current number of in-flight scan API requests.",
	})

	addressFindings := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "address_findings_total",
		Help:      "Address protection findings by chain and verdict.",
	}, []string{"chain", "verdict"})

	fileSentryFindings := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "file_sentry_findings_total",
		Help:      "Secrets detected in agent-written files by pattern and severity.",
	}, []string{"pattern", "severity", "agent"})

	adaptiveUpgrades := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "adaptive_upgrades_total",
		Help:      "Requests where adaptive enforcement upgraded the action (e.g. warn→block).",
	}, []string{"from_action", "to_action", "level"})

	adaptiveSessionsCurrent := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "adaptive_sessions_current",
		Help:      "Currently escalated sessions by enforcement level.",
	}, []string{"level"})

	sessionAutoDeescalations := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_session_auto_deescalation_total",
		Help: "Number of autonomous time-based session de-escalations.",
	}, []string{"from", "to"})

	reverseProxyRequests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "reverse_proxy_requests_total",
		Help:      "Total reverse proxy requests by method and status.",
	}, []string{"method", "status"})

	reverseProxyScanBlocked := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "reverse_proxy_scan_blocked_total",
		Help:      "Reverse proxy requests blocked by scanning.",
	}, []string{"direction", "reason"})

	captureDropped := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "capture_dropped_total",
		Help:      "Total capture entries dropped due to queue overflow.",
	})

	// Airlock metrics: graduated quarantine state tracking.
	airlockSessions := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "airlock_sessions",
		Help:      "Current sessions in each airlock tier.",
	}, []string{"tier"})
	airlockTransitions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "airlock_transitions_total",
		Help:      "Total airlock tier transitions.",
	}, []string{"from", "to", "trigger"})
	airlockDenials := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "airlock_denials_total",
		Help:      "Total requests denied by airlock enforcement.",
	}, []string{"tier", "transport", "action_class"})
	airlockDrainCompleted := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "airlock_drain_completed_total",
		Help:      "Sessions that completed drain (all in-flight requests finished).",
	})
	airlockDrainTimeout := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "airlock_drain_timeout_total",
		Help:      "Sessions where drain timed out before in-flight requests finished.",
	})

	// Browser Shield metrics: inline HTML/JS rewriting tracking.
	shieldRewrites := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "shield_rewrites_total",
		Help:      "Total browser shield rewrites by category and transport.",
	}, []string{"category", "transport"})
	shieldBytesStripped := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "shield_bytes_stripped_total",
		Help:      "Total bytes stripped by browser shield by category.",
	}, []string{"category"})
	shieldShimsInjected := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "shield_shims_injected_total",
		Help:      "Total shim script injections by transport.",
	}, []string{"transport"})
	shieldSkipped := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "shield_skipped_total",
		Help:      "Total shield processing skips by reason.",
	}, []string{"reason"})
	shieldLatency := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "pipelock",
		Name:      "shield_latency_seconds",
		Help:      "Browser shield rewriting latency in seconds.",
		Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
	}, []string{"transport"})

	reg.MustRegister(requestsTotal, scannerHits, requestLatency,
		tunnelsTotal, tunnelDuration, tunnelBytes, activeTunnels,
		wsConnectionsTotal, wsDuration, wsBytes, activeWS, wsFrames, wsScanHits, wsRedirectHints,
		killSwitchDenials, chainDetections, sniTotal,
		bodyDLPHits, headerDLPHits,
		sessionAnomalies, sessionEscalations, sessionsActive, sessionsEvicted,
		tlsInterceptTotal, tlsCertCacheSize, tlsHandshakeDuration, tlsRequestBlocked, tlsResponseBlocked,
		crossRequestEntropyExceeded, crossRequestDLPMatch, crossRequestFragmentBytes,
		scanAPIRequests, scanAPIDuration, scanAPIFindings, scanAPIErrors, scanAPIInflight,
		addressFindings,
		fileSentryFindings,
		adaptiveUpgrades, adaptiveSessionsCurrent,
		sessionAutoDeescalations,
		reverseProxyRequests, reverseProxyScanBlocked,
		captureDropped,
		airlockSessions, airlockTransitions, airlockDenials,
		airlockDrainCompleted, airlockDrainTimeout,
		shieldRewrites, shieldBytesStripped, shieldShimsInjected,
		shieldSkipped, shieldLatency)

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
		CrossRequestFragmentBytes:   crossRequestFragmentBytes,
		ScanAPIRequests:             scanAPIRequests,
		ScanAPIDuration:             scanAPIDuration,
		ScanAPIFindings:             scanAPIFindings,
		ScanAPIErrors:               scanAPIErrors,
		ScanAPIInflight:             scanAPIInflight,
		AddressFindings:             addressFindings,
		FileSentryFindings:          fileSentryFindings,
		adaptiveUpgrades:            adaptiveUpgrades,
		adaptiveSessionsCurrent:     adaptiveSessionsCurrent,
		sessionAutoDeescalations:    sessionAutoDeescalations,
		reverseProxyRequests:        reverseProxyRequests,
		reverseProxyScanBlocked:     reverseProxyScanBlocked,
		CaptureDropped:              captureDropped,
		airlockSessions:             airlockSessions,
		airlockTransitions:          airlockTransitions,
		airlockDenials:              airlockDenials,
		airlockDrainCompleted:       airlockDrainCompleted,
		airlockDrainTimeout:         airlockDrainTimeout,
		shieldRewrites:              shieldRewrites,
		shieldBytesStripped:         shieldBytesStripped,
		shieldShimsInjected:         shieldShimsInjected,
		shieldSkipped:               shieldSkipped,
		shieldLatency:               shieldLatency,
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

// RecordCaptureDrop increments the capture dropped counter.
func (m *Metrics) RecordCaptureDrop() {
	m.CaptureDropped.Inc()
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

// RecordAddressFinding increments the address findings counter.
func (m *Metrics) RecordAddressFinding(chain, verdict string) {
	m.AddressFindings.WithLabelValues(chain, verdict).Inc()
}

// RecordAdaptiveUpgrade increments the adaptive upgrades counter for a request
// where enforcement was upgraded from fromAction to toAction at the given level.
func (m *Metrics) RecordAdaptiveUpgrade(fromAction, toAction, level string) {
	if m == nil {
		return
	}
	m.adaptiveUpgrades.WithLabelValues(fromAction, toAction, level).Inc()
}

// SetAdaptiveSessionLevel adjusts the gauge tracking currently escalated sessions
// at the given level by delta (positive to increment, negative to decrement).
func (m *Metrics) SetAdaptiveSessionLevel(level string, delta float64) {
	if m == nil {
		return
	}
	m.adaptiveSessionsCurrent.WithLabelValues(level).Add(delta)
}

// RecordSessionAutoDeescalation increments the auto-deescalation counter for
// a session that autonomously dropped from one escalation level to another.
func (m *Metrics) RecordSessionAutoDeescalation(from, to string) {
	if m == nil {
		return
	}
	m.sessionAutoDeescalations.WithLabelValues(from, to).Inc()
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

// RecordReverseProxyScanBlocked increments the reverse proxy scan blocked counter.
// direction is "request" (DLP on inbound body) or "response" (injection on response).
func (m *Metrics) RecordReverseProxyScanBlocked(direction, reason string) {
	if m == nil {
		return
	}
	m.reverseProxyScanBlocked.WithLabelValues(direction, reason).Inc()
}

// RecordFileSentryFinding increments the file sentry findings counter.
// The agent label is "true" if the write was attributed to the agent process tree.
func (m *Metrics) RecordFileSentryFinding(pattern, severity string, isAgent bool) {
	if m == nil {
		return
	}
	agent := "false"
	if isAgent {
		agent = "true"
	}
	m.FileSentryFindings.WithLabelValues(pattern, severity, agent).Inc()
}

// RecordAirlockTransition increments the airlock tier transition counter
// and adjusts the per-tier session gauge.
func (m *Metrics) RecordAirlockTransition(from, to, trigger string) {
	if m == nil {
		return
	}
	m.airlockTransitions.WithLabelValues(from, to, trigger).Inc()
	if from != "" {
		m.airlockSessions.WithLabelValues(from).Dec()
	}
	if to != "" {
		m.airlockSessions.WithLabelValues(to).Inc()
	}
}

// RecordAirlockDenial increments the airlock denial counter.
func (m *Metrics) RecordAirlockDenial(tier, transport, actionClass string) {
	if m == nil {
		return
	}
	m.airlockDenials.WithLabelValues(tier, transport, actionClass).Inc()
}

// RecordAirlockDrainCompleted increments the completed drain counter.
func (m *Metrics) RecordAirlockDrainCompleted() {
	if m == nil {
		return
	}
	m.airlockDrainCompleted.Inc()
}

// RecordAirlockDrainTimeout increments the drain timeout counter.
func (m *Metrics) RecordAirlockDrainTimeout() {
	if m == nil {
		return
	}
	m.airlockDrainTimeout.Inc()
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
