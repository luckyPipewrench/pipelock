// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package metrics provides Prometheus instrumentation and a JSON stats endpoint
// for the Pipelock fetch proxy.
//
// The package is split into per-feature files. metrics.go owns the Metrics
// struct definition and the New constructor; per-feature files
// (proxy.go, websocket.go, dlp.go, session.go, tls.go, airlock.go,
// cross_request.go, scan_api.go, kill_switch.go, shield.go, capture.go)
// own the corresponding metric handles and Record/Set methods. The JSON
// stats and Prometheus HTTP handlers live in stats_handler.go.
package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics collects Prometheus counters and histograms for the fetch proxy.
type Metrics struct {
	registry *prometheus.Registry

	// Proxy / tunnel / SNI / reverse proxy (proxy.go).
	requestsTotal           *prometheus.CounterVec
	scannerHits             *prometheus.CounterVec
	requestLatency          prometheus.Histogram
	tunnelsTotal            *prometheus.CounterVec
	tunnelDuration          prometheus.Histogram
	tunnelBytes             prometheus.Counter
	activeTunnels           prometheus.Gauge
	sniTotal                *prometheus.CounterVec
	reverseProxyRequests    *prometheus.CounterVec
	reverseProxyScanBlocked *prometheus.CounterVec

	// WebSocket (websocket.go).
	wsConnectionsTotal *prometheus.CounterVec
	wsDuration         prometheus.Histogram
	wsBytes            *prometheus.CounterVec
	activeWS           prometheus.Gauge
	wsFrames           *prometheus.CounterVec
	wsScanHits         *prometheus.CounterVec
	wsRedirectHints    prometheus.Counter

	// DLP / address protection / file sentry (dlp.go).
	bodyDLPHits        *prometheus.CounterVec
	headerDLPHits      *prometheus.CounterVec
	dlpWarnMatches     *prometheus.CounterVec
	AddressFindings    *prometheus.CounterVec
	FileSentryFindings *prometheus.CounterVec

	// Sessions / adaptive enforcement / chain detection (session.go).
	sessionAnomalies         *prometheus.CounterVec
	sessionEscalations       *prometheus.CounterVec
	sessionsActive           prometheus.Gauge
	sessionsEvicted          prometheus.Counter
	adaptiveUpgrades         *prometheus.CounterVec
	adaptiveSessionsCurrent  *prometheus.GaugeVec
	sessionAutoDeescalations *prometheus.CounterVec
	chainDetections          *prometheus.CounterVec

	// TLS interception (tls.go).
	tlsInterceptTotal    *prometheus.CounterVec
	tlsCertCacheSize     prometheus.Gauge
	tlsHandshakeDuration *prometheus.HistogramVec
	tlsRequestBlocked    *prometheus.CounterVec
	tlsResponseBlocked   *prometheus.CounterVec

	// Airlock graduated quarantine (airlock.go).
	airlockSessions       *prometheus.GaugeVec
	airlockTransitions    *prometheus.CounterVec
	airlockDenials        *prometheus.CounterVec
	airlockDrainCompleted prometheus.Counter
	airlockDrainTimeout   prometheus.Counter

	// Cross-request exfiltration detection (cross_request.go).
	CrossRequestEntropyExceeded prometheus.Counter
	CrossRequestDLPMatch        prometheus.Counter
	CrossRequestFragmentBytes   prometheus.Gauge

	// Scan API (scan_api.go).
	ScanAPIRequests *prometheus.CounterVec
	ScanAPIDuration *prometheus.HistogramVec
	ScanAPIFindings *prometheus.CounterVec
	ScanAPIErrors   *prometheus.CounterVec
	ScanAPIInflight prometheus.Gauge

	// Kill switch (kill_switch.go).
	killSwitchDenials *prometheus.CounterVec

	// Browser shield + response scan exemption (shield.go).
	shieldRewrites          *prometheus.CounterVec
	shieldBytesStripped     *prometheus.CounterVec
	shieldShimsInjected     *prometheus.CounterVec
	shieldSkipped           *prometheus.CounterVec
	shieldLatency           *prometheus.HistogramVec
	responseScanExemptTotal *prometheus.CounterVec

	// Capture (capture.go).
	CaptureDropped prometheus.Counter

	// Stats endpoint state (stats_handler.go).
	mu                     sync.Mutex
	startTime              time.Time
	topBlockedDomains      map[string]int64
	topScannerHits         map[string]int64
	topAnomalyTypes        map[string]int64
	allowedCount           int64
	blockedCount           int64
	tunnelCount            int64
	wsConnectionCount      int64
	sessionActiveCount     int64
	sessionAnomalyCount    int64
	sessionEscalationCount int64
	agentStats             map[string]*agentCounters

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

// New creates a Metrics instance with its own Prometheus registry. Each
// per-feature register helper allocates that feature's metric handles,
// registers them with reg, and stores them on m. Splitting the
// constructor like this keeps each bundle's wiring colocated with the
// methods that use it without changing the underlying registry pattern
// (one registry per Metrics, one MustRegister call site per feature).
func New() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry:          reg,
		startTime:         time.Now(),
		topBlockedDomains: make(map[string]int64),
		topScannerHits:    make(map[string]int64),
		topAnomalyTypes:   make(map[string]int64),
		agentStats:        make(map[string]*agentCounters),
	}

	m.registerProxyMetrics(reg)
	m.registerWSMetrics(reg)
	m.registerDLPMetrics(reg)
	m.registerSessionMetrics(reg)
	m.registerTLSMetrics(reg)
	m.registerAirlockMetrics(reg)
	m.registerCrossRequestMetrics(reg)
	m.registerScanAPIMetrics(reg)
	m.registerKillSwitchMetrics(reg)
	m.registerShieldMetrics(reg)
	m.registerCaptureMetrics(reg)

	return m
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
