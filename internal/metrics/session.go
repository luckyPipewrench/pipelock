// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// adaptiveSessionGauge is a state-backed collector for the current adaptive
// enforcement levels. Transition deltas are inherently lossy across reloads
// and restored session state: a later de-escalation can otherwise decrement a
// fresh registry below zero. Session managers therefore supply current state
// at scrape time. The fallback is retained for metrics-only callers that do
// not have a SessionManager.
type adaptiveSessionGauge struct {
	desc *prometheus.Desc

	mu            sync.RWMutex
	sources       map[uint64]*adaptiveSessionSource
	sourceID      uint64
	authoritative bool
	fallback      map[string]float64
	// observed retains labels that this process has already exposed. GaugeVec
	// keeps an initialized label at zero after its value is decremented, and
	// alerting/dashboards may distinguish that from an absent time series.
	observed map[string]struct{}
}

type adaptiveSessionSource struct {
	mu      sync.RWMutex
	active  bool
	collect func() map[string]float64
}

func (s *adaptiveSessionSource) values() map[string]float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.active {
		return nil
	}
	return s.collect()
}

func (s *adaptiveSessionSource) deactivate() {
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
}

func newAdaptiveSessionGauge() *adaptiveSessionGauge {
	return &adaptiveSessionGauge{
		desc: prometheus.NewDesc(
			"pipelock_adaptive_sessions_current",
			"Currently escalated sessions by effective enforcement level.",
			[]string{"level"}, nil,
		),
		sources:  make(map[uint64]*adaptiveSessionSource),
		fallback: make(map[string]float64),
		observed: make(map[string]struct{}),
	}
}

func (g *adaptiveSessionGauge) Describe(ch chan<- *prometheus.Desc) {
	ch <- g.desc
}

func (g *adaptiveSessionGauge) Collect(ch chan<- prometheus.Metric) {
	g.mu.RLock()
	sources := make([]*adaptiveSessionSource, 0, len(g.sources))
	for _, source := range g.sources {
		sources = append(sources, source)
	}
	values := make(map[string]float64, len(g.fallback)+len(g.observed))
	for level := range g.observed {
		values[level] = 0
	}
	if !g.authoritative {
		for level, value := range g.fallback {
			values[level] = value
		}
	}
	g.mu.RUnlock()
	for _, source := range sources {
		for level, value := range source.values() {
			values[level] += value
			g.mu.Lock()
			g.observed[level] = struct{}{}
			g.mu.Unlock()
		}
	}

	levels := make([]string, 0, len(values))
	for level := range values {
		levels = append(levels, level)
	}
	sort.Strings(levels)
	for _, level := range levels {
		metric, err := prometheus.NewConstMetric(g.desc, prometheus.GaugeValue, values[level], level)
		if err == nil {
			ch <- metric
		}
	}
}

func (g *adaptiveSessionGauge) add(level string, delta float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.observed[level] = struct{}{}
	if !g.authoritative {
		g.fallback[level] += delta
	}
}

func (g *adaptiveSessionGauge) registerSource(source func() map[string]float64) func() {
	registered := &adaptiveSessionSource{active: true, collect: source}
	g.mu.Lock()
	g.sourceID++
	id := g.sourceID
	g.sources[id] = registered
	g.authoritative = true
	// A session manager source is authoritative. Discard prior transition
	// deltas and never resume them on this registry: long-lived transports may
	// retain a recorder after a reload disables session profiling and emit stale
	// deltas.
	g.fallback = make(map[string]float64)
	g.mu.Unlock()

	return func() {
		registered.deactivate()
		g.mu.Lock()
		defer g.mu.Unlock()
		delete(g.sources, id)
	}
}

// registerSessionMetrics builds and registers session anomaly/escalation
// counters, the active/evicted session lifecycle metrics, adaptive
// enforcement v2 upgrades + escalated session gauges, autonomous
// de-escalation counters, and the chain detection counter. Handles are
// attached to m.
func (m *Metrics) registerSessionMetrics(reg *prometheus.Registry) {
	m.sessionAnomalies = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "session_anomalies_total",
		Help:      "Total session behavioral anomalies by type.",
	}, []string{"type"})

	m.sessionEscalations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "session_escalations_total",
		Help:      "Total session enforcement escalations by transition.",
	}, []string{"from", "to"})

	m.sessionsActive = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "sessions_active",
		Help:      "Current number of active tracked sessions.",
	})

	m.sessionsEvicted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "sessions_evicted_total",
		Help:      "Total sessions evicted by TTL or capacity.",
	})

	m.adaptiveUpgrades = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "adaptive_upgrades_total",
		Help:      "Requests where adaptive enforcement upgraded the action (e.g. warn→block).",
	}, []string{"from_action", "to_action", "level"})

	m.adaptiveSessionsCurrent = newAdaptiveSessionGauge()

	m.sessionAutoDeescalations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_session_auto_deescalation_total",
		Help: "Number of autonomous session de-escalations.",
	}, []string{"from", "to"})

	m.chainDetections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "chain_detections_total",
		Help:      "Total tool call chain pattern detections.",
	}, []string{"pattern", "severity", "action"})

	reg.MustRegister(
		m.sessionAnomalies, m.sessionEscalations, m.sessionsActive, m.sessionsEvicted,
		m.adaptiveUpgrades, m.adaptiveSessionsCurrent,
		m.sessionAutoDeescalations,
		m.chainDetections,
	)
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

// RecordAdaptiveUpgrade increments the adaptive upgrades counter for a request
// where enforcement was upgraded from fromAction to toAction at the given level.
func (m *Metrics) RecordAdaptiveUpgrade(fromAction, toAction, level string) {
	if m == nil {
		return
	}
	m.adaptiveUpgrades.WithLabelValues(fromAction, toAction, level).Inc()
}

// SetAdaptiveSessionLevel adjusts the fallback gauge for callers without a
// SessionManager. A registered SessionManager state source overrides these
// deltas at scrape time.
func (m *Metrics) SetAdaptiveSessionLevel(level string, delta float64) {
	if m == nil {
		return
	}
	m.adaptiveSessionsCurrent.add(level, delta)
}

// RegisterAdaptiveSessionState adds source to the authoritative current
// adaptive-session gauge. Sources are summed for independently created session
// managers that intentionally share one Metrics registry. The returned function
// unregisters only its own source. The proxy runtime itself maintains one active
// session manager and reconfigures it in place across enabled-to-enabled reloads.
func (m *Metrics) RegisterAdaptiveSessionState(source func() map[string]float64) func() {
	if m == nil || source == nil {
		return func() {}
	}
	return m.adaptiveSessionsCurrent.registerSource(source)
}

// RecordSessionAutoDeescalation increments the auto-deescalation counter for
// a session that autonomously dropped from one escalation level to another.
func (m *Metrics) RecordSessionAutoDeescalation(from, to string) {
	if m == nil {
		return
	}
	m.sessionAutoDeescalations.WithLabelValues(from, to).Inc()
}

// RecordChainDetection increments the chain detection counter.
func (m *Metrics) RecordChainDetection(pattern, severity, action string) {
	m.chainDetections.WithLabelValues(pattern, severity, action).Inc()
}
