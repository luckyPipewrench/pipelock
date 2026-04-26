// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

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

	m.adaptiveSessionsCurrent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "adaptive_sessions_current",
		Help:      "Currently escalated sessions by enforcement level.",
	}, []string{"level"})

	m.sessionAutoDeescalations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pipelock_session_auto_deescalation_total",
		Help: "Number of autonomous time-based session de-escalations.",
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

// RecordChainDetection increments the chain detection counter.
func (m *Metrics) RecordChainDetection(pattern, severity, action string) {
	m.chainDetections.WithLabelValues(pattern, severity, action).Inc()
}
