// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// airlockTierNone mirrors config.AirlockTierNone to avoid importing the
// config package. Transitions from/to "none" must not adjust the gauge.
const airlockTierNone = "none"

// registerAirlockMetrics builds and registers the airlock tier session
// gauge, transition counter, denial counter, and drain completion/timeout
// counters. Handles are attached to m.
func (m *Metrics) registerAirlockMetrics(reg *prometheus.Registry) {
	m.airlockSessions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "airlock_sessions",
		Help:      "Current sessions in each airlock tier.",
	}, []string{"tier"})

	m.airlockTransitions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "airlock_transitions_total",
		Help:      "Total airlock tier transitions.",
	}, []string{"from", "to", "trigger"})

	m.airlockDenials = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "airlock_denials_total",
		Help:      "Total requests denied by airlock enforcement.",
	}, []string{"tier", "transport", "action_class"})

	m.airlockDrainCompleted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "airlock_drain_completed_total",
		Help:      "Sessions that completed drain (all in-flight requests finished).",
	})

	m.airlockDrainTimeout = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "airlock_drain_timeout_total",
		Help:      "Sessions where drain timed out before in-flight requests finished.",
	})

	reg.MustRegister(
		m.airlockSessions, m.airlockTransitions, m.airlockDenials,
		m.airlockDrainCompleted, m.airlockDrainTimeout,
	)
}

// RecordAirlockTransition increments the airlock tier transition counter
// and adjusts the per-tier session gauge.
func (m *Metrics) RecordAirlockTransition(from, to, trigger string) {
	if m == nil {
		return
	}
	m.airlockTransitions.WithLabelValues(from, to, trigger).Inc()
	// Only adjust the gauge for actual airlock tiers. "none" is the normal
	// (non-airlocked) state and should never appear in the gauge.
	if from != "" && from != airlockTierNone {
		m.airlockSessions.WithLabelValues(from).Dec()
	}
	if to != "" && to != airlockTierNone {
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
