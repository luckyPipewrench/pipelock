// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// learnNamespace is the Prometheus namespace for all learn-and-lock metrics.
// Per the v2.4 design, the observation pipeline emits under pipelock_learn_*;
// the rest of pipelock emits under pipelock_* directly. Keeping the
// namespaces separate makes alerting on observation-pipeline health
// independent of proxy/scanner alerts.
const learnNamespace = "pipelock_learn"

// learnActionClassUnclassified is the canonical wire-form label for
// observation events whose action class could not be resolved by the
// classifier. Kept as a const so the bookkeeping in RecordObservationEvent
// agrees with the upstream emitters byte-for-byte.
const learnActionClassUnclassified = "unclassified"

// registerLearnMetrics builds and registers the observation-pipeline counters
// (events emitted by event_kind, regulated data blocked by reason,
// unclassified action total) plus the unclassified rate gauge. Handles are
// attached to m.
func (m *Metrics) registerLearnMetrics(reg *prometheus.Registry) {
	m.learnObservationEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: learnNamespace,
		Name:      "observation_events_total",
		Help:      "Total observation events emitted to the recorder, labeled by action_class.",
	}, []string{"action_class"})

	m.learnRegulatedDataBlocked = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: learnNamespace,
		Name:      "regulated_data_blocked_total",
		Help:      "Observation events whose data class resolved to regulated and were dropped before reaching the recorder, labeled by reason.",
	}, []string{"reason"})

	m.learnUnclassifiedActions = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: learnNamespace,
		Name:      "unclassified_actions_total",
		Help:      "Subset of observation events with action_class=unclassified. Used by the v2.4 done-state classification debt gate (target: 0 on side-effecting/high-authority paths, <= 5% overall).",
	})

	m.learnUnclassifiedRate = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: learnNamespace,
		Name:      "unclassified_rate",
		Help:      "Sliding window unclassified-event ratio, computed and set by the observation pipeline. 0.0 = all events classified; 1.0 = none classified.",
	})

	reg.MustRegister(
		m.learnObservationEvents,
		m.learnRegulatedDataBlocked,
		m.learnUnclassifiedActions,
		m.learnUnclassifiedRate,
	)
}

// RecordObservationEvent increments the observation events counter for the
// given action class. The capture writer (and receipt emitter) call this
// on every recorder.Entry write for capture/action_receipt entries.
//
// actionClass is the wire-form label string (lower-case verb: read, derive,
// write, delegate, authorize, spend, commit, actuate, unclassified). The
// caller must pass the canonical form; this helper does NOT normalize.
func (m *Metrics) RecordObservationEvent(actionClass string) {
	if m == nil {
		return
	}
	m.learnObservationEvents.WithLabelValues(actionClass).Inc()
	if actionClass == learnActionClassUnclassified {
		m.learnUnclassifiedActions.Inc()
	}
}

// RecordRegulatedDataBlocked increments the regulated-data-blocked counter
// with the given reason label. The privacy enforcer calls this when an
// observation event's data class resolves to regulated and is dropped
// before reaching the recorder.
//
// reason should be a stable, low-cardinality string identifying which
// classifier rule fired (e.g., "field_class_regulated", "root_class_regulated",
// "explicit_block"). The caller is responsible for keeping the cardinality
// bounded; do not pass user-supplied or unbounded values.
func (m *Metrics) RecordRegulatedDataBlocked(reason string) {
	if m == nil {
		return
	}
	m.learnRegulatedDataBlocked.WithLabelValues(reason).Inc()
}

// SetUnclassifiedRate updates the unclassified-rate gauge. The observation
// pipeline's review pre-flight (PR 2.x) computes this over a sliding window
// and calls SetUnclassifiedRate to publish the value. PR 1.3 ships only the
// gauge; the value remains zero until the pre-flight calculator wires up.
func (m *Metrics) SetUnclassifiedRate(rate float64) {
	if m == nil {
		return
	}
	m.learnUnclassifiedRate.Set(rate)
}
