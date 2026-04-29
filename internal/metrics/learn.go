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

	m.learnInferenceClassifications = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: learnNamespace,
		Name:      "inference_classify_total",
		Help:      "Total inference classifications produced by the contract-compile engine, labeled by outcome (never_confirmed, brittle, stable). Used by the review UX to render the inference-verdict histogram.",
	}, []string{"outcome"})

	m.learnInferenceFloorFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: learnNamespace,
		Name:      "inference_floor_failures_total",
		Help:      "Total floor failures across all inference classifications, labeled by which floor caused the rule to fall back to never_confirmed (sessions, events, windows). Diagnostic for which floor is the bottleneck on a deployment's data volume.",
	}, []string{"floor"})

	reg.MustRegister(
		m.learnObservationEvents,
		m.learnRegulatedDataBlocked,
		m.learnUnclassifiedActions,
		m.learnUnclassifiedRate,
		m.learnInferenceClassifications,
		m.learnInferenceFloorFailures,
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

// InferenceOutcome is the closed wire-form domain for the
// inference_classify_total counter's outcome label. The string values
// agree byte-for-byte with inference.Confidence.String() so dashboards
// and alerts grouping by outcome see the same vocabulary the recorder
// emits. The metrics package owns the enum locally to avoid a layering
// import on internal/contract/inference; cross-package alignment is
// asserted by the metrics test pack.
type InferenceOutcome string

// Canonical InferenceOutcome values. Any value outside this set is
// dropped at record time to prevent label-cardinality drift.
const (
	OutcomeNeverConfirmed InferenceOutcome = "never_confirmed"
	OutcomeBrittle        InferenceOutcome = "brittle"
	OutcomeStable         InferenceOutcome = "stable"
)

// FloorFailure is the closed wire-form domain for the
// inference_floor_failures_total counter's floor label. Values match
// the YAML field-name suffix the operator sees in pipelock.yaml
// (learn.inference.floors.min_sessions etc.) so the diagnostic counter
// and the validator error message use one vocabulary.
type FloorFailure string

// Canonical FloorFailure values. Any value outside this set is dropped
// at record time to prevent label-cardinality drift.
const (
	FloorSessions FloorFailure = "sessions"
	FloorEvents   FloorFailure = "events"
	FloorWindows  FloorFailure = "windows"
)

// RecordInferenceClassification increments the inference_classify_total
// counter for the given outcome. Non-canonical values are dropped
// silently: Prometheus creates a new time series for every distinct
// label value, so accepting arbitrary strings would let a future caller
// bug expand cardinality without an obvious failure mode. The closed
// allowlist (OutcomeNeverConfirmed / Brittle / Stable) is enforced at
// runtime; the typed parameter steers callers toward the constants but
// untyped string literals still convert per Go's constant rules.
func (m *Metrics) RecordInferenceClassification(outcome InferenceOutcome) {
	if m == nil {
		return
	}
	switch outcome {
	case OutcomeNeverConfirmed, OutcomeBrittle, OutcomeStable:
		m.learnInferenceClassifications.WithLabelValues(string(outcome)).Inc()
	default:
		// Drop non-canonical: future caller drift cannot expand the
		// cardinality of pipelock_learn_inference_classify_total beyond
		// the three legitimate outcomes.
	}
}

// RecordInferenceFloorFailure increments the inference_floor_failures_total
// counter for the named floor. Same closed-allowlist contract as
// RecordInferenceClassification: non-canonical values drop silently to
// prevent cardinality drift on a security-relevant diagnostic counter.
func (m *Metrics) RecordInferenceFloorFailure(floor FloorFailure) {
	if m == nil {
		return
	}
	switch floor {
	case FloorSessions, FloorEvents, FloorWindows:
		m.learnInferenceFloorFailures.WithLabelValues(string(floor)).Inc()
	default:
		// Drop non-canonical (see RecordInferenceClassification).
	}
}
