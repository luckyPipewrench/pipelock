// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// CEEStats is a snapshot of cross-request exfiltration detection state
// for the JSON /stats endpoint.
type CEEStats struct {
	EntropyTrackerActive bool `json:"entropy_tracker_active"`
	FragmentBufferActive bool `json:"fragment_buffer_active"`
	FragmentBufferBytes  int  `json:"fragment_buffer_bytes"`
}

// registerCrossRequestMetrics builds and registers the cross-request
// exfiltration entropy/DLP counters and the fragment buffer gauge.
// Handles are attached to m.
func (m *Metrics) registerCrossRequestMetrics(reg *prometheus.Registry) {
	m.CrossRequestEntropyExceeded = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "cross_request_entropy_exceeded_total",
		Help:      "Entropy budget exceeded events.",
	})
	m.CrossRequestDLPMatch = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "cross_request_dlp_match_total",
		Help:      "Fragment reassembly DLP match events.",
	})
	m.CrossRequestFragmentCapacityExceeded = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "cross_request_fragment_session_capacity_exceeded_total",
		Help:      "Fragment reassembly requests denied because the session ledger is full.",
	})
	m.CrossRequestPathDepthExceeded = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "cross_request_path_depth_exceeded_total",
		Help:      "URL requests denied because their path exceeds the CEE tracking depth cap.",
	})
	m.CrossRequestJSONPartitionFallback = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "cross_request_json_partition_fallback_total",
		Help:      "JSON request bodies that did not produce a complete partitioned fragment map, by reason.",
	}, []string{"reason"})
	m.CrossRequestFragmentOwnerMismatch = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "cross_request_fragment_owner_mismatch_total",
		Help:      "Fragment appends refused because the stream already held another identity's evidence.",
	})
	m.CrossRequestFragmentBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "cross_request_fragment_buffer_bytes",
		Help:      "Total fragment buffer memory across all sessions.",
	})

	reg.MustRegister(
		m.CrossRequestEntropyExceeded, m.CrossRequestDLPMatch, m.CrossRequestFragmentCapacityExceeded, m.CrossRequestPathDepthExceeded, m.CrossRequestJSONPartitionFallback, m.CrossRequestFragmentOwnerMismatch, m.CrossRequestFragmentBytes,
	)
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

// RecordCrossRequestFragmentCapacityExceeded increments the fragment-session
// capacity-denial counter.
func (m *Metrics) RecordCrossRequestFragmentCapacityExceeded() {
	if m != nil {
		m.CrossRequestFragmentCapacityExceeded.Inc()
	}
}

// RecordCrossRequestPathDepthExceeded increments the path-depth denial counter.
func (m *Metrics) RecordCrossRequestPathDepthExceeded() {
	if m != nil {
		m.CrossRequestPathDepthExceeded.Inc()
	}
}

// RecordCrossRequestJSONPartitionFallback increments the JSON body partition
// fallback counter. reason is a small closed set (malformed, incomplete,
// unkeyed); unknown values are recorded as "other" so the label set cannot
// be attacker-grown.
func (m *Metrics) RecordCrossRequestJSONPartitionFallback(reason string) {
	if m == nil || m.CrossRequestJSONPartitionFallback == nil {
		return
	}
	switch reason {
	case "malformed", "incomplete", "unkeyed":
	case "":
		return
	default:
		reason = "other"
	}
	m.CrossRequestJSONPartitionFallback.WithLabelValues(reason).Inc()
}

// RecordCrossRequestFragmentOwnerMismatch increments the counter for a
// fragment append refused because the stream belonged to another identity.
// A nonzero value is an internal invariant failure, not an operator tuning
// signal: there is no configuration that permits blending two identities'
// evidence, so the request is reported as uninspected instead.
func (m *Metrics) RecordCrossRequestFragmentOwnerMismatch() {
	if m != nil && m.CrossRequestFragmentOwnerMismatch != nil {
		m.CrossRequestFragmentOwnerMismatch.Inc()
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
