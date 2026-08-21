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
	m.CrossRequestFragmentBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pipelock",
		Name:      "cross_request_fragment_buffer_bytes",
		Help:      "Total fragment buffer memory across all sessions.",
	})

	reg.MustRegister(
		m.CrossRequestEntropyExceeded, m.CrossRequestDLPMatch, m.CrossRequestFragmentCapacityExceeded, m.CrossRequestPathDepthExceeded, m.CrossRequestFragmentBytes,
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
