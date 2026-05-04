// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// CaptureSessionIDSanitizationReason is the closed label domain for
// pipelock_capture_session_id_sanitized_total.
type CaptureSessionIDSanitizationReason string

const (
	CaptureSessionIDUnsafePath CaptureSessionIDSanitizationReason = "unsafe_path"
	CaptureSessionIDOverlength CaptureSessionIDSanitizationReason = "overlength"
	CaptureSessionIDUnknown    CaptureSessionIDSanitizationReason = "unknown"
)

// CaptureActionClassSanitizationReason is the closed label domain for
// pipelock_capture_action_class_sanitized_total.
type CaptureActionClassSanitizationReason string

const (
	CaptureActionClassMissing      CaptureActionClassSanitizationReason = "missing"
	CaptureActionClassNormalized   CaptureActionClassSanitizationReason = "normalized"
	CaptureActionClassNonCanonical CaptureActionClassSanitizationReason = "non_canonical"
)

// registerCaptureMetrics builds and registers the capture-system counters.
// Handles are attached to m.
func (m *Metrics) registerCaptureMetrics(reg *prometheus.Registry) {
	m.CaptureDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "capture_dropped_total",
		Help:      "Total capture entries dropped due to queue overflow.",
	})

	m.captureSessionIDSanitized = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "capture_session_id_sanitized_total",
		Help:      "Total capture entries whose unsafe or overlength logical session ID was replaced with a bounded hashed session ID.",
	}, []string{"reason"})

	m.captureActionClassSanitized = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "capture_action_class_sanitized_total",
		Help:      "Total capture entries whose action_class was missing, normalized, or dropped because it was outside the canonical action taxonomy.",
	}, []string{"reason"})

	reg.MustRegister(m.CaptureDropped, m.captureSessionIDSanitized, m.captureActionClassSanitized)
}

// RecordCaptureDrop increments the capture dropped counter.
func (m *Metrics) RecordCaptureDrop() {
	if m == nil {
		return
	}
	m.CaptureDropped.Inc()
}

// RecordCaptureSessionIDSanitized increments the capture session-id
// sanitization counter for the given closed-domain reason. Non-canonical
// labels are dropped to avoid cardinality drift from untrusted identity input.
func (m *Metrics) RecordCaptureSessionIDSanitized(reason string) {
	if m == nil {
		return
	}
	switch CaptureSessionIDSanitizationReason(reason) {
	case CaptureSessionIDUnsafePath, CaptureSessionIDOverlength, CaptureSessionIDUnknown:
		m.captureSessionIDSanitized.WithLabelValues(reason).Inc()
	default:
	}
}

// RecordCaptureActionClassSanitized increments the action-class sanitization
// counter for the given closed-domain reason. Non-canonical labels are dropped
// to avoid cardinality drift from caller bugs.
func (m *Metrics) RecordCaptureActionClassSanitized(reason string) {
	if m == nil {
		return
	}
	switch CaptureActionClassSanitizationReason(reason) {
	case CaptureActionClassMissing, CaptureActionClassNormalized, CaptureActionClassNonCanonical:
		m.captureActionClassSanitized.WithLabelValues(reason).Inc()
	default:
	}
}
