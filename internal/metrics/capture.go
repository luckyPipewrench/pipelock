// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// registerCaptureMetrics builds and registers the capture-system drop
// counter. Handles are attached to m.
func (m *Metrics) registerCaptureMetrics(reg *prometheus.Registry) {
	m.CaptureDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "capture_dropped_total",
		Help:      "Total capture entries dropped due to queue overflow.",
	})

	reg.MustRegister(m.CaptureDropped)
}

// RecordCaptureDrop increments the capture dropped counter.
func (m *Metrics) RecordCaptureDrop() {
	m.CaptureDropped.Inc()
}
