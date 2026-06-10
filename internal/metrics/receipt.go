// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// receiptEmitFailureReasons is the closed label domain for
// pipelock_receipt_emit_failures_total. Bounding the label set prevents
// unbounded cardinality from arbitrary reason strings.
var receiptEmitFailureReasons = map[string]bool{
	"chain_init": true,
	"sign":       true,
	"hash":       true,
	"marshal":    true,
	"record":     true,
	"sealed":     true,
}

func (m *Metrics) registerReceiptMetrics(reg *prometheus.Registry) {
	m.receiptEmitFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "receipt_emit_failures_total",
		Help:      "Total signed action-receipt emission failures, labeled by reason. A non-zero rate means receipts are not being recorded; investigate the flight-recorder signing key and chain state.",
	}, []string{"reason"})

	reg.MustRegister(m.receiptEmitFailures)
}

// RecordEmitFailure increments the receipt-emit-failure counter for a
// closed-domain reason label. Implements receipt.MetricsSink. Non-canonical
// reasons are mapped to "unknown" to avoid unbounded cardinality while still
// surfacing the failure.
func (m *Metrics) RecordEmitFailure(reason string) {
	if m == nil {
		return
	}
	if !receiptEmitFailureReasons[reason] {
		reason = "unknown"
	}
	m.receiptEmitFailures.WithLabelValues(reason).Inc()
}
