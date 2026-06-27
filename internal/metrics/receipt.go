// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// receiptEmitFailureReasons is the closed label domain for
// pipelock_receipt_emit_failures_total. Bounding the label set prevents
// unbounded cardinality from arbitrary reason strings.
var receiptEmitFailureReasons = map[string]bool{
	"chain_init":  true,
	"sign":        true,
	"hash":        true,
	"marshal":     true,
	"record":      true,
	"sealed":      true,
	"unavailable": true,
}

var requiredReceiptBlockReasons = map[string]bool{
	"emit_error":  true,
	"unavailable": true,
}

func (m *Metrics) registerReceiptMetrics(reg *prometheus.Registry) {
	m.receiptEmitFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "receipt_emit_failures_total",
		Help:      "Total signed action-receipt emission failures, labeled by reason. A non-zero rate means receipts are not being recorded; investigate the flight-recorder signing key and chain state.",
	}, []string{"reason"})
	m.requiredReceiptBlockings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "required_receipt_blocks_total",
		Help:      "Total requests blocked because require_receipts was enabled and a signed action receipt could not be emitted.",
	}, []string{"reason", "transport"})

	reg.MustRegister(m.receiptEmitFailures)
	reg.MustRegister(m.requiredReceiptBlockings)
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
	m.mu.Lock()
	if m.receiptEmitFailureCounts != nil {
		m.receiptEmitFailureCounts[reason]++
	}
	m.mu.Unlock()
	if m.receiptEmitFailures != nil {
		m.receiptEmitFailures.WithLabelValues(reason).Inc()
	}
}

// RecordRequiredReceiptBlock increments the traffic-impact counter for a
// require_receipts fail-closed decision. The reason and transport label domains
// are bounded because this path can be reached from client-controlled requests.
func (m *Metrics) RecordRequiredReceiptBlock(reason, transport string) {
	if m == nil {
		return
	}
	if !requiredReceiptBlockReasons[reason] {
		reason = "unknown"
	}
	transport = normalizeReceiptTransport(transport)
	m.mu.Lock()
	if m.requiredReceiptBlocks != nil {
		m.requiredReceiptBlocks[requiredReceiptBlockKey(reason, transport)]++
	}
	m.mu.Unlock()
	if m.requiredReceiptBlockings != nil {
		m.requiredReceiptBlockings.WithLabelValues(reason, transport).Inc()
	}
}

func normalizeReceiptTransport(transport string) string {
	switch transport {
	case "fetch", "forward", "connect", "websocket", "intercept", "reverse", "mcp":
		return transport
	default:
		return "other"
	}
}

func requiredReceiptBlockKey(reason, transport string) string {
	return reason + "\x00" + transport
}

func splitRequiredReceiptBlockKey(key string) (reason, transport string) {
	parts := strings.SplitN(key, "\x00", 2)
	if len(parts) != 2 {
		return "unknown", "other"
	}
	return parts[0], parts[1]
}
