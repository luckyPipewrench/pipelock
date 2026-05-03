// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// EnvelopeVerifyResult is the closed label domain for
// pipelock_envelope_verify_total.
type EnvelopeVerifyResult string

const (
	EnvelopeVerifyDisabled EnvelopeVerifyResult = "disabled"
	EnvelopeVerifyVerified EnvelopeVerifyResult = "verified"
	EnvelopeVerifyMissing  EnvelopeVerifyResult = "missing"
	EnvelopeVerifyFailed   EnvelopeVerifyResult = "failed"
)

func (m *Metrics) registerEnvelopeMetrics(reg *prometheus.Registry) {
	m.envelopeVerifyTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "envelope_verify_total",
		Help:      "Total inbound mediation envelope verification attempts, labeled by result.",
	}, []string{"result"})

	reg.MustRegister(m.envelopeVerifyTotal)
}

// RecordEnvelopeVerify increments the inbound mediation-envelope verification
// counter for a closed-domain result label. Non-canonical labels are dropped to
// avoid unbounded cardinality from error text.
func (m *Metrics) RecordEnvelopeVerify(result EnvelopeVerifyResult) {
	if m == nil {
		return
	}
	switch result {
	case EnvelopeVerifyDisabled, EnvelopeVerifyVerified, EnvelopeVerifyMissing, EnvelopeVerifyFailed:
		m.envelopeVerifyTotal.WithLabelValues(string(result)).Inc()
	default:
	}
}
