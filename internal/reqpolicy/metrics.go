// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import "github.com/prometheus/client_golang/prometheus"

// Metrics holds the request_policy Prometheus counters. Label cardinality is
// deliberately bounded to rule name + action: rule names are validated to a
// short fixed charset at config load, while request host, operation name, and
// matched field values are attacker-influenced and must never become labels.
type Metrics struct {
	Decisions   *prometheus.CounterVec
	ParseErrors *prometheus.CounterVec
}

// NewMetrics registers the request_policy counters on reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pipelock_request_policy_decisions_total",
			Help: "request_policy matches by rule and action (action: block, warn, shadow_block, shadow_warn).",
		}, []string{"rule", "action"}),
		ParseErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pipelock_request_policy_parse_errors_total",
			Help: "request_policy operation parse/opaque failures by configured fail-closed reason.",
		}, []string{"reason"}),
	}
	reg.MustRegister(m.Decisions, m.ParseErrors)
	return m
}

// Record increments the decision counter for an enforced or shadow match.
// Shadow matches are labeled "shadow_<action>" so operators can distinguish
// would-have-blocked traffic from enforced blocks. A nil Metrics is a no-op.
func (m *Metrics) Record(d Decision) {
	if m == nil || !d.Matched() {
		return
	}
	action := d.Action
	if d.Shadow {
		action = "shadow_" + action
	}
	m.Decisions.WithLabelValues(d.RuleName, action).Inc()
}
