// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// registerRequestPolicyMetrics builds and registers the request_policy
// decision counter. Labels are deliberately limited to the matched rule name
// and the rule's action so cardinality stays bounded — never the request host,
// operation name, or any attacker-influenced value.
func (m *Metrics) registerRequestPolicyMetrics(reg *prometheus.Registry) {
	m.requestPolicyDecisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pipelock",
		Name:      "request_policy_decisions_total",
		Help:      "Total request_policy rule matches, by rule name and action.",
	}, []string{"rule", "action"})

	reg.MustRegister(m.requestPolicyDecisions)
}

// RecordRequestPolicyDecision increments the request_policy decision counter
// for a matched rule. rule is the bounded, operator-defined rule name; action
// is the rule's configured action (block or warn). Shadow matches are counted
// the same as enforced ones — the shadow vs enforced distinction lives in the
// audit log, not in metric cardinality.
func (m *Metrics) RecordRequestPolicyDecision(rule, action string) {
	// Guard the counter vec too: a zero-value &Metrics{} (no registry) leaves
	// it nil, and this helper is documented nil-safe.
	if m == nil || m.requestPolicyDecisions == nil {
		return
	}
	m.requestPolicyDecisions.WithLabelValues(rule, action).Inc()
}
