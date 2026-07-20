// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"sort"

	"github.com/prometheus/client_golang/prometheus"
)

// RuleBundleStats reports rule-bundle degradation visible through /stats.
type RuleBundleStats struct {
	DegradedCount int      `json:"degraded_count"`
	DegradedNames []string `json:"degraded_names,omitempty"`
}

func (m *Metrics) registerRuleBundleMetrics(reg *prometheus.Registry) {
	m.ruleBundlesDegraded = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pipelock_rule_bundles_degraded",
		Help: "Number of rule bundles whose live coverage is degraded due to load errors or clean removal.",
	})
	reg.MustRegister(m.ruleBundlesDegraded)
}

// SetRuleBundlesDegraded publishes the current degraded rule-bundle names.
func (m *Metrics) SetRuleBundlesDegraded(names []string) {
	if m == nil {
		return
	}
	copied := append([]string(nil), names...)
	sort.Strings(copied)
	m.mu.Lock()
	m.degradedRuleBundles = copied
	m.mu.Unlock()
	if m.ruleBundlesDegraded != nil {
		m.ruleBundlesDegraded.Set(float64(len(copied)))
	}
}
