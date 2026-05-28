//go:build !enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import "github.com/prometheus/client_golang/prometheus"

// registerConductorMetrics is a no-op in the Apache-only build. Conductor
// audit-queue metrics ship only in the enterprise build; the core binary
// does not run a Conductor follower so there is nothing to observe.
func (m *Metrics) registerConductorMetrics(_ *prometheus.Registry) {
	if m == nil {
		return
	}
	_ = m.conductorAuditQueuePending
	_ = m.conductorAuditQueueInflight
	_ = m.conductorAuditQueueDead
	_ = m.conductorAuditDeliveries
	_ = m.conductorServerRequests
	_ = m.conductorServerDuration
	_ = m.conductorServerAuditIngest
	_ = m.conductorServerAuditQueries
}
