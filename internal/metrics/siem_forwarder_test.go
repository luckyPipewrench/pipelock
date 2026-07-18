//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package metrics

import (
	"testing"
	"time"
)

func TestSIEMForwarderMetricsEnterprise(t *testing.T) {
	t.Parallel()
	m := New()
	m.SetQueued(3)
	m.RecordDelivered()
	m.RecordFailed()
	m.RecordDropped()
	m.SetLastSuccess(time.Unix(1_700_000_000, 0))
	m.SetSpoolBytes(4096)

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := make(map[string]bool)
	for _, family := range families {
		found[family.GetName()] = true
	}
	for _, name := range []string{
		"pipelock_siem_forwarder_queued",
		"pipelock_siem_forwarder_delivered_total",
		"pipelock_siem_forwarder_failed_total",
		"pipelock_siem_forwarder_dropped_total",
		"pipelock_siem_forwarder_last_success_timestamp_seconds",
		"pipelock_siem_forwarder_spool_bytes",
	} {
		if !found[name] {
			t.Errorf("enterprise metrics registry missing %q", name)
		}
	}
}
