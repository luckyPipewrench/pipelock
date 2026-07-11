//go:build !enterprise

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"
	"time"
)

func TestSIEMForwarderMetricStubs(t *testing.T) {
	t.Parallel()
	m := New()
	m.SetQueued(2)
	m.RecordDelivered()
	m.RecordFailed()
	m.RecordDropped()
	m.SetLastSuccess(time.Unix(1, 0))
	m.SetSpoolBytes(1024)

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() == "pipelock_siem_forwarder_queued" {
			t.Fatal("OSS metrics registry exposed Enterprise SIEM forwarder metrics")
		}
	}
}
