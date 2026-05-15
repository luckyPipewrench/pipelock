// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"
)

// TestGoRuntimeCollectorRegistered asserts that the built-in Go runtime
// collector is registered on a fresh Metrics. The collector is required by
// the agent-egress benchmark, which scrapes go_memstats_heap_alloc_bytes
// alongside /proc/<pid>/status RSS to report both numbers honestly.
func TestGoRuntimeCollectorRegistered(t *testing.T) {
	t.Parallel()
	m := New()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := map[string]bool{
		"go_memstats_heap_alloc_bytes":  false,
		"go_memstats_heap_sys_bytes":    false,
		"go_goroutines":                 false,
		"process_resident_memory_bytes": false,
		"process_virtual_memory_bytes":  false,
	}
	for _, mf := range families {
		if _, ok := want[mf.GetName()]; ok {
			want[mf.GetName()] = true
		}
	}
	for name, present := range want {
		if !present {
			t.Errorf("metric %q not exposed by Registry; runtime collectors broken", name)
		}
	}
}

// TestGoRuntimeCollectorIndependent confirms the runtime collector lives on
// the Metrics registry (not the global default registry). This guarantees test
// isolation — two Metrics instances must not pollute each other.
func TestGoRuntimeCollectorIndependent(t *testing.T) {
	t.Parallel()
	m1 := New()
	m2 := New()
	if m1.Registry() == m2.Registry() {
		t.Error("two Metrics share a registry; expected per-instance registries")
	}
	// Both must independently expose the collectors.
	for _, m := range []*Metrics{m1, m2} {
		families, err := m.Registry().Gather()
		if err != nil {
			t.Fatalf("Gather: %v", err)
		}
		found := false
		for _, mf := range families {
			if mf.GetName() == "go_goroutines" {
				found = true
				break
			}
		}
		if !found {
			t.Error("go_goroutines missing on independent Metrics instance")
		}
	}
}
