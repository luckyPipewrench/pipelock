// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package tools

import "testing"

func requireKnownTools(t testing.TB, baseline *ToolBaseline, names []string) {
	t.Helper()
	if err := baseline.SetKnownTools(names); err != nil {
		t.Fatalf("SetKnownTools: %v", err)
	}
}

func requireStoredDescription(t testing.TB, baseline *ToolBaseline, name, description string) {
	t.Helper()
	if err := baseline.StoreDesc(name, description); err != nil {
		t.Fatalf("StoreDesc(%q): %v", name, err)
	}
}

func requireStoredParams(t testing.TB, baseline *ToolBaseline, name string, params []string) {
	t.Helper()
	if err := baseline.StoreParams(name, params); err != nil {
		t.Fatalf("StoreParams(%q): %v", name, err)
	}
}

func requireHeaderBindings(t testing.TB, baseline *ToolBaseline, defs []ToolDef) {
	t.Helper()
	if err := baseline.SetToolHeaderBindings(defs); err != nil {
		t.Fatalf("SetToolHeaderBindings: %v", err)
	}
}
