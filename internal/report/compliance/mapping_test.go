// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

import "testing"

func TestFramework_CoverageSummary(t *testing.T) {
	f := Framework{
		ID:             frameworkOWASPMCPTop10,
		Name:           "OWASP MCP Top 10",
		Version:        "2025",
		MappingVersion: 1,
		Controls: []ControlMapping{
			{ID: "MCP01", Name: "Token Exposure", Status: StatusCovered, Features: []string{featureDLP, featureEnvLeak}},
			{ID: "MCP02", Name: "Privilege Escalation", Status: StatusCovered, Features: []string{featureToolPolicy}},
			{ID: "MCP03", Name: "Third Risk", Status: StatusPartial, Features: []string{featureSandbox}},
			{ID: "MCP04", Name: "Not Covered", Status: StatusNotCovered},
		},
	}

	summary := f.CoverageSummary()

	if summary.Total != 4 {
		t.Errorf("total: got %d", summary.Total)
	}
	if summary.Covered != 2 {
		t.Errorf("covered: got %d", summary.Covered)
	}
	if summary.Partial != 1 {
		t.Errorf("partial: got %d", summary.Partial)
	}
	if summary.NotCovered != 1 {
		t.Errorf("not_covered: got %d", summary.NotCovered)
	}
}

func TestCatalog_ReturnsFrameworks(t *testing.T) {
	frameworks := Catalog()
	// Catalog ordering is part of the rendered output contract — both
	// the free-tier compliance grid and the paid annex iterate in this
	// order, and any reorder is a visible UI change.
	wantOrder := []string{
		"owasp_mcp_top_10",
		"owasp_agentic_top_10",
		"mitre_atlas",
		"eu_ai_act",
		"nist_ai_rmf",
		"hipaa_security",
		"soc2_tsc",
	}
	if len(frameworks) != len(wantOrder) {
		t.Fatalf("Catalog() = %d frameworks, want %d", len(frameworks), len(wantOrder))
	}
	for i, want := range wantOrder {
		if frameworks[i].ID != want {
			t.Errorf("frameworks[%d].ID = %q, want %q", i, frameworks[i].ID, want)
		}
	}
}
