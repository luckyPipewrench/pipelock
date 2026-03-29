// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package compliance

import "testing"

func TestFramework_CoverageSummary(t *testing.T) {
	f := Framework{
		ID:             "owasp_mcp_top_10",
		Name:           "OWASP MCP Top 10",
		Version:        "2025",
		MappingVersion: 1,
		Controls: []ControlMapping{
			{ID: "MCP01", Name: "Token Exposure", Status: StatusCovered, Features: []string{"dlp", "env_leak"}},
			{ID: "MCP02", Name: "Privilege Escalation", Status: StatusCovered, Features: []string{"tool_policy"}},
			{ID: "MCP03", Name: "Third Risk", Status: StatusPartial, Features: []string{"sandbox"}},
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
	if len(frameworks) != 5 {
		t.Fatalf("Catalog() = %d frameworks, want 5", len(frameworks))
	}
	if frameworks[0].ID != "owasp_mcp_top_10" {
		t.Errorf("first framework = %q, want owasp_mcp_top_10", frameworks[0].ID)
	}
}
