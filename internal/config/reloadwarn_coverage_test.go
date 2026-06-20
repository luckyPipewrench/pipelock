// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestReloadActionDowngradeHelpersEdgeCases(t *testing.T) {
	t.Parallel()

	var warnings []ReloadWarning
	appendToolPolicyRuleActionDowngrades(&warnings, MCPToolPolicy{
		Action: ActionBlock,
		Rules: []ToolPolicyRule{
			{Name: "", Action: ActionBlock},
			{Name: "existing"},
		},
	}, MCPToolPolicy{
		Action: ActionWarn,
		Rules: []ToolPolicyRule{
			{Name: "missing", Action: ActionAllow},
			{Name: "existing"},
		},
	})
	if len(warnings) != 1 || warnings[0].Field != "mcp_tool_policy.rules.existing.action" {
		t.Fatalf("tool policy warnings = %#v, want existing rule downgrade only", warnings)
	}

	warnings = nil
	appendToolChainActionDowngrades(&warnings, ToolChainDetection{
		Enabled: true,
		Action:  ActionBlock,
		PatternOverrides: map[string]string{
			"empty-override": "",
		},
		CustomPatterns: []ChainPattern{
			{Name: "", Action: ActionBlock},
			{Name: "existing"},
		},
	}, ToolChainDetection{
		Enabled: true,
		Action:  ActionWarn,
		PatternOverrides: map[string]string{
			"other": ActionAllow,
		},
		CustomPatterns: []ChainPattern{
			{Name: "missing", Action: ActionAllow},
			{Name: "existing"},
		},
	})
	if len(warnings) != 2 {
		t.Fatalf("tool-chain warnings = %#v, want two downgrade warnings", warnings)
	}
}

func TestReloadActionStrengthCoversAllOrderedActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		action string
		valid  bool
	}{
		{ActionAllow, true},
		{ActionForward, true},
		{ActionWarn, true},
		{ActionStrip, true},
		{ActionRedirect, true},
		{ActionAsk, true},
		{ActionDefer, true},
		{ActionBlock, true},
		{"bogus", false},
	}
	for _, tc := range tests {
		if _, ok := reloadActionStrength(tc.action); ok != tc.valid {
			t.Fatalf("reloadActionStrength(%q) valid = %v, want %v", tc.action, ok, tc.valid)
		}
	}
}

func TestSuppressCoverageHelpersEdgeCases(t *testing.T) {
	t.Parallel()

	if suppressEntryCoveredByAny([]SuppressEntry{{Rule: "other", Path: "*"}}, SuppressEntry{Rule: "body_dlp", Path: "api.example"}) {
		t.Fatal("different rule must not cover suppress entry")
	}
	if !suppressPathCovers("", "") {
		t.Fatal("empty suppress path should only cover another empty path")
	}
	if suppressPathCovers("", "api.example") {
		t.Fatal("empty suppress path must not cover non-empty path")
	}
	if suppressPathCovers("api.*.example*", "api.prod.example") {
		t.Fatal("multi-glob suppress path must not be treated as covering")
	}
	if suppressPathCovers("api.*", "api.*.example*") {
		t.Fatal("updated multi-glob suppress path must not be treated as covered")
	}
}
