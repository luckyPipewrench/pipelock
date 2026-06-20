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
	wantFields := map[string]bool{
		"tool_chain_detection.pattern_overrides.empty-override": false,
		"tool_chain_detection.custom_patterns.existing.action":  false,
	}
	for _, warning := range warnings {
		if _, ok := wantFields[warning.Field]; ok {
			wantFields[warning.Field] = true
		}
	}
	for field, found := range wantFields {
		if !found {
			t.Fatalf("expected warning field %q not found in %#v", field, warnings)
		}
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
		t.Run(tc.action, func(t *testing.T) {
			t.Parallel()

			if _, ok := reloadActionStrength(tc.action); ok != tc.valid {
				t.Fatalf("reloadActionStrength(%q) valid = %v, want %v", tc.action, ok, tc.valid)
			}
		})
	}
}

func TestSuppressCoverageHelpersEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  func() bool
		want bool
	}{
		{
			name: "different rule does not cover",
			got: func() bool {
				return suppressEntryCoveredByAny([]SuppressEntry{{Rule: "other", Path: "*"}}, SuppressEntry{Rule: "body_dlp", Path: "api.example"})
			},
			want: false,
		},
		{
			name: "empty path covers empty path",
			got:  func() bool { return suppressPathCovers("", "") },
			want: true,
		},
		{
			name: "empty path does not cover non-empty path",
			got:  func() bool { return suppressPathCovers("", "api.example") },
			want: false,
		},
		{
			name: "multi-glob old path does not cover",
			got:  func() bool { return suppressPathCovers("api.*.example*", "api.prod.example") },
			want: false,
		},
		{
			name: "multi-glob updated path is not covered",
			got:  func() bool { return suppressPathCovers("api.*", "api.*.example*") },
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.got(); got != tc.want {
				t.Fatalf("coverage = %v, want %v", got, tc.want)
			}
		})
	}
}
