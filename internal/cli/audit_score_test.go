// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestScoreConfig_Defaults(t *testing.T) {
	cfg := config.Defaults()
	result := scoreConfig(cfg, "")

	// Defaults score modestly — many features disabled by default.
	// DLP + response scanning + enforcement mode are the main defaults.
	if result.Percentage < 20 {
		t.Errorf("defaults should score at least 20%%, got %d%%", result.Percentage)
	}
	if result.TotalScore == 0 {
		t.Error("defaults should have nonzero score (DLP + response scanning)")
	}
	if len(result.Categories) != 12 {
		t.Errorf("expected 12 categories, got %d", len(result.Categories))
	}
}

func TestScoreConfig_FullyConfigured(t *testing.T) {
	cfg := config.Defaults()
	cfg.Mode = config.ModeStrict
	cfg.MCPToolScanning.Enabled = true
	cfg.MCPToolScanning.Action = config.ActionBlock
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "r1", ToolPattern: "bash", ArgPattern: "curl", Action: config.ActionBlock},
		{Name: "r2", ToolPattern: "exec", ArgPattern: "rm", Action: config.ActionBlock},
		{Name: "r3", ToolPattern: "shell", Action: config.ActionBlock},
		{Name: "r4", ToolPattern: "write_file", Action: config.ActionBlock},
		{Name: "r5", ToolPattern: "delete", Action: config.ActionBlock},
		{Name: "r6", ToolPattern: "run_command", Action: config.ActionBlock},
		{Name: "r7", ToolPattern: "terminal", Action: config.ActionBlock},
		{Name: "r8", ToolPattern: "execute", Action: config.ActionBlock},
		{Name: "r9", ToolPattern: "modify_file", Action: config.ActionBlock},
		{Name: "r10", ToolPattern: "create_file", Action: config.ActionBlock},
	}
	cfg.MCPInputScanning.Enabled = true
	cfg.MCPSessionBinding.Enabled = true
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.APIListen = "127.0.0.1:9090"
	cfg.KillSwitch.SentinelFile = "/tmp/pipelock-kill"
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.FetchProxy.Monitoring.Blocklist = []string{"evil.com"}
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.ToolChainDetection.Enabled = true
	cfg.ToolChainDetection.CustomPatterns = []config.ChainPattern{{Name: "test", Sequence: []string{"read", "write"}}}
	cfg.Sandbox.Enabled = true

	result := scoreConfig(cfg, "test.yaml")

	if result.Percentage < 90 {
		t.Errorf("fully configured should score 90%%+, got %d%%", result.Percentage)
	}
	if result.Grade != "A" {
		t.Errorf("fully configured should be grade A, got %s", result.Grade)
	}
	if result.ConfigFile != "test.yaml" {
		t.Errorf("expected config file 'test.yaml', got %q", result.ConfigFile)
	}
}

func TestScoreConfig_Minimal(t *testing.T) {
	// Empty config with no features enabled.
	cfg := &config.Config{}

	result := scoreConfig(cfg, "")

	if result.Percentage > 30 {
		t.Errorf("minimal config should score below 30%%, got %d%%", result.Percentage)
	}
	if len(result.Findings) == 0 {
		t.Error("minimal config should have findings/recommendations")
	}

	// Should have critical findings.
	hasCritical := false
	for _, f := range result.Findings {
		if f.Severity == scoreSevCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("minimal config should have critical findings")
	}
}

func TestScoreConfig_ToolPolicyOverpermission(t *testing.T) {
	cfg := config.Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionWarn
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "wildcard", ToolPattern: "bash", ArgPattern: ".*", Action: config.ActionWarn},
		{Name: "high-risk-warn", ToolPattern: "exec", Action: config.ActionWarn},
	}

	result := scoreConfig(cfg, "")

	// Should flag wildcard arg pattern and warn-on-high-risk.
	foundWildcard := false
	foundHighRisk := false
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "wildcard arg_pattern") {
			foundWildcard = true
		}
		if strings.Contains(f.Message, "high-risk tools but effective action") {
			foundHighRisk = true
		}
	}
	if !foundWildcard {
		t.Error("should flag wildcard arg_pattern")
	}
	if !foundHighRisk {
		t.Error("should flag warn on high-risk tool pattern")
	}
}

func TestScoreConfig_NoBlockRules(t *testing.T) {
	cfg := config.Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "warn-only", ToolPattern: "test", Action: config.ActionWarn},
	}

	result := scoreConfig(cfg, "")

	found := false
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "No tool policy rules effectively block") {
			found = true
		}
	}
	if !found {
		t.Error("should warn about no blocking rules")
	}
}

func TestScoreConfig_InheritedBlockAction(t *testing.T) {
	cfg := config.Defaults()
	cfg.MCPToolPolicy.Enabled = true
	cfg.MCPToolPolicy.Action = config.ActionBlock // section-level default
	cfg.MCPToolPolicy.Rules = []config.ToolPolicyRule{
		{Name: "block-shell", ToolPattern: "bash"}, // no per-rule action — inherits block
	}

	result := scoreConfig(cfg, "")

	// Should NOT flag "high-risk tools but action is warn" since effective action is block.
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "high-risk tools but effective action") {
			t.Errorf("should not flag inherited block action as warning: %s", f.Message)
		}
	}
	// Should NOT flag "no rules use block" since inherited action is block.
	for _, f := range result.Findings {
		if strings.Contains(f.Message, "No tool policy rules effectively block") {
			t.Errorf("should not flag missing block when section default is block: %s", f.Message)
		}
	}
}

func TestAuditScoreCmd_Text(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", "score"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Config Security Score") {
		t.Error("expected score header in output")
	}
	if !strings.Contains(output, "Grade:") {
		t.Error("expected grade in output")
	}
}

func TestAuditScoreCmd_JSON(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", "score", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result ScoreResult
	if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result.MaxScore == 0 {
		t.Error("max_score should not be zero")
	}
	if len(result.Categories) == 0 {
		t.Error("categories should not be empty")
	}
}

func TestScoreGrade(t *testing.T) {
	tests := []struct {
		pct   int
		grade string
	}{
		{95, "A"},
		{90, "A"},
		{85, "B"},
		{75, "C"},
		{65, "D"},
		{50, "F"},
		{0, "F"},
	}
	for _, tc := range tests {
		t.Run(tc.grade, func(t *testing.T) {
			if got := scoreGrade(tc.pct); got != tc.grade {
				t.Errorf("scoreGrade(%d) = %q, want %q", tc.pct, got, tc.grade)
			}
		})
	}
}

func TestIsHighRiskToolPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		expected bool
	}{
		{"bash", true},
		{"(?i)^(bash|shell|exec)$", true},
		{"write_file", true},
		{"delete", true},
		{"search", false},
		{"list_files", false},
		{"read_url", false},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			if got := isHighRiskToolPattern(tc.pattern); got != tc.expected {
				t.Errorf("isHighRiskToolPattern(%q) = %v, want %v", tc.pattern, got, tc.expected)
			}
		})
	}
}

func TestScoreBar(t *testing.T) {
	tests := []struct {
		score, max int
		expected   string
	}{
		{10, 10, "[##########]"},
		{5, 10, "[#####-----]"},
		{0, 10, "[----------]"},
		{0, 0, "[----------]"},
	}
	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			if got := scoreBar(tc.score, tc.max); got != tc.expected {
				t.Errorf("scoreBar(%d, %d) = %q, want %q", tc.score, tc.max, got, tc.expected)
			}
		})
	}
}
