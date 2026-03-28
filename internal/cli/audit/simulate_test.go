// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestSimulateCmd_Text(t *testing.T) {
	cmd := testRoot()
	// Also add simulate as a top-level command for this test.
	cmd.AddCommand(SimulateCmd())
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"simulate"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Attack Simulation") {
		t.Error("expected simulation header in output")
	}
	if !strings.Contains(output, "Grade:") {
		t.Error("expected grade in output")
	}
	if !strings.Contains(output, "Score:") {
		t.Error("expected score in output")
	}
}

func TestSimulateCmd_JSON(t *testing.T) {
	cmd := testRoot()
	cmd.AddCommand(SimulateCmd())
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"simulate", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result SimulateResult
	if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
		t.Fatalf("invalid JSON: %v\noutput: %s", err, buf.String())
	}
	if result.Total == 0 {
		t.Error("total should not be zero")
	}
	if len(result.Scenarios) == 0 {
		t.Error("scenarios should not be empty")
	}
	if result.Grade == "" {
		t.Error("grade should not be empty")
	}
}

func TestBuildScenarios_DefaultConfig(t *testing.T) {
	cfg := config.Defaults()
	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := BuildSimScenarios(cfg, sc)
	if len(scenarios) == 0 {
		t.Fatal("expected scenarios for default config")
	}

	// Should have all categories.
	cats := make(map[string]bool)
	for _, s := range scenarios {
		cats[s.category] = true
	}
	expectedCats := []string{catDLP, catInjection, catPoison, catSSRF, catEvasion}
	for _, c := range expectedCats {
		if !cats[c] {
			t.Errorf("missing category: %s", c)
		}
	}
}

func TestBuildScenarios_NoSSRFWithNilInternal(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF
	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := BuildSimScenarios(cfg, sc)
	for _, s := range scenarios {
		if s.category == catSSRF {
			t.Error("SSRF scenarios should not be included when Internal is nil")
		}
	}
}

func TestRunSimulation_AllDefaultsDetected(t *testing.T) {
	cfg := config.Defaults()
	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := BuildSimScenarios(cfg, sc)
	result := RunSimulation(scenarios, "", cfg.Mode)

	// Default config should detect most attacks.
	if result.Percentage < 70 {
		t.Errorf("default config should detect at least 70%%, got %d%%", result.Percentage)
		for _, s := range result.Scenarios {
			if !s.Detected && !s.Limitation {
				t.Logf("MISSED: [%s] %s", s.Category, s.Name)
			}
		}
	}
}

func TestRunSimulation_GradeCalculation(t *testing.T) {
	tests := []struct {
		passed int
		total  int
		grade  string
	}{
		{24, 24, "A"},
		{20, 24, "B"},
		{17, 24, "C"},
		{15, 24, "D"},
		{10, 24, "F"},
	}

	for _, tc := range tests {
		scenarios := make([]simScenario, tc.total)
		for i := range scenarios {
			d := i < tc.passed // capture by value
			scenarios[i] = simScenario{
				name:     "test",
				category: catDLP,
				run: func() (bool, string) {
					return d, ""
				},
			}
		}
		result := RunSimulation(scenarios, "", "balanced")
		if result.Grade != tc.grade {
			t.Errorf("passed=%d/%d: got grade %s, want %s", tc.passed, tc.total, result.Grade, tc.grade)
		}
	}
}

func TestRunSimulation_StrictModeNoFalsePositives(t *testing.T) {
	// Strict mode with a narrow allowlist should NOT give DLP/SSRF credit
	// when the allowlist blocks the domain before those scanners run.
	cfg := config.Defaults()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.openai.com"}
	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := BuildSimScenarios(cfg, sc)
	result := RunSimulation(scenarios, "", cfg.Mode)

	// URL-based DLP scenarios should NOT be detected via allowlist.
	// Text DLP and injection scenarios use different scanners and are exempt.
	urlDLPScenarios := map[string]bool{
		"AWS access key in URL path":      true,
		"Base64-encoded GitHub token":     true,
		"Hex-encoded Slack token":         true,
		"OpenAI API key in URL":           true,
		"Private key (WIF format) in URL": true,
	}
	for _, s := range result.Scenarios {
		if urlDLPScenarios[s.Name] && s.Detected && s.Detail != scanner.ScannerDLP {
			t.Errorf("[%s] %q detected but by wrong scanner: %s (expected %s)",
				s.Category, s.Name, s.Detail, scanner.ScannerDLP)
		}
		if s.Category == catSSRF && s.Detected && s.Detail != scanner.ScannerSSRF {
			t.Errorf("[%s] %q detected but by wrong scanner: %s (expected %s)",
				s.Category, s.Name, s.Detail, scanner.ScannerSSRF)
		}
	}
}

func TestRunSimulation_URLScenariosAttributeCorrectScanner(t *testing.T) {
	cfg := config.Defaults()
	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := BuildSimScenarios(cfg, sc)
	result := RunSimulation(scenarios, "", cfg.Mode)

	// Verify URL-based DLP scenarios are attributed to the DLP scanner.
	expectedScanners := map[string]string{
		"AWS access key in URL path":      scanner.ScannerDLP,
		"Base64-encoded GitHub token":     scanner.ScannerDLP,
		"Hex-encoded Slack token":         scanner.ScannerDLP,
		"OpenAI API key in URL":           scanner.ScannerDLP,
		"Private key (WIF format) in URL": scanner.ScannerDLP,
		"URL-encoded secret in path":      scanner.ScannerDLP,
		"CRLF injection in URL":           scanner.ScannerCRLF,
		"Overlong URL":                    scanner.ScannerLength,
		"Private IP (10.0.0.1)":           scanner.ScannerSSRF,
		"Cloud metadata endpoint":         scanner.ScannerSSRF,
		"IPv6-mapped IPv4 loopback":       scanner.ScannerSSRF,
		"Link-local metadata":             scanner.ScannerSSRF,
	}

	for _, s := range result.Scenarios {
		expected, ok := expectedScanners[s.Name]
		if !ok {
			continue
		}
		if !s.Detected {
			continue // some may miss on this branch (pre-#270 patterns)
		}
		if s.Detail != expected {
			t.Errorf("[%s] %q: scanner=%s, want %s", s.Category, s.Name, s.Detail, expected)
		}
	}
}

func TestBuildScenarios_WithCanaryTokens(t *testing.T) {
	cfg := config.Defaults()
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{
		{
			Name:   "aws_canary",
			Value:  "AKIA" + "IOSFODNN7" + "CANARY1",
			EnvVar: "AWS_CANARY_KEY",
		},
	}
	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := BuildSimScenarios(cfg, sc)
	expected := []string{
		"Canary token in text body (aws_canary)",
		"URL-encoded canary token (aws_canary)",
		"Base64-encoded canary token (aws_canary)",
		"Hex-encoded canary token (aws_canary)",
		"Split canary token (aws_canary)",
		"Canary token in URL (aws_canary)",
	}

	have := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		have[s.name] = true
	}
	for _, name := range expected {
		if !have[name] {
			t.Fatalf("missing canary scenario %q", name)
		}
	}
}

func TestRunSimulation_CanaryScenariosDetected(t *testing.T) {
	cfg := config.Defaults()
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{
		{Name: "aws_canary", Value: "AKIA" + "IOSFODNN7" + "CANARY1"},
	}
	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := BuildSimScenarios(cfg, sc)
	result := RunSimulation(scenarios, "", cfg.Mode)

	for _, s := range result.Scenarios {
		if strings.Contains(strings.ToLower(s.Name), "canary") && !s.Detected {
			t.Fatalf("expected canary scenario to be detected: %q (%s)", s.Name, s.Detail)
		}
	}
}

func TestMatchNames(t *testing.T) {
	matches := []scanner.ResponseMatch{
		{PatternName: "Prompt Injection"},
		{PatternName: "Role Override"},
	}
	got := matchNames(matches)
	if got != "Prompt Injection, Role Override" {
		t.Errorf("matchNames = %q, want 'Prompt Injection, Role Override'", got)
	}

	if matchNames(nil) != "" {
		t.Error("matchNames(nil) should return empty string")
	}
}
