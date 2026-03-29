// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Test-scoped constants for coverage boost tests.
const (
	testCatDLP       = "DLP Exfiltration"
	testCatInjection = "Prompt Injection"
	testGradeA       = "A"
	testGradeB       = "B"
	testGradeC       = "C"
	testGradeD       = "D"
	testGradeF       = "F"
	testSevCritical  = "critical"
	testSevWarning   = "warning"
	testSevInfo      = "info"
)

func TestPrintSimulation_WithConfig(t *testing.T) {
	cmd := testRoot()
	cmd.AddCommand(SimulateCmd())

	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	result := SimulateResult{
		ConfigFile:  "test.yaml",
		Mode:        "balanced",
		Total:       5,
		Passed:      3,
		Failed:      1,
		KnownLimits: 1,
		Percentage:  75,
		Grade:       testGradeC,
		Scenarios: []ScenarioResult{
			{Name: "test1", Category: testCatDLP, Detected: true},
			{Name: "test2", Category: testCatDLP, Detected: false},
			{Name: "test3", Category: testCatInjection, Detected: true},
			{Name: "test4", Category: testCatInjection, Detected: true},
			{Name: "test5", Category: testCatInjection, Detected: false, Limitation: true},
		},
	}

	printSimulation(cmd, result)
	output := buf.String()

	if !strings.Contains(output, "test.yaml") {
		t.Error("expected config file in output")
	}
	if !strings.Contains(output, "balanced") {
		t.Error("expected mode in output")
	}
	if !strings.Contains(output, "MISSED") {
		t.Error("expected MISSED label for undetected scenarios")
	}
	if !strings.Contains(output, "KNOWN LIMIT") {
		t.Error("expected KNOWN LIMIT for limitation scenarios")
	}
	if !strings.Contains(output, testGradeC) {
		t.Error("expected grade C in output")
	}
}

func TestPrintSimulation_DefaultConfig(t *testing.T) {
	cmd := testRoot()
	cmd.AddCommand(SimulateCmd())

	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	result := SimulateResult{
		Mode:       "balanced",
		Total:      2,
		Passed:     2,
		Percentage: 100,
		Grade:      testGradeA,
		Scenarios: []ScenarioResult{
			{Name: "test1", Category: testCatDLP, Detected: true},
			{Name: "test2", Category: testCatDLP, Detected: true},
		},
	}

	printSimulation(cmd, result)
	output := buf.String()

	if !strings.Contains(output, "defaults") {
		t.Error("expected 'defaults' when no config file set")
	}
}

func TestPrintSimulation_NoFailures(t *testing.T) {
	cmd := testRoot()
	cmd.AddCommand(SimulateCmd())

	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	result := SimulateResult{
		Mode:       "strict",
		Total:      1,
		Passed:     1,
		Percentage: 100,
		Grade:      testGradeA,
		Scenarios: []ScenarioResult{
			{Name: "test1", Category: testCatDLP, Detected: true},
		},
	}

	printSimulation(cmd, result)
	output := buf.String()

	// No MISSED line should appear.
	if strings.Contains(output, "MISSED:") {
		t.Error("expected no MISSED summary when no failures")
	}
}

func TestHasCanaryMatch(t *testing.T) {
	tests := []struct {
		name       string
		result     scanner.TextDLPResult
		tokenName  string
		want       bool
		wantDetail string
	}{
		{
			name:      "clean result",
			result:    scanner.TextDLPResult{Clean: true},
			tokenName: "test",
			want:      false,
		},
		{
			name: "matching canary",
			result: scanner.TextDLPResult{
				Clean: false,
				Matches: []scanner.TextDLPMatch{
					{PatternName: "Canary Token (test-token)"},
				},
			},
			tokenName: "test-token",
			want:      true,
		},
		{
			name: "matching canary with encoding",
			result: scanner.TextDLPResult{
				Clean: false,
				Matches: []scanner.TextDLPMatch{
					{PatternName: "Canary Token (encoded-token)", Encoded: "base64"},
				},
			},
			tokenName:  "encoded-token",
			want:       true,
			wantDetail: "base64",
		},
		{
			name: "non-canary match",
			result: scanner.TextDLPResult{
				Clean: false,
				Matches: []scanner.TextDLPMatch{
					{PatternName: "AWS Access Key"},
				},
			},
			tokenName: "test",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := hasCanaryMatch(tc.result, tc.tokenName)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if tc.wantDetail != "" && !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("detail %q missing %q", detail, tc.wantDetail)
			}
		})
	}
}

func TestScanDetectedBy(t *testing.T) {
	tests := []struct {
		name            string
		result          scanner.Result
		expectedScanner string
		wantDetected    bool
		wantDetail      string
	}{
		{
			name:            "allowed",
			result:          scanner.Result{Allowed: true},
			expectedScanner: "dlp",
			wantDetected:    false,
			wantDetail:      "allowed",
		},
		{
			name:            "correct scanner",
			result:          scanner.Result{Allowed: false, Scanner: "dlp"},
			expectedScanner: "dlp",
			wantDetected:    true,
			wantDetail:      "dlp",
		},
		{
			name:            "wrong scanner",
			result:          scanner.Result{Allowed: false, Scanner: "blocklist"},
			expectedScanner: "dlp",
			wantDetected:    false,
			wantDetail:      "blocked by blocklist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			detected, detail := scanDetectedBy(tc.result, tc.expectedScanner)
			if detected != tc.wantDetected {
				t.Errorf("detected: got %v, want %v", detected, tc.wantDetected)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Errorf("detail: got %q, want substring %q", detail, tc.wantDetail)
			}
		})
	}
}

func TestScoreDLP(t *testing.T) {
	tests := []struct {
		name         string
		cfg          func() *config.Config
		wantMinScore int
		wantFindings bool
	}{
		{
			name: "no patterns",
			cfg: func() *config.Config {
				cfg := config.Defaults()
				cfg.DLP.Patterns = nil
				return cfg
			},
			wantMinScore: 0,
			wantFindings: true,
		},
		{
			name: "few patterns no env scan",
			cfg: func() *config.Config {
				cfg := config.Defaults()
				cfg.DLP.Patterns = cfg.DLP.Patterns[:5]
				cfg.DLP.ScanEnv = false
				cfg.FetchProxy.Monitoring.EntropyThreshold = 0
				return cfg
			},
			wantMinScore: 6,
			wantFindings: true,
		},
		{
			name: "full defaults",
			cfg: func() *config.Config {
				return config.Defaults()
			},
			wantMinScore: 10,
			wantFindings: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg()
			var findings []ScoreFinding
			cat := scoreDLP(cfg, &findings)
			if cat.Score < tc.wantMinScore {
				t.Errorf("score: got %d, want >= %d", cat.Score, tc.wantMinScore)
			}
			if tc.wantFindings && len(findings) == 0 {
				t.Error("expected findings")
			}
		})
	}
}

func TestScoreResponseScanning(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		action   string
		wantZero bool
	}{
		{"disabled", false, "", true},
		{"enabled block", true, config.ActionBlock, false},
		{"enabled warn", true, config.ActionWarn, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.ResponseScanning.Enabled = tc.enabled
			if tc.action != "" {
				cfg.ResponseScanning.Action = tc.action
			}
			var findings []ScoreFinding
			cat := scoreResponseScanning(cfg, &findings)
			if tc.wantZero && cat.Score != 0 {
				t.Errorf("expected 0, got %d", cat.Score)
			}
			if !tc.wantZero && cat.Score == 0 {
				t.Error("expected non-zero score")
			}
		})
	}
}

func TestScoreMCPToolPolicy(t *testing.T) {
	tests := []struct {
		name         string
		enabled      bool
		ruleCount    int
		action       string
		wantFindings int
	}{
		{"disabled", false, 0, "", 1},
		{"enabled no rules", true, 0, config.ActionBlock, 1},
		{"enabled with rules", true, 5, config.ActionBlock, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.MCPToolPolicy.Enabled = tc.enabled
			cfg.MCPToolPolicy.Action = tc.action
			cfg.MCPToolPolicy.Rules = nil
			for i := 0; i < tc.ruleCount; i++ {
				cfg.MCPToolPolicy.Rules = append(cfg.MCPToolPolicy.Rules, config.ToolPolicyRule{
					Name:        "test-rule",
					ToolPattern: "bash",
					Action:      config.ActionBlock,
				})
			}
			cat, findings := scoreMCPToolPolicy(cfg)
			if cat.Score < 0 {
				t.Errorf("score should be >= 0, got %d", cat.Score)
			}
			if tc.wantFindings > 0 && len(findings) < tc.wantFindings {
				t.Errorf("findings: got %d, want >= %d", len(findings), tc.wantFindings)
			}
		})
	}
}

func TestIsHighRiskToolPattern_Boost(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{"bash", true},
		{"BASH_EXEC", true},
		{"write_file", true},
		{"safe-tool", false},
		{"my_delete_handler", true},
	}

	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			got := isHighRiskToolPattern(tc.pattern)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsWildcardArgPattern_Boost(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{".*", true},
		{".+", true},
		{"^.*$", true},
		{"^.+$", true},
		{"specific-pattern", false},
		{"foo.*bar", false},
	}

	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			got := isWildcardArgPattern(tc.pattern)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEffectiveAction_Boost(t *testing.T) {
	tests := []struct {
		rule string
		def  string
		want string
	}{
		{"block", "warn", "block"},
		{"", "warn", "warn"},
		{"", "", ""},
		{"ask", "", "ask"},
	}

	for _, tc := range tests {
		t.Run(tc.rule+"_"+tc.def, func(t *testing.T) {
			got := effectiveAction(tc.rule, tc.def)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScoreGrade_AllBoundaries(t *testing.T) {
	tests := []struct {
		pct  int
		want string
	}{
		{100, testGradeA},
		{90, testGradeA},
		{89, testGradeB},
		{80, testGradeB},
		{79, testGradeC},
		{70, testGradeC},
		{69, testGradeD},
		{60, testGradeD},
		{59, testGradeF},
		{0, testGradeF},
	}

	for _, tc := range tests {
		t.Run(strings.Repeat("*", tc.pct/10), func(t *testing.T) {
			got := scoreGrade(tc.pct)
			if got != tc.want {
				t.Errorf("scoreGrade(%d) = %q, want %q", tc.pct, got, tc.want)
			}
		})
	}
}

func TestSimGrade(t *testing.T) {
	// Same thresholds as scoreGrade.
	tests := []struct {
		pct  int
		want string
	}{
		{95, testGradeA},
		{85, testGradeB},
		{75, testGradeC},
		{65, testGradeD},
		{50, testGradeF},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := simGrade(tc.pct)
			if got != tc.want {
				t.Errorf("simGrade(%d) = %q, want %q", tc.pct, got, tc.want)
			}
		})
	}
}

func TestMatchNames_Boost(t *testing.T) {
	tests := []struct {
		name    string
		matches []scanner.ResponseMatch
		want    string
	}{
		{"empty", nil, ""},
		{"single", []scanner.ResponseMatch{{PatternName: "PI-001"}}, "PI-001"},
		{"multiple", []scanner.ResponseMatch{{PatternName: "PI-001"}, {PatternName: "PI-002"}}, "PI-001, PI-002"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchNames(tc.matches)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestScoreBar_Boost(t *testing.T) {
	tests := []struct {
		score    int
		maxScore int
		wantLen  int
	}{
		{0, 100, 12}, // "[----------]"
		{100, 100, 12},
		{50, 100, 12},
		{0, 0, 12},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			bar := scoreBar(tc.score, tc.maxScore)
			if len(bar) != tc.wantLen {
				t.Errorf("bar length: got %d, want %d: %q", len(bar), tc.wantLen, bar)
			}
		})
	}
}

func TestScoreConfig_DefaultsFullCoverage(t *testing.T) {
	cfg := config.Defaults()
	result := ScoreConfig(cfg, "")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.MaxScore == 0 {
		t.Error("expected non-zero max score")
	}
	if result.Grade == "" {
		t.Error("expected non-empty grade")
	}
	if len(result.Categories) == 0 {
		t.Error("expected categories")
	}
}

func TestScoreConfig_BareMinimum(t *testing.T) {
	// Bare-minimum config should produce findings.
	cfg := &config.Config{}
	result := ScoreConfig(cfg, "minimal.yaml")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.ConfigFile != "minimal.yaml" {
		t.Errorf("ConfigFile: got %q, want %q", result.ConfigFile, "minimal.yaml")
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for minimal config")
	}
}

func TestScoreKillSwitch(t *testing.T) {
	tests := []struct {
		name     string
		cfg      func() *config.Config
		wantZero bool
	}{
		{
			name: "no sources",
			cfg: func() *config.Config {
				return &config.Config{}
			},
			wantZero: true,
		},
		{
			name: "config enabled",
			cfg: func() *config.Config {
				cfg := &config.Config{}
				cfg.KillSwitch.Enabled = true
				return cfg
			},
			wantZero: false,
		},
		{
			name: "api listen",
			cfg: func() *config.Config {
				cfg := &config.Config{}
				cfg.KillSwitch.APIListen = "127.0.0.1:9999"
				return cfg
			},
			wantZero: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg()
			var findings []ScoreFinding
			cat := scoreKillSwitch(cfg, &findings)
			if tc.wantZero && cat.Score != 0 {
				t.Errorf("expected 0, got %d", cat.Score)
			}
			if !tc.wantZero && cat.Score == 0 {
				t.Error("expected non-zero score")
			}
		})
	}
}

func TestScoreEnforcement(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want int
	}{
		{"strict", config.ModeStrict, 10},
		{"balanced", config.ModeBalanced, 8},
		{"audit", config.ModeAudit, 6},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Mode = tc.mode
			var findings []ScoreFinding
			cat := scoreEnforcement(cfg, &findings)
			if cat.Score != tc.want {
				t.Errorf("score: got %d, want %d", cat.Score, tc.want)
			}
		})
	}
}

func TestScoreToolChainDetection(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		cfg := &config.Config{}
		var findings []ScoreFinding
		cat := scoreToolChainDetection(cfg, &findings)
		if cat.Score != 0 {
			t.Errorf("expected 0, got %d", cat.Score)
		}
	})

	t.Run("enabled with custom patterns", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.ToolChainDetection.Enabled = true
		cfg.ToolChainDetection.CustomPatterns = []config.ChainPattern{
			{Name: "test", Sequence: []string{"read", "write"}},
		}
		var findings []ScoreFinding
		cat := scoreToolChainDetection(cfg, &findings)
		if cat.Score < 3 {
			t.Errorf("expected >= 3, got %d", cat.Score)
		}
	})
}

func TestPrintScoreResult(t *testing.T) {
	cmd := testRoot()
	cmd.AddCommand(Cmd())

	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	result := &ScoreResult{
		TotalScore: 80,
		MaxScore:   100,
		Percentage: 80,
		Grade:      testGradeB,
		ConfigFile: "test.yaml",
		Categories: []ScoreCategory{
			{Name: "DLP", Score: 15, MaxScore: 15, Detail: "40 patterns"},
			{Name: "Kill Switch", Score: 0, MaxScore: 10},
		},
		Findings: []ScoreFinding{
			{Severity: testSevCritical, Category: "Test", Message: "critical finding"},
			{Severity: testSevWarning, Category: "Test", Message: "warning finding"},
			{Severity: testSevInfo, Category: "Test", Message: "info finding"},
		},
	}

	printScoreResult(cmd, result)
	output := buf.String()

	if !strings.Contains(output, "Config Security Score") {
		t.Error("expected header")
	}
	if !strings.Contains(output, "test.yaml") {
		t.Error("expected config file")
	}
	if !strings.Contains(output, "[CRITICAL]") {
		t.Error("expected CRITICAL tag")
	}
	if !strings.Contains(output, "[WARNING]") {
		t.Error("expected WARNING tag")
	}
	if !strings.Contains(output, "[INFO]") {
		t.Error("expected INFO tag")
	}
}

func TestPrintScoreResult_NoConfig(t *testing.T) {
	cmd := testRoot()
	cmd.AddCommand(Cmd())

	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	result := &ScoreResult{
		TotalScore: 50,
		MaxScore:   100,
		Percentage: 50,
		Grade:      testGradeF,
		Categories: []ScoreCategory{},
	}

	printScoreResult(cmd, result)
	output := buf.String()

	if !strings.Contains(output, "built-in defaults") {
		t.Error("expected 'built-in defaults' when no config file")
	}
}

func TestJoinMax(t *testing.T) {
	tests := []struct {
		name    string
		items   []string
		limit   int
		wantSub string
	}{
		{"under limit", []string{"a", "b"}, 5, "a, b"},
		{"at limit", []string{"a", "b", "c"}, 3, "a, b, c"},
		{"over limit", []string{"a", "b", "c", "d"}, 2, "(+2 more)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := joinMax(tc.items, tc.limit)
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("got %q, want substring %q", got, tc.wantSub)
			}
		})
	}
}
