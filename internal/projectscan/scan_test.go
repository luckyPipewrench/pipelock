// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package projectscan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScan_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.AgentType != AgentGeneric {
		t.Errorf("expected generic agent, got %q", report.AgentType)
	}
	if report.Score != 0 {
		t.Errorf("expected score 0, got %d", report.Score)
	}
	if report.ScoreWith <= 0 {
		t.Error("expected positive score with config")
	}
	if report.Config == nil {
		t.Error("expected non-nil config suggestion")
	}
}

func TestScan_NonexistentDir(t *testing.T) {
	_, err := Scan("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestScan_NotADir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Scan(f)
	if err == nil {
		t.Error("expected error for non-directory")
	}
}

func TestScan_ClaudeCodeProject(t *testing.T) {
	dir := t.TempDir()

	// Claude Code marker
	if err := os.Mkdir(filepath.Join(dir, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}

	// Git repo
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}

	// Go project
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.AgentType != AgentClaudeCode {
		t.Errorf("expected claude-code, got %q", report.AgentType)
	}
	if len(report.Languages) == 0 || report.Languages[0] != "Go" {
		t.Errorf("expected Go as language, got %v", report.Languages)
	}

	// Should have ecosystem detection
	foundGo := false
	for _, e := range report.Ecosystems {
		if e == EcoGoMod {
			foundGo = true
		}
	}
	if !foundGo {
		t.Error("expected Go ecosystem")
	}

	// Should have info findings
	if len(report.Findings) == 0 {
		t.Error("expected at least some findings")
	}

	// Config should suggest claude-code preset
	if report.Config.Preset != AgentClaudeCode {
		t.Errorf("expected claude-code preset, got %q", report.Config.Preset)
	}
	if !report.Config.GitEnabled {
		t.Error("expected git protection enabled")
	}
}

func TestScan_CriticalFindingPenalizesScore(t *testing.T) {
	dir := t.TempDir()
	// Plant a .env with a fake API key so Scan() produces a critical finding
	fakeKey := "sk-proj-" + "abcdefghijklmnop" + "qrstuvwxyz1234567890"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY="+fakeKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must have at least one critical finding
	criticals := 0
	for _, f := range report.Findings {
		if f.Severity == "critical" {
			criticals++
		}
	}
	if criticals == 0 {
		t.Fatal("expected at least one critical finding from .env secret")
	}

	// ScoreWith should be penalized (base score minus 5 per critical)
	baseWith := computeScore(report.Config)
	expectedWith := baseWith - criticals*5
	if expectedWith < 0 {
		expectedWith = 0
	}
	if report.ScoreWith != expectedWith {
		t.Errorf("ScoreWith = %d, want %d (base %d minus %d criticals * 5)", report.ScoreWith, expectedWith, baseWith, criticals)
	}
}

func TestScan_WithMCPServers(t *testing.T) {
	dir := t.TempDir()
	mcp := `{"mcpServers": {"filesystem": {"command": "npx"}, "postgres": {"command": "npx"}}}`
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(mcp), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Scan(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.MCPServers) != 2 {
		t.Errorf("expected 2 MCP servers, got %d", len(report.MCPServers))
	}

	// Should have an info finding about MCP
	foundMCP := false
	for _, f := range report.Findings {
		if f.Category == "config" && strings.Contains(f.Message, "mcp.json") {
			foundMCP = true
		}
	}
	if !foundMCP {
		t.Error("expected finding about MCP servers")
	}
}

func TestScanFiles_DotEnv(t *testing.T) {
	dir := t.TempDir()
	// Build fake API key at runtime to avoid gitleaks
	fakeKey := "sk-proj-" + "abcdefghijklmnop" + "qrstuvwxyz1234567890"
	envContent := "# Database\nDB_HOST=localhost\nOPENAI_API_KEY=" + fakeKey + "\nSIMPLE=short\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := scanFiles(dir, compileDLPPatterns())
	if len(findings) == 0 {
		t.Fatal("expected findings from .env file")
	}

	// Should find the OpenAI key via DLP pattern
	foundDLP := false
	for _, f := range findings {
		if f.Pattern == "OpenAI API Key" {
			foundDLP = true
		}
	}
	if !foundDLP {
		t.Error("expected DLP match for OpenAI API Key in .env")
	}
}

func TestScanFiles_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules", "bad-pkg")
	if err := os.MkdirAll(nm, 0o750); err != nil {
		t.Fatal(err)
	}
	// Secret in node_modules should be skipped
	fakeKey := "sk-proj-" + "abcdefghijklmnop" + "qrstuvwxyz1234567890"
	if err := os.WriteFile(filepath.Join(nm, ".env"), []byte("KEY="+fakeKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := scanFiles(dir, compileDLPPatterns())
	for _, f := range findings {
		if f.File != "" && filepath.Base(filepath.Dir(f.File)) == "bad-pkg" {
			t.Error("should not scan files in node_modules")
		}
	}
}

func TestScanFiles_LargeFileSkipped(t *testing.T) {
	dir := t.TempDir()
	// Create a file just over 1MB
	large := make([]byte, 1<<20+1)
	if err := os.WriteFile(filepath.Join(dir, ".env"), large, 0o600); err != nil {
		t.Fatal(err)
	}

	findings := scanFiles(dir, compileDLPPatterns())
	if len(findings) != 0 {
		t.Error("expected no findings from oversized file")
	}
}

func TestScanFiles_YAMLConfig(t *testing.T) {
	dir := t.TempDir()
	// Build fake key at runtime to avoid gitleaks
	fakeAnthropic := "sk-ant-" + "api03-XXXXXXXXX" + "XXXXXXXXXXXXXXXX"
	yamlContent := "api_key: " + fakeAnthropic + "\ndatabase: postgres://localhost/mydb\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := scanFiles(dir, compileDLPPatterns())
	foundAnthropic := false
	for _, f := range findings {
		if f.Pattern == "Anthropic API Key" {
			foundAnthropic = true
		}
	}
	if !foundAnthropic {
		t.Error("expected DLP match for Anthropic API Key in YAML")
	}
}

func TestScanFileForEntropy(t *testing.T) {
	dir := t.TempDir()
	// Build high-entropy value at runtime to avoid gitleaks
	highEntropy := "aB3cD4eF5gH6" + "iJ7kL8mN9oP0" + "qR1sT2uV3wX4yZ5"
	envContent := "SIMPLE=hello\nHIGH_ENTROPY=" + highEntropy + "\n"
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := scanFileForEntropy(path, ".env")
	if len(findings) == 0 {
		t.Error("expected entropy finding for high-entropy value")
	}
	for _, f := range findings {
		if f.Severity != "warning" {
			t.Errorf("expected warning severity, got %q", f.Severity)
		}
	}
}

func TestScanFileForEntropy_ShortValues(t *testing.T) {
	dir := t.TempDir()
	envContent := "SHORT=abc\nALSO_SHORT=12345\n"
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := scanFileForEntropy(path, ".env")
	if len(findings) != 0 {
		t.Error("expected no findings for short values")
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"short", "***"},
		{"exactly8", "***"},
		{"longerstring", "longerst..."},
		{"sk-proj-" + "abcdefghijklmnop", "sk-proj-..."},
	}
	for _, tt := range tests {
		if got := redact(tt.input); got != tt.want {
			t.Errorf("redact(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestScanFiles_EnvPrefix(t *testing.T) {
	dir := t.TempDir()
	fakeKey := "sk-proj-" + "abcdefghijklmnop" + "qrstuvwxyz1234567890"
	envContent := "KEY=" + fakeKey + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env.production"), []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := scanFiles(dir, compileDLPPatterns())
	if len(findings) == 0 {
		t.Error("expected findings from .env.production file")
	}
}

func TestScanFiles_UnreadableEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on Windows")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, ".env")
	fakeKey := "sk-proj-" + "abcdefghijklmnop" + "qrstuvwxyz1234567890"
	if err := os.WriteFile(secret, []byte("KEY="+fakeKey+"\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	findings := scanFiles(dir, compileDLPPatterns())
	if len(findings) != 0 {
		t.Error("expected no findings for unreadable file")
	}
}

func TestScanFileForSecrets_UnreadableFile(t *testing.T) {
	findings := scanFileForSecrets("/nonexistent/file", "file", nil)
	if len(findings) != 0 {
		t.Error("expected no findings for unreadable file")
	}
}

func TestScanFileForEntropy_UnreadableFile(t *testing.T) {
	findings := scanFileForEntropy("/nonexistent/file", "file")
	if len(findings) != 0 {
		t.Error("expected no findings for unreadable file")
	}
}

// --- AdjustScoreForFindings tests ---

func TestAdjustScoreForFindings_NoCriticals(t *testing.T) {
	cfg := &SuggestCfg{Preset: AgentGeneric}
	r := &Report{
		Config: cfg,
		Findings: []Finding{
			{Severity: "info", Category: "agent", Message: "detected"},
			{Severity: "warning", Category: "secret", Message: "high entropy"},
		},
	}
	r.AdjustScoreForFindings()
	expected := computeScore(cfg)
	if r.ScoreWith != expected {
		t.Errorf("ScoreWith = %d, want %d (no criticals, no penalty)", r.ScoreWith, expected)
	}
}

func TestAdjustScoreForFindings_WithCriticals(t *testing.T) {
	cfg := &SuggestCfg{Preset: AgentGeneric}
	r := &Report{
		Config: cfg,
		Findings: []Finding{
			{Severity: severityCritical, Category: "secret", Message: "API key found"},
			{Severity: severityCritical, Category: "secret", Message: "another key"},
			{Severity: "info", Category: "agent", Message: "detected"},
		},
	}
	r.AdjustScoreForFindings()
	expected := computeScore(cfg) - 10 // 2 criticals * 5
	if expected < 0 {
		expected = 0
	}
	if r.ScoreWith != expected {
		t.Errorf("ScoreWith = %d, want %d (2 criticals * 5 penalty)", r.ScoreWith, expected)
	}
}

func TestAdjustScoreForFindings_ClampsToZero(t *testing.T) {
	// Enough criticals to push score below zero.
	cfg := &SuggestCfg{Preset: AgentGeneric}
	baseScore := computeScore(cfg)
	numCriticals := (baseScore / 5) + 5 // guaranteed to overshoot

	findings := make([]Finding, numCriticals)
	for i := range findings {
		findings[i] = Finding{Severity: severityCritical, Category: "secret", Message: "leaked"}
	}
	r := &Report{Config: cfg, Findings: findings}
	r.AdjustScoreForFindings()
	if r.ScoreWith != 0 {
		t.Errorf("ScoreWith = %d, want 0 (clamped)", r.ScoreWith)
	}
}

func TestAdjustScoreForFindings_EmptyFindings(t *testing.T) {
	cfg := &SuggestCfg{Preset: AgentGeneric}
	r := &Report{Config: cfg, Findings: nil}
	r.AdjustScoreForFindings()
	expected := computeScore(cfg)
	if r.ScoreWith != expected {
		t.Errorf("ScoreWith = %d, want %d (no findings)", r.ScoreWith, expected)
	}
}

func TestAdjustScoreForFindings_NilConfig(t *testing.T) {
	r := &Report{
		Config: nil,
		Findings: []Finding{
			{Severity: severityCritical, Category: "secret", Message: "found"},
		},
	}
	r.AdjustScoreForFindings()
	// computeScore(nil) = 0, minus 5 for 1 critical, clamped to 0.
	if r.ScoreWith != 0 {
		t.Errorf("ScoreWith = %d, want 0 (nil config)", r.ScoreWith)
	}
}

func TestScanFileForEntropy_QuotedValues(t *testing.T) {
	dir := t.TempDir()
	// Build high-entropy value at runtime to avoid gitleaks
	highEntropy := "aB3cD4eF5gH6" + "iJ7kL8mN9oP0" + "qR1sT2uV3wX4yZ5"
	envContent := `SECRET="` + highEntropy + "\"" + "\n"
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := scanFileForEntropy(path, ".env")
	if len(findings) == 0 {
		t.Error("expected entropy finding for quoted high-entropy value")
	}
}

// TestEnvValueIsNeverSecret covers the structural path filter used to
// prevent the env-var scanner from flagging file paths as credentials.
func TestEnvValueIsNeverSecret(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{"unix_absolute", "/home/runner/work/_temp/_runner_file_commands/set_output_1234567890123456", true},
		{"unix_nested", "/usr/local/bin/pipelock", true},
		{"unix_root_only", "/", false},
		{"unix_single_slash", "/foo", false},
		{"windows_backslash", `C:\Users\runner\file`, true},
		{"windows_forward", "C:/Users/runner/file", true},
		{"windows_no_drive", "Users/runner", false},
		{"non_path_secret", "AKIAIOSFODNN7EXAMPLE", false},
		{"non_path_token", "sk-ant-api03-test1234567890", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := envValueIsNeverSecret(tc.value); got != tc.want {
				t.Errorf("envValueIsNeverSecret(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// TestScanEnvSecrets_SkipsSafeNames asserts that the GitHub Actions
// runner env vars (and other well-known safe names) are excluded from
// DLP scanning so digit-heavy temp paths do not produce false
// positives against the Credit Card Number pattern.
func TestScanEnvSecrets_SkipsSafeNames(t *testing.T) {
	// Set a GITHUB_PATH-like value that would otherwise match the CCN
	// regex (\b\d{4}(?:[- ]?\d){11,15}\b). Using 16 digits lets the
	// raw regex match; the filter has to skip by name.
	t.Setenv("GITHUB_PATH", "/home/runner/work/_temp/set_output_1234567890123456")
	findings := scanEnvSecrets(compileDLPPatterns())
	for _, f := range findings {
		if strings.Contains(f.Message, "GITHUB_PATH") {
			t.Errorf("GITHUB_PATH should be skipped, got finding: %s", f.Message)
		}
	}
}

// TestScanEnvSecrets_SkipsPathValues asserts that env vars whose
// values look like absolute file paths are excluded regardless of
// their name. Paths can match digit-heavy regexes by coincidence but
// are never themselves secrets.
func TestScanEnvSecrets_SkipsPathValues(t *testing.T) {
	// Unknown var name — wouldn't be in envVarAlwaysSafe — but with a
	// path-shaped value, it must still be skipped.
	t.Setenv("MY_CUSTOM_PATH", "/tmp/_some_long_path_with_digits_1234567890123456")
	findings := scanEnvSecrets(compileDLPPatterns())
	for _, f := range findings {
		if strings.Contains(f.Message, "MY_CUSTOM_PATH") {
			t.Errorf("absolute path value should be skipped, got finding: %s", f.Message)
		}
	}
}
