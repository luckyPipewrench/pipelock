package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

func TestAuditCmd_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Pipelock Security Audit") {
		t.Error("expected audit header in output")
	}
	if !strings.Contains(output, "generic") {
		t.Error("expected generic agent type")
	}
}

func TestAuditCmd_WithClaudeCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "claude-code") {
		t.Error("expected claude-code agent type")
	}
	if !strings.Contains(output, "Git repository detected") {
		t.Error("expected git finding")
	}
}

func TestAuditCmd_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", dir, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"agent_type"`) {
		t.Error("expected JSON output with agent_type field")
	}
	if !strings.Contains(output, `"score"`) {
		t.Error("expected JSON output with score field")
	}
}

func TestAuditCmd_OutputFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(t.TempDir(), "suggested.yaml")

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", dir, "-o", outFile})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(outFile) //nolint:gosec // test file path
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if !strings.Contains(string(data), "version:") {
		t.Error("expected YAML config in output file")
	}
}

func TestAuditCmd_NoArgs(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error with no arguments")
	}
}

func TestAuditCmd_InvalidDir(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", "/nonexistent/path"})

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestAuditCmd_ShowsScores(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Security Score:") {
		t.Error("expected security score in output")
	}
	if !strings.Contains(output, "With suggested config:") {
		t.Error("expected suggested score in output")
	}
}

func TestAuditCmd_WithEcosystems(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module test"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "npm") {
		t.Error("expected npm ecosystem in output")
	}
	if !strings.Contains(output, "go") {
		t.Error("expected go ecosystem in output")
	}
}

func TestAuditCmd_HelpRegistered(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "audit") {
		t.Error("expected audit command in help output")
	}
}

func TestAuditCmd_WithSecretFile(t *testing.T) {
	dir := t.TempDir()
	// Create a .env file with a fake secret to trigger findings with file+line info
	envContent := "DATABASE_URL=postgres://user:password@localhost/db\n" +
		"API_KEY=" + "sk-ant-" + "api03-XXXXXXXXXXXX" + "XXXXXXXXXXXXXXXX\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"audit", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "[CRITICAL]") || !strings.Contains(output, "[WARNING]") {
		// At minimum we should see critical or warning findings from the .env scan
		if !strings.Contains(output, "[CRITICAL]") && !strings.Contains(output, "[WARNING]") && !strings.Contains(output, "[INFO]") {
			t.Error("expected findings with severity prefixes from .env file")
		}
	}
	// The findings should include file reference
	if !strings.Contains(output, ".env") {
		t.Error("expected .env file reference in findings")
	}
}

func TestPrintReport_AllSeverities(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	report := &projectscan.Report{
		Dir:       "/test/project",
		AgentType: "claude-code",
		Languages: []string{"Go", "Python"},
		Findings: []projectscan.Finding{
			{Severity: "critical", Category: "secret", Message: "API key found", File: "config.yaml", Line: 42},
			{Severity: "warning", Category: "config", Message: "No lockfile"},
			{Severity: "info", Category: "agent", Message: "Agent detected"},
			{Severity: "critical", Category: "secret", Message: "Token in file", File: ".env"},
		},
		Score:     0,
		ScoreWith: 85,
	}

	// printReport writes to cmd.ErrOrStderr, so we need the actual subcommand
	// Since printReport is package-level, call it directly with a cobra command.
	printReport(cmd.Commands()[0], report)

	output := buf.String()
	if !strings.Contains(output, "[CRITICAL]") {
		t.Error("expected [CRITICAL] prefix")
	}
	if !strings.Contains(output, "[WARNING]") {
		t.Error("expected [WARNING] prefix")
	}
	if !strings.Contains(output, "[INFO]") {
		t.Error("expected [INFO] prefix")
	}
	if !strings.Contains(output, "config.yaml:42") {
		t.Error("expected file:line reference for finding with line number")
	}
	if !strings.Contains(output, "(.env)") {
		t.Error("expected file reference for finding without line number")
	}
	if !strings.Contains(output, "Criticals: 2") {
		t.Error("expected 2 criticals in summary")
	}
	if !strings.Contains(output, "Warnings: 1") {
		t.Error("expected 1 warning in summary")
	}
	if !strings.Contains(output, "Info: 1") {
		t.Error("expected 1 info in summary")
	}
}

func TestPrintReport_NoFindings(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	report := &projectscan.Report{
		Dir:       "/clean/project",
		AgentType: "generic",
		Score:     0,
		ScoreWith: 100,
	}

	printReport(cmd.Commands()[0], report)

	output := buf.String()
	if !strings.Contains(output, "No findings.") {
		t.Error("expected 'No findings.' for empty report")
	}
}

func TestJoinMax_WithinLimit(t *testing.T) {
	result := joinMax([]string{"Go", "Python", "Rust"}, 5)
	if result != "Go, Python, Rust" {
		t.Errorf("expected 'Go, Python, Rust', got %q", result)
	}
}

func TestJoinMax_ExceedsLimit(t *testing.T) {
	items := []string{"Go", "Python", "Rust", "Java", "TypeScript", "C++", "Ruby"}
	result := joinMax(items, 3)
	if !strings.Contains(result, "Go, Python, Rust") {
		t.Errorf("expected first 3 items, got %q", result)
	}
	if !strings.Contains(result, "(+4 more)") {
		t.Errorf("expected '+4 more' suffix, got %q", result)
	}
}

func TestJoinMax_ExactLimit(t *testing.T) {
	result := joinMax([]string{"a", "b", "c"}, 3)
	if result != "a, b, c" {
		t.Errorf("expected 'a, b, c', got %q", result)
	}
}

func TestJoin_Empty(t *testing.T) {
	result := join(nil)
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestJoin_Single(t *testing.T) {
	result := join([]string{"only"})
	if result != "only" {
		t.Errorf("expected 'only', got %q", result)
	}
}
