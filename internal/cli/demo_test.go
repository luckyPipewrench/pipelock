package cli

import (
	"strings"
	"testing"
)

func TestDemoCmd(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Pipelock Demo") {
		t.Error("expected demo header in output")
	}
}

func TestDemoCmd_AllBlocked(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "5/5 attacks blocked") {
		t.Errorf("expected all 5 scenarios blocked, got output:\n%s", output)
	}
}

func TestDemoCmd_ScenarioNames(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	scenarios := []string{
		"Credential Exfiltration",
		"Prompt Injection",
		"Data Exfiltration via Paste Service",
		"High-Entropy Data Smuggling",
		"MCP Tool Poisoning",
	}
	for _, name := range scenarios {
		if !strings.Contains(output, name) {
			t.Errorf("expected scenario %q in output", name)
		}
	}
}

func TestDemoCmd_BlockedResults(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	// Each scenario should produce a [BLOCKED] result
	if strings.Count(output, "[BLOCKED]") != 5 {
		t.Errorf("expected 5 [BLOCKED] results, got %d", strings.Count(output, "[BLOCKED]"))
	}
}

func TestDemoCmd_DLPDetail(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Anthropic API Key") {
		t.Error("expected DLP match detail for Anthropic API Key")
	}
}

func TestDemoCmd_PromptInjectionDetail(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Prompt Injection detected") {
		t.Error("expected prompt injection detection detail")
	}
}

func TestDemoCmd_MCPDetail(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "action: block") {
		t.Error("expected MCP block action in output")
	}
}

func TestDemoCmd_HelpRegistered(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "demo") {
		t.Error("expected demo command in help output")
	}
}

func TestDemoCmd_AuditHint(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "pipelock audit") {
		t.Error("expected audit command hint in output")
	}
}
