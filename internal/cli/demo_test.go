package cli

import (
	"strings"
	"testing"
)

func TestDemoCmd(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	t.Run("header", func(t *testing.T) {
		if !strings.Contains(output, "Pipelock Demo") {
			t.Error("expected demo header in output")
		}
	})

	t.Run("all_blocked", func(t *testing.T) {
		if !strings.Contains(output, "5/5 attacks blocked") {
			t.Errorf("expected 5/5 blocked, got:\n%s", output)
		}
	})

	t.Run("blocked_count", func(t *testing.T) {
		if strings.Count(output, "[BLOCKED]") != 5 {
			t.Errorf("expected 5 [BLOCKED] results, got %d", strings.Count(output, "[BLOCKED]"))
		}
	})

	t.Run("scenario_names", func(t *testing.T) {
		names := []string{
			"Credential Exfiltration",
			"Prompt Injection",
			"Data Exfiltration via Paste Service",
			"High-Entropy Data Smuggling",
			"MCP Tool Poisoning",
		}
		for _, name := range names {
			if !strings.Contains(output, name) {
				t.Errorf("missing scenario %q in output", name)
			}
		}
	})

	t.Run("dlp_detail", func(t *testing.T) {
		if !strings.Contains(output, "Anthropic API Key") {
			t.Error("expected DLP detail for Anthropic API Key")
		}
	})

	t.Run("injection_detail", func(t *testing.T) {
		if !strings.Contains(output, "Prompt Injection detected") {
			t.Error("expected prompt injection detection detail")
		}
	})

	t.Run("mcp_action", func(t *testing.T) {
		if !strings.Contains(output, "action: block") {
			t.Error("expected MCP block action in output")
		}
	})

	t.Run("audit_hint", func(t *testing.T) {
		if !strings.Contains(output, "pipelock audit") {
			t.Error("expected audit command hint in output")
		}
	})
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
