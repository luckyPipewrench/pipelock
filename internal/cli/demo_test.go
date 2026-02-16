package cli

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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
		if !strings.Contains(output, "7/7 attacks blocked") {
			t.Errorf("expected 7/7 blocked, got:\n%s", output)
		}
	})

	t.Run("blocked_count", func(t *testing.T) {
		if strings.Count(output, "[BLOCKED]") != 7 {
			t.Errorf("expected 7 [BLOCKED] results, got %d", strings.Count(output, "[BLOCKED]"))
		}
	})

	t.Run("scenario_names", func(t *testing.T) {
		names := []string{
			"Credential Exfiltration",
			"Prompt Injection",
			"Data Exfiltration via Paste Service",
			"High-Entropy Data Smuggling",
			"MCP Response Injection",
			"MCP Input Secret Leak",
			"MCP Tool Description Attack",
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

	t.Run("tool_poison_detail", func(t *testing.T) {
		if !strings.Contains(output, "Instruction Tag") {
			t.Error("expected tool poison detection detail")
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

func TestUseColor_NOCOLOREnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if useColor() {
		t.Error("expected useColor() to return false when NO_COLOR is set")
	}
}

func TestBuildScenarios_Count(t *testing.T) {
	scenarios := buildScenarios()
	if len(scenarios) != 7 {
		t.Errorf("expected 7 scenarios, got %d", len(scenarios))
	}
	for i, s := range scenarios {
		if s.name == "" {
			t.Errorf("scenario %d has empty name", i)
		}
		if s.attack == "" {
			t.Errorf("scenario %d has empty attack description", i)
		}
		if s.run == nil {
			t.Errorf("scenario %d has nil run function", i)
		}
	}
}

func TestDemoCmd_OutputContainsSeparator(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	// Non-color mode uses '=' separators
	if !strings.Contains(output, "=======") {
		t.Error("expected '=' separator in non-color output")
	}
	// Should mention additional protections
	if !strings.Contains(output, "SSRF") {
		t.Error("expected SSRF mention in footer")
	}
	if !strings.Contains(output, "DNS rebinding") {
		t.Error("expected DNS rebinding mention in footer")
	}
}

func TestDemoCmd_AllScenariosRunAndBlock(t *testing.T) {
	// Directly run each scenario to cover all run functions
	scenarios := buildScenarios()

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.ResponseScanning.Action = "block" //nolint:goconst // test value
			cfg.DLP.ScanEnv = false

			sc := scanner.New(cfg)
			defer sc.Close()

			blocked, detail := s.run(sc)
			if !blocked {
				t.Errorf("expected scenario %q to be blocked, got: %s", s.name, detail)
			}
			if detail == "" {
				t.Errorf("expected non-empty detail for scenario %q", s.name)
			}
		})
	}
}
