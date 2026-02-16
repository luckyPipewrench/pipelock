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

func TestDemoCmd_ColorOutput(t *testing.T) {
	// Call runDemo directly with color=true to exercise ANSI color branches.
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	// Find the demo subcommand so we can call runDemo on it.
	demoSub, _, _ := cmd.Find([]string{"demo"})
	if demoSub == nil {
		t.Fatal("demo subcommand not found")
	}

	if err := runDemo(demoSub, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	// Color output uses ANSI bold for header, not '=' separators.
	if !strings.Contains(output, "\033[1m") {
		t.Error("expected ANSI bold escape in color output")
	}
	if !strings.Contains(output, "\033[0m") {
		t.Error("expected ANSI reset escape in color output")
	}
	// Color output uses '─' separator, not '='.
	if !strings.Contains(output, "─") {
		t.Error("expected '─' separator in color output")
	}
	// Color output uses "✓ BLOCKED" not "[BLOCKED]".
	if !strings.Contains(output, "✓ BLOCKED") {
		t.Error("expected '✓ BLOCKED' in color output")
	}
	// Should still show all scenarios and final count.
	if !strings.Contains(output, "7/7 attacks blocked") {
		t.Errorf("expected 7/7 blocked in color output, got:\n%s", output)
	}
}

func TestBuildScenarios_PermissiveScanner(t *testing.T) {
	// Run each scenario with a scanner that has no detection patterns.
	// This exercises the "not blocked" / fallback paths in each closure.
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.Patterns = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.Blocklist = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 99 // effectively disable entropy
	cfg.ResponseScanning.Enabled = false
	cfg.ResponseScanning.Patterns = nil

	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := buildScenarios()

	// Scenarios that should NOT block with a permissive scanner
	expectAllow := map[string]string{
		"Credential Exfiltration":             demoScanAllowed,
		"Prompt Injection":                    "no injection found",
		"Data Exfiltration via Paste Service": demoScanAllowed,
		"High-Entropy Data Smuggling":         demoScanAllowed,
		"MCP Response Injection":              "no injection found",
		"MCP Input Secret Leak":               "no leak detected",
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			blocked, detail := s.run(sc)
			if expected, ok := expectAllow[s.name]; ok {
				if blocked {
					t.Errorf("expected %q to pass with permissive scanner, got blocked: %s", s.name, detail)
				}
				if detail != expected {
					t.Errorf("detail = %q, want %q", detail, expected)
				}
			}
			// MCP Tool Description Attack still blocks (built-in poison heuristics)
			if s.name == "MCP Tool Description Attack" && !blocked {
				t.Error("expected tool description attack to still be detected by built-in heuristics")
			}
		})
	}
}

func TestDemoCmd_NoColorFlag(t *testing.T) {
	cmd := rootCmd()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"demo", "--no-color"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	// --no-color should produce plain text with [BLOCKED], not ANSI codes.
	if strings.Contains(output, "\033[") {
		t.Error("expected no ANSI escape codes with --no-color flag")
	}
	if !strings.Contains(output, "[BLOCKED]") {
		t.Error("expected [BLOCKED] markers in no-color output")
	}
}
