// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/spf13/cobra"
)

// demoRoot creates a minimal root command with the demo subcommand registered.
func demoRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "pipelock",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(DemoCmd())
	return root
}

func TestDemoCmd(t *testing.T) {
	cmd := demoRoot()
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
			"Cloud Metadata SSRF",
			"Data Exfiltration via Paste Service",
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
		var detailLine string
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "[BLOCKED]") && strings.Contains(line, "Prompt Injection") {
				detailLine = line
				break
			}
		}
		if detailLine == "" {
			t.Fatalf("expected prompt injection detection detail, got:\n%s", output)
		}
		if !strings.Contains(detailLine, "Prompt Injection") ||
			!strings.Contains(detailLine, "System Prompt Disclosure") ||
			!strings.Contains(detailLine, "detected (action: block)") {
			t.Errorf("expected prompt injection detection detail, got %q", detailLine)
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
	cmd := demoRoot()
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

func TestBuildScenarios_Count(t *testing.T) {
	scenarios := buildScenarios(nil)
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
		if s.layer == "" {
			t.Errorf("scenario %d (%s) has empty layer", i, s.name)
		}
		if s.severity == "" {
			t.Errorf("scenario %d (%s) has empty severity", i, s.name)
		}
		if s.severity != config.SeverityHigh && s.severity != config.SeverityCritical {
			t.Errorf("scenario %d (%s) severity = %q, want shared config severity constant", i, s.name, s.severity)
		}
	}
}

func TestDemoCmd_OutputContainsSeparator(t *testing.T) {
	cmd := demoRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"demo"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "=======") {
		t.Error("expected '=' separator in non-color output")
	}
	if !strings.Contains(output, "SSRF") {
		t.Error("expected SSRF mention in footer")
	}
	if !strings.Contains(output, "DNS rebinding") {
		t.Error("expected DNS rebinding mention in footer")
	}
}

func TestDemoCmd_AllScenariosRunAndBlock(t *testing.T) {
	scenarios := buildScenarios(nil)

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
			cfg.ResponseScanning.Action = "block"
			cfg.DLP.ScanEnv = false

			sc := scanner.New(cfg)
			defer sc.Close()

			blocked, detail, _ := s.run(sc)
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
	cmd := demoRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	demoSub, _, _ := cmd.Find([]string{"demo"})
	if demoSub == nil {
		t.Fatal("demo subcommand not found")
	}

	if err := runDemo(demoSub, false, true, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "\033[1m") {
		t.Error("expected ANSI bold escape in color output")
	}
	if !strings.Contains(output, "\033[0m") {
		t.Error("expected ANSI reset escape in color output")
	}
	if !strings.Contains(output, "─") {
		t.Error("expected '─' separator in color output")
	}
	if !strings.Contains(output, "✓ BLOCKED") {
		t.Error("expected '✓ BLOCKED' in color output")
	}
	if !strings.Contains(output, "7/7 attacks blocked") {
		t.Errorf("expected 7/7 blocked in color output, got:\n%s", output)
	}
}

func TestBuildScenarios_PermissiveScanner(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.DLP.Patterns = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.Blocklist = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 99
	cfg.ResponseScanning.Enabled = false
	cfg.ResponseScanning.Patterns = nil

	sc := scanner.New(cfg)
	defer sc.Close()

	scenarios := buildScenarios(nil)

	expectAllow := map[string]string{
		"Credential Exfiltration":             demoScanAllowed,
		"Data Exfiltration via Paste Service": demoScanAllowed,
		"MCP Input Secret Leak":               "no leak detected",
	}

	expectBlock := map[string]bool{
		"Prompt Injection":       true,
		"Cloud Metadata SSRF":    true,
		"MCP Response Injection": true,
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			blocked, detail, _ := s.run(sc)
			if expected, ok := expectAllow[s.name]; ok {
				if blocked {
					t.Errorf("expected %q to pass with permissive scanner, got blocked: %s", s.name, detail)
				}
				if detail != expected {
					t.Errorf("detail = %q, want %q", detail, expected)
				}
			}
			if expectBlock[s.name] && !blocked {
				t.Errorf("expected %q to be blocked by core patterns, got allowed: %s", s.name, detail)
			}
			if s.name == "MCP Tool Description Attack" && !blocked {
				t.Error("expected tool description attack to still be detected by built-in heuristics")
			}
		})
	}
}

func TestDemoCmd_NoColorFlag(t *testing.T) {
	cmd := demoRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"demo", "--no-color"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Error("expected no ANSI escape codes with --no-color flag")
	}
	if !strings.Contains(output, "[BLOCKED]") {
		t.Error("expected [BLOCKED] markers in no-color output")
	}
}

func TestDemoCmd_InteractiveReadsCommandInput(t *testing.T) {
	cmd := demoRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetIn(strings.NewReader(strings.Repeat("\n", 6)))
	cmd.SetArgs([]string{"demo", "--no-color", "--interactive"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if got := strings.Count(output, "Press Enter for next scenario"); got != 6 {
		t.Errorf("expected 6 interactive prompts, got %d\n%s", got, output)
	}
	if !strings.Contains(output, "7/7 attacks blocked") {
		t.Errorf("expected completed interactive demo, got:\n%s", output)
	}
}

func TestDemoCmd_EmitsReceipts(t *testing.T) {
	cmd := demoRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"demo", "--no-color"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "demo public key:") {
		t.Errorf("expected full demo public key in output, got:\n%s", output)
	}
	if got := strings.Count(output, "signed, verified offline"); got != 7 {
		t.Errorf("expected 7 verified receipts, got %d\n%s", got, output)
	}
	if got := strings.Count(output, "Receipt:"); got != 7 {
		t.Errorf("expected 7 Receipt lines, got %d", got)
	}
}

func TestDemoCmd_ReceiptsDir(t *testing.T) {
	dir := t.TempDir()
	cmd := demoRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"demo", "--no-color", "--receipts-dir", dir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Wrote 7 signed receipts") {
		t.Errorf("expected written-count line, got:\n%s", output)
	}
	if !strings.Contains(output, "verify-receipt") || !strings.Contains(output, "--key") {
		t.Error("expected verify-receipt --key instruction")
	}

	pubData, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "signer.pub")))
	if err != nil {
		t.Fatalf("signer.pub not written: %v", err)
	}
	pubHex := strings.TrimSpace(string(pubData))

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	jsonCount := 0
	sideEffects := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		jsonCount++
		data, rErr := os.ReadFile(filepath.Clean(filepath.Join(dir, e.Name())))
		if rErr != nil {
			t.Fatal(rErr)
		}
		var r receipt.Receipt
		if uErr := json.Unmarshal(data, &r); uErr != nil {
			t.Fatalf("receipt %s: unmarshal: %v", e.Name(), uErr)
		}
		// Must verify against the pinned demo key, not just its embedded key.
		if vErr := receipt.VerifyWithKey(r, pubHex); vErr != nil {
			t.Errorf("receipt %s: verify with pinned key failed: %v", e.Name(), vErr)
		}
		ar := r.ActionRecord
		if ar.Verdict != "block" {
			t.Errorf("receipt %s: verdict = %q, want block", e.Name(), ar.Verdict)
		}
		if ar.Layer == "" {
			t.Errorf("receipt %s: missing layer evidence", e.Name())
		}
		if ar.Severity == "" {
			t.Errorf("receipt %s: missing severity evidence", e.Name())
		}
		if ar.Pattern == "" {
			t.Errorf("receipt %s: missing detection pattern", e.Name())
		}
		if len(ar.PolicyHash) != 64 {
			t.Errorf("receipt %s: policy hash length = %d, want 64", e.Name(), len(ar.PolicyHash))
		}
		sideEffects[string(ar.SideEffectClass)] = true
	}

	if jsonCount != 7 {
		t.Fatalf("expected 7 receipt files, got %d", jsonCount)
	}
	// Side-effect class must reflect the action, not be hardcoded: read-side
	// scenarios are external_read, write-side are external_write.
	if !sideEffects["external_read"] || !sideEffects["external_write"] {
		t.Errorf("expected both external_read and external_write receipts, got %v", sideEffects)
	}
}

func TestDemoCmd_ReceiptsDirIsCleaned(t *testing.T) {
	base := t.TempDir()
	rawDir := filepath.Join(base, "nested", "..", "receipts")
	cleanDir := filepath.Clean(rawDir)
	cmd := demoRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"demo", "--no-color", "--receipts-dir", rawDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(cleanDir, "signer.pub")); err != nil {
		t.Fatalf("expected signer.pub under cleaned receipts dir %q: %v", cleanDir, err)
	}
	if !strings.Contains(buf.String(), cleanDir) {
		t.Errorf("expected output to use cleaned receipts dir %q, got:\n%s", cleanDir, buf.String())
	}
}

func TestRunDemo_ReceiptsDirSetupErrors(t *testing.T) {
	t.Run("receipts dir is file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "receipts")
		if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		cmd := &cobra.Command{}
		cmd.SetOut(&strings.Builder{})

		err := runDemo(cmd, false, false, path)
		if err == nil || !strings.Contains(err.Error(), "create receipts dir") {
			t.Fatalf("runDemo error = %v, want create receipts dir error", err)
		}
	})

	t.Run("signer pub path is directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "signer.pub"), 0o750); err != nil {
			t.Fatalf("Mkdir signer.pub: %v", err)
		}
		cmd := &cobra.Command{}
		cmd.SetOut(&strings.Builder{})

		err := runDemo(cmd, false, false, dir)
		if err == nil || !strings.Contains(err.Error(), "write signer public key") {
			t.Fatalf("runDemo error = %v, want write signer public key error", err)
		}
	})
}

func TestDemoReceipts_emitErrorPaths(t *testing.T) {
	mkCmd := func() (*cobra.Command, *strings.Builder) {
		c := &cobra.Command{}
		b := &strings.Builder{}
		c.SetOut(b)
		return c, b
	}
	s := scenario{name: "x", actionType: receipt.ActionWrite, transport: "demo", target: "https://t.example", layer: "dlp", severity: config.SeverityHigh}

	t.Run("sign error on bad key", func(t *testing.T) {
		c, b := mkCmd()
		d := &demoReceipts{cmd: c, privKey: ed25519.PrivateKey([]byte("too-short")), color: false}
		if err := d.emit(s, true, []string{"pat"}); err == nil {
			t.Error("expected error from sign with bad key")
		}
		if !strings.Contains(b.String(), "receipt error") {
			t.Errorf("expected sign error line, got %q", b.String())
		}
		if d.written != 0 {
			t.Errorf("written = %d, want 0 on sign error", d.written)
		}
	})

	t.Run("missing detection pattern on blocked receipt", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		c, b := mkCmd()
		d := &demoReceipts{cmd: c, privKey: priv, pubHex: fmt.Sprintf("%x", pub), color: false}
		if err := d.emit(s, true, nil); err == nil {
			t.Error("expected error from missing detection pattern")
		}
		if !strings.Contains(b.String(), "missing detection pattern") {
			t.Errorf("expected missing-pattern error line, got %q", b.String())
		}
		if d.written != 0 {
			t.Errorf("written = %d, want 0 on missing pattern", d.written)
		}
	})

	t.Run("verify error on mismatched key", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		wrongPub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		c, b := mkCmd()
		d := &demoReceipts{cmd: c, privKey: priv, pubHex: fmt.Sprintf("%x", wrongPub), color: true}
		if err := d.emit(s, true, []string{"pat"}); err == nil {
			t.Error("expected error from mismatched verify key")
		}
		out := b.String()
		if !strings.Contains(out, "receipt verify failed") {
			t.Errorf("expected verify error line, got %q", out)
		}
		if !strings.Contains(out, ansiBoldRed+"✗"+ansiReset) {
			t.Errorf("expected color error marker, got %q", out)
		}
		if d.written != 0 {
			t.Errorf("written = %d, want 0 on verify error", d.written)
		}
	})

	t.Run("write error on bad dir", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		c, b := mkCmd()
		badDir := filepath.Join(t.TempDir(), "does", "not", "exist")
		d := &demoReceipts{cmd: c, privKey: priv, pubHex: fmt.Sprintf("%x", pub), dir: badDir, color: false}
		if err := d.emit(s, true, []string{"pat"}); err == nil {
			t.Error("expected error from write to nonexistent dir")
		}
		if !strings.Contains(b.String(), "receipt write failed") {
			t.Errorf("expected write error line, got %q", b.String())
		}
		if d.written != 0 {
			t.Errorf("written = %d, want 0 on write error", d.written)
		}
	})
}

func TestSideEffectFor(t *testing.T) {
	se, rev := sideEffectFor(receipt.ActionRead)
	if se != receipt.SideEffectExternalRead || rev != receipt.ReversibilityFull {
		t.Errorf("read mapped to %s/%s, want external_read/full", se, rev)
	}
	se, rev = sideEffectFor(receipt.ActionWrite)
	if se != receipt.SideEffectExternalWrite || rev != receipt.ReversibilityIrreversible {
		t.Errorf("write mapped to %s/%s, want external_write/irreversible", se, rev)
	}
}

func TestShortID(t *testing.T) {
	if got := shortID("abc"); got != "abc" {
		t.Errorf("shortID short = %q, want abc", got)
	}
	if got := shortID("0123456789"); got != "01234567…" {
		t.Errorf("shortID long = %q, want 01234567…", got)
	}
}
