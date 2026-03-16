// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDiagnoseDefault(t *testing.T) {
	var buf bytes.Buffer
	cmd := diagnoseCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--no-color"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("diagnose failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "PASS") {
		t.Error("expected PASS in output")
	}
	if strings.Contains(out, "FAIL") {
		t.Errorf("unexpected FAIL in output: %s", out)
	}
	// fetch_hint should be skipped by default (explain_blocks not set).
	if !strings.Contains(out, "SKIP") {
		t.Error("expected SKIP for fetch_hint check")
	}
}

func TestDiagnoseJSON(t *testing.T) {
	var buf bytes.Buffer
	cmd := diagnoseCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("diagnose --json failed: %v", err)
	}
	var report diagnoseReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, buf.String())
	}
	if report.Total != 7 {
		t.Errorf("expected 7 checks, got %d", report.Total)
	}
	if report.Failed != 0 {
		t.Errorf("expected 0 failures, got %d", report.Failed)
	}
	// fetch_hint skipped (no explain_blocks) + rules skipped (no bundles).
	if report.Skipped != 2 {
		t.Errorf("expected 2 skips (fetch_hint + rules), got %d", report.Skipped)
	}
	// Verify check names.
	names := make(map[string]bool)
	for _, c := range report.Checks {
		names[c.Name] = true
	}
	for _, expected := range []string{"health", "fetch_allowed", "fetch_blocked", "fetch_hint", "forward_allowed", "forward_blocked", "rules"} {
		if !names[expected] {
			t.Errorf("missing check %q in report", expected)
		}
	}
}

func TestDiagnoseConfigError(t *testing.T) {
	var buf bytes.Buffer
	cmd := diagnoseCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "nonexistent.yaml")})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
	if ExitCodeOf(err) != 2 {
		t.Errorf("expected exit code 2, got %d", ExitCodeOf(err))
	}
}

func TestDiagnoseHintSkipMessage(t *testing.T) {
	var buf bytes.Buffer
	cmd := diagnoseCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("diagnose failed: %v", err)
	}
	var report diagnoseReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, c := range report.Checks {
		if c.Name == "fetch_hint" {
			if c.Status != "skip" {
				t.Errorf("expected fetch_hint to be skip, got %s", c.Status)
			}
			if !strings.Contains(c.Detail, "explain_blocks") {
				t.Errorf("skip detail should mention explain_blocks, got: %s", c.Detail)
			}
			return
		}
	}
	t.Error("fetch_hint check not found in report")
}

func TestDiagnoseHintEnabled(t *testing.T) {
	// Write temp config with explain_blocks enabled.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("explain_blocks: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := diagnoseCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--json", "--config", cfgPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("diagnose with explain_blocks=true failed: %v", err)
	}

	var report diagnoseReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	for _, c := range report.Checks {
		if c.Name == "fetch_hint" {
			if c.Status != "pass" {
				t.Errorf("expected fetch_hint to pass with explain_blocks=true, got %s: %s", c.Status, c.Detail)
			}
			if !strings.Contains(c.Detail, "hint=") {
				t.Errorf("expected hint detail, got: %s", c.Detail)
			}
			return
		}
	}
	t.Error("fetch_hint check not found in report")
}

func TestCheckRules_EmptyDir(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Rules.RulesDir = t.TempDir()

	result := checkRules("", "", cfg)
	if result.Status != statusSkip {
		t.Errorf("expected skip, got %s", result.Status)
	}
	if !strings.Contains(result.Detail, "no bundles installed") {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckRules_ValidBundle(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	cfg := &config.Config{}
	cfg.Rules.RulesDir = rulesDir

	result := checkRules("", "", cfg)
	if result.Status != statusPass {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
	if !strings.Contains(result.Detail, "test-bundle") {
		t.Errorf("expected bundle name in detail, got: %s", result.Detail)
	}
	if !strings.Contains(result.Detail, "1 rules") {
		t.Errorf("expected rule count in detail, got: %s", result.Detail)
	}
	if !strings.Contains(result.Detail, "[unsigned]") {
		t.Errorf("expected [unsigned] marker in detail, got: %s", result.Detail)
	}
}

func TestCheckRules_TamperedBundle(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	setupUnsignedBundle(t, rulesDir, testBundleName, []byte(validBundleYAML))

	// Tamper: overwrite bundle.yaml with different content (hash mismatch).
	bundlePath := filepath.Join(rulesDir, testBundleName, "bundle.yaml")
	if err := os.WriteFile(bundlePath, []byte("tampered content"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Rules.RulesDir = rulesDir

	result := checkRules("", "", cfg)
	if result.Status != statusFail {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
	if !strings.Contains(result.Detail, "FAILED") {
		t.Errorf("expected FAILED in detail, got: %s", result.Detail)
	}
}
