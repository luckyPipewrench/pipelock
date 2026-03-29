// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestStrictPreset(t *testing.T) {
	cfg := strictPreset()
	if cfg.Mode != config.ModeStrict {
		t.Errorf("mode = %q, want strict", cfg.Mode)
	}
	if cfg.FetchProxy.Monitoring.EntropyThreshold == 0 {
		t.Error("expected non-zero entropy threshold in strict preset")
	}
}

func TestAuditPreset(t *testing.T) {
	cfg := auditPreset()
	if cfg.Mode != config.ModeAudit {
		t.Errorf("mode = %q, want audit", cfg.Mode)
	}
	if cfg.Enforce == nil || *cfg.Enforce {
		t.Error("audit preset should have enforce=false")
	}
	if !cfg.Logging.IncludeAllowed {
		t.Error("audit preset should log allowed requests")
	}
}

func TestCmd_StrictPreset(t *testing.T) {
	cmd := Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"config", "--preset", "strict"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected YAML output")
	}
}

func TestCmd_AuditPreset(t *testing.T) {
	cmd := Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"config", "--preset", "audit"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected YAML output")
	}
}

func TestCmd_InvalidPreset(t *testing.T) {
	cmd := Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"config", "--preset", "nonexistent"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid preset")
	}
}

func TestCmd_OutputToFile(t *testing.T) {
	dir := t.TempDir()
	cmd := Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"config", "--preset", "balanced", "--output", dir + "/test.yaml"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	outPath := filepath.Join(dir, "test.yaml")
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("output file not created: %v", err)
	}
}
