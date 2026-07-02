// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli/presets"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestStrictPreset(t *testing.T) {
	cfg, err := presets.Config(config.ModeStrict)
	if err != nil {
		t.Fatalf("Config(strict): %v", err)
	}
	if cfg.Mode != config.ModeStrict {
		t.Errorf("mode = %q, want strict", cfg.Mode)
	}
	if cfg.FetchProxy.Monitoring.EntropyThreshold == 0 {
		t.Error("expected non-zero entropy threshold in strict preset")
	}
	if cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold != 3.5 {
		t.Errorf("SubdomainEntropyThreshold = %v, want 3.5", cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold)
	}
}

func TestAuditPreset(t *testing.T) {
	cfg, err := presets.Config(config.ModeAudit)
	if err != nil {
		t.Fatalf("Config(audit): %v", err)
	}
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

func TestCmd_AllPresetsProduceLoadableConfig(t *testing.T) {
	for _, name := range presets.All {
		t.Run(name, func(t *testing.T) {
			cmd := Cmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetArgs([]string{"config", "--preset", name})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute: %v", err)
			}

			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
				t.Fatalf("writing generated config: %v", err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load generated %s config: %v", name, err)
			}
			switch cfg.Mode {
			case config.ModeStrict, config.ModeBalanced, config.ModeAudit:
			default:
				t.Fatalf("mode = %q, want valid mode", cfg.Mode)
			}
		})
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
	for _, name := range presets.All {
		if !bytes.Contains([]byte(err.Error()), []byte(name)) {
			t.Errorf("error %q does not list %q", err, name)
		}
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
