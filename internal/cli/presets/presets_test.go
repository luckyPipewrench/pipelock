// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestYAMLProducesLoadableConfigForEveryPreset(t *testing.T) {
	t.Parallel()

	for _, name := range All {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := YAML(name)
			if err != nil {
				t.Fatalf("YAML(%q): %v", name, err)
			}

			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatalf("writing config: %v", err)
			}

			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load(%q): %v", name, err)
			}
			switch cfg.Mode {
			case config.ModeStrict, config.ModeBalanced, config.ModeAudit:
			default:
				t.Fatalf("mode = %q, want sane preset mode", cfg.Mode)
			}
		})
	}
}

func TestConfigAcceptsEveryPreset(t *testing.T) {
	t.Parallel()

	for _, name := range All {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Config(name)
			if err != nil {
				t.Fatalf("Config(%q): %v", name, err)
			}
			if cfg.Mode == "" {
				t.Fatal("expected mode to be set")
			}
		})
	}
}

func TestUnknownPresetErrorListsAllValidNames(t *testing.T) {
	t.Parallel()

	_, err := YAML("nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, name := range All {
		if !strings.Contains(msg, name) {
			t.Errorf("error %q does not list %q", msg, name)
		}
	}
}

func TestProgrammaticPresetValues(t *testing.T) {
	t.Parallel()

	strict, err := Config(config.ModeStrict)
	if err != nil {
		t.Fatalf("strict Config: %v", err)
	}
	if strict.Mode != config.ModeStrict {
		t.Errorf("strict mode = %q, want %q", strict.Mode, config.ModeStrict)
	}
	if strict.FetchProxy.Monitoring.SubdomainEntropyThreshold != 3.5 {
		t.Errorf("strict SubdomainEntropyThreshold = %v, want 3.5", strict.FetchProxy.Monitoring.SubdomainEntropyThreshold)
	}

	audit, err := Config(config.ModeAudit)
	if err != nil {
		t.Fatalf("audit Config: %v", err)
	}
	if audit.Mode != config.ModeAudit {
		t.Errorf("audit mode = %q, want %q", audit.Mode, config.ModeAudit)
	}
	if audit.Enforce == nil || *audit.Enforce {
		t.Error("audit preset should have enforce=false")
	}
	if !audit.Logging.IncludeAllowed {
		t.Error("audit preset should log allowed requests")
	}
}
