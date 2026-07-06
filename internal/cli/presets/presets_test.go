// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package presets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/configs"
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
			if got, want := cfg.Mode, expectedMode(name); got != want {
				t.Fatalf("mode = %q, want %q", got, want)
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
			if got, want := cfg.Mode, expectedMode(name); got != want {
				t.Fatalf("mode = %q, want %q", got, want)
			}
		})
	}
}

func TestListDescribesEveryPreset(t *testing.T) {
	t.Parallel()

	infos := List()
	if len(infos) != len(All) {
		t.Fatalf("List returned %d presets, want %d", len(infos), len(All))
	}
	for i, info := range infos {
		if info.Name != All[i] {
			t.Errorf("preset[%d] name = %q, want %q", i, info.Name, All[i])
		}
		if info.Mode == "" {
			t.Errorf("%s mode is empty", info.Name)
		}
		if info.DefaultAction == "" {
			t.Errorf("%s default action is empty", info.Name)
		}
		if !strings.Contains(info.Reachability, "allowlist") && !strings.Contains(info.Reachability, "blocklist") {
			t.Errorf("%s reachability = %q, want allowlist/blocklist posture", info.Name, info.Reachability)
		}
	}
}

func TestPrintListIncludesEveryPreset(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := PrintList(&buf); err != nil {
		t.Fatalf("PrintList: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"NAME", "MODE", "DEFAULT ACTION", "REACHABILITY"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing header %q:\n%s", want, out)
		}
	}
	for _, name := range All {
		if !strings.Contains(out, name) {
			t.Fatalf("output missing preset %q:\n%s", name, out)
		}
	}
}

func TestCmdListsEveryPreset(t *testing.T) {
	t.Parallel()

	cmd := Cmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, name := range All {
		if !strings.Contains(buf.String(), name) {
			t.Fatalf("output missing preset %q:\n%s", name, buf.String())
		}
	}
}

func TestFilePresetYAMLMatchesEmbeddedBytes(t *testing.T) {
	t.Parallel()

	for _, name := range []string{PresetClaudeCode, PresetCursor, PresetGenericAgent, PresetHostileModel} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := YAML(name)
			if err != nil {
				t.Fatalf("YAML(%q): %v", name, err)
			}
			want, ok := configs.Preset(name)
			if !ok {
				t.Fatalf("configs.Preset(%q) not found", name)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("YAML(%q) changed embedded bytes", name)
			}
		})
	}
}

func TestUnknownPresetErrorListsAllValidNames(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", " ", "nonexistent", "Balanced", "CLAUDE-CODE"} {
		t.Run(bad, func(t *testing.T) {
			t.Parallel()

			_, err := YAML(bad)
			if err == nil {
				t.Fatal("expected error")
			}
			if _, err := Config(bad); err == nil {
				t.Fatal("expected Config error")
			}
			msg := err.Error()
			for _, name := range All {
				if !strings.Contains(msg, name) {
					t.Errorf("error %q does not list %q", msg, name)
				}
			}
		})
	}
}

func TestFilePresetRejectsUnembeddedName(t *testing.T) {
	t.Parallel()

	if _, _, err := filePreset("missing"); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidatedConfigRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	if _, err := validatedConfig("bad", &config.Config{Mode: "bad"}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestParseConfigRejectsInvalidPresetYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte("")},
		{name: "document marker only", data: []byte("---\n")},
		{name: "null", data: []byte("null\n")},
		{name: "sequence", data: []byte("- mode: balanced\n")},
		{name: "multiple documents", data: []byte("mode: balanced\n---\nmode: audit\n")},
		{name: "decode error", data: []byte("mode: [\n")},
		{name: "invalid mode", data: []byte("mode: permissive\n")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseConfig(tt.data); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func expectedMode(name string) string {
	switch name {
	case config.ModeStrict, PresetHostileModel:
		return config.ModeStrict
	case config.ModeBalanced, PresetClaudeCode, PresetCursor, PresetGenericAgent:
		return config.ModeBalanced
	case config.ModeAudit:
		return config.ModeAudit
	default:
		panic("unexpected preset " + name)
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
