// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_CredentialAudienceHostsRejectedFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	yaml := `version: 1
mode: balanced
dlp:
  patterns:
    - name: OpenAI API Key
      regex: '(?:^|[^A-Za-z0-9_-])sk-proj-[a-zA-Z0-9\-_]{20,}'
      severity: critical
      credential_audience_hosts:
        - api.attacker.example
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() succeeded with operator-configured credential_audience_hosts")
	}
	if !strings.Contains(err.Error(), "credential_audience_hosts") {
		t.Fatalf("strict decode error = %v, want credential_audience_hosts", err)
	}
}

func TestMarkBuiltInCredentialAudienceHosts_OnlyExactBuiltins(t *testing.T) {
	builtIn := DefaultDLPPatterns()[0]
	builtIn.CredentialAudienceHosts = nil // generated YAML cannot serialize it.

	patterns := []DLPPattern{builtIn}
	markBuiltInCredentialAudienceHosts(patterns)
	if got := patterns[0].CredentialAudienceHosts; len(got) != 1 || got[0] != "*.anthropic.com" {
		t.Fatalf("exact built-in audience hosts = %#v, want [*.anthropic.com]", got)
	}

	patterns[0].CredentialAudienceHosts = nil
	patterns[0].Regex += "(?:changed)"
	markBuiltInCredentialAudienceHosts(patterns)
	if got := patterns[0].CredentialAudienceHosts; len(got) != 0 {
		t.Fatalf("customized pattern received immutable audience hosts %#v", got)
	}
}

func TestValidate_CredentialAudienceControlsCannotWeakenBuiltins(t *testing.T) {
	const pattern = "OpenAI API Key"
	tests := []struct {
		name      string
		configure func(*Config)
		want      string
	}{
		{
			name: "pattern exemption",
			configure: func(cfg *Config) {
				for i := range cfg.DLP.Patterns {
					if cfg.DLP.Patterns[i].Name == pattern {
						cfg.DLP.Patterns[i].ExemptDomains = []string{"api.vendor.example"}
					}
				}
			},
			want: "immutable credential audience",
		},
		{
			name: "suppression",
			configure: func(cfg *Config) {
				cfg.Suppress = []SuppressEntry{{Rule: pattern, Path: "https://api.vendor.example/*"}}
			},
			want: "immutable credential audience",
		},
		{
			name: "disable body scanning",
			configure: func(cfg *Config) {
				cfg.RequestBodyScanning.DisablePatterns = []string{pattern}
			},
			want: "immutable credential audience",
		},
		{
			name: "warn body scanning",
			configure: func(cfg *Config) {
				cfg.RequestBodyScanning.PatternActions = map[string]string{pattern: ActionWarn}
			},
			want: "immutable credential audience",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.configure(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.want)
			}
		})
	}
}
