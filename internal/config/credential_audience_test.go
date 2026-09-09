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

func TestLoad_CredentialAudienceLegacySubsetControlsWarn(t *testing.T) {
	const legacy = `version: 1
mode: balanced
dlp:
  patterns:
    - name: OpenAI API Key
      regex: '(?:^|[^A-Za-z0-9_-])sk-proj-[a-zA-Z0-9\-_]{20,}'
      severity: critical
      exempt_domains:
        - '*.openai.com'
suppress:
  - rule: OpenAI API Key
    path: '*.openai.com*'
    reason: provider-bound credential
`
	cfg, err := LoadBytes([]byte(legacy))
	if err != nil {
		t.Fatalf("LoadBytes legacy preset stanza: %v", err)
	}
	foundAudience := false
	for _, pattern := range cfg.DLP.Patterns {
		if pattern.Name == "OpenAI API Key" && len(pattern.CredentialAudienceHosts) == 1 && pattern.CredentialAudienceHosts[0] == "*.openai.com" {
			foundAudience = true
			break
		}
		if pattern.Name == "OpenAI API Key" {
			t.Fatalf("legacy OpenAI pattern lost compiled audience: %#v", pattern.CredentialAudienceHosts)
		}
	}
	if !foundAudience {
		t.Fatal("legacy OpenAI pattern missing compiled audience")
	}
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings legacy preset stanza: %v", err)
	}
	var patternWarning, suppressWarning bool
	for _, warning := range warnings {
		switch {
		case strings.HasPrefix(warning.Field, "dlp.patterns[") && strings.HasSuffix(warning.Field, ".exempt_domains"):
			patternWarning = strings.Contains(warning.Message, warning.Field)
		case warning.Field == "suppress[0].path":
			suppressWarning = strings.Contains(warning.Message, warning.Field)
		}
	}
	if !patternWarning || !suppressWarning {
		t.Fatalf("legacy config warnings missing or did not name their fields: %#v", warnings)
	}
}

func TestValidate_CredentialAudienceWideningControlsAreActionable(t *testing.T) {
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
						cfg.DLP.Patterns[i].ExemptDomains = []string{"api.attacker.example"}
					}
				}
			},
			want: "delete dlp.patterns",
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

func TestValidate_CredentialAudienceProperSubsetControlsWarn(t *testing.T) {
	const pattern = "OpenAI API Key"
	cfg := Defaults()
	for i := range cfg.DLP.Patterns {
		if cfg.DLP.Patterns[i].Name == pattern {
			cfg.DLP.Patterns[i].ExemptDomains = []string{"api.openai.com"}
			break
		}
	}
	cfg.Suppress = []SuppressEntry{{Rule: pattern, Path: "https://api.openai.com/*"}}

	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings proper audience subset: %v", err)
	}
	var patternWarning, suppressWarning bool
	for _, warning := range warnings {
		switch {
		case strings.HasPrefix(warning.Field, "dlp.patterns[") && strings.HasSuffix(warning.Field, ".exempt_domains"):
			patternWarning = strings.Contains(warning.Message, warning.Field)
		case warning.Field == "suppress[0].path":
			suppressWarning = strings.Contains(warning.Message, warning.Field)
		}
	}
	if !patternWarning || !suppressWarning {
		t.Fatalf("proper-subset warnings missing or did not name their fields: %#v", warnings)
	}
}

// The three controls below WIDEN a compiled credential audience: they let a
// provider credential leave for a destination the vendor does not own. That is
// a decision an operator is entitled to make, most often for an internal relay,
// so each one warns and the config still loads.
//
// This is deliberately a permissive failure direction, chosen over the
// alternative it replaced. Rejecting these stopped a previously valid config
// from loading on upgrade, which takes the whole proxy down on a product every
// request depends on, and told the operator to delete a control they may
// genuinely need. An over-strict guard that gets routed around by disabling
// something broader is the outcome this avoids. The immutable CORE DLP floor is
// unaffected and still rejects all three; see the sibling test above.
func TestValidate_CredentialAudienceWideningWarnsAndLoads(t *testing.T) {
	const pattern = "Anthropic API Key"
	tests := []struct {
		name      string
		configure func(*Config)
		wantField string
	}{
		{
			name: "suppression",
			configure: func(cfg *Config) {
				cfg.Suppress = []SuppressEntry{{Rule: pattern, Path: "https://relay.internal.example/*"}}
			},
			wantField: "suppress[0]",
		},
		{
			name: "disable body scanning",
			configure: func(cfg *Config) {
				cfg.RequestBodyScanning.DisablePatterns = []string{pattern}
			},
			wantField: "request_body_scanning.disable_patterns[0]",
		},
		{
			name: "warn body scanning",
			configure: func(cfg *Config) {
				cfg.RequestBodyScanning.PatternActions = map[string]string{pattern: ActionWarn}
			},
			wantField: "request_body_scanning.pattern_actions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.configure(cfg)
			warnings, err := cfg.ValidateWithWarnings()
			if err != nil {
				t.Fatalf("config must still load: %v", err)
			}
			var found bool
			for _, w := range warnings {
				if strings.Contains(w.Field, tt.wantField) {
					found = true
				}
			}
			if !found {
				t.Fatalf("widening the audience produced no warning naming %q: %+v", tt.wantField, warnings)
			}
		})
	}
}
