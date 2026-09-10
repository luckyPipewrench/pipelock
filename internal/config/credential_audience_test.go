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

// The suppress-path subset check decides whether an operator's suppression is
// contained by the compiled audience, which is what separates a redundant entry
// (warned and ignored) from a real widening (warned and honored). Both the
// legacy host-glob form and the URL form must be recognized, and anything that
// cannot prove its host scope must be treated as NOT a subset, which is the
// fail-closed direction for this check.
func TestCredentialAudienceSuppressPathSubset_Direction(t *testing.T) {
	audience := []string{"*.anthropic.com"}
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"url inside the audience", "https://api.anthropic.com/v1/messages", true},
		{"url on a subdomain of the audience", "https://eu.api.anthropic.com/v1", true},
		{"url outside the audience", "https://relay.internal.example/v1", false},
		// The legacy host glob is star-delimited on BOTH ends; a leading-star
		// form alone is not recognized as a host scope and therefore is not a
		// subset, which is the fail-closed direction.
		{"host glob inside the audience", "*.anthropic.com*", true},
		{"host glob outside the audience", "*.attacker.example*", false},
		{"leading star alone proves no host scope", "*.anthropic.com", false},
		{"lookalike suffix is not contained", "https://notanthropic.com/v1", false},
		{"embedded credentials are refused", "https://user:pw@api.anthropic.com/v1", false},
		{"bare path proves no host scope", "config/initializers/*.rb", false},
		{"non-http scheme proves no host scope", "ftp://api.anthropic.com/v1", false},
		{"empty is not a subset", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := credentialAudienceSuppressPathSubset(tt.path, audience); got != tt.want {
				t.Fatalf("credentialAudienceSuppressPathSubset(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// A wildcard audience contains its own apex and dot-bounded subdomains, and
// nothing else. A suffix lookalike must not be treated as contained.
func TestCredentialAudienceDomainContains_Direction(t *testing.T) {
	tests := []struct {
		allowed, candidate string
		want               bool
	}{
		{"*.anthropic.com", "*.anthropic.com", true},
		{"*.anthropic.com", "*.eu.anthropic.com", true},
		{"*.anthropic.com", "api.anthropic.com", true},
		{"*.anthropic.com", "*.notanthropic.com", false},
		{"*.anthropic.com", "anthropic.com.attacker.example", false},
		{"api.anthropic.com", "api.anthropic.com", true},
		{"api.anthropic.com", "other.anthropic.com", false},
	}
	for _, tt := range tests {
		if got := credentialAudienceDomainContains(tt.allowed, tt.candidate); got != tt.want {
			t.Fatalf("credentialAudienceDomainContains(%q, %q) = %v, want %v",
				tt.allowed, tt.candidate, got, tt.want)
		}
	}
}

// A legacy exempt_domains entry on an audience-bearing pattern is tolerated only
// when it is contained by the compiled audience, and an entry that cannot be
// validated as a domain must not be treated as contained. That is the
// fail-closed direction: an unparseable value must never widen an audience.
func TestCredentialAudienceExemptDomainsSubset_Direction(t *testing.T) {
	audience := []string{"*.anthropic.com"}
	tests := []struct {
		name    string
		domains []string
		want    bool
	}{
		{"no entries is vacuously contained", nil, true},
		{"exact apex is contained", []string{"anthropic.com"}, true},
		{"subdomain is contained", []string{"api.anthropic.com"}, true},
		{"unrelated host is not contained", []string{"relay.internal.example"}, false},
		{"lookalike suffix is not contained", []string{"notanthropic.com"}, false},
		{"one contained and one not is not contained", []string{"api.anthropic.com", "evil.example"}, false},
		{"an invalid domain is refused rather than assumed", []string{"http://api.anthropic.com/x"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := credentialAudienceExemptDomainsSubset(tt.domains, audience); got != tt.want {
				t.Fatalf("credentialAudienceExemptDomainsSubset(%v) = %v, want %v", tt.domains, got, tt.want)
			}
		})
	}
}
