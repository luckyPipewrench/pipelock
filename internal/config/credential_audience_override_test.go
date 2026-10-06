// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

const azureSASRegexYAML = `\bsig=(?:[A-Za-z0-9%]{43,}%3d\b|[A-Za-z0-9+/]{43}=)`

func azureSASOverrideYAML(extra string) string {
	return fmt.Sprintf(`version: 1
mode: balanced
dlp:
  patterns:
    - name: Azure SAS Token
      regex: '%s'
      severity: high
%s`, azureSASRegexYAML, extra)
}

func loadedPattern(t *testing.T, cfg *Config, name string) DLPPattern {
	t.Helper()
	var found []DLPPattern
	for _, p := range cfg.DLP.Patterns {
		if p.Name == name {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		t.Fatalf("pattern %q appears %d times after merge, want 1", name, len(found))
	}
	return found[0]
}

func warningsFor(t *testing.T, cfg *Config) []Warning {
	t.Helper()
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	return warnings
}

// hasFieldWarning reports whether a warning on a dlp.patterns[N] field ending
// in suffix carries every part. The operator's pattern sits after the shipped
// ones, so the index is not fixed.
func hasFieldWarning(warnings []Warning, suffix string, parts ...string) bool {
	for _, w := range warnings {
		if !strings.HasPrefix(w.Field, "dlp.patterns[") || !strings.HasSuffix(w.Field, suffix) {
			continue
		}
		ok := true
		for _, part := range parts {
			ok = ok && strings.Contains(w.Message, part)
		}
		if ok {
			return true
		}
	}
	return false
}

// A same-name pattern that changes only exempt_domains keeps the built-in's
// compiled audience and carrier. Losing it silently blocked every GitHub
// release download for a config that added one unrelated exemption.
func TestLoad_SameNamePatternWithOnlyExemptionKeepsAudience(t *testing.T) {
	cfg, err := LoadBytes([]byte(azureSASOverrideYAML("      exempt_domains:\n        - \"*.oaiusercontent.com\"\n")))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	p := loadedPattern(t, cfg, "Azure SAS Token")
	if len(p.CredentialAudienceHosts) == 0 || p.CredentialAudienceCarrierMask&CredentialAudienceCarrierReleaseGrantSAS == 0 {
		t.Fatalf("exempt-only override lost its audience: hosts=%v mask=%d", p.CredentialAudienceHosts, p.CredentialAudienceCarrierMask)
	}
	warnings := warningsFor(t, cfg)
	if !hasFieldWarning(warnings, ".exempt_domains", "oaiusercontent.com", "outside the compiled credential audience") {
		t.Fatalf("no warning names the widening exemption: %+v", warnings)
	}
	for _, w := range warnings {
		if strings.Contains(w.Message, "no longer applies") {
			t.Fatalf("audience was kept but a warning says it was dropped: %+v", w)
		}
	}
}

// An entry the audience already covers is ignored and says so; one outside it
// is honored and says so. Both are reported when a list mixes them.
func TestLoad_ExemptionInsideAndOutsideAudienceWarnSeparately(t *testing.T) {
	cfg, err := LoadBytes([]byte(azureSASOverrideYAML("      exempt_domains:\n        - release-assets.githubusercontent.com\n        - download.vendor.example\n")))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	warnings := warningsFor(t, cfg)
	if !hasFieldWarning(warnings, ".exempt_domains", "release-assets.githubusercontent.com", "redundant subset") {
		t.Fatalf("no redundant-entry warning: %+v", warnings)
	}
	if !hasFieldWarning(warnings, ".exempt_domains", "download.vendor.example", "outside the compiled credential audience") {
		t.Fatalf("no widening warning: %+v", warnings)
	}
}

// A same-name pattern that changes what the pattern matches replaces the
// built-in, drops its audience and now says so, naming the field that did it.
func TestLoad_SameNamePatternChangingIdentityWarnsAudienceDropped(t *testing.T) {
	for _, tc := range []struct {
		name  string
		yaml  string
		field string
	}{
		{"regex", strings.Replace(azureSASOverrideYAML(""), azureSASRegexYAML, azureSASRegexYAML+`|\bsv=zz\b`, 1), "regex"},
		{"severity", strings.Replace(azureSASOverrideYAML(""), "severity: high", "severity: medium", 1), "severity"},
		{"action", azureSASOverrideYAML("      action: warn\n"), "action"},
		{"validator", azureSASOverrideYAML("      validator: luhn\n"), "validator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("LoadBytes: %v", err)
			}
			p := loadedPattern(t, cfg, "Azure SAS Token")
			if len(p.CredentialAudienceHosts) != 0 || p.CredentialAudienceCarrierMask != 0 {
				t.Fatalf("customized pattern kept the compiled audience: %#v", p)
			}
			warnings := warningsFor(t, cfg)
			if !hasFieldWarning(warnings, "]", "replaces the built-in", tc.field, "release-assets.githubusercontent.com") {
				t.Fatalf("dropped audience produced no warning naming %q and the hosts: %+v", tc.field, warnings)
			}
		})
	}
}

// Controls: the unmodified override is the built-in, and a pattern under a
// different name is a separate pattern. Neither loses anything, so neither warns.
func TestLoad_SameNamePatternControlsStaySilent(t *testing.T) {
	exact, err := LoadBytes([]byte(azureSASOverrideYAML("")))
	if err != nil {
		t.Fatalf("LoadBytes exact: %v", err)
	}
	if p := loadedPattern(t, exact, "Azure SAS Token"); len(p.CredentialAudienceHosts) == 0 {
		t.Fatalf("an exact copy of the built-in lost its audience: %#v", p)
	}
	for _, w := range warningsFor(t, exact) {
		if strings.HasPrefix(w.Field, "dlp.patterns[") {
			t.Fatalf("exact copy of the built-in warned: %+v", w)
		}
	}

	renamed, err := LoadBytes([]byte(strings.Replace(azureSASOverrideYAML(""), "name: Azure SAS Token", "name: azure sas token (corp)", 1)))
	if err != nil {
		t.Fatalf("LoadBytes renamed: %v", err)
	}
	if p := loadedPattern(t, renamed, "Azure SAS Token"); len(p.CredentialAudienceHosts) == 0 {
		t.Fatalf("a differently named pattern cost the built-in its audience: %#v", p)
	}
	for _, w := range warningsFor(t, renamed) {
		if strings.HasPrefix(w.Field, "dlp.patterns[") {
			t.Fatalf("differently named pattern warned: %+v", w)
		}
	}
}

// The immutable core floor still refuses an exemption: a core name with
// exempt_domains is rejected at load, whatever the audience rules do.
func TestLoad_CoreNamedPatternStillRefusesExemption(t *testing.T) {
	yaml := `version: 1
mode: balanced
dlp:
  patterns:
    - name: AWS Access ID
      regex: '(AKIA|ASIA)[A-Z0-9]{16}'
      severity: critical
      exempt_domains:
        - download.vendor.example
`
	if _, err := LoadBytes([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "core safety-floor") {
		t.Fatalf("LoadBytes error = %v, want the core safety-floor refusal", err)
	}
}

func TestAudienceDroppedWarningDoesNotOverridePolicy(t *testing.T) {
	for _, extra := range []string{
		"      action: warn\n",
		"      exempt_domains:\n        - downloads.vendor.example\n",
	} {
		t.Run(extra, func(t *testing.T) {
			yaml := strings.Replace(azureSASOverrideYAML(extra), "severity: high", "severity: medium", 1)
			cfg, err := LoadBytes([]byte(yaml))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, w := range warningsFor(t, cfg) {
				if strings.Contains(w.Message, "no longer applies") {
					found = true
					if strings.Contains(w.Message, "every match blocks") {
						t.Fatalf("warning contradicts configured policy: %s", w.Message)
					}
				}
			}
			if !found {
				t.Fatal("missing dropped-audience warning")
			}
		})
	}
}

func TestShippedPresetsHaveNoAudienceOverrideWarnings(t *testing.T) {
	paths, err := filepath.Glob("../../configs/*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("preset inventory: %v %v", paths, err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cfg, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range warningsFor(t, cfg) {
				if strings.HasPrefix(w.Field, "dlp.patterns[") && strings.Contains(w.Message, "compiled credential audience") {
					t.Fatalf("shipped preset acquired audience warning: %+v", w)
				}
			}
		})
	}
}

func TestHostilePresetCustomizationStillWarns(t *testing.T) {
	patterns, err := PresetDLPPatterns(DLPPresetProfileHostile)
	if err != nil {
		t.Fatal(err)
	}
	for i := range patterns {
		if patterns[i].Name == "Google API Key" {
			patterns[i].Regex += "|custom-value"
		}
	}
	RestoreBuiltInCredentialAudienceHosts(patterns)
	cfg := Defaults()
	cfg.DLP.Patterns = patterns
	if p := loadedPattern(t, cfg, "Google API Key"); len(p.CredentialAudienceHosts) != 0 || p.Severity != SeverityCritical {
		t.Fatalf("customized hostile pattern state: %+v", p)
	}
	if !hasFieldWarning(warningsFor(t, cfg), "]", "Google API Key", "regex", "no longer applies") {
		t.Fatal("customized preset suppressed dropped-audience warning")
	}
}
