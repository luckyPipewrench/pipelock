// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pattern that reuses a core floor name cannot carry exempt_domains: the
// scanner never honors it for that class, so accepting it would ship a knob
// that reads as an allowance and does nothing.
func TestValidate_DLPExemptDomainsRejectedOnCorePatternName(t *testing.T) {
	for _, name := range []string{"AWS Access ID", "aws access id", "GCP Service Account Key"} {
		cfg := Defaults()
		cfg.DLP.Patterns = []DLPPattern{
			{Name: name, Regex: `AKIA[0-9A-Z]{16}`, Severity: SeverityCritical, ExemptDomains: []string{"api.vendor.example"}},
		}
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("%q: expected core pattern with exempt_domains to be rejected", name)
		}
		if !strings.Contains(err.Error(), "core safety-floor pattern") {
			t.Fatalf("%q: error must name the core floor, got %v", name, err)
		}
	}
}

func TestValidate_DLPExemptDomainsAcceptedOnCustomPatternName(t *testing.T) {
	cfg := Defaults()
	cfg.DLP.Patterns = []DLPPattern{
		{Name: "Vendor Token", Regex: `vt-[a-z0-9]{32}`, Severity: SeverityCritical, ExemptDomains: []string{"api.vendor.example"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("custom pattern exemption must stay valid: %v", err)
	}
}

func TestValidate_DLPDefaultCorePatternsCarryNoExemptions(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	for _, p := range cfg.DLP.Patterns {
		if IsCoreDLPPatternName(p.Name) && len(p.ExemptDomains) > 0 {
			t.Fatalf("shipped core pattern %q carries exempt_domains", p.Name)
		}
	}
}

// First load and hot reload go through the same validator, so a reload that
// introduces the exemption on a core name fails the same way a fresh start does.
func TestReload_DLPExemptDomainsOnCorePatternNameRejected(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	clean := `
version: 1
dlp:
  patterns:
    - name: Vendor Token
      regex: 'vt-[a-z0-9]{32}'
      severity: critical
      exempt_domains:
        - api.vendor.example
`
	tainted := `
version: 1
dlp:
  patterns:
    - name: AWS Access ID
      regex: 'AKIA[0-9A-Z]{16}'
      severity: critical
      exempt_domains:
        - api.vendor.example
`
	if err := os.WriteFile(cfgPath, []byte(clean), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath); err != nil {
		t.Fatalf("first load must accept a custom exemption: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(tainted), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("reload into a core-name exemption must be rejected")
	}
}
