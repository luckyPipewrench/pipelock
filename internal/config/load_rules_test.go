// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadForRules_SkipsRuntimeOnlyFiles(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	cfgYAML := `version: 1
mode: balanced
license_file: missing-license.token
dlp:
  secrets_file: /root/not-readable/pipelock-secrets.env
tls_interception:
  enabled: true
  ca_cert: /root/not-readable/ca.pem
  ca_key: /root/not-readable/ca-key.pem
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadForRules(cfgPath)
	if err != nil {
		t.Fatalf("LoadForRules should skip runtime-only files: %v", err)
	}
	if cfg.LicenseFile != "" || cfg.LicenseKey != "" {
		t.Fatalf("LoadForRules should scrub license fields, got license_file=%q license_key=%q", cfg.LicenseFile, cfg.LicenseKey)
	}
}

func TestLoadForRules_ValidatesRulesFacingConfig(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "rules",
			yaml: `version: 1
mode: balanced
rules:
  min_confidence: impossible
`,
			wantErr: "min_confidence",
		},
		{
			name: "dlp",
			yaml: `version: 1
mode: balanced
dlp:
  patterns:
    - name: bad
      regex: "["
`,
			wantErr: "DLP pattern",
		},
		{
			name: "response scanning",
			yaml: `version: 1
mode: balanced
response_scanning:
  exempt_domains:
    - "*.com"
`,
			wantErr: "wildcard must target a concrete domain",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := LoadForRules(cfgPath)
			if err == nil {
				t.Fatal("expected invalid rules-facing config to fail")
			}
			if !strings.Contains(err.Error(), "invalid rules config") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected %q validation error, got %v", tc.wantErr, err)
			}
		})
	}
}
