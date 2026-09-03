// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/rules"
)

const unverifiableBundleNote = "rule bundle warning: bundle \"warn-bundle\" loaded although min_pipelock"

// installUnversionedWarningBundle writes an unsigned bundle that declares a
// min_pipelock into a fresh rules directory. A test binary carries no release
// stamp, so merging the bundle yields the unprovable-version warning that the
// explain reports must carry as a note.
func installUnversionedWarningBundle(t *testing.T) string {
	t.Helper()
	bundleYAML := []byte(`format_version: 1
name: warn-bundle
version: "2026.03.1"
author: Test Author
description: A bundle that declares a minimum version
min_pipelock: "0.1.0"
license: Apache-2.0
rules:
  - id: warn-rule-one
    type: dlp
    status: stable
    name: Warn Rule
    description: Detects test patterns
    severity: high
    confidence: high
    pattern:
      regex: "warn-secret-[a-z]+"
`)
	rulesDir := t.TempDir()
	bundleDir := filepath.Join(rulesDir, "warn-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "bundle.yaml"), bundleYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bundleYAML)
	lf := &rules.LockFile{
		InstalledVersion: "2026.03.1",
		InstalledAt:      "2026-03-15T10:00:00Z",
		Source:           "local:/tmp/warn-rules",
		LastCheck:        "2026-03-15T10:00:00Z",
		BundleSHA256:     hex.EncodeToString(sum[:]),
		Unsigned:         true,
	}
	if err := rules.WriteLockFile(filepath.Join(bundleDir, "bundle.lock"), lf); err != nil {
		t.Fatal(err)
	}
	return rulesDir
}

func hasNote(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

func TestExplainCmd_URLReportCarriesUnverifiableBundleWarning(t *testing.T) {
	rulesDir := installUnversionedWarningBundle(t)
	cfgPath := writeConfig(t, fmt.Sprintf("mode: audit\ninternal: []\nrules:\n  rules_dir: %s\n", rulesDir))

	report, err := decodeExplainJSON(t, "--config", cfgPath, "https://example.com/path")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if !hasNote(report.Notes, unverifiableBundleNote) {
		t.Fatalf("URL report notes = %q, want the unprovable-version bundle warning", report.Notes)
	}
}

func TestExplainCmd_SurfaceReportCarriesUnverifiableBundleWarning(t *testing.T) {
	rulesDir := installUnversionedWarningBundle(t)
	cfgPath := writeConfig(t, fmt.Sprintf("mode: audit\ninternal: []\nrules:\n  rules_dir: %s\n", rulesDir))

	report, err := decodeExplainJSON(t, "--config", cfgPath, "--command", "ls -la")
	if err != nil {
		t.Fatalf("explain --command: %v", err)
	}
	if !hasNote(report.Notes, unverifiableBundleNote) {
		t.Fatalf("surface report notes = %q, want the unprovable-version bundle warning", report.Notes)
	}
}

func TestBuildMCPExplainReport_CarriesUnverifiableBundleWarning(t *testing.T) {
	cfg := config.Defaults()
	cfg.Rules.RulesDir = installUnversionedWarningBundle(t)

	report, err := buildMCPExplainReport(cfg, "(test)", "code-assistant", []byte(mcpJailbreak))
	if err != nil {
		t.Fatalf("buildMCPExplainReport: %v", err)
	}
	if !hasNote(report.Notes, unverifiableBundleNote) {
		t.Fatalf("MCP report notes = %q, want the unprovable-version bundle warning", report.Notes)
	}
}
