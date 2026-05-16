// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package atrimport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDir_DefaultsSkipExperimentalAndNonPattern(t *testing.T) {
	t.Parallel()
	got, err := LoadDir("testdata", Options{})
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	// Under defaults: 09001 → 2 Injection, 09002 → 1 DLP; the rest skipped.
	if l := len(got.Injection); l != 2 {
		t.Errorf("Injection len = %d, want 2", l)
	}
	if l := len(got.DLP); l != 1 {
		t.Errorf("DLP len = %d, want 1", l)
	}
	if len(got.Skipped) == 0 {
		t.Fatal("expected Skipped records, got 0")
	}
	for _, s := range got.Skipped {
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("Skipped record %+v has empty Reason", s)
		}
	}
	for _, p := range got.DLP {
		if p.Severity == "" || p.Bundle != SourceName {
			t.Errorf("DLP pattern %+v missing severity or wrong bundle", p)
		}
	}
}

func TestLoadDir_IncludeExperimentalImportsDraft(t *testing.T) {
	t.Parallel()
	got, err := LoadDir("testdata", Options{IncludeExperimental: true})
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if l := len(got.Injection); l != 3 {
		t.Errorf("Injection len = %d, want 3", l)
	}
}

func TestLoadDir_MinSeverityFiltersBelow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, min       string
		wantDLP, wantIJ int
	}{
		{"low admits all", "low", 1, 2},
		{"medium admits all", "medium", 1, 2},
		{"high drops medium", "high", 0, 2},
		{"critical drops all", "critical", 0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := LoadDir("testdata", Options{MinSeverity: tc.min})
			if err != nil {
				t.Fatalf("LoadDir: %v", err)
			}
			if len(got.DLP) != tc.wantDLP || len(got.Injection) != tc.wantIJ {
				t.Errorf("got DLP=%d Injection=%d, want DLP=%d Injection=%d",
					len(got.DLP), len(got.Injection), tc.wantDLP, tc.wantIJ)
			}
		})
	}
}

func TestLoadDir_ScanTargetAllowList(t *testing.T) {
	t.Parallel()
	got, err := LoadDir("testdata", Options{ScanTargets: []string{"mcp"}})
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(got.Injection) != 0 || len(got.DLP) != 1 {
		t.Errorf("got DLP=%d Injection=%d, want 1/0", len(got.DLP), len(got.Injection))
	}
}

func TestLoadDir_EmptyDirReturnsError(t *testing.T) {
	t.Parallel()
	if _, err := LoadDir("", Options{}); err == nil {
		t.Fatal("LoadDir(\"\") returned nil error, want one")
	}
}

func TestLoadDir_MissingDirReportsError(t *testing.T) {
	t.Parallel()
	if _, err := LoadDir(filepath.Join("testdata", "missing"), Options{}); err == nil {
		t.Fatal("LoadDir on missing dir returned nil error, want one")
	}
}

func TestLoadDir_OversizeFileSkipped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	big := make([]byte, MaxRuleFileBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "big.yaml"), big, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := LoadDir(dir, Options{})
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(got.Skipped) != 1 || !strings.Contains(got.Skipped[0].Reason, "exceeds") {
		t.Errorf("got Skipped=%+v, want one record mentioning 'exceeds'", got.Skipped)
	}
}

func TestLoadDir_InvalidRegexReported(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := []byte(`
title: bad regex
id: ATR-2026-09099
status: stable
detection_tier: pattern
severity: high
tags:
  scan_target: mcp
detection:
  condition: any
  conditions:
    - field: url
      operator: regex
      value: "[unclosed"
`)
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), bad, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := LoadDir(dir, Options{})
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(got.DLP) != 0 || len(got.Skipped) != 1 ||
		!strings.Contains(got.Skipped[0].Reason, "invalid regex") {
		t.Errorf("got DLP=%d Skipped=%+v, want zero DLP + one invalid-regex skip", len(got.DLP), got.Skipped)
	}
}

func TestLoadDir_RuleIDMustMatchPattern(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := []byte(`
title: bad id
id: "not a valid id"
status: stable
detection_tier: pattern
severity: high
tags:
  scan_target: mcp
detection:
  condition: any
  conditions:
    - field: url
      operator: regex
      value: "abc"
`)
	if err := os.WriteFile(filepath.Join(dir, "rule.yaml"), bad, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := LoadDir(dir, Options{})
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(got.DLP)+len(got.Injection) != 0 ||
		len(got.Skipped) != 1 ||
		!strings.Contains(got.Skipped[0].Reason, "does not match") {
		t.Errorf("got DLP=%d Inj=%d Skipped=%+v, want zero imports + one id-mismatch skip",
			len(got.DLP), len(got.Injection), got.Skipped)
	}
}
