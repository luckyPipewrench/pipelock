// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cliutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
	"github.com/luckyPipewrench/pipelock/internal/projectscan"
)

// ---------- suppress.go ----------

func TestSuppressRe_Matches(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantMatch bool
		wantRule  string
	}{
		{"double-slash all", "x = 1 // pipelock:ignore", true, ""},
		{"double-slash named", "x = 1 // pipelock:ignore my-rule", true, "my-rule"},
		{"hash all", "# pipelock:ignore", true, ""},
		{"hash named", "# pipelock:ignore some_rule", true, "some_rule"},
		{"no match", "x = 1 // regular comment", false, ""},
		{"partial match", "// pipelock:ignoremore", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := SuppressRe.FindStringSubmatch(tc.line)
			if tc.wantMatch && m == nil {
				t.Error("expected match")
			}
			if !tc.wantMatch && m != nil {
				t.Errorf("unexpected match: %v", m)
			}
			if tc.wantMatch && m != nil {
				rule := strings.TrimSpace(m[1])
				if rule != tc.wantRule {
					t.Errorf("captured rule = %q, want %q", rule, tc.wantRule)
				}
			}
		})
	}
}

func TestCheckInlineSuppression(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.go")

	content := "line 1\nvalue = secret // pipelock:ignore\nline 3\nfoo = bar // pipelock:ignore my-rule\n"
	if err := os.WriteFile(testFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("suppress all on line 2", func(t *testing.T) {
		r := CheckInlineSuppression(testFile, 2, "any-rule")
		if !r.Suppressed {
			t.Error("expected suppressed")
		}
		if r.Source != SuppressSourceInline {
			t.Errorf("Source = %q, want inline", r.Source)
		}
	})

	t.Run("no suppression on line 1", func(t *testing.T) {
		r := CheckInlineSuppression(testFile, 1, "any-rule")
		if r.Suppressed {
			t.Error("expected not suppressed")
		}
	})

	t.Run("named suppression matches", func(t *testing.T) {
		r := CheckInlineSuppression(testFile, 4, "my-rule")
		if !r.Suppressed {
			t.Error("expected suppressed for matching rule name")
		}
	})

	t.Run("named suppression wrong rule", func(t *testing.T) {
		r := CheckInlineSuppression(testFile, 4, "other-rule")
		if r.Suppressed {
			t.Error("expected not suppressed for non-matching rule name")
		}
	})

	t.Run("empty file path", func(t *testing.T) {
		r := CheckInlineSuppression("", 1, "rule")
		if r.Suppressed {
			t.Error("expected not suppressed for empty file")
		}
	})

	t.Run("zero line number", func(t *testing.T) {
		r := CheckInlineSuppression(testFile, 0, "rule")
		if r.Suppressed {
			t.Error("expected not suppressed for line 0")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		r := CheckInlineSuppression("/nonexistent/file.go", 1, "rule")
		if r.Suppressed {
			t.Error("expected not suppressed for nonexistent file")
		}
	})
}

func TestCheckConfigSuppression(t *testing.T) {
	entries := []config.SuppressEntry{
		{Rule: "aws-key", Path: "vendor/*", Reason: "vendored code"},
	}

	t.Run("matching entry", func(t *testing.T) {
		r := CheckConfigSuppression("vendor/lib.go", "aws-key", entries)
		if !r.Suppressed {
			t.Error("expected suppressed")
		}
		if r.Source != SuppressSourceConfig {
			t.Errorf("Source = %q, want config", r.Source)
		}
		if r.Reason != "vendored code" {
			t.Errorf("Reason = %q, want 'vendored code'", r.Reason)
		}
	})

	t.Run("non-matching rule", func(t *testing.T) {
		r := CheckConfigSuppression("vendor/lib.go", "gcp-key", entries)
		if r.Suppressed {
			t.Error("expected not suppressed for non-matching rule")
		}
	})

	t.Run("non-matching path", func(t *testing.T) {
		r := CheckConfigSuppression("src/main.go", "aws-key", entries)
		if r.Suppressed {
			t.Error("expected not suppressed for non-matching path")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		r := CheckConfigSuppression("", "aws-key", entries)
		if r.Suppressed {
			t.Error("expected not suppressed for empty file")
		}
	})

	t.Run("nil entries", func(t *testing.T) {
		r := CheckConfigSuppression("vendor/lib.go", "aws-key", nil)
		if r.Suppressed {
			t.Error("expected not suppressed for nil entries")
		}
	})
}

func TestCheckFinding(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.go")
	content := "value = secret // pipelock:ignore\n"
	if err := os.WriteFile(testFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	entries := []config.SuppressEntry{
		{Rule: "config-rule", Path: "*.go", Reason: "config suppression"},
	}

	t.Run("inline takes priority", func(t *testing.T) {
		r := CheckFinding(testFile, 1, "config-rule", entries)
		if !r.Suppressed {
			t.Fatal("expected suppressed")
		}
		if r.Source != SuppressSourceInline {
			t.Errorf("Source = %q, want inline", r.Source)
		}
	})

	t.Run("falls through to config", func(t *testing.T) {
		r := CheckFinding(testFile, 99, "config-rule", entries) // line 99 doesn't exist
		// The inline check returns not suppressed (line out of range).
		// Falls through to config check. testFile basename is test.go which matches "*.go".
		if !r.Suppressed {
			t.Error("expected config suppression fallthrough")
		}
		if r.Source != SuppressSourceConfig {
			t.Errorf("Source = %q, want config", r.Source)
		}
	})
}

func TestSuppressGitFindings(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.go")
	content := "value = secret // pipelock:ignore\nother = safe\n"
	if err := os.WriteFile(testFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := []gitprotect.Finding{
		{File: testFile, Line: 1, Pattern: "secret-pat"},
		{File: testFile, Line: 2, Pattern: "other-pat"},
	}

	kept, suppressed, reasons := SuppressGitFindings(findings, nil)

	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed, got %d", len(suppressed))
	}
	if len(kept) != 1 {
		t.Errorf("expected 1 kept, got %d", len(kept))
	}
	if len(reasons) != 1 {
		t.Errorf("expected 1 reason, got %d", len(reasons))
	}
}

func TestSuppressProjectFindings(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.go")
	content := "value = secret // pipelock:ignore\nother = safe\n"
	if err := os.WriteFile(testFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	findings := []projectscan.Finding{
		{File: testFile, Line: 1, Pattern: "secret-pat"},
		{File: testFile, Line: 2, Pattern: "other-pat"},
	}

	kept, suppressed, reasons := SuppressProjectFindings(findings, nil)

	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed, got %d", len(suppressed))
	}
	if len(kept) != 1 {
		t.Errorf("expected 1 kept, got %d", len(kept))
	}
	if len(reasons) != 1 {
		t.Errorf("expected 1 reason, got %d", len(reasons))
	}
}

func TestSuppressProjectFindings_WithBaseDir(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "src", "test.go")
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o750); err != nil {
		t.Fatal(err)
	}
	content := "value = secret // pipelock:ignore\n"
	if err := os.WriteFile(testFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	// Finding has relative path.
	findings := []projectscan.Finding{
		{File: "src/test.go", Line: 1, Pattern: "secret-pat"},
	}

	_, suppressed, _ := SuppressProjectFindings(findings, nil, dir)

	if len(suppressed) != 1 {
		t.Errorf("expected 1 suppressed with baseDir, got %d", len(suppressed))
	}
}

func TestPrintSuppressed(t *testing.T) {
	var buf strings.Builder

	t.Run("inline", func(t *testing.T) {
		buf.Reset()
		PrintSuppressed(&buf, "test.go", 5, "my-pattern", SuppressResult{
			Suppressed: true,
			Source:     SuppressSourceInline,
		})
		got := buf.String()
		if !strings.Contains(got, "test.go:5") {
			t.Errorf("expected file:line, got %q", got)
		}
		if !strings.Contains(got, "(inline)") {
			t.Errorf("expected (inline), got %q", got)
		}
	})

	t.Run("config with reason", func(t *testing.T) {
		buf.Reset()
		PrintSuppressed(&buf, "test.go", 0, "my-pattern", SuppressResult{
			Suppressed: true,
			Source:     SuppressSourceConfig,
			Reason:     "vendored code",
		})
		got := buf.String()
		if !strings.Contains(got, "vendored code") {
			t.Errorf("expected reason in output, got %q", got)
		}
		if !strings.Contains(got, "(config:") {
			t.Errorf("expected (config:) in output, got %q", got)
		}
	})

	t.Run("config without reason", func(t *testing.T) {
		buf.Reset()
		PrintSuppressed(&buf, "test.go", 0, "my-pattern", SuppressResult{
			Suppressed: true,
			Source:     SuppressSourceConfig,
		})
		got := buf.String()
		if !strings.Contains(got, "(config)") {
			t.Errorf("expected (config), got %q", got)
		}
	})
}

func TestPrintSuppressedGit(t *testing.T) {
	var buf strings.Builder
	findings := []gitprotect.Finding{
		{File: "a.go", Line: 1, Pattern: "p1"},
		{File: "b.go", Line: 2, Pattern: "p2"},
	}
	reasons := []SuppressResult{
		{Suppressed: true, Source: SuppressSourceInline},
		{Suppressed: true, Source: SuppressSourceConfig, Reason: "ok"},
	}

	PrintSuppressedGit(&buf, findings, reasons)
	got := buf.String()
	if !strings.Contains(got, "a.go:1") || !strings.Contains(got, "b.go:2") {
		t.Errorf("expected both findings in output, got %q", got)
	}
}

func TestPrintSuppressedProject(t *testing.T) {
	var buf strings.Builder
	findings := []projectscan.Finding{
		{File: "c.go", Line: 3, Pattern: "p3"},
	}
	reasons := []SuppressResult{
		{Suppressed: true, Source: SuppressSourceInline},
	}

	PrintSuppressedProject(&buf, findings, reasons)
	got := buf.String()
	if !strings.Contains(got, "c.go:3") {
		t.Errorf("expected finding in output, got %q", got)
	}
}

// ---------- ReadSourceLine ----------

func TestReadSourceLine(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	content := "line one\nline two\nline three\n"
	if err := os.WriteFile(testFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("valid line", func(t *testing.T) {
		got, err := ReadSourceLine(testFile, 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "line two" {
			t.Errorf("got %q, want %q", got, "line two")
		}
	})

	t.Run("first line", func(t *testing.T) {
		got, err := ReadSourceLine(testFile, 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "line one" {
			t.Errorf("got %q, want %q", got, "line one")
		}
	})

	t.Run("line out of range", func(t *testing.T) {
		_, err := ReadSourceLine(testFile, 100)
		if err == nil {
			t.Error("expected error for out-of-range line")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := ReadSourceLine("/nonexistent/file.txt", 1)
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})
}

// ---------- color.go ----------

func TestUseColor(t *testing.T) {
	// NO_COLOR set should disable color.
	t.Run("NO_COLOR set", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		if UseColor() {
			t.Error("UseColor should return false when NO_COLOR is set")
		}
	})

	t.Run("NO_COLOR empty", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		// In test environment, stdout is usually not a terminal.
		// So we expect false here too, but the NO_COLOR path is at least not triggered.
		_ = UseColor() // Just ensure no panic.
	})
}

func TestDetectRunContext(t *testing.T) {
	// Default test environment should return "host" (not in k8s or container).
	t.Run("host environment", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		got := DetectRunContext()
		// Don't assert exact value since CI may be a container.
		if got != RunContextHost && got != RunContextContainer && got != RunContextPod {
			t.Errorf("unexpected run context: %q", got)
		}
	})

	t.Run("kubernetes pod", func(t *testing.T) {
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
		got := DetectRunContext()
		if got != RunContextPod {
			t.Errorf("expected pod, got %q", got)
		}
	})
}

// ---------- config.go ----------

func TestLoadConfigOrDefault_Default(t *testing.T) {
	cfg, err := LoadConfigOrDefault("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoadConfigOrDefault_ValidFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfigOrDefault(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestLoadConfigOrDefault_BadFile(t *testing.T) {
	_, err := LoadConfigOrDefault("/nonexistent/pipelock.yaml")
	if err == nil {
		t.Error("expected error for nonexistent config file")
	}
}

// ---------- exclude.go ----------

func TestToSlash(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"a/b/c", "a/b/c"},
		{`a\b\c`, "a/b/c"},
		{"no-slashes", "no-slashes"},
		{"", ""},
	}
	for _, tc := range cases {
		got := ToSlash(tc.input)
		if got != tc.want {
			t.Errorf("ToSlash(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestShouldExclude(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		patterns []string
		want     bool
	}{
		{"empty patterns", "src/main.go", nil, false},
		{"dir prefix match", "vendor/lib/foo.go", []string{"vendor/"}, true},
		{"dir prefix no match", "src/main.go", []string{"vendor/"}, false},
		{"exact match", "README.md", []string{"README.md"}, true},
		{"exact no match", "readme.md", []string{"README.md"}, false},
		{"glob full path", "pkg/foo.generated.go", []string{"*.generated.go"}, true},
		{"glob basename match", "deep/nested/test.go", []string{"*.go"}, true},
		{"glob no match", "test.py", []string{"*.go"}, false},
		{"empty pattern skipped", "file.go", []string{""}, false},
		{"backslash path normalized", `vendor\lib\foo.go`, []string{"vendor/"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShouldExclude(tc.file, tc.patterns)
			if got != tc.want {
				t.Errorf("ShouldExclude(%q, %v) = %v, want %v", tc.file, tc.patterns, got, tc.want)
			}
		})
	}
}

// ---------- version.go ----------

func TestVersionDefaults(t *testing.T) {
	// These are set at build time; in test they should be the defaults.
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if BuildDate == "" {
		t.Error("BuildDate should not be empty")
	}
}

// ---------- resolve.go: ResolvedHome ----------

func TestResolvedHome(t *testing.T) {
	t.Run("flag takes priority", func(t *testing.T) {
		old := PipelockHome
		PipelockHome = "/flag-home"
		t.Cleanup(func() { PipelockHome = old })
		t.Setenv("PIPELOCK_HOME", "/env-home")

		got := ResolvedHome()
		if got != "/flag-home" {
			t.Errorf("ResolvedHome() = %q, want /flag-home", got)
		}
	})

	t.Run("env fallback", func(t *testing.T) {
		old := PipelockHome
		PipelockHome = ""
		t.Cleanup(func() { PipelockHome = old })
		t.Setenv("PIPELOCK_HOME", "/env-home")

		got := ResolvedHome()
		if got != "/env-home" {
			t.Errorf("ResolvedHome() = %q, want /env-home", got)
		}
	})

	t.Run("neither set", func(t *testing.T) {
		old := PipelockHome
		PipelockHome = ""
		t.Cleanup(func() { PipelockHome = old })
		t.Setenv("PIPELOCK_HOME", "")

		got := ResolvedHome()
		if got != "" {
			t.Errorf("ResolvedHome() = %q, want empty", got)
		}
	})
}
