// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/filescan"
)

// zw builds a string with the given codepoint so this source stays pure ASCII.
func zw(r rune) string { return string(r) }

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := Cmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestScanCmd_Clean(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "ok.md"), "clean content\n")
	out, err := run(t, dir)
	if err != nil {
		t.Fatalf("clean dir should exit 0, got %v", err)
	}
	if !strings.Contains(out, "0 finding(s)") {
		t.Errorf("expected zero-finding tally, got: %q", out)
	}
}

func TestScanCmd_Planted(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "CLAUDE.md"), "hi"+zw(0x200B)+"dden")
	out, err := run(t, dir)
	if !errors.Is(err, filescan.ErrFindings) {
		t.Fatalf("planted file should return ErrFindings, got %v", err)
	}
	if code := cliutil.ExitCodeOf(err); code != exitFindings {
		t.Errorf("exit code = %d, want %d", code, exitFindings)
	}
	if !strings.Contains(out, "U+200B") || !strings.Contains(out, "high") {
		t.Errorf("report should name codepoint + severity, got: %q", out)
	}
}

func TestScanCmd_JSON(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "f.md"), "a"+zw(0x202E)+"b")
	out, err := run(t, "--json", dir)
	if !errors.Is(err, filescan.ErrFindings) {
		t.Fatalf("expected findings error, got %v", err)
	}
	var parsed struct {
		Findings []struct {
			CodePoint string `json:"code_point"`
			Category  string `json:"category"`
			Severity  string `json:"severity"`
		} `json:"findings"`
	}
	if jErr := json.Unmarshal([]byte(out), &parsed); jErr != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", jErr, out)
	}
	if len(parsed.Findings) != 1 || parsed.Findings[0].CodePoint != "U+202E" {
		t.Errorf("unexpected JSON findings: %+v", parsed.Findings)
	}
	if parsed.Findings[0].Category != "bidi-control" || parsed.Findings[0].Severity != "high" {
		t.Errorf("want bidi-control/high, got %s/%s", parsed.Findings[0].Category, parsed.Findings[0].Severity)
	}
}

func TestScanCmd_MinSeverityGating(t *testing.T) {
	dir := t.TempDir()
	// soft hyphen = low severity only
	mustWrite(t, filepath.Join(dir, "prose.md"), "co"+zw(0x00AD)+"op")

	t.Run("low finding does not trip default high threshold", func(t *testing.T) {
		out, err := run(t, dir)
		if err != nil {
			t.Fatalf("low-only finding should exit 0 by default, got %v", err)
		}
		if !strings.Contains(out, "U+00AD") {
			t.Errorf("finding should still be reported: %q", out)
		}
	})
	t.Run("low finding trips explicit low threshold", func(t *testing.T) {
		_, err := run(t, "--min-severity", "low", dir)
		if !errors.Is(err, filescan.ErrFindings) {
			t.Fatalf("explicit min-severity low should gate on the soft hyphen, got %v", err)
		}
	})
}

func TestScanCmd_SkipPolicy(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "blob.bin")
	blob := binaryFixture()
	if err := os.WriteFile(binary, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("explicit skipped file is exit 2", func(t *testing.T) {
		out, err := run(t, binary)
		if err == nil || errors.Is(err, filescan.ErrFindings) {
			t.Fatalf("explicit skipped file should be scan error, got %v\n%s", err, out)
		}
		if code := cliutil.ExitCodeOf(err); code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(out, "skipped") {
			t.Errorf("skip should be visible in output: %q", out)
		}
	})

	t.Run("directory skip is allowed by default", func(t *testing.T) {
		out, err := run(t, dir)
		if err != nil {
			t.Fatalf("directory skip should not fail by default, got %v\n%s", err, out)
		}
		if !strings.Contains(out, "blob.bin") {
			t.Errorf("skip should be visible in output: %q", out)
		}
	})

	t.Run("fail-on-skip fails directory skips", func(t *testing.T) {
		_, err := run(t, "--fail-on-skip", dir)
		if err == nil || errors.Is(err, filescan.ErrFindings) {
			t.Fatalf("--fail-on-skip should return scan error, got %v", err)
		}
		if code := cliutil.ExitCodeOf(err); code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
	})
}

func TestScanCmd_DefaultCwd(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "AGENTS.md"), "x"+zw(0x200B)+"y")
	t.Chdir(dir)
	_, err := run(t)
	if !errors.Is(err, filescan.ErrFindings) {
		t.Fatalf("default cwd scan should find planted char, got %v", err)
	}
}

func TestScanCmd_Errors(t *testing.T) {
	t.Run("missing path is exit 2", func(t *testing.T) {
		_, err := run(t, filepath.Join(t.TempDir(), "does-not-exist"))
		if err == nil || errors.Is(err, filescan.ErrFindings) {
			t.Fatalf("missing path should be a scan error, got %v", err)
		}
		if code := cliutil.ExitCodeOf(err); code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
	})
	t.Run("invalid min-severity is exit 2", func(t *testing.T) {
		_, err := run(t, "--min-severity", "bogus", t.TempDir())
		if err == nil {
			t.Fatal("expected error for invalid severity")
		}
		if code := cliutil.ExitCodeOf(err); code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
	})
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestScanCmd_RefusalBoundary pins the skip-versus-refusal boundary at the CLI
// layer, which is where the original bypass showed up: a directory scan accepts
// skips by default, so an uninspectable agent-context file exited 0 and reported
// clean. The paired non-context case must still exit 0, or the change would just
// be a stricter scan rather than a targeted one.
func TestScanCmd_RefusalBoundary(t *testing.T) {
	blob := binaryFixture()

	t.Run("uninspectable context file exits 2 without fail-on-skip", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "CLAUDE.md"), blob, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := run(t, dir)
		if err == nil || errors.Is(err, filescan.ErrFindings) {
			t.Fatalf("refused context file should be a scan error, got %v\n%s", err, out)
		}
		if code := cliutil.ExitCodeOf(err); code != exitError {
			t.Errorf("exit code = %d, want %d", code, exitError)
		}
		if !strings.Contains(out, "REFUSED") {
			t.Errorf("refusal should be visible in output: %q", out)
		}
	})

	t.Run("same content under a non-context name still exits 0", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "blob.bin"), blob, 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := run(t, dir)
		if err != nil {
			t.Fatalf("ordinary binary asset must not fail a scan, got %v\n%s", err, out)
		}
	})
}

// binaryFixture builds content that classifies as binary under the current rule
// rather than the old one. The previous fixture was "a\x00b", binary only while a
// single NUL was treated as proof; that input is now correctly scanned as text.
//
// The skip-versus-refusal tests share this one fixture deliberately: the pair only
// means anything if both sides differ by the FILE NAME alone, and two separately
// maintained payloads could drift until the comparison proved nothing.
func binaryFixture() []byte {
	blob := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	for i := range 256 {
		if i%3 == 0 {
			blob = append(blob, 0)
			continue
		}
		blob = append(blob, byte(128+(i%127)))
	}
	return blob
}
