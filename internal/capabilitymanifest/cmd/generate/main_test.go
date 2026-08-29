// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up to the module root so the test can read the real manifest
// rather than a fixture that agrees with the code by construction.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the module root")
	return ""
}

func TestRunRewritesTheGeneratedSection(t *testing.T) {
	root := repoRoot(t)
	manifest := filepath.Join(root, "docs", "security", "capability-manifest.json")
	if _, err := os.Stat(manifest); err != nil {
		t.Skipf("real manifest not present: %v", err)
	}

	source, err := os.ReadFile(filepath.Clean(filepath.Join(root, "AGENTS.md")))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	agents := filepath.Join(t.TempDir(), "AGENTS.md")
	if err := os.WriteFile(agents, source, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stderr bytes.Buffer
	if code := run(manifest, agents, &stderr); code != 0 {
		t.Fatalf("run = %d, stderr = %s", code, stderr.String())
	}

	out, err := os.ReadFile(filepath.Clean(agents))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	// Regenerating an already-current file must not change it: the generator is
	// run in CI to detect drift, so a non-idempotent one would always report drift.
	if !bytes.Equal(source, out) {
		t.Fatal("regenerating a current AGENTS.md changed it; the generator is not idempotent")
	}
}

func TestRunReportsFailures(t *testing.T) {
	root := repoRoot(t)
	realManifest := filepath.Join(root, "docs", "security", "capability-manifest.json")
	dir := t.TempDir()

	for _, tc := range []struct {
		name     string
		manifest string
		agents   string
		wantCode int
		wantErr  string
	}{
		{"no arguments", "", "", 2, "usage"},
		{"manifest only", realManifest, "", 2, "usage"},
		{"missing manifest", filepath.Join(dir, "absent.json"), filepath.Join(dir, "AGENTS.md"), 1, "load manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := run(tc.manifest, tc.agents, &stderr)
			if code != tc.wantCode {
				t.Fatalf("run = %d, want %d (stderr %q)", code, tc.wantCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Fatalf("stderr = %q, want it to mention %q", stderr.String(), tc.wantErr)
			}
		})
	}

	t.Run("unreadable AGENTS.md", func(t *testing.T) {
		if _, err := os.Stat(realManifest); err != nil {
			t.Skipf("real manifest not present: %v", err)
		}
		var stderr bytes.Buffer
		code := run(realManifest, filepath.Join(dir, "does-not-exist.md"), &stderr)
		if code != 1 || !strings.Contains(stderr.String(), "read AGENTS.md") {
			t.Fatalf("run = %d, stderr = %q", code, stderr.String())
		}
	})

	t.Run("AGENTS.md without the generated markers", func(t *testing.T) {
		if _, err := os.Stat(realManifest); err != nil {
			t.Skipf("real manifest not present: %v", err)
		}
		bare := filepath.Join(dir, "bare.md")
		if err := os.WriteFile(bare, []byte("# no markers here\n"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		var stderr bytes.Buffer
		code := run(realManifest, bare, &stderr)
		if code != 1 || !strings.Contains(stderr.String(), "render AGENTS.md") {
			t.Fatalf("run = %d, stderr = %q", code, stderr.String())
		}
	})
}

func TestRunReportsAnUnwritableTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the write-permission bit")
	}
	root := repoRoot(t)
	manifest := filepath.Join(root, "docs", "security", "capability-manifest.json")
	if _, err := os.Stat(manifest); err != nil {
		t.Skipf("real manifest not present: %v", err)
	}

	source, err := os.ReadFile(filepath.Clean(filepath.Join(root, "AGENTS.md")))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	agents := filepath.Join(t.TempDir(), "AGENTS.md")
	if err := os.WriteFile(agents, source, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Readable but not writable, so the generator gets past load and read and
	// fails on the write, which is the branch under test.
	if err := os.Chmod(agents, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(agents, 0o600) })

	var stderr bytes.Buffer
	if code := run(manifest, agents, &stderr); code != 1 {
		t.Fatalf("run = %d, want 1 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "write AGENTS.md") {
		t.Fatalf("stderr = %q, want it to name the write failure", stderr.String())
	}
}
