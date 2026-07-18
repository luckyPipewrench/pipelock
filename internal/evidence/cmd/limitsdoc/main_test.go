// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainWritesHardLimitsDoc(t *testing.T) {
	workdir := filepath.Join(t.TempDir(), "internal", "evidence", "cmd", "limitsdoc")
	outDir := filepath.Clean(filepath.Join(workdir, "..", "..", "docs", "evidence"))
	for _, dir := range []string{workdir, outDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	t.Chdir(workdir)

	main()

	data, err := os.ReadFile(filepath.Join(outDir, "hard-limits.md"))
	if err != nil {
		t.Fatalf("read generated doc: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		"# Evidence Hard Limits",
		"## How to Read This",
		"## What Pipelock DOES Prove",
		"Why no rung closes it",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated doc missing %q:\n%s", want, got)
		}
	}
}
