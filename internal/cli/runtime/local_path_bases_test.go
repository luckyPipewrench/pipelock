// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLocalPathBasesFromArgs(t *testing.T) {
	base := t.TempDir()
	abs := t.TempDir()
	for _, dir := range []string{"rel", "flagged"} {
		if err := os.Mkdir(filepath.Join(base, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(base, "file.txt")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got := localPathBasesFromArgs(base, []string{
		"dist/index.js", abs, "rel", "--root=flagged", "-v", "--missing=/nonexistent-dir", file,
	})
	want := []string{abs, filepath.Join(base, "rel"), filepath.Join(base, "flagged")}
	if !slices.Equal(got, want) {
		t.Fatalf("localPathBasesFromArgs = %q, want %q", got, want)
	}
	if got := localPathBasesFromArgs("", []string{"rel", abs}); !slices.Equal(got, []string{abs}) {
		t.Fatalf("relative argument resolved without a base: %q", got)
	}
}
