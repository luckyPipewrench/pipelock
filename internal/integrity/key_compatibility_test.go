// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

// The committed fixture is written by the base revision's Generate and Save.
// PIPELOCK_JSON_UPGRADE_FIXTURE regenerates it in a base checkout.
func TestCaseDistinctManifestUpgrade(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"README.md", "readme.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := Generate(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, DefaultManifestFile)
	if output := os.Getenv("PIPELOCK_JSON_UPGRADE_FIXTURE"); output != "" {
		if err := manifest.Save(filepath.Clean(output)); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := manifest.Save(path); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{path, "testdata/case-distinct-manifest.json"} {
		loaded, err := Load(path)
		if err != nil {
			t.Fatalf("load case-distinct manifest: %v", err)
		}
		if len(loaded.Files) != 2 || loaded.Files["README.md"].SHA256 == "" || loaded.Files["readme.md"].SHA256 == "" {
			t.Fatalf("lost case-distinct paths: %+v", loaded.Files)
		}
	}
}
