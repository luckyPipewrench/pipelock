// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Save coverage tests (62.5% -> higher) ---

func TestSave_Success_VerifyJSONAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	now := time.Now().UTC().Truncate(time.Second)
	m := &Manifest{
		Version: ManifestVersion,
		Created: now,
		Updated: now,
		Files: map[string]FileEntry{
			"main.go":   {SHA256: "aabbcc", Size: 100, Mode: "0644"},
			"config.go": {SHA256: "ddeeff", Size: 200, Mode: "0600"},
		},
		Excludes: []string{"*.log"},
	}

	if err := m.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("permissions = %04o, want 0600", info.Mode().Perm())
	}

	// Verify valid JSON.
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var parsed Manifest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("saved manifest is not valid JSON: %v", err)
	}
	if parsed.Version != ManifestVersion {
		t.Errorf("version = %d, want %d", parsed.Version, ManifestVersion)
	}
	if len(parsed.Files) != 2 {
		t.Errorf("files count = %d, want 2", len(parsed.Files))
	}
}

func TestSave_TrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := &Manifest{
		Version: ManifestVersion,
		Files:   map[string]FileEntry{},
	}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("saved manifest should end with newline")
	}
}

func TestSave_AtomicNoLeftoverOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := &Manifest{
		Version: ManifestVersion,
		Files:   map[string]FileEntry{"a.txt": {SHA256: "abc", Size: 10, Mode: "0600"}},
	}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestSave_EmptyFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty-files.json")

	m := &Manifest{
		Version:  ManifestVersion,
		Files:    map[string]FileEntry{},
		Excludes: []string{},
	}
	if err := m.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Files) != 0 {
		t.Errorf("expected 0 files, got %d", len(loaded.Files))
	}
}

func TestSave_LargeManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "large.json")

	files := make(map[string]FileEntry, 500)
	for i := range 500 {
		name := fmt.Sprintf("src/file_%04d.go", i)
		files[name] = FileEntry{
			SHA256: strings.Repeat("ab", 32),
			Size:   int64(i * 100),
			Mode:   "0644",
		}
	}

	m := &Manifest{
		Version: ManifestVersion,
		Created: time.Now().UTC(),
		Updated: time.Now().UTC(),
		Files:   files,
	}
	if err := m.Save(path); err != nil {
		t.Fatalf("Save large manifest: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load large manifest: %v", err)
	}
	if len(loaded.Files) != 500 {
		t.Errorf("expected 500 files, got %d", len(loaded.Files))
	}
}

func TestSave_OverwritePreservesNewContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overwrite.json")

	m1 := &Manifest{
		Version: ManifestVersion,
		Files:   map[string]FileEntry{"old.txt": {SHA256: "old", Size: 1, Mode: "0600"}},
	}
	if err := m1.Save(path); err != nil {
		t.Fatal(err)
	}

	m2 := &Manifest{
		Version: ManifestVersion,
		Files:   map[string]FileEntry{"new.txt": {SHA256: "new", Size: 2, Mode: "0600"}},
	}
	if err := m2.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Files["old.txt"]; ok {
		t.Error("old content should not be present after overwrite")
	}
	if _, ok := loaded.Files["new.txt"]; !ok {
		t.Error("new content should be present after overwrite")
	}
}

// --- Load error path coverage ---

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestLoad_ValidJSONWrongStructure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wrong.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"files":{"a":{"sha256":"x","size":1,"mode":"0600"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := Load(path)
	if err != nil {
		t.Fatalf("should load valid manifest: %v", err)
	}
	if len(m.Files) != 1 {
		t.Errorf("expected 1 file, got %d", len(m.Files))
	}
}
