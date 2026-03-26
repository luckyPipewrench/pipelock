// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestAssessInit_CreatesManifest verifies that a successful init writes
// manifest.json with the expected fields and creates the evidence/ subdir.
func TestAssessInit_CreatesManifest(t *testing.T) {
	tmp := t.TempDir()

	// Write a minimal valid config file.
	cfgFile := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(cfgFile, []byte("mode: audit\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	outDir := filepath.Join(tmp, "run-001")
	dir, err := runAssessInit(cfgFile, outDir)
	if err != nil {
		t.Fatalf("runAssessInit: %v", err)
	}
	if dir != outDir {
		t.Errorf("returned dir %q, want %q", dir, outDir)
	}

	// Verify manifest.json exists and is valid.
	manifestPath := filepath.Join(outDir, "manifest.json")
	data, err := os.ReadFile(filepath.Clean(manifestPath))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}

	var manifest AssessManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}

	if manifest.Status != assessStatusInitialized {
		t.Errorf("Status = %q, want %q", manifest.Status, assessStatusInitialized)
	}
	if manifest.RunID == "" {
		t.Error("RunID must not be empty")
	}
	if manifest.ConfigHash == "" {
		t.Error("ConfigHash must not be empty for a real config file")
	}
	if manifest.SchemaVersion != assessSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", manifest.SchemaVersion, assessSchemaVersion)
	}
	if manifest.ConfigFile != cfgFile {
		t.Errorf("ConfigFile = %q, want %q", manifest.ConfigFile, cfgFile)
	}
	if manifest.ScoringVersion != assessScoringVersion {
		t.Errorf("ScoringVersion = %q, want %q", manifest.ScoringVersion, assessScoringVersion)
	}
	if manifest.RendererVersion != assessRendererVersion {
		t.Errorf("RendererVersion = %q, want %q", manifest.RendererVersion, assessRendererVersion)
	}
	if manifest.Platform == "" {
		t.Error("Platform must not be empty")
	}

	// Verify evidence/ subdirectory exists.
	evidenceDir := filepath.Join(outDir, "evidence")
	if info, err := os.Stat(evidenceDir); err != nil || !info.IsDir() {
		t.Errorf("evidence/ directory not created: %v", err)
	}

	// Verify manifest.json file permissions are 0o600.
	info, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("manifest.json permissions = %o, want 0600", perm)
	}
}

// TestAssessInit_ConfigPathCanonicalized verifies that a relative config path
// is stored as an absolute path in the manifest, so run and finalize work
// from any working directory.
func TestAssessInit_ConfigPathCanonicalized(t *testing.T) {
	tmp := t.TempDir()

	// Write config at an absolute path.
	cfgFile := filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(cfgFile, []byte("mode: audit\n"), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Create a relative path that resolves to the same file.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	outDir := filepath.Join(tmp, "run-rel")
	_, err = runAssessInit("pipelock.yaml", outDir)
	if err != nil {
		t.Fatalf("runAssessInit: %v", err)
	}

	manifestPath := filepath.Clean(filepath.Join(outDir, "manifest.json"))
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var manifest AssessManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}

	if !filepath.IsAbs(manifest.ConfigFile) {
		t.Errorf("ConfigFile = %q, want absolute path", manifest.ConfigFile)
	}
	if manifest.ConfigFile != cfgFile {
		t.Errorf("ConfigFile = %q, want %q", manifest.ConfigFile, cfgFile)
	}
}

// TestAssessInit_RefusesClobber verifies that init returns an error when the
// output directory already exists, protecting against accidental overwrites.
func TestAssessInit_RefusesClobber(t *testing.T) {
	tmp := t.TempDir()

	// Create the output directory before calling init.
	outDir := filepath.Join(tmp, "already-exists")
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, err := runAssessInit("", outDir)
	if err == nil {
		t.Fatal("expected error when output directory already exists, got nil")
	}
}

// TestAssessInit_InvalidConfig verifies that a nonexistent config file causes
// an error before any directory is created.
func TestAssessInit_InvalidConfig(t *testing.T) {
	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "should-not-exist")

	_, err := runAssessInit("/no/such/config.yaml", outDir)
	if err == nil {
		t.Fatal("expected error for nonexistent config file, got nil")
	}

	// The output directory must NOT have been created.
	if _, statErr := os.Stat(outDir); statErr == nil {
		t.Error("output directory was created despite config error")
	}
}

// TestAssessInit_DefaultOutputDir verifies that when outputDir is empty,
// runAssessInit creates an assessment-<prefix>/ directory under cwd.
func TestAssessInit_DefaultOutputDir(t *testing.T) {
	tmp := t.TempDir()

	// Change working directory to the temp dir so the default output goes there.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(orig)
	})

	dir, err := runAssessInit("", "")
	if err != nil {
		t.Fatalf("runAssessInit: %v", err)
	}

	// Dir should start with "assessment-" and exist.
	base := filepath.Base(dir)
	if len(base) < len("assessment-")+8 {
		t.Errorf("default dir name %q is too short", base)
	}
	if base[:len("assessment-")] != "assessment-" {
		t.Errorf("default dir name %q does not start with assessment-", base)
	}

	if _, err := os.Stat(dir); err != nil {
		t.Errorf("default output dir %q not found: %v", dir, err)
	}

	// Manifest must exist with status initialized.
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "manifest.json")))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var manifest AssessManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	if manifest.Status != assessStatusInitialized {
		t.Errorf("Status = %q, want %q", manifest.Status, assessStatusInitialized)
	}
	// Config hash must be empty for defaults (no file hashed).
	if manifest.ConfigHash != "" {
		t.Errorf("ConfigHash = %q, want empty for defaults", manifest.ConfigHash)
	}
	if manifest.ConfigFile != configLabelDefaults {
		t.Errorf("ConfigFile = %q, want %q", manifest.ConfigFile, configLabelDefaults)
	}
}

// TestNewUUIDV4_Format verifies that newUUIDV4 produces a well-formed UUID.
func TestNewUUIDV4_Format(t *testing.T) {
	id, err := newUUIDV4()
	if err != nil {
		t.Fatalf("newUUIDV4: %v", err)
	}

	// UUID format: 8-4-4-4-12 hex chars separated by hyphens.
	parts := make([]string, 0, 5)
	start := 0
	for i := 0; i < len(id); i++ {
		if id[i] == '-' {
			parts = append(parts, id[start:i])
			start = i + 1
		}
	}
	parts = append(parts, id[start:])

	if len(parts) != 5 {
		t.Fatalf("UUID has %d segments, want 5: %q", len(parts), id)
	}

	expected := []int{8, 4, 4, 4, 12}
	for i, length := range expected {
		if len(parts[i]) != length {
			t.Errorf("segment %d len = %d, want %d (UUID %q)", i, len(parts[i]), length, id)
		}
	}

	// Verify version bit (byte 6 bits 76-79 = 0100).
	version := id[14] // first char of third segment
	if version != '4' {
		t.Errorf("UUID version char = %q, want '4'", version)
	}

	// Verify variant bits (byte 8 bits 70-71 = 10xx).
	variant := id[19] // first char of fourth segment
	if variant != '8' && variant != '9' && variant != 'a' && variant != 'b' {
		t.Errorf("UUID variant char = %q, want 8/9/a/b", variant)
	}
}
