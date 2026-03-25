// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/discover"
)

const testMinimalConfig = "mode: audit\n"

// initTestRun is a test helper that creates a minimal config file and runs
// runAssessInit, returning the run directory path. Fails the test on error.
func initTestRun(t *testing.T) (runDir, cfgFile string) {
	t.Helper()
	tmp := t.TempDir()

	cfgFile = filepath.Join(tmp, "pipelock.yaml")
	if err := os.WriteFile(cfgFile, []byte(testMinimalConfig), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	outDir := filepath.Join(tmp, "run-test")
	dir, err := runAssessInit(cfgFile, outDir)
	if err != nil {
		t.Fatalf("runAssessInit: %v", err)
	}

	return dir, cfgFile
}

// readTestManifest reads and unmarshals the manifest from the given run dir.
func readTestManifest(t *testing.T, runDir string) AssessManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "manifest.json")))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m AssessManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	return m
}

func TestAssessRun_CompletesSuccessfully(t *testing.T) {
	runDir, _ := initTestRun(t)

	if err := runAssessRun(runDir, false, nil); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	manifest := readTestManifest(t, runDir)
	if manifest.Status != assessStatusCompleted {
		t.Errorf("Status = %q, want %q", manifest.Status, assessStatusCompleted)
	}
	if manifest.CompletedAt == nil {
		t.Error("CompletedAt must not be nil on completion")
	}

	// All 4 evidence files should exist.
	evidenceDir := filepath.Join(runDir, "evidence")
	expectedFiles := []string{
		"simulate.jsonl",
		"audit-score.jsonl",
		"verify-install.jsonl",
		"discover.jsonl",
	}
	for _, name := range expectedFiles {
		path := filepath.Join(evidenceDir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("evidence file %s not found: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("evidence file %s is empty", name)
		}
		// Verify file permissions are 0o600.
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("evidence file %s permissions = %o, want 0600", name, perm)
		}
	}
}

func TestAssessRun_ConfigDrift(t *testing.T) {
	runDir, cfgFile := initTestRun(t)

	// Modify the config file after init (balanced is valid without api_allowlist).
	if err := os.WriteFile(cfgFile, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("modifying config: %v", err)
	}

	err := runAssessRun(runDir, false, nil)
	if err == nil {
		t.Fatal("expected error for config drift, got nil")
	}

	// Config drift should return exit code 2, distinct from primitive failure (1).
	if got := ExitCodeOf(err); got != 2 {
		t.Errorf("exit code = %d, want 2 for config drift", got)
	}

	// Verify the manifest was set to failed.
	manifest := readTestManifest(t, runDir)
	if manifest.Status != assessStatusFailed {
		t.Errorf("Status = %q, want %q", manifest.Status, assessStatusFailed)
	}
	if manifest.FailureReason == "" {
		t.Error("FailureReason must not be empty after drift failure")
	}
}

func TestAssessRun_ConfigDriftForced(t *testing.T) {
	runDir, cfgFile := initTestRun(t)

	// Modify the config file after init (balanced is valid without api_allowlist).
	if err := os.WriteFile(cfgFile, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatalf("modifying config: %v", err)
	}

	if err := runAssessRun(runDir, true, nil); err != nil {
		t.Fatalf("runAssessRun with force: %v", err)
	}

	manifest := readTestManifest(t, runDir)
	if manifest.Status != assessStatusCompleted {
		t.Errorf("Status = %q, want %q", manifest.Status, assessStatusCompleted)
	}
	if !manifest.ConfigDrifted {
		t.Error("ConfigDrifted should be true when forced past drift")
	}
}

func TestAssessRun_SkipPrimitive(t *testing.T) {
	runDir, _ := initTestRun(t)

	if err := runAssessRun(runDir, false, []string{primitiveVerifyInstall}); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	manifest := readTestManifest(t, runDir)
	if manifest.Status != assessStatusCompleted {
		t.Errorf("Status = %q, want %q", manifest.Status, assessStatusCompleted)
	}

	// 3 evidence files should exist, verify-install.jsonl should not.
	evidenceDir := filepath.Join(runDir, "evidence")
	presentFiles := []string{"simulate.jsonl", "audit-score.jsonl", "discover.jsonl"}
	for _, name := range presentFiles {
		if _, err := os.Stat(filepath.Join(evidenceDir, name)); err != nil {
			t.Errorf("expected evidence file %s to exist: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(evidenceDir, "verify-install.jsonl")); err == nil {
		t.Error("verify-install.jsonl should not exist when skipped")
	}

	// Check skipped primitives recorded in manifest.
	if len(manifest.SkippedPrimitives) != 1 || manifest.SkippedPrimitives[0] != primitiveVerifyInstall {
		t.Errorf("SkippedPrimitives = %v, want [%s]", manifest.SkippedPrimitives, primitiveVerifyInstall)
	}
}

func TestAssessRun_SkipMultiplePrimitives(t *testing.T) {
	runDir, _ := initTestRun(t)

	if err := runAssessRun(runDir, false, []string{primitiveVerifyInstall, primitiveDiscover}); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	manifest := readTestManifest(t, runDir)
	if len(manifest.SkippedPrimitives) != 2 {
		t.Errorf("SkippedPrimitives has %d entries, want 2", len(manifest.SkippedPrimitives))
	}

	// Verify alphabetical ordering.
	if len(manifest.SkippedPrimitives) == 2 && manifest.SkippedPrimitives[0] > manifest.SkippedPrimitives[1] {
		t.Errorf("SkippedPrimitives not sorted: %v", manifest.SkippedPrimitives)
	}

	evidenceDir := filepath.Join(runDir, "evidence")
	if _, err := os.Stat(filepath.Join(evidenceDir, "verify-install.jsonl")); err == nil {
		t.Error("verify-install.jsonl should not exist when skipped")
	}
	if _, err := os.Stat(filepath.Join(evidenceDir, "discover.jsonl")); err == nil {
		t.Error("discover.jsonl should not exist when skipped")
	}
}

func TestAssessRun_NotInitialized(t *testing.T) {
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "run-bad")

	// Create a manifest with completed status.
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		t.Fatalf("creating dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(runDir, "evidence"), 0o750); err != nil {
		t.Fatalf("creating evidence dir: %v", err)
	}

	manifest := AssessManifest{
		SchemaVersion: assessSchemaVersion,
		Status:        assessStatusCompleted,
		ConfigFile:    configLabelDefaults,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "manifest.json"), data, 0o600); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}

	err = runAssessRun(runDir, false, nil)
	if err == nil {
		t.Fatal("expected error for non-initialized run directory, got nil")
	}
}

func TestAssessRun_MissingManifest(t *testing.T) {
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "run-empty")
	if err := os.MkdirAll(runDir, 0o750); err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	err := runAssessRun(runDir, false, nil)
	if err == nil {
		t.Fatal("expected error for missing manifest, got nil")
	}
}

func TestAssessRun_DefaultsConfig(t *testing.T) {
	// Test running with "defaults" config (no file).
	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "run-defaults")

	// Change working directory to temp dir.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	dir, err := runAssessInit("", outDir)
	if err != nil {
		t.Fatalf("runAssessInit: %v", err)
	}

	if err := runAssessRun(dir, false, nil); err != nil {
		t.Fatalf("runAssessRun with defaults: %v", err)
	}

	manifest := readTestManifest(t, dir)
	if manifest.Status != assessStatusCompleted {
		t.Errorf("Status = %q, want %q", manifest.Status, assessStatusCompleted)
	}
}

func TestWriteEvidenceJSONL_ValidJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.jsonl")

	type entry struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}
	lines := []any{
		entry{Name: "alpha", Value: 1},
		entry{Name: "beta", Value: 2},
	}

	if err := writeEvidenceJSONL(path, lines); err != nil {
		t.Fatalf("writeEvidenceJSONL: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	// Each line should be valid JSON.
	jsonLines := splitNonEmpty(string(data))
	if len(jsonLines) != 2 {
		t.Fatalf("expected 2 JSON lines, got %d", len(jsonLines))
	}

	for i, line := range jsonLines {
		var e entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}

	// Verify file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestWrapDiscoverReport(t *testing.T) {
	r := &discover.Report{
		Summary: discover.Summary{
			TotalClients: 2,
			TotalServers: 3,
		},
	}

	wrapped := wrapDiscoverReport(r, "/home/test")
	if wrapped.SchemaVersion != assessSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", wrapped.SchemaVersion, assessSchemaVersion)
	}
	if wrapped.ScannedRoot != "/home/test" {
		t.Errorf("ScannedRoot = %q, want /home/test", wrapped.ScannedRoot)
	}
	if wrapped.Summary.TotalClients != 2 {
		t.Errorf("Summary.TotalClients = %d, want 2", wrapped.Summary.TotalClients)
	}
}

// splitNonEmpty splits a string on newlines and returns non-empty segments.
func splitNonEmpty(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				result = append(result, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}
