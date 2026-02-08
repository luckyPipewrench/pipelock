package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/integrity"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestIntegrityCmd_RegisteredInHelp(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--help"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "integrity") {
		t.Error("expected help output to list 'integrity' command")
	}
}

func TestIntegrityInit_Basic(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "hello.txt", "hello world\n")

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "init", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1 file") {
		t.Errorf("expected '1 file' in output, got: %q", output)
	}

	// Verify manifest was created.
	mPath := filepath.Join(dir, integrity.DefaultManifestFile)
	if _, err := os.Stat(mPath); err != nil {
		t.Errorf("expected manifest file to exist: %v", err)
	}
}

func TestIntegrityInit_CustomManifestPath(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	mPath := filepath.Join(t.TempDir(), "custom-manifest.json")

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "init", dir, "--manifest", mPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(mPath); err != nil {
		t.Errorf("expected custom manifest file to exist: %v", err)
	}
}

func TestIntegrityCheck_CustomManifestInsideWorkspace(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	mPath := filepath.Join(dir, "custom-manifest.json")

	// Init with custom manifest inside workspace.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir, "--manifest", mPath})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Check should not report the custom manifest as an "ADDED" violation.
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir, "--manifest", mPath})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected clean check, got error: %v\noutput: %s", err, buf.String())
	}

	if !strings.Contains(buf.String(), "All files match") {
		t.Errorf("expected clean check, got: %q", buf.String())
	}
}

func TestIntegrityInit_WithExcludes(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "keep.txt", "keep\n")
	writeTestFile(t, dir, "skip.log", "skip\n")

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "init", dir, "--exclude", "*.log"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "1 file") {
		t.Errorf("expected '1 file' in output, got: %q", buf.String())
	}
}

func TestIntegrityInit_AlreadyExists(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	// Create manifest first.
	mPath := filepath.Join(dir, integrity.DefaultManifestFile)
	if err := os.WriteFile(mPath, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "init", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when manifest already exists")
	}
}

func TestIntegrityInit_NonexistentDir(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "init", "/nonexistent/dir"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestIntegrityInit_FileNotDir(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "notadir.txt")
	writeTestFile(t, dir, "notadir.txt", "content\n")

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "init", filePath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when target is a file, not a directory")
	}
}

func TestIntegrityUpdate_ReplacesExcludes(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "keep.txt", "keep\n")
	writeTestFile(t, dir, "skip.log", "skip\n")

	// Init with *.log excluded.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir, "--exclude", "*.log"})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Update with *.txt excluded instead (replaces *.log).
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "update", dir, "--exclude", "*.txt"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Verify the excludes were replaced, not merged.
	mPath := filepath.Join(dir, integrity.DefaultManifestFile)
	m, err := integrity.Load(mPath)
	if err != nil {
		t.Fatal(err)
	}

	if len(m.Excludes) != 1 || m.Excludes[0] != "*.txt" {
		t.Errorf("expected excludes [*.txt], got %v", m.Excludes)
	}

	// skip.log should now be tracked (no longer excluded).
	if _, ok := m.Files["skip.log"]; !ok {
		t.Error("expected skip.log to be tracked after exclude replacement")
	}
	// keep.txt should now be excluded.
	if _, ok := m.Files["keep.txt"]; ok {
		t.Error("expected keep.txt to be excluded after exclude replacement")
	}
}

func TestIntegrityCheck_Clean(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	// Init first.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Check — should be clean.
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "All files match") {
		t.Errorf("expected clean check output, got: %q", buf.String())
	}
}

func TestIntegrityCheck_DetectsModification(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "original\n")

	// Init.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Tamper.
	writeTestFile(t, dir, "file.txt", "tampered\n")

	// Check — should detect violation.
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for integrity violation")
	}
	if !errors.Is(err, ErrIntegrityViolation) {
		t.Errorf("expected ErrIntegrityViolation, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "MODIFIED") {
		t.Errorf("expected MODIFIED in output, got: %q", output)
	}
	if !strings.Contains(output, "file.txt") {
		t.Errorf("expected file.txt in output, got: %q", output)
	}
	if !strings.Contains(output, "1 violation") {
		t.Errorf("expected '1 violation' in output, got: %q", output)
	}
}

func TestIntegrityCheck_DetectsAddition(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "original.txt", "original\n")

	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	writeTestFile(t, dir, "new.txt", "surprise\n")

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	err := cmd.Execute()
	if !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation, got: %v", err)
	}

	if !strings.Contains(buf.String(), "ADDED") {
		t.Errorf("expected ADDED in output, got: %q", buf.String())
	}
}

func TestIntegrityCheck_DetectsRemoval(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	if err := os.Remove(filepath.Join(dir, "file.txt")); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	err := cmd.Execute()
	if !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation, got: %v", err)
	}

	if !strings.Contains(buf.String(), "REMOVED") {
		t.Errorf("expected REMOVED in output, got: %q", buf.String())
	}
}

func TestIntegrityCheck_MissingManifest(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when manifest is missing")
	}
}

func TestIntegrityUpdate_Basic(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "original\n")

	// Init.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Modify file.
	writeTestFile(t, dir, "file.txt", "changed\n")

	// Update.
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "update", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "updated") {
		t.Errorf("expected 'updated' in output, got: %q", buf.String())
	}

	// Check should now be clean.
	checkCmd := rootCmd()
	checkCmd.SetArgs([]string{"integrity", "check", dir})

	checkBuf := &strings.Builder{}
	checkCmd.SetOut(checkBuf)

	if err := checkCmd.Execute(); err != nil {
		t.Errorf("expected clean check after update, got: %v", err)
	}
}

func TestIntegrityUpdate_PreservesCreatedTime(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	// Init.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Load original manifest to get created time.
	mPath := filepath.Join(dir, integrity.DefaultManifestFile)
	original, err := integrity.Load(mPath)
	if err != nil {
		t.Fatal(err)
	}

	// Update.
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "update", dir})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Load updated manifest.
	updated, err := integrity.Load(mPath)
	if err != nil {
		t.Fatal(err)
	}

	if !updated.Created.Equal(original.Created) {
		t.Errorf("created time changed: %v -> %v", original.Created, updated.Created)
	}
}

func TestIntegrityUpdate_PreservesExcludes(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	// Init with excludes.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir, "--exclude", "*.log"})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Update without --exclude flags.
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "update", dir})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("update: %v", err)
	}

	// Verify excludes were preserved.
	mPath := filepath.Join(dir, integrity.DefaultManifestFile)
	m, err := integrity.Load(mPath)
	if err != nil {
		t.Fatal(err)
	}

	if len(m.Excludes) != 1 || m.Excludes[0] != "*.log" {
		t.Errorf("expected excludes [*.log], got %v", m.Excludes)
	}
}

func TestIntegrityUpdate_MissingManifest(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "update", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error when manifest is missing for update")
	}
}

func TestIntegrityCheck_MultipleViolations(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "modify.txt", "original\n")
	writeTestFile(t, dir, "delete.txt", "will go\n")
	writeTestFile(t, dir, "keep.txt", "stays\n")

	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	writeTestFile(t, dir, "modify.txt", "changed\n")
	if err := os.Remove(filepath.Join(dir, "delete.txt")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "added.txt", "new\n")

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	err := cmd.Execute()
	if !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "3 violation") {
		t.Errorf("expected '3 violation' in output, got: %q", output)
	}
	if !strings.Contains(output, "MODIFIED") {
		t.Error("expected MODIFIED in output")
	}
	if !strings.Contains(output, "ADDED") {
		t.Error("expected ADDED in output")
	}
	if !strings.Contains(output, "REMOVED") {
		t.Error("expected REMOVED in output")
	}
}

func TestIntegrityCheck_JSONClean(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir, "--json"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result checkResult
	if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if !result.OK {
		t.Error("expected ok=true for clean check")
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(result.Violations))
	}
}

func TestIntegrityCheck_JSONViolations(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "original\n")

	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	writeTestFile(t, dir, "file.txt", "tampered\n")
	writeTestFile(t, dir, "new.txt", "added\n")

	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "check", dir, "--json"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	err := cmd.Execute()
	if !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation, got: %v", err)
	}

	var result checkResult
	if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if result.OK {
		t.Error("expected ok=false for violations")
	}
	if len(result.Violations) != 2 {
		t.Errorf("expected 2 violations, got %d", len(result.Violations))
	}
}

func TestIntegrityCmd_DefaultsToCurrentDir(t *testing.T) {
	// Just verify --help works with no positional arg (don't actually run in cwd).
	cmd := rootCmd()
	cmd.SetArgs([]string{"integrity", "init", "--help"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "[directory]") {
		t.Error("expected [directory] in help output")
	}
}

func TestIntegrityInit_WithSign(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	// Generate agent key.
	ks := signing.NewKeystore(ksDir)
	if _, err := ks.GenerateAgent("test-agent"); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{
		"integrity", "init", dir,
		"--sign", "--agent", "test-agent", "--keystore", ksDir,
	})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("init --sign error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "1 file") {
		t.Errorf("expected '1 file' in output, got: %q", output)
	}
	if !strings.Contains(output, "signed") || !strings.Contains(output, "test-agent") {
		t.Errorf("expected signing confirmation in output, got: %q", output)
	}

	// Verify .sig file was created.
	mPath := filepath.Join(dir, integrity.DefaultManifestFile)
	sigPath := mPath + signing.SigExtension
	if _, err := os.Stat(sigPath); err != nil {
		t.Errorf("signature file not created: %v", err)
	}
}

func TestIntegrityCheck_WithVerify(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	ks := signing.NewKeystore(ksDir)
	if _, err := ks.GenerateAgent("test-agent"); err != nil {
		t.Fatal(err)
	}

	// Init and sign.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{
		"integrity", "init", dir,
		"--sign", "--agent", "test-agent", "--keystore", ksDir,
	})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	// Check with verify — should pass.
	cmd := rootCmd()
	cmd.SetArgs([]string{
		"integrity", "check", dir,
		"--verify", "--agent", "test-agent", "--keystore", ksDir,
	})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("check --verify error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "verified") {
		t.Errorf("expected signature verified message, got: %q", output)
	}
	if !strings.Contains(output, "All files match") {
		t.Errorf("expected clean check, got: %q", output)
	}
}

func TestIntegrityCheck_VerifyTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	ks := signing.NewKeystore(ksDir)
	if _, err := ks.GenerateAgent("test-agent"); err != nil {
		t.Fatal(err)
	}

	// Init and sign.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{
		"integrity", "init", dir,
		"--sign", "--agent", "test-agent", "--keystore", ksDir,
	})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	// Tamper with the manifest file by appending data.
	mPath := filepath.Join(dir, integrity.DefaultManifestFile)
	data, err := os.ReadFile(mPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mPath, append(data, []byte("\n// tampered")...), 0o600); err != nil {
		t.Fatal(err)
	}

	// Check with verify — should fail signature verification.
	cmd := rootCmd()
	cmd.SetArgs([]string{
		"integrity", "check", dir,
		"--verify", "--agent", "test-agent", "--keystore", ksDir,
	})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for tampered manifest signature")
	}
}

func TestIntegrityUpdate_WithSign(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "original\n")

	ks := signing.NewKeystore(ksDir)
	if _, err := ks.GenerateAgent("test-agent"); err != nil {
		t.Fatal(err)
	}

	// Init without signing.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{"integrity", "init", dir})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	// Modify file.
	writeTestFile(t, dir, "file.txt", "changed\n")

	// Update with signing.
	cmd := rootCmd()
	cmd.SetArgs([]string{
		"integrity", "update", dir,
		"--sign", "--agent", "test-agent", "--keystore", ksDir,
	})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("update --sign error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "updated") {
		t.Errorf("expected 'updated' in output, got: %q", output)
	}
	if !strings.Contains(output, "signed") {
		t.Errorf("expected signing confirmation in output, got: %q", output)
	}

	// Verify the signature is valid.
	mPath := filepath.Join(dir, integrity.DefaultManifestFile)
	sigPath := mPath + signing.SigExtension
	if _, err := os.Stat(sigPath); err != nil {
		t.Errorf("signature file not created: %v", err)
	}

	// Check with verify should pass.
	checkCmd := rootCmd()
	checkCmd.SetArgs([]string{
		"integrity", "check", dir,
		"--verify", "--agent", "test-agent", "--keystore", ksDir,
	})
	checkCmd.SetOut(&strings.Builder{})
	if err := checkCmd.Execute(); err != nil {
		t.Fatalf("check --verify after update: %v", err)
	}
}

func TestIntegrityCheck_VerifyWrongAgent(t *testing.T) {
	dir := t.TempDir()
	ksDir := t.TempDir()
	writeTestFile(t, dir, "file.txt", "content\n")

	ks := signing.NewKeystore(ksDir)
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.GenerateAgent("bob"); err != nil {
		t.Fatal(err)
	}

	// Init and sign as alice.
	initCmd := rootCmd()
	initCmd.SetArgs([]string{
		"integrity", "init", dir,
		"--sign", "--agent", "alice", "--keystore", ksDir,
	})
	initCmd.SetOut(&strings.Builder{})
	if err := initCmd.Execute(); err != nil {
		t.Fatal(err)
	}

	// Check with verify as bob — should fail.
	cmd := rootCmd()
	cmd.SetArgs([]string{
		"integrity", "check", dir,
		"--verify", "--agent", "bob", "--keystore", ksDir,
	})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when verifying with wrong agent's key")
	}
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
