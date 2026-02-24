package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/gitprotect"
)

const cleanDiff = `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,2 +1,3 @@
 package main
+import "fmt"

`

// fakeKey builds a test credential at runtime to avoid gitleaks false positives.
func fakeKey() string {
	return "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
}

func TestGitCmd_Help(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "--help"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "scan-diff") {
		t.Error("expected help to list scan-diff command")
	}
	if !strings.Contains(output, "install-hooks") {
		t.Error("expected help to list install-hooks command")
	}
}

func TestGitCmd_InRootHelp(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--help"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "git") {
		t.Error("expected root help to list 'git' command")
	}
}

func TestScanDiffCmd_CleanDiff(t *testing.T) {
	diff := cleanDiff
	r, w, _ := os.Pipe()
	_, _ = w.WriteString(diff)
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error for clean diff, got: %v", err)
	}
}

func TestScanDiffCmd_FindsSecret(t *testing.T) {
	key := fakeKey()
	diff := fmt.Sprintf(`diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -1,2 +1,3 @@
 package config
+var key = "%s"

`, key)

	r, w, _ := os.Pipe()
	_, _ = w.WriteString(diff)
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when secrets found")
	}
	if !errors.Is(err, ErrSecretsFound) {
		t.Fatalf("expected ErrSecretsFound, got: %v", err)
	}
}

func TestScanDiffCmd_EmptyStdin(t *testing.T) {
	r, w, _ := os.Pipe()
	_ = w.Close() // empty stdin

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error for empty stdin, got: %v", err)
	}
}

func TestInstallHooksCmd_CreatesHook(t *testing.T) {
	// Create a fake git repo
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Change to the fake repo dir
	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-push")
	data, err := os.ReadFile(hookPath) //nolint:gosec // test reads its own temp file
	if err != nil {
		t.Fatalf("hook file not created: %v", err)
	}

	content := string(data)
	if !strings.HasPrefix(content, "#!/bin/sh") {
		t.Error("hook should start with shebang")
	}
	if !strings.Contains(content, "scan-diff") {
		t.Error("hook should contain scan-diff command")
	}

	// Verify file is executable
	info, _ := os.Stat(hookPath)
	if info.Mode()&0o111 == 0 {
		t.Error("hook file should be executable")
	}
}

func TestInstallHooksCmd_ExistingHookBlocked(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(gitDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Create existing hook
	hookPath := filepath.Join(gitDir, "pre-push")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // test file
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when hook already exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}

func TestInstallHooksCmd_ForceOverwrite(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git", "hooks")
	if err := os.MkdirAll(gitDir, 0o750); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(gitDir, "pre-push")
	if err := os.WriteFile(hookPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // test file
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks", "--force"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected --force to succeed, got: %v", err)
	}

	data, _ := os.ReadFile(hookPath) //nolint:gosec // test reads its own temp file
	if !strings.Contains(string(data), "scan-diff") {
		t.Error("hook should have been overwritten with pipelock content")
	}
}

func TestInstallHooksCmd_NoGitDir(t *testing.T) {
	dir := t.TempDir() // no .git directory

	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when not in git repo")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("expected 'not a git repository' error, got: %v", err)
	}
}

func TestInstallHooksCmd_GitFile_Worktree(t *testing.T) {
	// Simulate a git worktree where .git is a file pointing to the real gitdir
	dir := t.TempDir()
	realGitDir := filepath.Join(dir, "real-gitdir")
	if err := os.MkdirAll(realGitDir, 0o750); err != nil {
		t.Fatal(err)
	}

	worktreeDir := filepath.Join(dir, "worktree")
	if err := os.MkdirAll(worktreeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Write .git file that points to the real gitdir
	gitFile := filepath.Join(worktreeDir, ".git")
	if err := os.WriteFile(gitFile, []byte("gitdir: "+realGitDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	_ = os.Chdir(worktreeDir)
	defer func() { _ = os.Chdir(oldDir) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error for worktree .git file: %v", err)
	}

	hookPath := filepath.Join(realGitDir, "hooks", "pre-push")
	data, err := os.ReadFile(hookPath) //nolint:gosec // test reads its own temp file
	if err != nil {
		t.Fatalf("hook file not created in worktree gitdir: %v", err)
	}
	if !strings.Contains(string(data), "scan-diff") {
		t.Error("hook should contain scan-diff command")
	}
}

func TestInstallHooksCmd_WithBinary(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o750); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks", "--binary", "/usr/local/bin/pipelock"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-push")
	data, _ := os.ReadFile(hookPath) //nolint:gosec // test reads its own temp file
	if !strings.Contains(string(data), "/usr/local/bin/pipelock") {
		t.Error("hook should contain the custom binary path")
	}
}

func TestResolveGitFile_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	gitFilePath := filepath.Join(dir, ".git")

	// Write a .git file without the "gitdir: " prefix.
	if err := os.WriteFile(gitFilePath, []byte("not a valid git pointer\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := resolveGitFile(gitFilePath, dir)
	if err == nil {
		t.Fatal("expected error for invalid .git file content")
	}
	if !strings.Contains(err.Error(), "invalid .git file") {
		t.Errorf("expected 'invalid .git file' error, got: %v", err)
	}
}

func TestResolveGitFile_NonexistentGitdir(t *testing.T) {
	dir := t.TempDir()
	gitFilePath := filepath.Join(dir, ".git")

	// Write a .git file pointing to a nonexistent directory.
	if err := os.WriteFile(gitFilePath, []byte("gitdir: /nonexistent/gitdir/path\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := resolveGitFile(gitFilePath, dir)
	if err == nil {
		t.Fatal("expected error for nonexistent gitdir path")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("expected 'does not exist' error, got: %v", err)
	}
}

func TestResolveGitFile_RelativePath(t *testing.T) {
	dir := t.TempDir()

	// Create a real gitdir directory at a relative path.
	realGitDir := filepath.Join(dir, "sub", "real-gitdir")
	if err := os.MkdirAll(realGitDir, 0o750); err != nil {
		t.Fatal(err)
	}

	gitFilePath := filepath.Join(dir, ".git")
	// Write a .git file with a relative path.
	if err := os.WriteFile(gitFilePath, []byte("gitdir: sub/real-gitdir\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := resolveGitFile(gitFilePath, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != realGitDir {
		t.Errorf("expected %q, got %q", realGitDir, result)
	}
}

func TestResolveGitFile_AbsolutePath(t *testing.T) {
	dir := t.TempDir()

	// Create a real gitdir directory at an absolute path.
	realGitDir := filepath.Join(dir, "absolute-gitdir")
	if err := os.MkdirAll(realGitDir, 0o750); err != nil {
		t.Fatal(err)
	}

	gitFilePath := filepath.Join(dir, ".git")
	// Write a .git file with an absolute path.
	if err := os.WriteFile(gitFilePath, []byte("gitdir: "+realGitDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := resolveGitFile(gitFilePath, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != realGitDir {
		t.Errorf("expected %q, got %q", realGitDir, result)
	}
}

func TestResolveGitFile_PointsToFile(t *testing.T) {
	dir := t.TempDir()

	// Create a regular file (not a directory) where the gitdir should be.
	notADir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(notADir, []byte("just a file"), 0o600); err != nil {
		t.Fatal(err)
	}

	gitFilePath := filepath.Join(dir, ".git-pointer")
	if err := os.WriteFile(gitFilePath, []byte("gitdir: "+notADir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := resolveGitFile(gitFilePath, dir)
	if err == nil {
		t.Fatal("expected error when gitdir points to a file, not a directory")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %v", err)
	}
}

func TestScanDiffCmd_WithConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pipelock.yaml")

	yaml := `
version: 1
mode: balanced
api_allowlist:
  - "*.anthropic.com"
fetch_proxy:
  listen: "127.0.0.1:9999"
  timeout_seconds: 15
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	diff := cleanDiff
	r, w, _ := os.Pipe()
	_, _ = w.WriteString(diff)
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--config", cfgPath})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error for clean diff with config, got: %v", err)
	}
}

func TestScanDiffCmd_InvalidConfig(t *testing.T) {
	r, w, _ := os.Pipe()
	_, _ = w.WriteString("some diff\n")
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--config", "/nonexistent/config.yaml"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
}

func TestInstallHooksCmd_WithConfig(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o750); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks", "--config", "/etc/pipelock.yaml"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-push")
	data, _ := os.ReadFile(hookPath) //nolint:gosec // test reads its own temp file
	if !strings.Contains(string(data), "/etc/pipelock.yaml") {
		t.Error("hook should contain the config path")
	}
}

func TestScanDiffCmd_JSON_CleanDiff(t *testing.T) {
	diff := cleanDiff
	r, w, _ := os.Pipe()
	_, _ = w.WriteString(diff)
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--json"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != "[]" {
		t.Errorf("expected [], got %q", output)
	}
}

func TestScanDiffCmd_JSON_FindsSecret(t *testing.T) {
	key := fakeKey()
	diff := fmt.Sprintf(`diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -1,2 +1,3 @@
 package config
+var key = "%s"

`, key)

	r, w, _ := os.Pipe()
	_, _ = w.WriteString(diff)
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--json"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if !errors.Is(err, ErrSecretsFound) {
		t.Fatalf("expected ErrSecretsFound, got: %v", err)
	}

	var findings []gitprotect.Finding
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &findings); err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %q", err, buf.String())
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].File != "config.go" {
		t.Errorf("expected file config.go, got %q", findings[0].File)
	}
	if findings[0].Pattern == "" {
		t.Error("expected non-empty pattern")
	}
}

func TestScanDiffCmd_JSON_EmptyStdin(t *testing.T) {
	r, w, _ := os.Pipe()
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--json"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != "[]" {
		t.Errorf("expected [] for empty stdin, got %q", output)
	}
}

func TestInstallHooksCmd_ReadOnlyGitDir(t *testing.T) {
	// MkdirAll for hooks dir fails when .git is read-only.
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	// Make .git dir read-only so MkdirAll("hooks") fails.
	if err := os.Chmod(gitDir, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(gitDir, 0o700) }) //nolint:gosec // restore

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for read-only .git dir")
	}
	if !strings.Contains(err.Error(), "creating hooks directory") {
		t.Errorf("expected 'creating hooks directory' error, got: %v", err)
	}
}

func TestInstallHooksCmd_ReadOnlyHooksDir(t *testing.T) {
	// WriteFile fails when hooks dir exists but is read-only.
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	// Make hooks dir read-only so WriteFile fails.
	if err := os.Chmod(hooksDir, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hooksDir, 0o700) }) //nolint:gosec // restore

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for read-only hooks dir")
	}
	if !strings.Contains(err.Error(), "writing hook") {
		t.Errorf("expected 'writing hook' error, got: %v", err)
	}
}

func TestResolveGitFile_Unreadable(t *testing.T) {
	dir := t.TempDir()
	gitFile := filepath.Join(dir, ".git")
	if err := os.WriteFile(gitFile, []byte("gitdir: ../somewhere"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Make .git file unreadable.
	if err := os.Chmod(gitFile, 0o000); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(gitFile, 0o600) }) //nolint:gosec // restore

	_, err := resolveGitFile(gitFile, dir)
	if err == nil {
		t.Fatal("expected error for unreadable .git file")
	}
	if !strings.Contains(err.Error(), "reading .git file") {
		t.Errorf("expected 'reading .git file' error, got: %v", err)
	}
}

func TestScanDiffCmd_ExcludePaths(t *testing.T) {
	key := fakeKey()
	diff := fmt.Sprintf(`diff --git a/vendor/lib.go b/vendor/lib.go
--- a/vendor/lib.go
+++ b/vendor/lib.go
@@ -1,2 +1,3 @@
 package lib
+var key = "%s"

`, key)

	r, w, _ := os.Pipe()
	_, _ = w.WriteString(diff)
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--exclude", "vendor/"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// Should succeed because the finding in vendor/ is excluded
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error with excluded path, got: %v", err)
	}
}

func TestScanDiffCmd_ExcludeGlob(t *testing.T) {
	key := fakeKey()
	diff := fmt.Sprintf(`diff --git a/pkg/gen.pb.go b/pkg/gen.pb.go
--- a/pkg/gen.pb.go
+++ b/pkg/gen.pb.go
@@ -1,2 +1,3 @@
 package pkg
+var key = "%s"

`, key)

	r, w, _ := os.Pipe()
	_, _ = w.WriteString(diff)
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--json", "--exclude", "*.pb.go"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error with excluded glob, got: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output != "[]" {
		t.Errorf("expected empty findings [], got %q", output)
	}
}

func TestScanDiffCmd_ExcludeDoesNotAffectOtherFiles(t *testing.T) {
	key := fakeKey()
	diff := fmt.Sprintf(`diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -1,2 +1,3 @@
 package config
+var key = "%s"

`, key)

	r, w, _ := os.Pipe()
	_, _ = w.WriteString(diff)
	_ = w.Close()

	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "scan-diff", "--exclude", "vendor/"})

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	// config.go is NOT excluded, so the secret should still be found
	err := cmd.Execute()
	if !errors.Is(err, ErrSecretsFound) {
		t.Fatalf("expected ErrSecretsFound for non-excluded file, got: %v", err)
	}
}

func TestInstallHooksCmd_BadGitFile(t *testing.T) {
	// .git is a file with invalid content (no "gitdir: " prefix).
	// This exercises the findGitDir → resolveGitFile error path.
	dir := t.TempDir()
	gitFile := filepath.Join(dir, ".git")
	if err := os.WriteFile(gitFile, []byte("garbage content\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldDir, _ := os.Getwd()
	_ = os.Chdir(dir)
	defer func() { _ = os.Chdir(oldDir) }()

	cmd := rootCmd()
	cmd.SetArgs([]string{"git", "install-hooks"})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid .git file content")
	}
}
