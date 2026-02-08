package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKey builds a test credential at runtime to avoid gitleaks false positives.
func fakeKey(suffix string) string {
	return "AK" + "IA" + "IOSFODNN7" + suffix
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
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -1,2 +1,3 @@
 package main
+import "fmt"

`
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
	key := fakeKey("EXAMPLE")
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
