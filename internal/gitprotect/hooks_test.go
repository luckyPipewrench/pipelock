package gitprotect

import (
	"strings"
	"testing"
)

func TestGeneratePrePushHook_DefaultBinary(t *testing.T) {
	hook := GeneratePrePushHook("pipelock", "")
	if !strings.HasPrefix(hook, "#!/bin/sh") {
		t.Error("hook should start with shebang")
	}
	if strings.Contains(hook, "set -e") {
		t.Error("hook should not use set -e (causes dead code with explicit error handling)")
	}
	if !strings.Contains(hook, "git scan-diff") {
		t.Error("hook should invoke git scan-diff")
	}
	// Should NOT have --config flag when configPath is empty
	if strings.Contains(hook, "--config") {
		t.Error("hook should not contain --config when configPath is empty")
	}
}

func TestGeneratePrePushHook_WithConfigPath(t *testing.T) {
	hook := GeneratePrePushHook("pipelock", "/etc/pipelock.yaml")
	if !strings.Contains(hook, "--config") {
		t.Error("hook should contain --config when configPath is set")
	}
	if !strings.Contains(hook, "/etc/pipelock.yaml") {
		t.Error("hook should contain the config path")
	}
}

func TestGeneratePrePushHook_BinaryQuoted(t *testing.T) {
	// Binary with spaces should be safely single-quoted (POSIX shell)
	hook := GeneratePrePushHook("/path/to/my pipelock", "")
	if !strings.Contains(hook, `'/path/to/my pipelock'`) {
		t.Errorf("binary path with spaces should be single-quoted, got:\n%s", hook)
	}
}

func TestGeneratePrePushHook_SingleQuoteEscaped(t *testing.T) {
	// Binary with single quotes should be safely escaped
	hook := GeneratePrePushHook("pipe'lock", "")
	if !strings.Contains(hook, `'pipe'"'"'lock'`) {
		t.Errorf("single quotes in binary should be escaped, got:\n%s", hook)
	}
}

func TestGeneratePrePushHook_ConfigQuoted(t *testing.T) {
	hook := GeneratePrePushHook("pipelock", "/path/to/my config.yaml")
	if !strings.Contains(hook, `'/path/to/my config.yaml'`) {
		t.Errorf("config path with spaces should be single-quoted, got:\n%s", hook)
	}
}

func TestGeneratePrePushHook_FailClosed(t *testing.T) {
	hook := GeneratePrePushHook("pipelock", "")
	// Should fail-closed when binary not found
	if !strings.Contains(hook, "exit 1") {
		t.Error("hook should exit 1 when binary not found")
	}
}

func TestGeneratePrePushHook_SkipsBranchDeletion(t *testing.T) {
	hook := GeneratePrePushHook("pipelock", "")
	if !strings.Contains(hook, "Deleting a branch") {
		t.Error("hook should handle branch deletion (skip)")
	}
}

func TestGeneratePrePushHook_HandlesNewBranch(t *testing.T) {
	hook := GeneratePrePushHook("pipelock", "")
	if !strings.Contains(hook, "empty_tree") {
		t.Error("hook should handle new branches by diffing against empty tree")
	}
}

func TestGeneratePrePushHook_ExplicitErrorHandling(t *testing.T) {
	hook := GeneratePrePushHook("pipelock", "")
	// Should use if ! cmd pattern instead of set -e + $?
	if !strings.Contains(hook, "if ! git diff") {
		t.Error("hook should use 'if ! cmd' pattern for error handling")
	}
	if strings.Contains(hook, "$? -ne 0") {
		t.Error("hook should not use $? check (incompatible with set -e)")
	}
}
