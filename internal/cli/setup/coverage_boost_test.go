// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// restoreDirPerms restores directory permissions for test cleanup.
// Directories need the execute bit (0o700) for traversal and removal.
// This is extracted as a helper because gosec G302 flags os.Chmod with
// permissions > 0o600, but 0o600 on a directory prevents removal.
func restoreDirPerms(dir string) { _ = os.Chmod(dir, os.ModeDir|0o700) }

// ---------------------------------------------------------------------------
// atomicWriteFile tests (64.7% -> target 100%)
// ---------------------------------------------------------------------------

func TestAtomicWriteFile(t *testing.T) {
	const (
		originalContent = "original-content"
		updatedContent  = "updated-content"
	)

	t.Run("writes file atomically with backup", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "test.json")
		if err := os.WriteFile(path, []byte(originalContent), 0o600); err != nil {
			t.Fatalf("setup: %v", err)
		}

		if err := atomicWriteFile(path, []byte(updatedContent), true); err != nil {
			t.Fatalf("atomicWriteFile: %v", err)
		}

		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read result: %v", err)
		}
		if string(got) != updatedContent {
			t.Errorf("expected %q, got %q", updatedContent, got)
		}

		bak, err := os.ReadFile(filepath.Clean(path + ".bak"))
		if err != nil {
			t.Fatalf("read backup: %v", err)
		}
		if string(bak) != originalContent {
			t.Errorf("backup should contain original, got %q", bak)
		}
	})

	t.Run("writes file atomically without backup", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "nobackup.json")
		if err := os.WriteFile(path, []byte(originalContent), 0o600); err != nil {
			t.Fatalf("setup: %v", err)
		}

		if err := atomicWriteFile(path, []byte(updatedContent), false); err != nil {
			t.Fatalf("atomicWriteFile: %v", err)
		}

		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read result: %v", err)
		}
		if string(got) != updatedContent {
			t.Errorf("expected %q, got %q", updatedContent, got)
		}

		// No backup should exist.
		if _, err := os.Stat(path + ".bak"); err == nil {
			t.Error("backup file should not exist when doBackup=false")
		}
	})

	t.Run("errors when file does not exist", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "nonexistent.json")
		err := atomicWriteFile(path, []byte("data"), false)
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
		if !strings.Contains(err.Error(), "stat") {
			t.Errorf("expected stat error, got: %v", err)
		}
	})

	t.Run("errors when backup read fails", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "unreadable.json")
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Make file unreadable after stat succeeds.
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		defer func() { _ = os.Chmod(path, 0o600) }()

		err := atomicWriteFile(path, []byte("new"), true)
		if err == nil {
			t.Fatal("expected error when file is unreadable for backup")
		}
		if !strings.Contains(err.Error(), "reading original for backup") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("errors when backup dir is read-only", func(t *testing.T) {
		dir := t.TempDir()
		subdir := filepath.Join(dir, "readonly")
		if err := os.MkdirAll(subdir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		path := filepath.Join(subdir, "test.json")
		if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Make directory no-access so the function fails on stat or backup.
		if err := os.Chmod(subdir, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { restoreDirPerms(subdir); _ = os.RemoveAll(subdir) })

		err := atomicWriteFile(path, []byte("new"), true)
		if err == nil {
			t.Fatal("expected error when directory is inaccessible")
		}
	})
}

// ---------------------------------------------------------------------------
// writeClaudeResponse tests (57.1% -> target 100%)
// ---------------------------------------------------------------------------

func TestWriteClaudeResponse_Variations(t *testing.T) {
	t.Run("marshals allow response", func(t *testing.T) {
		var buf bytes.Buffer
		resp := claudeCodeFullResponse{
			HookSpecificOutput: claudeCodeHookOutput{
				HookEventName:      claudeHookEventPreToolUse,
				PermissionDecision: decisionAllow,
			},
		}
		writeClaudeResponse(&buf, resp)

		output := strings.TrimSpace(buf.String())
		var parsed claudeCodeResponse
		if err := json.Unmarshal([]byte(output), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if parsed.HookSpecificOutput.PermissionDecision != decisionAllow {
			t.Errorf("expected allow, got %s", parsed.HookSpecificOutput.PermissionDecision)
		}
	})

	t.Run("deny response with reason", func(t *testing.T) {
		var buf bytes.Buffer
		resp := claudeCodeFullResponse{
			HookSpecificOutput: claudeCodeHookOutput{
				HookEventName:            claudeHookEventPreToolUse,
				PermissionDecision:       decisionDeny,
				PermissionDecisionReason: "secret detected",
			},
		}
		writeClaudeResponse(&buf, resp)

		output := strings.TrimSpace(buf.String())
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(output), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
	})

	t.Run("output ends with newline", func(t *testing.T) {
		var buf bytes.Buffer
		resp := claudeCodeFullResponse{
			HookSpecificOutput: claudeCodeHookOutput{
				HookEventName:      claudeHookEventPreToolUse,
				PermissionDecision: decisionAllow,
			},
		}
		writeClaudeResponse(&buf, resp)
		if !strings.HasSuffix(buf.String(), "\n") {
			t.Error("output should end with newline")
		}
	})
}

// ---------------------------------------------------------------------------
// writeResponse (cursor) tests — complements existing TestWriteResponse
// ---------------------------------------------------------------------------

func TestWriteResponse_DenyWithMessage(t *testing.T) {
	var buf bytes.Buffer
	writeResponse(&buf, cursorResponse{
		Permission:  decisionDeny,
		UserMessage: "pipelock: blocked secret",
	})
	var resp cursorResponse
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Permission != decisionDeny {
		t.Errorf("expected deny, got %s", resp.Permission)
	}
	if resp.UserMessage != "pipelock: blocked secret" {
		t.Errorf("unexpected message: %s", resp.UserMessage)
	}
}

func TestWriteResponse_EndsWithNewline(t *testing.T) {
	var buf bytes.Buffer
	writeResponse(&buf, cursorResponse{
		Permission: decisionAllow,
	})
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Error("output should end with newline")
	}
}

// ---------------------------------------------------------------------------
// writeClaudeSettingsFile tests (56% -> target 100%)
// ---------------------------------------------------------------------------

func TestWriteClaudeSettingsFile(t *testing.T) {
	newTestCmd := func() *cobra.Command {
		cmd := &cobra.Command{Use: "test"}
		cmd.SetOut(&bytes.Buffer{})
		return cmd
	}

	t.Run("creates directory and writes file", func(t *testing.T) {
		dir := t.TempDir()
		targetDir := filepath.Join(dir, "newdir", ".claude")
		targetPath := filepath.Join(targetDir, "settings.json")
		output := []byte(`{"hooks":{}}` + "\n")

		cmd := newTestCmd()
		err := writeClaudeSettingsFile(cmd, targetPath, targetDir, nil, os.ErrNotExist, output)
		if err != nil {
			t.Fatalf("writeClaudeSettingsFile: %v", err)
		}

		got, err := os.ReadFile(filepath.Clean(targetPath))
		if err != nil {
			t.Fatalf("read result: %v", err)
		}
		if string(got) != string(output) {
			t.Errorf("expected %q, got %q", output, got)
		}
	})

	t.Run("creates backup of existing file", func(t *testing.T) {
		dir := t.TempDir()
		targetDir := filepath.Join(dir, ".claude")
		if err := os.MkdirAll(targetDir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		targetPath := filepath.Join(targetDir, "settings.json")

		existingData := []byte(`{"existing": true}`)
		if err := os.WriteFile(targetPath, existingData, 0o600); err != nil {
			t.Fatalf("setup: %v", err)
		}

		newData := []byte(`{"hooks":{"PreToolUse":[]}}` + "\n")
		cmd := newTestCmd()
		err := writeClaudeSettingsFile(cmd, targetPath, targetDir, existingData, nil, newData)
		if err != nil {
			t.Fatalf("writeClaudeSettingsFile: %v", err)
		}

		// Check backup.
		bak, err := os.ReadFile(filepath.Clean(targetPath + ".bak"))
		if err != nil {
			t.Fatalf("read backup: %v", err)
		}
		if string(bak) != string(existingData) {
			t.Errorf("backup mismatch: %q", bak)
		}

		// Check new content.
		got, err := os.ReadFile(filepath.Clean(targetPath))
		if err != nil {
			t.Fatalf("read result: %v", err)
		}
		if string(got) != string(newData) {
			t.Errorf("content mismatch: %q", got)
		}

		// Check file permissions.
		info, err := os.Stat(targetPath)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("expected 0600, got %o", info.Mode().Perm())
		}
	})

	t.Run("errors on uncreateable directory", func(t *testing.T) {
		dir := t.TempDir()
		readonlyDir := filepath.Join(dir, "readonly")
		if err := os.MkdirAll(readonlyDir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(readonlyDir, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { restoreDirPerms(readonlyDir); _ = os.RemoveAll(readonlyDir) })

		targetDir := filepath.Join(readonlyDir, "subdir")
		targetPath := filepath.Join(targetDir, "settings.json")

		cmd := newTestCmd()
		err := writeClaudeSettingsFile(cmd, targetPath, targetDir, nil, os.ErrNotExist, []byte("{}"))
		if err == nil {
			t.Fatal("expected error for read-only directory")
		}
		if !strings.Contains(err.Error(), "creating directory") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("errors when backup write fails on read-only dir", func(t *testing.T) {
		dir := t.TempDir()
		targetDir := filepath.Join(dir, "rodir")
		if err := os.MkdirAll(targetDir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		targetPath := filepath.Join(targetDir, "settings.json")
		existingData := []byte(`{"existing":true}`)
		if err := os.WriteFile(targetPath, existingData, 0o600); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Make directory read-only so backup write fails.
		if err := os.Chmod(targetDir, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { restoreDirPerms(targetDir); _ = os.RemoveAll(targetDir) })

		cmd := newTestCmd()
		err := writeClaudeSettingsFile(cmd, targetPath, targetDir, existingData, nil, []byte("new"))
		if err == nil {
			t.Fatal("expected error when backup write fails")
		}
		if !strings.Contains(err.Error(), "creating backup") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// marshalClaudeSettings tests (80% -> target 100%)
// ---------------------------------------------------------------------------

func TestMarshalClaudeSettings_Coverage(t *testing.T) {
	t.Run("preserves unknown fields", func(t *testing.T) {
		rawMap := map[string]json.RawMessage{
			"theme":     json.RawMessage(`"dark"`),
			"telemetry": json.RawMessage(`false`),
		}
		settings := &claudeSettings{
			Hooks: map[string][]claudeMatcherGroup{
				"PreToolUse": {{Matcher: "Bash", Hooks: []claudeHookEntry{
					{Type: "command", Command: "echo test"},
				}}},
			},
		}

		data, err := marshalClaudeSettings(settings, rawMap)
		if err != nil {
			t.Fatalf("marshalClaudeSettings: %v", err)
		}

		var parsed map[string]json.RawMessage
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if string(parsed["theme"]) != `"dark"` {
			t.Errorf("theme not preserved: %s", parsed["theme"])
		}
		if string(parsed["telemetry"]) != `false` {
			t.Errorf("telemetry not preserved: %s", parsed["telemetry"])
		}
		if _, ok := parsed["hooks"]; !ok {
			t.Error("hooks section missing")
		}
	})

	t.Run("creates rawMap when nil", func(t *testing.T) {
		settings := &claudeSettings{
			Hooks: map[string][]claudeMatcherGroup{},
		}
		data, err := marshalClaudeSettings(settings, nil)
		if err != nil {
			t.Fatalf("marshalClaudeSettings: %v", err)
		}
		if !strings.Contains(string(data), "hooks") {
			t.Error("expected hooks in output")
		}
	})

	t.Run("output ends with newline", func(t *testing.T) {
		settings := &claudeSettings{Hooks: map[string][]claudeMatcherGroup{}}
		data, err := marshalClaudeSettings(settings, nil)
		if err != nil {
			t.Fatalf("marshalClaudeSettings: %v", err)
		}
		if data[len(data)-1] != '\n' {
			t.Error("output should end with newline")
		}
	})
}

// ---------------------------------------------------------------------------
// vscodeAtomicWrite tests (50% -> target 100%)
// ---------------------------------------------------------------------------

func TestVscodeAtomicWrite(t *testing.T) {
	const testContent = `{"servers":{}}`

	t.Run("writes file with correct permissions", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "mcp.json")

		if err := vscodeAtomicWrite(path, []byte(testContent), dir); err != nil {
			t.Fatalf("vscodeAtomicWrite: %v", err)
		}

		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != testContent {
			t.Errorf("expected %q, got %q", testContent, got)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("expected 0600, got %o", info.Mode().Perm())
		}
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "mcp.json")
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatalf("setup: %v", err)
		}

		newContent := `{"servers":{"a":{}}}`
		if err := vscodeAtomicWrite(path, []byte(newContent), dir); err != nil {
			t.Fatalf("vscodeAtomicWrite: %v", err)
		}

		got, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != newContent {
			t.Errorf("expected %q, got %q", newContent, got)
		}
	})

	t.Run("errors when temp dir is read-only", func(t *testing.T) {
		dir := t.TempDir()
		readonlyDir := filepath.Join(dir, "readonly")
		if err := os.MkdirAll(readonlyDir, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(readonlyDir, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { restoreDirPerms(readonlyDir); _ = os.RemoveAll(readonlyDir) })

		path := filepath.Join(readonlyDir, "mcp.json")
		err := vscodeAtomicWrite(path, []byte("data"), readonlyDir)
		if err == nil {
			t.Fatal("expected error for read-only dir")
		}
		if !strings.Contains(err.Error(), "creating temp file") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// marshalVscodeConfig tests (82.4% -> target 100%)
// ---------------------------------------------------------------------------

func TestMarshalVscodeConfig_Coverage(t *testing.T) {
	t.Run("preserves unknown top-level fields", func(t *testing.T) {
		original := []byte(`{"servers":{},"inputs":[{"type":"secret"}],"customField":"value"}`)
		cfg := &vscodeMCPConfig{
			Servers: map[string]map[string]interface{}{
				"test": {
					"command": "test-cmd",
					"args":    []interface{}{"arg1"},
				},
			},
			Inputs: json.RawMessage(`[{"type":"secret"}]`),
		}

		data, err := marshalVscodeConfig(original, cfg)
		if err != nil {
			t.Fatalf("marshalVscodeConfig: %v", err)
		}

		var parsed map[string]json.RawMessage
		if err := json.Unmarshal(data, &parsed); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if string(parsed["customField"]) != `"value"` {
			t.Errorf("customField not preserved: %s", parsed["customField"])
		}
	})

	t.Run("marshals from scratch when no original", func(t *testing.T) {
		cfg := &vscodeMCPConfig{
			Servers: map[string]map[string]interface{}{
				"s1": {"command": "cmd1"},
			},
		}

		data, err := marshalVscodeConfig(nil, cfg)
		if err != nil {
			t.Fatalf("marshalVscodeConfig: %v", err)
		}
		if !strings.Contains(string(data), "cmd1") {
			t.Error("expected cmd1 in output")
		}
	})

	t.Run("marshals from scratch when original is invalid JSON", func(t *testing.T) {
		cfg := &vscodeMCPConfig{
			Servers: map[string]map[string]interface{}{
				"s1": {"command": "cmd1"},
			},
		}

		data, err := marshalVscodeConfig([]byte("{invalid"), cfg)
		if err != nil {
			t.Fatalf("marshalVscodeConfig: %v", err)
		}
		if !strings.Contains(string(data), "cmd1") {
			t.Error("expected cmd1 in output")
		}
	})

	t.Run("output ends with newline", func(t *testing.T) {
		cfg := &vscodeMCPConfig{
			Servers: map[string]map[string]interface{}{},
		}
		data, err := marshalVscodeConfig(nil, cfg)
		if err != nil {
			t.Fatalf("marshalVscodeConfig: %v", err)
		}
		if data[len(data)-1] != '\n' {
			t.Error("expected trailing newline")
		}
	})
}
