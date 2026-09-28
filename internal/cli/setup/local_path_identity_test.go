// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// hookAliasFixture builds a disposable home with a protected file and a
// workspace symlink that resolves to it, and points HOME at it.
func hookAliasFixture(t *testing.T, protectedRel string) (alias, plain string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixtures need POSIX link semantics")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	ws := filepath.Join(root, "ws")
	protected := filepath.Join(home, protectedRel)
	for _, dir := range []string{filepath.Dir(protected), ws} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{protected, filepath.Join(ws, "plain.txt")} {
		if err := os.WriteFile(file, []byte("baseline\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alias = filepath.Join(ws, "notes.txt")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return alias, filepath.Join(ws, "plain.txt")
}

func TestClaudeHookCmd_WriteThroughSymlinkToProtectedFile(t *testing.T) {
	alias, plain := hookAliasFixture(t, ".bashrc")
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: alias, want: decisionDeny},
		{path: plain, want: decisionAllow},
	} {
		input := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":` +
			strconv.Quote(tc.path) + `,"content":"echo hi"},"tool_use_id":"t1"}`
		cmd := ClaudeCmd()
		cmd.SetArgs([]string{"hook"})
		cmd.SetIn(bytes.NewReader([]byte(input)))
		buf := &strings.Builder{}
		cmd.SetOut(buf)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var resp claudeCodeResponse
		if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
			t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
		}
		if got := resp.HookSpecificOutput.PermissionDecision; got != tc.want {
			t.Errorf("Write %s: decision %s, want %s (%s)", filepath.Base(tc.path), got, tc.want,
				resp.HookSpecificOutput.PermissionDecisionReason)
		}
	}
}

func TestCursorHookCmd_ReadThroughSymlinkToCredential(t *testing.T) {
	alias, plain := hookAliasFixture(t, filepath.Join(".ssh", "id_ed25519"))
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: alias, want: decisionDeny},
		{path: plain, want: decisionAllow},
	} {
		input := `{"hook_event_name":"beforeReadFile","file_path":` + strconv.Quote(tc.path) +
			`,"content":"","conversation_id":"abc","generation_id":"def"}`
		cmd := CursorCmd()
		cmd.SetArgs([]string{"hook"})
		cmd.SetIn(bytes.NewReader([]byte(input)))
		buf := &strings.Builder{}
		cmd.SetOut(buf)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var resp cursorResponse
		if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &resp); err != nil {
			t.Fatalf("output not valid JSON: %v\noutput: %s", err, buf.String())
		}
		if resp.Permission != tc.want {
			t.Errorf("read %s: permission %s, want %s", filepath.Base(tc.path), resp.Permission, tc.want)
		}
	}
}
