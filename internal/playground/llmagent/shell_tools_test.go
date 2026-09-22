// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package llmagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func toolByName(tools []Tool, name string) (Tool, bool) {
	for _, tl := range tools {
		if tl.Name == name {
			return tl, true
		}
	}
	return Tool{}, false
}

func TestShellTools_RunCommandGatedByAllowExec(t *testing.T) {
	// Off by default: run_command must NOT be offered. An arbitrary shell's egress
	// is bounded only by host kernel containment, so it must never be available on
	// a host the operator has not declared contained.
	off := shellTools(t.TempDir(), false, 0)
	if _, ok := toolByName(off, ToolRunCommand); ok {
		t.Fatal("run_command must not be present when allowExec is false")
	}
	// read_file/list_dir never egress, so they are always offered.
	if _, ok := toolByName(off, ToolReadFile); !ok {
		t.Fatal("read_file must always be present")
	}
	if _, ok := toolByName(off, ToolListDir); !ok {
		t.Fatal("list_dir must always be present")
	}

	on := shellTools(t.TempDir(), true, 0)
	if _, ok := toolByName(on, ToolRunCommand); !ok {
		t.Fatal("run_command must be present when allowExec is true")
	}
}

func TestRunCommand_RunsInScratchAndCapturesOutput(t *testing.T) {
	scratch := t.TempDir()
	rc, ok := toolByName(shellTools(scratch, true, 0), ToolRunCommand)
	if !ok {
		t.Fatal("run_command missing")
	}
	args, _ := json.Marshal(map[string]string{"command": "echo hello && pwd"})
	result, ev := rc.Invoke(context.Background(), args)
	if !strings.Contains(result, "hello") {
		t.Fatalf("output missing echo: %q", result)
	}
	// cmd.Dir is scratch; pwd should resolve under it (macOS symlinks /tmp, so
	// compare the base name rather than the full path).
	if !strings.Contains(result, filepath.Base(scratch)) {
		t.Fatalf("command did not run in scratch dir: %q", result)
	}
	if ev.Kind != EventToolResult || ev.Tool != ToolRunCommand || ev.Note != "ran" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Detail != "shell command" {
		t.Fatalf("run_command event detail = %q, want generic shell detail", ev.Detail)
	}
}

func TestRunCommand_NonzeroExitReported(t *testing.T) {
	rc, _ := toolByName(shellTools(t.TempDir(), true, 0), ToolRunCommand)
	args, _ := json.Marshal(map[string]string{"command": "exit 3"})
	_, ev := rc.Invoke(context.Background(), args)
	if ev.Note != "exited nonzero" {
		t.Fatalf("note = %q, want exited nonzero", ev.Note)
	}
}

func TestRunCommand_Timeout(t *testing.T) {
	rc, _ := toolByName(shellTools(t.TempDir(), true, 100*time.Millisecond), ToolRunCommand)
	args, _ := json.Marshal(map[string]string{"command": "sleep 5"})
	start := time.Now()
	_, ev := rc.Invoke(context.Background(), args)
	if ev.Note != "timed out" {
		t.Fatalf("note = %q, want timed out", ev.Note)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout did not bound the command")
	}
}

func TestRunCommand_BadArgs(t *testing.T) {
	rc, _ := toolByName(shellTools(t.TempDir(), true, 0), ToolRunCommand)
	for _, bad := range []string{`{}`, `{"command":""}`, `not json`} {
		result, ev := rc.Invoke(context.Background(), json.RawMessage(bad))
		if !strings.Contains(result, "needs") || ev.Note != "bad arguments" {
			t.Fatalf("bad args %q: result=%q ev=%+v", bad, result, ev)
		}
	}
}

func TestRunCommand_OutputCapped(t *testing.T) {
	rc, _ := toolByName(shellTools(t.TempDir(), true, 0), ToolRunCommand)
	// Emit far more than the cap; the result must be truncated with the marker.
	args, _ := json.Marshal(map[string]string{"command": "head -c 100000 /dev/zero | tr '\\0' 'a'"})
	result, _ := rc.Invoke(context.Background(), args)
	if len(result) > maxCommandOutputBytes+8 {
		t.Fatalf("output not capped: %d bytes", len(result))
	}
	if !strings.HasSuffix(result, "…") {
		t.Fatal("capped output should end with the truncation marker")
	}
}

func TestReadFile_RelativeResolvesToScratch(t *testing.T) {
	scratch := t.TempDir()
	if err := os.WriteFile(filepath.Join(scratch, "creds.txt"), []byte("AKIA"+"DEADBEEF"), 0o600); err != nil {
		t.Fatal(err)
	}
	rf, _ := toolByName(shellTools(scratch, false, 0), ToolReadFile)
	args, _ := json.Marshal(map[string]string{"path": "creds.txt"})
	result, ev := rf.Invoke(context.Background(), args)
	if !strings.Contains(result, "AKIA") {
		t.Fatalf("read result = %q", result)
	}
	if ev.Note != "read" {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestReadFile_Missing(t *testing.T) {
	rf, _ := toolByName(shellTools(t.TempDir(), false, 0), ToolReadFile)
	args, _ := json.Marshal(map[string]string{"path": "nope.txt"})
	result, ev := rf.Invoke(context.Background(), args)
	if !strings.Contains(result, "could not read") || ev.Note != "read error" {
		t.Fatalf("result=%q ev=%+v", result, ev)
	}
}

func TestReadFile_BadArgs(t *testing.T) {
	rf, _ := toolByName(shellTools(t.TempDir(), false, 0), ToolReadFile)
	result, ev := rf.Invoke(context.Background(), json.RawMessage(`{"path":""}`))
	if !strings.Contains(result, "needs") || ev.Note != "bad arguments" {
		t.Fatalf("result=%q ev=%+v", result, ev)
	}
}

func TestReadFile_Capped(t *testing.T) {
	scratch := t.TempDir()
	big := strings.Repeat("x", maxReadFileBytes+500)
	if err := os.WriteFile(filepath.Join(scratch, "big.txt"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	rf, _ := toolByName(shellTools(scratch, false, 0), ToolReadFile)
	args, _ := json.Marshal(map[string]string{"path": "big.txt"})
	result, _ := rf.Invoke(context.Background(), args)
	if len(result) > maxReadFileBytes+8 {
		t.Fatalf("read not capped: %d", len(result))
	}
}

func TestListDir_ListsScratchByDefault(t *testing.T) {
	scratch := t.TempDir()
	_ = os.WriteFile(filepath.Join(scratch, "a.txt"), []byte("x"), 0o600)
	_ = os.Mkdir(filepath.Join(scratch, "sub"), 0o750)
	ld, _ := toolByName(shellTools(scratch, false, 0), ToolListDir)
	result, ev := ld.Invoke(context.Background(), json.RawMessage(`{}`))
	if !strings.Contains(result, "a.txt") || !strings.Contains(result, "sub/") {
		t.Fatalf("listing = %q", result)
	}
	if ev.Note != "listed" {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestListDir_EmptyAndMissing(t *testing.T) {
	scratch := t.TempDir()
	ld, _ := toolByName(shellTools(scratch, false, 0), ToolListDir)
	result, _ := ld.Invoke(context.Background(), json.RawMessage(``))
	if result != "(empty directory)" {
		t.Fatalf("empty listing = %q", result)
	}
	missing, ev := ld.Invoke(context.Background(), json.RawMessage(`{"path":"does-not-exist"}`))
	if !strings.Contains(missing, "could not list") || ev.Note != "list error" {
		t.Fatalf("missing dir: result=%q ev=%+v", missing, ev)
	}
}

func TestListDir_BadArgs(t *testing.T) {
	ld, _ := toolByName(shellTools(t.TempDir(), false, 0), ToolListDir)
	result, ev := ld.Invoke(context.Background(), json.RawMessage(`not json`))
	if !strings.Contains(result, "not valid JSON") || ev.Note != "bad arguments" {
		t.Fatalf("result=%q ev=%+v", result, ev)
	}
}

func TestResolveScratchPath(t *testing.T) {
	const scratch = "/tmp/scratch"
	cases := []struct {
		in, want string
	}{
		{"~", scratch},
		{"~/.aws/credentials", filepath.Join(scratch, ".aws/credentials")},
		{".aws/credentials", filepath.Join(scratch, ".aws/credentials")},
		{"/etc/passwd", "/etc/passwd"},                       // absolute passes through (demo realism)
		{"~notuser/x", filepath.Join(scratch, "~notuser/x")}, // only a bare ~ or ~/ expands
	}
	for _, tc := range cases {
		if got := resolveScratchPath(scratch, tc.in); got != tc.want {
			t.Errorf("resolveScratchPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := resolveScratchPath("", "~/.aws"); got != "~/.aws" {
		t.Errorf("empty scratch should pass through, got %q", got)
	}
}
