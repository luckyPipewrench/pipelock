// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadToolsListRejectsMalformedPolicyLines(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for name, body := range map[string]string{
		"bad name":        "bad name\t/bin/true\n",
		"missing tab":     "tool\n",
		"relative target": "tool\trelative/bin\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(env.toolsListPath, []byte(body), 0o600); err != nil {
				t.Fatalf("write tools.list: %v", err)
			}
			if _, err := readToolsList(env); err == nil || !strings.Contains(err.Error(), "malformed tools.list") {
				t.Fatalf("err: %v", err)
			}
		})
	}
}

func TestRunAddToolAutoResolvedTargetIsPinned(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	target, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	runner.on(argvFor(testSudoCmd, "-n", "-u", "pipelock-agent", "--", "which", "discovered"), target+"\n", 0, nil)
	if err := runAddTool(context.Background(), env, "discovered", addToolOpts{}); err != nil {
		t.Fatalf("add tool: %v", err)
	}
	entries, err := readToolsList(env)
	if err != nil {
		t.Fatalf("read tools.list: %v", err)
	}
	for _, entry := range entries {
		if entry.name == "discovered" {
			if entry.target != target {
				t.Fatalf("auto-resolved target not pinned: got %q want %q", entry.target, target)
			}
			return
		}
	}
	t.Fatalf("missing discovered entry: %+v", entries)
}

func TestRunAddToolRejectsSymlinkTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	link := filepath.Join(t.TempDir(), "tool-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err = runAddTool(context.Background(), env, "linked", addToolOpts{target: link})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink target rejection, got %v", err)
	}
}

func TestPrivilegedWritesRejectSymlinkTargets(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(env.configDir, "target")
	link := filepath.Join(env.configDir, "link")
	if err := os.WriteFile(target, []byte("original-bytes"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := backupAndWrite(env, link, []byte("new"), 0o600); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	got, err := os.ReadFile(target) //nolint:gosec // tmpdir-scoped test path
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "original-bytes" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

func TestWriteFileAtomicWritesModeAndReportsBadParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.txt")
	if err := writeFileAtomic(path, []byte("body"), 0o600); err != nil {
		t.Fatalf("write atomic: %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "body" {
		t.Fatalf("body: %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%s want 0o600", got)
	}
	if err := writeFileAtomic(filepath.Join(dir, "missing", "file"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected missing parent error")
	}
}

func TestEnsureSafeDirectoryRejectsBadPaths(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := ensureSafeDirectory(env, "relative"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative err: %v", err)
	}
	root := t.TempDir()
	filePath := filepath.Join(root, "not-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := ensureSafeDirectory(env, filePath); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file err: %v", err)
	}
	realParent := filepath.Join(root, "real")
	if err := os.MkdirAll(realParent, 0o750); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	linkParent := filepath.Join(root, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	if err := ensureSafeDirectory(env, filepath.Join(linkParent, "child")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink parent err: %v", err)
	}
}

func TestWriteToolsListRejectsSymlinkTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "outside-tools.list")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Remove(env.toolsListPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove old tools.list: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(env.toolsListPath), 0o750); err != nil {
		t.Fatalf("mkdir tools.list parent: %v", err)
	}
	if err := os.Symlink(target, env.toolsListPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := writeToolsList(env, []toolsListEntry{{name: "claude", target: "/usr/bin/claude"}})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestAppendInventoryRejectsSymlinkInventory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(t.TempDir(), "outside-inventory.json")
	if err := os.WriteFile(target, []byte(`{"wrappers":[]}`), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(env.wrapperInvPath), 0o750); err != nil {
		t.Fatalf("mkdir inventory parent: %v", err)
	}
	if err := os.Symlink(target, env.wrapperInvPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := appendInventory(env, "plk-claude")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}
