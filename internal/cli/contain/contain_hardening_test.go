// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"os"
	"os/user"
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
	runner.on(argvFor(testSudoCmd, "-n", "-u", "pipelock-agent", "--", "env", "PATH="+agentExecPath("pipelock-agent"), "sh", "-c", "command -v -- \"$1\"", "sh", "discovered"), target+"\n", 0, nil)
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

func TestBackupAndWriteIfChangedRejectsUnchangedSymlinkTarget(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	target := filepath.Join(env.configDir, "target")
	link := filepath.Join(env.configDir, "link")
	if err := os.WriteFile(target, []byte("same"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	applied, err := backupAndWriteIfChanged(env, link, []byte("same"), modeAllowListReadable)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got applied=%v err=%v", applied, err)
	}
	if applied {
		t.Fatal("symlink rejection must not report applied")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("symlink target mode changed: got %s want 0o600", got)
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

func TestEnsureSafeWriteTargetRejectsRelativeAndDirectory(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := ensureSafeWriteTarget(env, "relative"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative err: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "dir")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := ensureSafeWriteTarget(env, dir); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("directory err: %v", err)
	}
}

func TestBackupAndWriteRejectsSymlinkBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	if err := os.WriteFile(path, []byte("current"), 0o600); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path+".bak"); err != nil {
		t.Fatalf("symlink backup: %v", err)
	}
	err := backupAndWrite(env, path, []byte("new"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "symlink backup") {
		t.Fatalf("expected symlink backup rejection, got %v", err)
	}
}

func TestRestoreBackupRejectsSymlinkBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	const current = "restore-backup-current"
	if err := os.WriteFile(path, []byte(current), 0o600); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path+".bak"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	err := restoreBackup(env, path)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink backup rejection, got %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(got) != current {
		t.Fatalf("current file changed: %q", got)
	}
}

func TestRestoreBackupIfPresentRejectsSymlinkBackup(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "host.conf")
	const current = "restore-if-present-current"
	if err := os.WriteFile(path, []byte(current), 0o600); err != nil {
		t.Fatalf("write current: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), path+".bak"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	err := restoreBackupIfPresent(env, path)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink backup rejection, got %v", err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // tmpdir-scoped test path
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if string(got) != current {
		t.Fatalf("current file changed: %q", got)
	}
}

func TestStepWriteCombinedCABundleBranches(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.WriteFile(env.caExportPath, []byte("PIPELOCK"), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	step := stepWriteCombinedCABundle()
	applied, err := step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected initial bundle write")
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	applied, err = step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if !applied {
		t.Fatal("expected restored bundle to be written again")
	}
	applied, err = step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	if applied {
		t.Fatal("expected idempotent bundle skip")
	}
	if err := os.Remove(env.caExportPath); err != nil {
		t.Fatalf("remove ca: %v", err)
	}
	if _, err := step.apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "read pipelock CA") {
		t.Fatalf("missing ca err: %v", err)
	}
}

func TestStepWritePipelockConfigUndoRestoresMigratedArtifacts(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	home := t.TempDir()
	env.lookupUser = func(name string) (*user.User, error) {
		if name == containInstallOperatorUser {
			return &user.User{Uid: "1000", Gid: "1000", Username: name, HomeDir: home}, nil
		}
		return &user.User{Uid: "988", Gid: "988", Username: name, HomeDir: "/tmp"}, nil
	}
	configDir := filepath.Join(home, ".config", "pipelock")
	license := filepath.Join(configDir, "license.token")
	mustWriteFile(t, license, "token\n")
	src := filepath.Join(configDir, "pipelock.yaml")
	mustWriteFile(t, src, "license_file: "+license+"\n")
	step := stepWritePipelockConfig(installOpts{configSource: src})
	applied, err := step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected config write")
	}
	migrated := filepath.Join(env.configDir, "license.token")
	if _, err := os.Stat(migrated); err != nil {
		t.Fatalf("migrated license missing: %v", err)
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if _, err := os.Stat(migrated); !os.IsNotExist(err) {
		t.Fatalf("migrated license should be removed, stat err=%v", err)
	}
}

func TestStepExportPipelockCAUndoAndErrorBranches(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	step := stepExportPipelockCA()
	env.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "bad", 0, nil
	}
	if _, err := step.apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "invalid CA PEM") {
		t.Fatalf("expected invalid pem error, got %v", err)
	}
	if err := os.WriteFile(env.caExportPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	applied, err := step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("existing ca apply: %v", err)
	}
	if applied {
		t.Fatal("existing CA should skip")
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if _, err := os.Stat(env.caExportPath); err != nil {
		t.Fatalf("CA export should be preserved on skipped apply, stat err=%v", err)
	}
}

func TestEnsureIntegrityOwnershipSurfacesFilesystemErrors(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.integrityDir, 0o750); err != nil {
		t.Fatalf("mkdir integrity: %v", err)
	}
	if err := os.WriteFile(env.integrityPin, []byte("pin"), 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	env.chmod = func(path string, _ os.FileMode) error {
		if path == env.integrityDir {
			return stringError("chmod denied")
		}
		return nil
	}
	if err := ensureIntegrityOwnership(env); err == nil || !strings.Contains(err.Error(), "chmod denied") {
		t.Fatalf("expected chmod error, got %v", err)
	}
}

func TestWalkAndChownSkipsSymlinkAndSurfacesChownError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "regular"), "x")
	if err := os.Symlink(filepath.Join(root, "regular"), filepath.Join(root, "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	var seen []string
	env.chown = func(path string, _, _ int) error {
		seen = append(seen, filepath.Base(path))
		if filepath.Base(path) == "regular" {
			return stringError("chown denied")
		}
		return nil
	}
	err := walkAndChown(env, root, 1, 1)
	if err == nil || !strings.Contains(err.Error(), "chown denied") {
		t.Fatalf("expected chown error, got %v", err)
	}
	for _, base := range seen {
		if base == "link" {
			t.Fatalf("chowned symlink: %v", seen)
		}
	}
}

func TestStepWriteToolWrappersRollsBackPartialWrite(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := writeToolsList(env, []toolsListEntry{
		{name: "claude", target: "/usr/bin/claude"},
		{name: "codex", target: "/usr/bin/codex"},
	}); err != nil {
		t.Fatalf("write tools.list: %v", err)
	}
	origWrite := env.writeFile
	env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
		if filepath.Base(path) == "plk-codex" {
			return stringError("disk full")
		}
		return origWrite(path, contents, mode)
	}
	step := stepWriteToolWrappers()
	if _, err := step.apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("expected partial write error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(env.wrapperDir, "plk-claude")); !os.IsNotExist(err) {
		t.Fatalf("partial wrapper should be rolled back, stat err=%v", err)
	}
}

func TestStepWriteToolWrappersBacksUpAndRestoresStaleDefault(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := writeToolsList(env, []toolsListEntry{{name: "claude", target: "/usr/bin/claude"}}); err != nil {
		t.Fatalf("write tools.list: %v", err)
	}
	stale := filepath.Join(env.wrapperDir, "plk-playwright")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale wrapper: %v", err)
	}
	step := stepWriteToolWrappers()
	applied, err := step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied {
		t.Fatal("expected wrapper changes")
	}
	if _, err := os.Stat(stale + ".bak"); err != nil {
		t.Fatalf("stale backup missing: %v", err)
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if got, err := os.ReadFile(stale); err != nil || string(got) != "stale" { //nolint:gosec // tmpdir-scoped test path
		t.Fatalf("stale wrapper not restored, got %q err=%v", got, err)
	}
}

func TestStepWriteWrapperInventoryBranches(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := writeToolsList(env, []toolsListEntry{{name: "claude", target: "/usr/bin/claude"}}); err != nil {
		t.Fatalf("write tools.list: %v", err)
	}
	step := stepWriteWrapperInventory()
	applied, err := step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	if !applied {
		t.Fatal("expected inventory write")
	}
	applied, err = step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("idempotent apply: %v", err)
	}
	if applied {
		t.Fatal("expected inventory skip")
	}
	if err := os.WriteFile(env.wrapperInvPath, []byte(`{"wrappers":["plk-old"]}`), 0o600); err != nil {
		t.Fatalf("write mismatched inventory: %v", err)
	}
	applied, err = step.apply(context.Background(), env)
	if err != nil {
		t.Fatalf("rewrite apply: %v", err)
	}
	if !applied {
		t.Fatal("expected mismatched inventory rewrite")
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if err := os.WriteFile(env.wrapperInvPath, []byte("{"), 0o600); err != nil {
		t.Fatalf("write bad inventory: %v", err)
	}
	if _, err := step.apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "parse wrapper inventory") {
		t.Fatalf("expected parse error, got %v", err)
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
