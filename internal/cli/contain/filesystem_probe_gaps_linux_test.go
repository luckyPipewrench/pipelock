// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestProbeFilesystemConfinementEnforceRejectsBeforeCreatingCanaries(t *testing.T) {
	status, detail := probeFilesystemConfinementEnforce(context.Background(), nil, filesystemProfile{Mode: config.ContainmentFilesystemModeEnforce})
	if status != statusFail || !strings.Contains(detail, "no command runner") {
		t.Fatalf("nil env = %s %s", status, detail)
	}
	env := &probeEnv{runCmd: func(context.Context, string, ...string) (string, int, error) {
		return "", 0, nil
	}}
	status, detail = probeFilesystemConfinementEnforce(context.Background(), env, filesystemProfile{Mode: config.ContainmentFilesystemModeOff})
	if status != statusFilesystemOff || detail != "filesystem profile: off" {
		t.Fatalf("off = %s %s", status, detail)
	}
	status, detail = probeFilesystemConfinementEnforce(context.Background(), &probeEnv{}, filesystemProfile{Mode: config.ContainmentFilesystemModeEnforce})
	if status != statusFail || !strings.Contains(detail, "no command runner") {
		t.Fatalf("nil runner = %s %s", status, detail)
	}
}

func TestProbeFilesystemConfinementEnforceStopsAtParentAndCommandFailures(t *testing.T) {
	prevRoot := filesystemCanaryRoot
	prevOp := filesystemOperatorCanaryParent
	prevState := filesystemStateCanaryParent
	t.Cleanup(func() {
		filesystemCanaryRoot = prevRoot
		filesystemOperatorCanaryParent = prevOp
		filesystemStateCanaryParent = prevState
	})
	filesystemCanaryRoot = func() bool { return true }

	writable := t.TempDir()
	readonly := t.TempDir()
	if err := os.Chmod(readonly, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o750) })

	env := filesystemCanaryEnv(func(context.Context, string, ...string) (string, int, error) {
		return "", 0, nil
	})
	profile := env.filesystem

	filesystemOperatorCanaryParent = filepath.Join(t.TempDir(), "missing-operator")
	filesystemStateCanaryParent = writable
	status, detail := probeFilesystemConfinementEnforce(context.Background(), env, profile)
	if status != statusFail || !strings.Contains(detail, "open operator home canary parent") {
		t.Fatalf("missing operator parent = %s %s", status, detail)
	}

	filesystemOperatorCanaryParent = readonly
	status, detail = probeFilesystemConfinementEnforce(context.Background(), env, profile)
	if status != statusFail || !strings.Contains(detail, "create operator home canary") {
		t.Fatalf("read-only operator parent = %s %s", status, detail)
	}

	filesystemOperatorCanaryParent = writable
	filesystemStateCanaryParent = filepath.Join(t.TempDir(), "missing-state")
	status, detail = probeFilesystemConfinementEnforce(context.Background(), env, profile)
	if status != statusFail || !strings.Contains(detail, "open filesystem canary parent") {
		t.Fatalf("missing state parent = %s %s", status, detail)
	}

	filesystemStateCanaryParent = readonly
	status, detail = probeFilesystemConfinementEnforce(context.Background(), env, profile)
	if status != statusFail || !strings.Contains(detail, "create write canary") {
		t.Fatalf("read-only state parent = %s %s", status, detail)
	}
}

func TestProbeFilesystemConfinementEnforceReportsCanaryFailures(t *testing.T) {
	root := t.TempDir()
	withFilesystemCanaryRoot(t, root)
	workspace := t.TempDir()
	if err := os.Chmod(workspace, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(workspace, 0o750) })

	env := filesystemCanaryEnv(func(context.Context, string, ...string) (string, int, error) {
		return "", 0, nil
	})
	env.agentHome = filepath.Join(root, "agent-home")
	env.filesystem.BindPaths = []string{
		workspace + ":" + workspace + ":norbind",
		env.agentHome + ":" + env.agentHome + ":norbind",
	}
	status, detail := probeFilesystemConfinementEnforce(context.Background(), env, env.filesystem)
	if status != statusFail || !strings.Contains(detail, "write workspace canary") {
		t.Fatalf("workspace = %s %s", status, detail)
	}

	lookups := 0
	env = filesystemCanaryEnv(func(context.Context, string, ...string) (string, int, error) {
		return "", 0, nil
	})
	env.lookupUser = func(name string) (*user.User, error) {
		lookups++
		if lookups > 1 {
			return nil, errors.New("lookup closed")
		}
		return &user.User{Uid: "966", Gid: "966", Username: name, HomeDir: "/srv/agent-home"}, nil
	}
	status, detail = probeFilesystemConfinementEnforce(context.Background(), env, env.filesystem)
	if status != statusFail || !strings.Contains(detail, "prepare filesystem confinement canary") || !strings.Contains(detail, "lookup closed") {
		t.Fatalf("second prepare = %s %s", status, detail)
	}

	env = filesystemCanaryEnv(func(_ context.Context, _ string, args ...string) (string, int, error) {
		if strings.Contains(strings.Join(args, "\n"), "ProtectSystem=strict") {
			return "", 0, errors.New("canary start failed")
		}
		return "", 0, nil
	})
	status, detail = probeFilesystemConfinementEnforce(context.Background(), env, env.filesystem)
	if status != statusFail || !strings.Contains(detail, "could not start") {
		t.Fatalf("start = %s %s", status, detail)
	}

	cases := []struct {
		code   int
		output string
		want   string
	}{
		{code: 22, want: "secret canary is not a valid proof"},
		{code: 37, want: "baseline exited 37"},
		{code: 37, output: "baseline broke", want: "baseline broke"},
	}
	for _, tc := range cases {
		env = filesystemCanaryEnv(func(context.Context, string, ...string) (string, int, error) {
			return tc.output, tc.code, nil
		})
		status, detail = probeFilesystemConfinementEnforce(context.Background(), env, env.filesystem)
		if status != statusFail || !strings.Contains(detail, tc.want) {
			t.Fatalf("code %d = %s %s", tc.code, status, detail)
		}
	}
}

func TestOpenNoFollowDirRejectsRootAndRelativePaths(t *testing.T) {
	if _, err := openNoFollowDir(""); err == nil {
		t.Fatal("empty path opened")
	}
	if _, err := openNoFollowDir("/"); err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("root = %v", err)
	}
}

func TestOpenNoFollowDirReportsAFileDescriptorLimit(t *testing.T) {
	dir := t.TempDir()
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	orig := lim
	t.Cleanup(func() { _ = unix.Setrlimit(unix.RLIMIT_NOFILE, &orig) })
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	lim.Cur = uint64(len(entries) + 8)
	if lim.Cur > orig.Max {
		lim.Cur = orig.Max
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	var opened []int
	t.Cleanup(func() {
		for _, fd := range opened {
			_ = unix.Close(fd)
		}
	})
	for len(opened) < 64 {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			if !errors.Is(err, unix.EMFILE) && !errors.Is(err, unix.ENFILE) {
				t.Fatalf("open /dev/null: %v", err)
			}
			break
		}
		opened = append(opened, fd)
	}
	if len(opened) == 0 {
		t.Fatal("descriptor limit was already exhausted")
	}
	// One descriptor can be released between the failing open and the call
	// under test. Hold every successful root open until the next one fails.
	var leaked []*noFollowDir
	t.Cleanup(func() {
		for _, d := range leaked {
			d.close()
		}
	})
	var openErr error
	for range 32 {
		openedDir, err := openNoFollowDir(dir)
		if err != nil {
			openErr = err
			break
		}
		leaked = append(leaked, openedDir)
	}
	if openErr == nil || !strings.Contains(openErr.Error(), "open filesystem root") {
		t.Fatalf("open = %v after %d extra directories", openErr, len(leaked))
	}
}

func TestCanaryCreateAndCleanupEdges(t *testing.T) {
	base := writableSymlinkFreeDir(t)
	parent, err := openNoFollowDir(base)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()

	var closed *noFollowDir
	closed.unlink("x")
	closed.removeDir("x")
	if err := closed.removeBounded(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed = %v", err)
	}
	opened, err := openNoFollowDir(base)
	if err != nil {
		t.Fatal(err)
	}
	opened.close()
	if err := opened.removeBounded(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed file = %v", err)
	}

	locked := t.TempDir()
	lockedDir, err := openNoFollowDir(locked)
	if err != nil {
		t.Fatal(err)
	}
	defer lockedDir.close()
	if err := os.Chmod(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o750) })
	if _, _, err := lockedDir.mkdirExclusive("blocked-", 0o755); err == nil {
		t.Fatal("mkdir on a read-only directory succeeded")
	}
	if _, _, err := parent.mkdirExclusive("mode0-", 0); err == nil || !errors.Is(err, unix.EACCES) {
		t.Fatalf("mode 0 mkdir = %v", err)
	}
	if _, _, err := lockedDir.createExclusiveFile("blocked-", 0o644, []byte("x")); err == nil {
		t.Fatal("create on a read-only directory succeeded")
	}

	leaf := filepath.Join(base, "leaf")
	if err := os.WriteFile(leaf, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent.path = ""
	seen := 0
	if err := parent.removeTree(context.Background(), "leaf", 0, &seen); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("leaf = %v", err)
	}
	parent.path = base
	if err := parent.removeTree(context.Background(), "missing-leaf", 0, &seen); err == nil || !strings.Contains(err.Error(), "missing-leaf") {
		t.Fatalf("missing = %v", err)
	}

	name, dir, err := parent.mkdirExclusive("nilctx-", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	dir.close()
	if err := parent.removeBounded(nil, name); err != nil {
		t.Fatal(err)
	}

	name, dir, err = parent.mkdirExclusive("readdir-", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	full := dir.path
	dir.close()
	reopen, err := openNoFollowDir(full)
	if err != nil {
		t.Fatal(err)
	}
	reopen.close()
	if err := reopen.removeChildren(context.Background(), 0, &seen); err == nil || !strings.Contains(err.Error(), full) {
		t.Fatalf("readdir = %v", err)
	}
	if err := parent.removeBounded(context.Background(), name); err != nil {
		t.Fatal(err)
	}

	name, dir, err = parent.mkdirExclusive("cancel-", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.path, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir.close()
	ctx := &errAfter{Context: context.Background(), remain: 2}
	if err := parent.removeBounded(ctx, name); err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("cancel = %v", err)
	}
	if err := parent.removeBounded(context.Background(), name); err != nil {
		t.Fatal(err)
	}

	name, dir, err = parent.mkdirExclusive("stuck-", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	stuck := filepath.Join(dir.path, "keep")
	if err := os.WriteFile(stuck, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir.path, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir.path, 0o750) })
	if err := dir.removeOne(context.Background(), "keep", 0, &seen); err == nil || !strings.Contains(err.Error(), "keep") {
		t.Fatalf("unlink = %v", err)
	}
	if err := os.Chmod(dir.path, 0o750); err != nil {
		t.Fatal(err)
	}
	dir.close()
	if err := parent.removeBounded(context.Background(), name); err != nil {
		t.Fatal(err)
	}

	if err := parent.removeOne(context.Background(), "absent", 0, &seen); err == nil {
		t.Fatal("missing child was removed")
	}
}

func TestCanaryDirectoryRemovalStopsWhenTheParentIsReadOnly(t *testing.T) {
	base := writableSymlinkFreeDir(t)
	parent, err := openNoFollowDir(base)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	name, child, err := parent.mkdirExclusive("kept-", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	child.close()
	if err := os.Chmod(base, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o750) })
	seen := 0
	if err := parent.removeTree(context.Background(), name, 0, &seen); err == nil || !strings.Contains(err.Error(), name) {
		t.Fatalf("rmdir = %v", err)
	}
	if err := os.Chmod(base, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := parent.removeBounded(context.Background(), name); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, child, err = parent.mkdirExclusive("cancel-", 0o755)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	if err := child.removeChildren(ctx, 0, &seen); err == nil || !strings.Contains(err.Error(), child.path) {
		t.Fatalf("cancelled cleanup = %v", err)
	}
}

func TestProbeFilesystemConfinementEnforceStopsWhenBaselinePrepFails(t *testing.T) {
	root := t.TempDir()
	withFilesystemCanaryRoot(t, root)
	env := filesystemCanaryEnv(func(context.Context, string, ...string) (string, int, error) {
		t.Fatal("baseline command ran after account lookup failed")
		return "", 0, nil
	})
	env.lookupUser = func(string) (*user.User, error) {
		return nil, errors.New("lookup closed")
	}
	status, detail := probeFilesystemConfinementEnforce(context.Background(), env, env.filesystem)
	if status != statusFail || !strings.Contains(detail, "prepare filesystem confinement baseline") || !strings.Contains(detail, "lookup closed") {
		t.Fatalf("baseline = %s %s", status, detail)
	}
}

type errAfter struct {
	context.Context
	remain int
}

func (e *errAfter) Err() error {
	if e.remain <= 0 {
		return context.Canceled
	}
	e.remain--
	return nil
}

func TestMkdiratPermissionIsNotRetried(t *testing.T) {
	// Mkdirat's non-existence error is the one the create loop returns
	// immediately. EEXIST is the only retry, and a read-only directory is not that.
	base := writableSymlinkFreeDir(t)
	parent, err := openNoFollowDir(base)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	if err := os.Chmod(base, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(base, 0o750) })
	_, _, err = parent.mkdirExclusive("once-", 0o755)
	if err == nil || errors.Is(err, unix.EEXIST) {
		t.Fatalf("err = %v", err)
	}
}
