// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserDirPinnedOperations(t *testing.T) {
	env, _, _, _ := browserDefaultsEnv(t)
	root, err := openAgentBrowserHome(env)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	dir, err := openBrowserDir(env, root, true, 987, 987)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	for _, name := range []string{"../escape", "a/b", ".", ".."} {
		if _, err := dir.open(name, os.O_RDONLY, 0); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("open %q: %v", name, err)
		}
		if _, err := dir.lstat(name); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("lstat %q: %v", name, err)
		}
		if err := dir.remove(name); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("remove %q: %v", name, err)
		}
		if err := dir.rename(name, "valid"); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("rename source %q: %v", name, err)
		}
		if err := dir.rename("valid", name); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("rename destination %q: %v", name, err)
		}
	}
	if _, err := dir.open("absent", os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open absent: %v", err)
	}
	if err := dir.remove("absent"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remove absent: %v", err)
	}
	if err := dir.rename("absent", "renamed"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rename absent: %v", err)
	}
	if err := root.Symlink("outside", filepath.Join(agentBrowserDir, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := dir.lstat("linked"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("lstat symlink: %v", err)
	}
	if _, err := dir.open("linked", os.O_RDONLY, 0); err == nil {
		t.Fatal("opened symlink")
	}
	if err := dir.remove("linked"); err != nil {
		t.Fatalf("remove symlink: %v", err)
	}
	if _, err := root.Lstat(filepath.Join(agentBrowserDir, "linked")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("linked path remains: %v", err)
	}
}

func TestBrowserDirLstatHandlesLeafRemovedAfterPrecheck(t *testing.T) {
	env, _, path, _ := browserDefaultsEnv(t)
	writeAgentBrowserConfigFixture(t, path, "body")
	root, err := openAgentBrowserHome(env)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	dir, err := openBrowserDir(env, root, false, 987, 987)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	env.agentBrowserLstat = func(root *os.Root, name string) (os.FileInfo, error) {
		info, err := root.Lstat(name)
		if err == nil && name == agentBrowserFile {
			if removeErr := root.Remove(name); removeErr != nil {
				t.Fatal(removeErr)
			}
		}
		return info, err
	}
	if _, err := dir.lstat("config.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lstat removed leaf: %v", err)
	}
}

func TestBrowserDirRefusesUnsafeDirectory(t *testing.T) {
	t.Run("mkdir denied", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory permissions")
		}
		env, _, _, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		home := agentHomeDir(env)
		if err := env.chmod(home, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = env.chmod(home, 0o700) })
		env.agentBrowserLstat = func(*os.Root, string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		if _, err := openBrowserDir(env, root, true, 987, 987); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("mkdir denied: %v", err)
		}
	})
	t.Run("closed home root", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		env.agentBrowserLstat = func(*os.Root, string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		if _, err := openBrowserDir(env, root, true, 987, 987); err == nil || !strings.Contains(err.Error(), "open agent home") {
			t.Fatalf("closed home root: %v", err)
		}
	})
	t.Run("closed pinned descriptor", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		file, err := root.Open(".")
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := checkedBrowserDir(env, root, file, 987); err == nil || !strings.Contains(err.Error(), "stat agent-browser directory") {
			t.Fatalf("closed descriptor: %v", err)
		}
	})
	t.Run("new directory chown denied", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		env.agentBrowserFchown = func(*os.File, int, int) error { return os.ErrPermission }
		if _, err := openBrowserDir(env, root, true, 987, 987); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("new directory chown: %v", err)
		}
	})
	t.Run("wrong owner", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		env.agentBrowserDirOwner = func(*os.File, int) bool { return false }
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if _, err := openBrowserDir(env, root, true, 987, 987); err == nil || !strings.Contains(err.Error(), "not agent-owned") {
			t.Fatalf("wrong owner: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := root.Symlink(t.TempDir(), agentBrowserDir); err != nil {
			t.Fatal(err)
		}
		if _, err := openBrowserDir(env, root, false, 987, 987); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("symlink accepted: %v", err)
		}
	})
	t.Run("lstat denied", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		env.agentBrowserLstat = func(*os.Root, string) (os.FileInfo, error) { return nil, os.ErrPermission }
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if _, err := openBrowserDir(env, root, true, 987, 987); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("lstat denied: %v", err)
		}
	})
}
