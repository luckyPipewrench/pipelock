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

func TestBrowserDefaultsPinnedArchiveAndRestore(t *testing.T) {
	env, _, path, _ := browserDefaultsEnv(t)
	writeAgentBrowserConfigFixture(t, path, `{"args":"old"}`)
	if err := os.WriteFile(path+".bak", []byte(`{"args":"older"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := openAgentBrowserHome(env)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := backupAndWriteAgentBrowserRoot(env, root, []byte(`{"args":"new"}`), 987, 987); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Clean(path)); err != nil || string(got) != `{"args":"new"}` {
		t.Fatalf("managed config = %s, %v", got, err)
	}
	if err := restoreAgentBrowserRoot(env, root); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Clean(path)); err != nil || string(got) != `{"args":"old"}` {
		t.Fatalf("restored config = %s, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Clean(path + ".bak")); err != nil || string(got) != `{"args":"older"}` {
		t.Fatalf("restored backup = %s, %v", got, err)
	}
}

func TestBrowserDefaultsPinnedFailurePaths(t *testing.T) {
	t.Run("closed home root", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		if err := ownAgentBrowserDirs(env, root, 987, 987); err == nil || !strings.Contains(err.Error(), "open agent home") {
			t.Fatalf("closed home: %v", err)
		}
	})
	t.Run("home chown denied", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		env.agentBrowserFchown = func(*os.File, int, int) error { return os.ErrPermission }
		if err := ownAgentBrowserDirs(env, root, 987, 987); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("home chown: %v", err)
		}
	})
	t.Run("write directory wrong owner", func(t *testing.T) {
		env, _, _, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		env.agentBrowserDirOwner = func(*os.File, int) bool { return false }
		if err := writeAgentBrowserRoot(env, root, agentBrowserFile, []byte("x"), 987, 987); err == nil || !strings.Contains(err.Error(), "not agent-owned") {
			t.Fatalf("write: %v", err)
		}
		if err := backupAndWriteAgentBrowserRoot(env, root, []byte("x"), 987, 987); err == nil || !strings.Contains(err.Error(), "not agent-owned") {
			t.Fatalf("backup: %v", err)
		}
	})
	t.Run("restore absent and wrong owner", func(t *testing.T) {
		env, _, path, _ := browserDefaultsEnv(t)
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := restoreAgentBrowserRoot(env, root); err != nil {
			t.Fatalf("restore absent: %v", err)
		}
		writeAgentBrowserConfigFixture(t, path, "body")
		env.agentBrowserDirOwner = func(*os.File, int) bool { return false }
		if err := restoreAgentBrowserRoot(env, root); err == nil || !strings.Contains(err.Error(), "not agent-owned") {
			t.Fatalf("restore wrong owner: %v", err)
		}
	})
	t.Run("backup lstat denied", func(t *testing.T) {
		env, _, path, _ := browserDefaultsEnv(t)
		writeAgentBrowserConfigFixture(t, path, "body")
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		prior := env.agentBrowserLstat
		env.agentBrowserLstat = func(root *os.Root, name string) (os.FileInfo, error) {
			if name == agentBrowserFile {
				return nil, os.ErrPermission
			}
			if prior != nil {
				return prior(root, name)
			}
			return root.Lstat(name)
		}
		if err := backupAndWriteAgentBrowserRoot(env, root, []byte("new"), 987, 987); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("backup lstat: %v", err)
		}
	})
	t.Run("write nonregular leaf", func(t *testing.T) {
		env, _, path, _ := browserDefaultsEnv(t)
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if err := writeAgentBrowserRoot(env, root, path, []byte("new"), 987, 987); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("write directory leaf: %v", err)
		}
	})
	t.Run("restore backup remove denied", func(t *testing.T) {
		env, _, path, _ := browserDefaultsEnv(t)
		writeAgentBrowserConfigFixture(t, path, "managed")
		if err := os.WriteFile(path+".bak", []byte("previous"), 0o600); err != nil {
			t.Fatal(err)
		}
		root, err := openAgentBrowserHome(env)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		env.agentBrowserRemove = func(*os.Root, string) error { return os.ErrPermission }
		if err := restoreAgentBrowserRoot(env, root); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("restore remove: %v", err)
		}
		if got, _ := os.ReadFile(filepath.Clean(path)); string(got) != "managed" {
			t.Fatalf("config changed: %s", got)
		}
	})
}
