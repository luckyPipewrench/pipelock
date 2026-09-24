// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// setHermesTestCacheDir points the lock at a fixture cache. os.UserCacheDir
// reads a different variable on each platform, so tests set the location
// directly rather than through the environment.
func setHermesTestCacheDir(t *testing.T, dir string) {
	t.Helper()
	old := hermesUserCacheDir
	hermesUserCacheDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { hermesUserCacheDir = old })
}

func lockTestEnvironment(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cache := filepath.Join(root, "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	setHermesTestCacheDir(t, cache)
	old := hermesLockTimeout
	hermesLockTimeout = 40 * time.Millisecond
	t.Cleanup(func() { hermesLockTimeout = old })
	return root
}

func TestHermesCommandLockResourcesAndContention(t *testing.T) {
	root := lockTestEnvironment(t)
	configA := filepath.Join(root, "a", "config.yaml")
	configB := filepath.Join(root, "b", "config.yaml")
	homeA := filepath.Join(root, "home-a")
	homeB := filepath.Join(root, "home-b")
	for _, tc := range []struct{ name, heldConfig, heldHome, secondConfig, secondHome string }{
		{"same home", configA, homeA, configB, homeA},
		{"same config", configA, homeA, configA, homeB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- withHermesCommandLock(tc.heldConfig, []string{tc.heldHome}, func() error { close(entered); <-release; return nil })
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("held lock failed before entering: %v", err)
			}
			called := false
			err := withHermesCommandLock(tc.secondConfig, []string{tc.secondHome}, func() error { called = true; return nil })
			if err == nil || called || !strings.Contains(err.Error(), "another pipelock hermes install or rollback") || !strings.Contains(err.Error(), ".lock") {
				t.Errorf("contention err=%v called=%v", err, called)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := withHermesCommandLock(tc.secondConfig, []string{tc.secondHome}, func() error { called = true; return nil }); err != nil || !called {
				t.Fatalf("after release err=%v called=%v", err, called)
			}
		})
	}
}

// Every command must take its locks in the same order, or two commands that
// share both resources could each hold one and wait on the other.
func TestHermesCommandLockOrder(t *testing.T) {
	root := lockTestEnvironment(t)
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	forward, err := hermesLockResources(filepath.Join(a, "config.yaml"), []string{b})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := hermesLockResources(filepath.Join(b, "config.yaml"), []string{a})
	if err != nil {
		t.Fatal(err)
	}
	if len(forward) != 2 || !slices.Equal(forward, reverse) || !slices.IsSorted(forward) {
		t.Fatalf("lock order differs: %v vs %v", forward, reverse)
	}
	same, err := hermesLockResources(filepath.Join(a, "config.yaml"), []string{a})
	if err != nil {
		t.Fatal(err)
	}
	if len(same) != 1 {
		t.Fatalf("shared config and home should lock once, got %v", same)
	}
}

func TestHermesCommandLockRejectsSymlink(t *testing.T) {
	root := lockTestEnvironment(t)
	resource := filepath.Join(root, "resource")
	canonical, err := canonicalLockResource(resource)
	if err != nil {
		t.Fatal(err)
	}
	lockDir := filepath.Join(root, "cache", hermesLockDirName, "locks")
	if err := ensureHermesLockDir(lockDir); err != nil {
		t.Fatal(err)
	}
	path := hermesLockPath(lockDir, canonical)
	if err := os.Symlink(filepath.Join(root, "target"), path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := withHermesCommandLock(filepath.Join(resource, "config.yaml"), []string{resource}, func() error { return nil }); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestHermesLockCanonicalizesExistingSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(realDir, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got, err := canonicalLockResource(filepath.Join(alias, "missing"))
	if err != nil {
		t.Fatal(err)
	}
	resolvedReal, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(resolvedReal, "missing")
	if got != want {
		t.Fatalf("canonical path = %s; want %s", got, want)
	}
}

// Case-insensitive platforms hash every spelling of a directory to one lock;
// Linux keeps case because its filesystems are case-sensitive.
func TestHermesLockKeyFoldsCaseWhereTheFilesystemDoes(t *testing.T) {
	upper, lower := "/Users/Op/Hermes", "/users/op/hermes"
	for _, goos := range []string{"darwin", "windows"} {
		if hermesLockKey(goos, upper) != hermesLockKey(goos, lower) {
			t.Fatalf("%s: case variants got different lock keys", goos)
		}
	}
	if hermesLockKey("linux", upper) == hermesLockKey("linux", lower) {
		t.Fatal("linux: distinct case-sensitive directories share a lock key")
	}
}
