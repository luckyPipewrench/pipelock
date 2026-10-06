// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemCanaryCleanupIsBounded(t *testing.T) {
	base := writableSymlinkFreeDir(t)
	parent, err := openNoFollowDir(base)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()

	t.Run("entry limit", func(t *testing.T) {
		name, dir, err := parent.mkdirExclusive("entries-", 0o755)
		if err != nil {
			t.Fatal(err)
		}
		dir.close()
		full := filepath.Join(base, name)
		for i := 0; i < filesystemCleanupMaxEntries+1; i++ {
			if err := os.WriteFile(filepath.Join(full, fmt.Sprintf("f%02d", i)), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		err = parent.removeBounded(context.Background(), name)
		if err == nil || !strings.Contains(err.Error(), full) {
			t.Fatalf("err = %v, want the leftover directory", err)
		}
		if _, statErr := os.Stat(full); statErr != nil {
			t.Fatalf("leftover directory = %v", statErr)
		}
	})

	t.Run("depth limit", func(t *testing.T) {
		name, dir, err := parent.mkdirExclusive("depth-", 0o755)
		if err != nil {
			t.Fatal(err)
		}
		dir.close()
		cur := filepath.Join(base, name)
		for i := 0; i < filesystemCleanupMaxDepth+1; i++ {
			cur = filepath.Join(cur, "d")
			if err := os.Mkdir(cur, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		err = parent.removeBounded(context.Background(), name)
		if err == nil || !strings.Contains(err.Error(), "depth") {
			t.Fatalf("err = %v", err)
		}
		if _, statErr := os.Stat(cur); statErr != nil {
			t.Fatalf("deep directory = %v", statErr)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		name, dir, err := parent.mkdirExclusive("cancel-", 0o755)
		if err != nil {
			t.Fatal(err)
		}
		dir.close()
		full := filepath.Join(base, name)
		if err := os.WriteFile(filepath.Join(full, "keep"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err = parent.removeBounded(ctx, name)
		if err == nil || !strings.Contains(err.Error(), full) {
			t.Fatalf("err = %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(full, "keep")); statErr != nil {
			t.Fatalf("cancelled cleanup removed %s: %v", full, statErr)
		}
	})

	t.Run("symlink is not followed", func(t *testing.T) {
		name, dir, err := parent.mkdirExclusive("link-", 0o755)
		if err != nil {
			t.Fatal(err)
		}
		dir.close()
		victim := filepath.Join(base, "victim")
		if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(dir.path, "link")); err != nil {
			t.Fatal(err)
		}
		if err := parent.removeBounded(context.Background(), name); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(victim)
		if err != nil || string(got) != "keep" {
			t.Fatalf("victim = %q %v", got, err)
		}
		if _, err := os.Lstat(filepath.Join(base, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("canary directory = %v", err)
		}
	})

	t.Run("small tree is removed", func(t *testing.T) {
		name, dir, err := parent.mkdirExclusive("small-", 0o755)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir.path, "one"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		dir.close()
		parent.removeDir(name)
		if _, err := os.Lstat(filepath.Join(base, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("small directory = %v", err)
		}
	})
}

func TestFilesystemCleanupFailureReplacesPass(t *testing.T) {
	status, detail := filesystemCleanupResult(statusPass, "contained", errors.New("filesystem canary cleanup exceeded its entry limit at /var/lib/canary"))
	if status != statusFail || !strings.Contains(detail, "/var/lib/canary") {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
	status, detail = filesystemCleanupResult(statusFail, "operator home canary was visible", errors.New("filesystem canary cleanup stopped at /home/canary"))
	if status != statusFail || !strings.Contains(detail, "operator home canary was visible") || !strings.Contains(detail, "/home/canary") {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
}
