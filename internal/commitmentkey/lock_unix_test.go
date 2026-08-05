// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package commitmentkey

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLifecycleLockRejectsSymlinkAndBadParent(t *testing.T) {
	t.Run("symlinked_lock", func(t *testing.T) {
		dir := t.TempDir()
		keyringPath := filepath.Join(dir, "keyring.json")
		lockTarget := filepath.Join(dir, "lock-target")
		if err := os.WriteFile(lockTarget, nil, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := os.Symlink(lockTarget, keyringPath+".lock"); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if err := withLifecycleLock(keyringPath, func() error { return nil }); !errors.Is(err, ErrSymlink) {
			t.Fatalf("symlink lock error = %v, want ErrSymlink", err)
		}
	})
	t.Run("absent_parent", func(t *testing.T) {
		dir := t.TempDir()
		if err := withLifecycleLock(filepath.Join(dir, "absent", "keyring.json"), func() error { return nil }); err == nil {
			t.Fatal("lock below absent parent succeeded")
		}
	})
}
