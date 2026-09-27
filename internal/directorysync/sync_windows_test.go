// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package directorysync

import (
	"path/filepath"
	"testing"
)

func TestSyncDirectoryWindows(t *testing.T) {
	t.Parallel()
	if err := Sync(t.TempDir()); err != nil {
		t.Fatalf("Sync existing directory: %v", err)
	}
	if err := Sync(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Sync accepted a missing directory")
	}
}
