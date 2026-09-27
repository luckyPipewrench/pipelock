// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package directorysync

import (
	"path/filepath"
	"testing"
)

func TestSyncDirectoryRejectsMissingPathDarwin(t *testing.T) {
	if err := Sync(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Sync accepted a missing directory")
	}
}

func TestSyncDirectoryDarwin(t *testing.T) {
	if err := Sync(t.TempDir()); err != nil {
		t.Fatalf("Sync directory: %v", err)
	}
}
