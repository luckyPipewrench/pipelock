// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package ael

import (
	"path/filepath"
	"testing"
)

func TestSyncDirectoryRejectsMissingPath(t *testing.T) {
	t.Parallel()
	if err := syncDirectory(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("syncDirectory accepted a missing path")
	}
}
