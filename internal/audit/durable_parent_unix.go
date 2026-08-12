// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"fmt"
	"os"
	"path/filepath"
)

// syncDurableAuditParent persists the directory entry for a newly created
// durable audit log. Syncing the file alone does not guarantee that a new name
// survives a power failure on Unix filesystems.
func syncDurableAuditParent(path string) error {
	dir, err := os.Open(filepath.Dir(filepath.Clean(path)))
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return nil
}
