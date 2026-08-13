// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"fmt"
	"os"
	"path/filepath"
)

var syncDurableAuditParent = syncDurableAuditParentDirectory

// syncDurableAuditParentDirectory persists the directory entry for a durable
// audit log. Syncing the file alone does not guarantee that a name survives a
// power failure, including a name left behind by an earlier failed attempt.
func syncDurableAuditParentDirectory(path string) error {
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
