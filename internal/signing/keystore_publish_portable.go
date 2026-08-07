// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func publishAgentDirectoryPortable(targetDir, stageDir, backupDir string) error {
	return publishAgentDirectoryPortableWithSync(targetDir, stageDir, backupDir, syncDirectory)
}

func publishAgentDirectoryPortableWithSync(targetDir, stageDir, backupDir string, syncDir func(string)) error {
	parentDir := filepath.Dir(targetDir)
	if err := os.RemoveAll(backupDir); err != nil {
		return fmt.Errorf("removing stale agent backup: %w", err)
	}
	if err := os.Rename(targetDir, backupDir); err != nil {
		return fmt.Errorf("backing up active agent directory: %w", err)
	}
	// The active path is temporarily empty, so checkpoint the old pair in its
	// recovery location before installing the staged one. The helper is
	// best-effort for the same reason as atomicfile.Write: a filesystem that
	// cannot fsync directories still has durable key data and atomic renames.
	syncDir(parentDir)
	if err := installStagedAgentDirectory(targetDir, stageDir); err != nil {
		if removeErr := removeEmptyDirectory(targetDir); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("installing staged agent directory: %w", errors.Join(err, fmt.Errorf("clearing active path for rollback: %w", removeErr)))
		}
		if restoreErr := os.Rename(backupDir, targetDir); restoreErr != nil {
			return fmt.Errorf("installing staged agent directory: %w", errors.Join(err, fmt.Errorf("restoring prior key pair: %w", restoreErr)))
		}
		syncDir(parentDir)
		return fmt.Errorf("installing staged agent directory: %w", err)
	}
	// The new pair is already committed. Cleanup is best-effort so a cleanup
	// failure cannot turn a successful force-regenerate into an ambiguous error.
	// The next generation recovers by keeping the coherent active pair.
	_ = os.RemoveAll(backupDir)
	syncDir(parentDir)
	return nil
}

// syncDirectory checkpoints parent-directory entry changes when the platform
// supports it. Key-file writes already fsync their data before publication;
// a directory sync adds crash durability for renames but is not a reason to
// reject an identity that is already active on filesystems without that support.
func syncDirectory(path string) {
	dir, err := os.Open(filepath.Clean(path))
	if err != nil {
		return
	}
	_ = dir.Sync()
	_ = dir.Close()
}

func installStagedAgentDirectory(targetDir, stageDir string) error {
	const maxConcurrentPreflightRetries = 64
	var lastErr error
	for range maxConcurrentPreflightRetries {
		if err := os.Rename(stageDir, targetDir); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if err := removeEmptyDirectory(targetDir); err != nil {
			return lastErr
		}
	}
	return lastErr
}

func removeEmptyDirectory(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("active agent directory is not empty")
	}
	return os.Remove(path)
}
