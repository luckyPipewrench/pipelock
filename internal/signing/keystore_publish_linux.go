// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package signing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishAgentDirectory(targetDir, stageDir, backupDir string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, stageDir, unix.AT_FDCWD, targetDir, unix.RENAME_EXCHANGE); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return publishAgentDirectoryPortable(targetDir, stageDir, backupDir)
		}
		return fmt.Errorf("exchanging staged and active agent directories: %w", err)
	}
	// The exchange has already happened. Whatever the sync does, the new pair is
	// live from here on, so a sync failure cannot be reported as a failed
	// publication.
	if err := syncDirectory(filepath.Dir(targetDir)); err != nil {
		return fmt.Errorf("%w: %w", ErrPublishedNotDurable, err)
	}
	return nil
}

// syncDirectory fsyncs the parent directory so the rename that just swapped the
// staged and active key directories survives a crash. The exchange is atomic
// with respect to other processes the moment it returns, but it is not durable
// until the directory entry reaches disk, so dropping this error would leave a
// publication that reports success and can still be absent after a power loss.
// That is the failure this whole transaction exists to prevent, which is why it
// is reported rather than swallowed.
func syncDirectory(path string) error {
	dir, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("opening agent directory parent for sync: %w", err)
	}
	if syncErr := dir.Sync(); syncErr != nil {
		_ = dir.Close()
		return fmt.Errorf("syncing agent directory parent: %w", syncErr)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("closing agent directory parent after sync: %w", err)
	}
	return nil
}
