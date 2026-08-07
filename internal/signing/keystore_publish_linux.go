// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package signing

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func publishAgentDirectory(targetDir, stageDir, backupDir string) error {
	return publishAgentDirectoryWithSync(targetDir, stageDir, backupDir, syncDirectory)
}

func publishAgentDirectoryWithSync(targetDir, stageDir, backupDir string, syncDir func(string)) error {
	if err := unix.Renameat2(unix.AT_FDCWD, stageDir, unix.AT_FDCWD, targetDir, unix.RENAME_EXCHANGE); err != nil {
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return publishAgentDirectoryPortable(targetDir, stageDir, backupDir)
		}
		return fmt.Errorf("exchanging staged and active agent directories: %w", err)
	}
	// The exchange has already happened. The checkpoint can improve crash
	// durability where the filesystem supports directory fsync, but it cannot
	// turn the already-live identity into a failed publication.
	syncDir(filepath.Dir(targetDir))
	return nil
}
