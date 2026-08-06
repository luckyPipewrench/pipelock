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
	syncDirectory(filepath.Dir(targetDir))
	return nil
}

func syncDirectory(path string) {
	dir, err := os.Open(filepath.Clean(path))
	if err != nil {
		return
	}
	_ = dir.Sync()
	_ = dir.Close()
}
