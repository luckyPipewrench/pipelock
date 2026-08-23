// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package evidence

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func exchangeEvidenceDirectories(active, stage string) error {
	if filepath.Dir(active) != filepath.Dir(stage) {
		return fmt.Errorf("active and staged evidence directories must share a parent")
	}
	err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, active, unix.RENAME_EXCHANGE)
	return compactExchangeError(err)
}

func compactExchangeError(err error) error {
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP) {
		return fmt.Errorf("atomic directory exchange is unavailable on this kernel or filesystem: %w", err)
	}
	return err
}

func copyCompactOwnershipAndMode(source, target, what string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("stat %s has no unix ownership", what)
	}
	if err := os.Chmod(target, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chown(target, int(st.Uid), int(st.Gid))
}

func prepareCompactStage(active, stage string) error {
	return copyCompactOwnershipAndMode(active, stage, "active evidence directory")
}

func preserveCompactFileMetadata(source, target string) error {
	return copyCompactOwnershipAndMode(source, target, "source evidence file")
}

func syncCompactFile(path string) error {
	// #nosec G304 -- path names a staged shard created by this ceremony.
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	return errors.Join(syncErr, f.Close())
}

func syncCompactDirectory(path string) error {
	// #nosec G304 -- path is the validated evidence directory or its parent.
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	return errors.Join(syncErr, f.Close())
}
