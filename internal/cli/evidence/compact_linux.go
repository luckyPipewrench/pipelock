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
	return unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, active, unix.RENAME_EXCHANGE)
}

func prepareCompactStage(active, stage string) error {
	info, err := os.Stat(active)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("stat active evidence directory has no unix ownership")
	}
	if err := os.Chmod(stage, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chown(stage, int(st.Uid), int(st.Gid))
}

func preserveCompactFileMetadata(source, target string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("stat source evidence file has no unix ownership")
	}
	if err := os.Chmod(target, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chown(target, int(st.Uid), int(st.Gid))
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
