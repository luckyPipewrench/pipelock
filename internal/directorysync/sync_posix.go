// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package directorysync

import (
	"errors"
	"path/filepath"
	"syscall"
)

type directorySyncer interface {
	Sync() error
	Close() error
}

func syncWithOpen(path string, open func(string) (directorySyncer, error)) error {
	dir, err := open(filepath.Clean(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncDarwinDirectory(fd int, fullSync, fsync func(int) error) error {
	err := fullSync(fd)
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTTY) {
		return fsync(fd)
	}
	return err
}
