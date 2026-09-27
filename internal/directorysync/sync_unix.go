// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package directorysync

import (
	"os"
	"path/filepath"
)

type directorySyncer interface {
	Sync() error
	Close() error
}

func Sync(path string) error {
	return syncWithOpen(path, func(name string) (directorySyncer, error) {
		// #nosec G304 -- the artifact directory is intentionally operator-configured.
		return os.Open(name)
	})
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
