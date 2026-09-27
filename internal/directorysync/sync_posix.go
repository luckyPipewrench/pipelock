// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package directorysync

import "path/filepath"

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
