// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package directorysync

import (
	"os"

	"golang.org/x/sys/unix"
)

type darwinDirectorySyncer struct{ *os.File }

func (d darwinDirectorySyncer) Sync() error { return unix.Fsync(int(d.Fd())) }

// Sync flushes the directory entry after the artifact file itself is synced.
func Sync(path string) error {
	return syncWithOpen(path, func(name string) (directorySyncer, error) {
		// #nosec G304 -- the artifact directory is intentionally operator-configured.
		dir, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		return darwinDirectorySyncer{dir}, nil
	})
}
