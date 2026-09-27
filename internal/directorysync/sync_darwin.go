// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package directorysync

import (
	"os"

	"golang.org/x/sys/unix"
)

type darwinDirectorySyncer struct{ *os.File }

func (d darwinDirectorySyncer) Sync() error {
	return syncDarwinDirectory(int(d.Fd()), func(fd int) error {
		// Apple's fsync(2) and fcntl(2) document F_FULLFSYNC as the
		// stronger request to flush the drive's buffered data.
		_, err := unix.FcntlInt(uintptr(fd), unix.F_FULLFSYNC, 0)
		return err
	}, unix.Fsync)
}

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
