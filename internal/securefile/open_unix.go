//go:build unix

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import (
	"os"
	"syscall"
)

func openRegularNonblocking(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
