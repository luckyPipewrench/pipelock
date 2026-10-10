// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package scanner

import (
	"os"
	"path/filepath"
	"syscall"
)

// openFixtureNonblocking opens path read-only with O_NONBLOCK, so opening a
// FIFO with no writer returns at once instead of waiting for one.
func openFixtureNonblocking(path string) (*os.File, error) {
	return os.OpenFile(filepath.Clean(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
