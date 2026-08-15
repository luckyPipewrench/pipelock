// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandbox

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func duplicateTestFD(t *testing.T, file *os.File) uintptr {
	t.Helper()
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatalf("duplicate test descriptor: %v", err)
	}
	return uintptr(fd)
}
