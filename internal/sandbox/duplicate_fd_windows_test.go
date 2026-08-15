// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sandbox

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func duplicateTestFD(t *testing.T, file *os.File) uintptr {
	t.Helper()
	var duplicate windows.Handle
	err := windows.DuplicateHandle(
		windows.CurrentProcess(),
		windows.Handle(file.Fd()),
		windows.CurrentProcess(),
		&duplicate,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	)
	if err != nil {
		t.Fatalf("duplicate test descriptor: %v", err)
	}
	return uintptr(duplicate)
}
