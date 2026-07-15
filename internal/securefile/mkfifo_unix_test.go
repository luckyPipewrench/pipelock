//go:build unix

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import "syscall"

func syscallMkfifo(path string, mode uint32) error {
	return syscall.Mkfifo(path, mode)
}
