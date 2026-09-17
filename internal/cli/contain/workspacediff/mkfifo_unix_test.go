// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspacediff

import "syscall"

func makeFIFO(path string) error {
	return syscall.Mkfifo(path, 0o600)
}
