//go:build unix && !aix && !js && !wasip1

// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package securefile

import "syscall"

func syscallMkfifo(path string, mode uint32) error {
	return syscall.Mkfifo(path, mode)
}
