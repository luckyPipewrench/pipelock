// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

// Package processexec centralizes intentional process replacement after a
// caller has resolved and validated the executable and arguments.
package processexec

import "syscall"

// Replace replaces the calling process image and returns only on failure.
func Replace(binary string, argv, environment []string) error {
	return syscall.Exec(binary, argv, environment) //nolint:gosec // G204: callers resolve and validate the exact executable before replacement
}
