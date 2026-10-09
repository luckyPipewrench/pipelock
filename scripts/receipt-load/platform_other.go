// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import "errors"

// filesystemType is only implemented on Linux.
func filesystemType(string) string { return "unavailable: not linux" }

// holdLock is only implemented on Linux.
func holdLock(string) (func(), error) {
	return nil, errors.New("--lock-file is only supported on linux")
}
