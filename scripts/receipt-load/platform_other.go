// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"context"
	"errors"
)

// filesystemType is only implemented on Linux.
func filesystemType(string) string { return "unavailable: not linux" }

// clockTicks is unavailable because non-Linux platforms do not expose the
// process tick rate through the Linux auxiliary vector used by this harness.
func clockTicks(context.Context) (float64, error) {
	return 0, errors.New("CPU clock ticks unavailable: not linux")
}

// holdLock is only implemented on Linux.
func holdLock(string) (func(), error) {
	return nil, errors.New("--lock-file is only supported on linux")
}
