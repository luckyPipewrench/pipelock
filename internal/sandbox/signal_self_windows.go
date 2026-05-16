// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sandbox

import (
	"os"
	"syscall"
)

func terminateSelfWithSignal(sig syscall.Signal) {
	os.Exit(128 + int(sig))
}
