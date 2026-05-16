// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandbox

import (
	"os"
	"os/signal"
	"syscall"
)

func terminateSelfWithSignal(sig syscall.Signal) {
	signal.Reset(sig)
	_ = syscall.Kill(syscall.Getpid(), sig)
	os.Exit(128 + int(sig))
}
