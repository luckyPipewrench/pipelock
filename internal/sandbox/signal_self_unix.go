// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandbox

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

func terminateSelfWithSignal(sig syscall.Signal) {
	signal.Reset(sig)
	_ = syscall.Kill(syscall.Getpid(), sig)
	time.Sleep(100 * time.Millisecond)
	os.Exit(128 + int(sig))
}
