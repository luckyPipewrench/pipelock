// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"os"
	"syscall"
)

func controlSignals() []os.Signal {
	return []os.Signal{syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGTERM, syscall.SIGINT}
}

func isPauseSignal(sig os.Signal) bool {
	return sig == syscall.SIGUSR1
}

func isResumeSignal(sig os.Signal) bool {
	return sig == syscall.SIGUSR2
}

func isShutdownSignal(sig os.Signal) bool {
	return sig == syscall.SIGTERM || sig == syscall.SIGINT
}
