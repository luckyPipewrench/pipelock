// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"syscall"
)

func controlSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func isPauseSignal(os.Signal) bool {
	return false
}

func isResumeSignal(os.Signal) bool {
	return false
}

func isShutdownSignal(sig os.Signal) bool {
	return sig == os.Interrupt || sig == syscall.SIGTERM
}
