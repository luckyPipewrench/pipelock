// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyReloadSignal registers SIGHUP to trigger config reload on Unix.
func notifyReloadSignal(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGHUP)
}
