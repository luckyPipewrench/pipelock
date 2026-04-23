// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package runtime

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// RegisterKillSwitchSignal sets up SIGUSR1 to toggle the kill switch.
// Returns a cleanup function that must be deferred.
func RegisterKillSwitchSignal(ks *killswitch.Controller, stderr io.Writer) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)

	go func() {
		for sig := range ch {
			if sig == nil {
				return
			}
			active := ks.ToggleSignal()
			if active {
				_, _ = fmt.Fprintln(stderr, "pipelock: kill switch ACTIVATED via SIGUSR1")
			} else {
				_, _ = fmt.Fprintln(stderr, "pipelock: kill switch DEACTIVATED via SIGUSR1")
			}
		}
	}()

	return func() {
		signal.Stop(ch)
		close(ch)
	}
}

// ReloadSignalHint returns the platform-specific hint for the config reload
// startup message. On Unix, SIGHUP triggers a reload.
func ReloadSignalHint() string {
	return ", SIGHUP to reload"
}
