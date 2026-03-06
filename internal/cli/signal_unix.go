// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// registerKillSwitchSignal sets up SIGUSR1 to toggle the kill switch.
// Returns a cleanup function that must be deferred.
func registerKillSwitchSignal(ks *killswitch.Controller, cmd *cobra.Command) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)

	go func() {
		for sig := range ch {
			if sig == nil {
				return
			}
			active := ks.ToggleSignal()
			if active {
				cmd.PrintErrln("pipelock: kill switch ACTIVATED via SIGUSR1")
			} else {
				cmd.PrintErrln("pipelock: kill switch DEACTIVATED via SIGUSR1")
			}
		}
	}()

	return func() {
		signal.Stop(ch)
		close(ch)
	}
}

// reloadSignalHint returns the platform-specific hint for the config reload
// startup message. On Unix, SIGHUP triggers a reload.
func reloadSignalHint() string {
	return ", SIGHUP to reload"
}
