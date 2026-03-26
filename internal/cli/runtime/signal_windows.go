// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package runtime

import (
	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// RegisterKillSwitchSignal is a no-op on Windows where SIGUSR1 does not exist.
// The kill switch can still be toggled via the API endpoint or sentinel file.
func RegisterKillSwitchSignal(_ *killswitch.Controller, _ *cobra.Command) func() {
	return func() {}
}

// ReloadSignalHint returns an empty string on Windows where SIGHUP does not
// exist. Config reload still works via fsnotify file watching.
func ReloadSignalHint() string {
	return ""
}
