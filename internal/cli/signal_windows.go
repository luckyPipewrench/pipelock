//go:build windows

package cli

import (
	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// registerKillSwitchSignal is a no-op on Windows where SIGUSR1 does not exist.
// The kill switch can still be toggled via the API endpoint or sentinel file.
func registerKillSwitchSignal(_ *killswitch.Controller, _ *cobra.Command) func() {
	return func() {}
}

// reloadSignalHint returns an empty string on Windows where SIGHUP does not
// exist. Config reload still works via fsnotify file watching.
func reloadSignalHint() string {
	return ""
}
