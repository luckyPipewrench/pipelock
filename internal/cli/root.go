// Package cli implements the Pipelock command-line interface using cobra.
package cli

import (
	"errors"
	"strconv"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/spf13/cobra"
)

// ExitError wraps an error with a specific exit code for main() to use.
type ExitError struct {
	Err  error
	Code int
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return "exit code " + strconv.Itoa(e.Code)
	}
	return e.Err.Error()
}
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCodeError wraps err with a non-standard exit code.
// Returns nil when err is nil (no error to wrap).
func ExitCodeError(code int, err error) error {
	if err == nil {
		return nil
	}
	return &ExitError{Err: err, Code: code}
}

// ExitCodeOf returns the exit code for an error, defaulting to 1.
func ExitCodeOf(err error) int {
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 1
}

// Build metadata, set at build time via ldflags. Defaults are used when
// building with plain "go build" (without the Makefile).
var (
	Version   = "0.1.0-dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
	GoVersion = "unknown"
)

// Execute runs the root command.
func Execute() error {
	proxy.Version = Version // sync so /health reports the same version as CLI
	return rootCmd().Execute()
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pipelock",
		Short: "Open-source firewall for AI agents",
		Long: `Pipelock is an application-layer firewall that controls what your AI agent
can access on the network, preventing credential exfiltration while preserving
web browsing capability.

Three modes:
  strict    - Agent can only reach allowlisted API domains (airtight)
  balanced  - Capability separation with monitored web browsing (default)
  audit     - Log everything, restrict nothing (evaluation)

Quick start:
  pipelock run
  pipelock run --config pipelock.yaml
  pipelock check --config pipelock.yaml`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(
		auditCmd(),
		demoCmd(),
		runCmd(),
		logsCmd(),
		checkCmd(),
		generateCmd(),
		gitCmd(),
		integrityCmd(),
		keygenCmd(),
		mcpCmd(),
		signCmd(),
		testCmd(),
		verifyCmd(),
		trustCmd(),
		versionCmd(),
		healthcheckCmd(),
	)

	return cmd
}
