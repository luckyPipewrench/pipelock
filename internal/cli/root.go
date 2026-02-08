// Package cli implements the Pipelock command-line interface using cobra.
package cli

import (
	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "0.1.0-dev"

// Execute runs the root command.
func Execute() error {
	return rootCmd().Execute()
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pipelock",
		Short: "Security harness for AI agents",
		Long: `Pipelock controls what your AI agent can access on the network,
preventing credential exfiltration while preserving web browsing capability.

Three modes:
  strict    - Agent can only reach allowlisted API domains (airtight)
  balanced  - Capability separation with monitored web browsing (default)
  audit     - Log everything, restrict nothing (evaluation)

Quick start:
  pipelock run -- python my_agent.py
  pipelock run --config pipelock.yaml -- ./my-agent
  pipelock check --config pipelock.yaml`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(
		runCmd(),
		logsCmd(),
		checkCmd(),
		generateCmd(),
	)

	return cmd
}
