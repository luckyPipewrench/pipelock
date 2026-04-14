// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package session implements the `pipelock session` operator CLI for
// inspecting and recovering airlocked sessions. Subcommands talk to the
// session admin API on the running pipelock instance using the shared
// client defined in client.go.
package session

import (
	"github.com/spf13/cobra"
)

// Shared flag names used across subcommands. Kept in one place so the
// help strings and env-var fallbacks stay aligned.
const (
	flagAPIURL   = "api-url"
	flagAPIToken = "api-token" //nolint:gosec // flag name, not a credential
	flagConfig   = "config"
	flagJSON     = "json"
)

// Shared usage strings so goconst stays quiet and help text is consistent.
const (
	usageAPIURL   = "admin API base URL (default: derived from config file kill_switch.api_listen)"
	usageAPIToken = "admin API bearer token (default: PIPELOCK_KILLSWITCH_API_TOKEN env or config file)"
	usageConfig   = "pipelock config file path (default: PIPELOCK_CONFIG env, ~/.config/pipelock/pipelock.yaml, or /etc/pipelock/pipelock.yaml)"
	usageJSON     = "machine-readable JSON output"
)

// rootFlags collects the flag values shared by every session subcommand.
// Each subcommand binds its own copy of these via addCommonFlags so that
// table-driven tests can construct isolated command instances.
type rootFlags struct {
	apiURL     string
	apiToken   string
	configPath string
}

// Cmd is the parent command for `pipelock session`. Exported so the root
// CLI can register it alongside the other top-level commands.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "session",
		Short: "Inspect and recover airlocked agent sessions",
		Long: `Operator commands for the per-session airlock. Use these commands to
investigate sessions that have been quarantined by adaptive enforcement
and to release or terminate them once the underlying incident is resolved.

Every subcommand talks to the running pipelock's session admin API
(requires kill_switch.api_token). The API URL and token are resolved
from flags, environment variables, or the pipelock config file — see
the global flags for details.

Examples:
  pipelock session list
  pipelock session list --tier hard --json
  pipelock session inspect "agent|10.0.0.1"
  pipelock session explain "agent|10.0.0.1"
  pipelock session release "agent|10.0.0.1" --to none
  pipelock session terminate "agent|10.0.0.1"
  pipelock session recover "agent|10.0.0.1"`,
	}
	cmd.AddCommand(
		listCmd(),
		inspectCmd(),
		explainCmd(),
		releaseCmd(),
		terminateCmd(),
		recoverCmd(),
	)
	return cmd
}

// addCommonFlags wires the shared --api-url, --api-token, --config flags
// onto a subcommand. Returns a pointer to the flag-backed struct so the
// subcommand's RunE closure can read the values at execution time.
func addCommonFlags(cmd *cobra.Command) *rootFlags {
	flags := &rootFlags{}
	cmd.Flags().StringVar(&flags.apiURL, flagAPIURL, "", usageAPIURL)
	cmd.Flags().StringVar(&flags.apiToken, flagAPIToken, "", usageAPIToken)
	cmd.Flags().StringVar(&flags.configPath, flagConfig, "", usageConfig)
	return flags
}
