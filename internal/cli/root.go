// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the Pipelock command-line interface using cobra.
// Subpackages contain the actual command implementations; this package
// wires them into the root command.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cli/assess"
	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/canary"
	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	"github.com/luckyPipewrench/pipelock/internal/cli/generate"
	"github.com/luckyPipewrench/pipelock/internal/cli/git"
	"github.com/luckyPipewrench/pipelock/internal/cli/rules"
	"github.com/luckyPipewrench/pipelock/internal/cli/runtime"
	"github.com/luckyPipewrench/pipelock/internal/cli/setup"
	clisigning "github.com/luckyPipewrench/pipelock/internal/cli/signing"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// extraCommands holds commands registered by enterprise packages via init().
var extraCommands []*cobra.Command

// RegisterCommand adds a subcommand to the root command. Called by enterprise
// CLI packages during init() to register license management commands.
func RegisterCommand(cmd *cobra.Command) {
	extraCommands = append(extraCommands, cmd)
}

// Execute runs the root command.
func Execute() error {
	proxy.Version = cliutil.Version // sync so /health reports the same version as CLI
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
		Version:       cliutil.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.PersistentFlags().StringVar(&cliutil.PipelockHome, "home", "",
		"pipelock home directory (default ~/.pipelock, or set PIPELOCK_HOME)")

	cmd.AddCommand(
		// Assess
		assess.Cmd(),
		// Audit & reporting
		audit.Cmd(),
		// Canary tokens
		canary.Cmd(),
		audit.ReportCmd(),
		audit.SimulateCmd(),
		// Diagnostics
		diag.DiagnoseCmd(),
		diag.DiscoverCmd(),
		diag.PreflightCmd(),
		diag.CheckCmd(),
		diag.VerifyInstallCmd(),
		diag.TestCmd(),
		diag.DemoCmd(),
		diag.LogsCmd(),
		// Generate
		generate.Cmd(),
		// Git
		git.Cmd(),
		// Rules
		rules.Cmd(),
		// Runtime
		runtime.RunCmd(),
		runtime.McpCmd(),
		runtime.SandboxCmd(),
		runtime.InternalRedirectCmd(),
		runtime.HealthcheckCmd(),
		// Setup (IDE integrations)
		setup.ClaudeCmd(),
		setup.CursorCmd(),
		setup.VscodeCmd(),
		setup.JetbrainsCmd(),
		// Signing & integrity
		clisigning.IntegrityCmd(),
		clisigning.SignCmd(),
		clisigning.VerifyCmd(),
		clisigning.KeygenCmd(),
		clisigning.TrustCmd(),
		clisigning.TlsCmd(),
		// Version
		versionCmd(),
	)

	// Enterprise packages register extra commands via RegisterCommand().
	for _, extra := range extraCommands {
		cmd.AddCommand(extra)
	}

	return cmd
}
