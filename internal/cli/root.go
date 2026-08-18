// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the Pipelock command-line interface using cobra.
// Subpackages contain the actual command implementations; this package
// wires them into the root command.
package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cli/anchor"
	"github.com/luckyPipewrench/pipelock/internal/cli/assess"
	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/cli/canary"
	commitmentkeycmd "github.com/luckyPipewrench/pipelock/internal/cli/commitmentkey"
	"github.com/luckyPipewrench/pipelock/internal/cli/contain"
	"github.com/luckyPipewrench/pipelock/internal/cli/diag"
	clienvelope "github.com/luckyPipewrench/pipelock/internal/cli/envelope"
	"github.com/luckyPipewrench/pipelock/internal/cli/evidence"
	"github.com/luckyPipewrench/pipelock/internal/cli/generate"
	"github.com/luckyPipewrench/pipelock/internal/cli/git"
	cliguard "github.com/luckyPipewrench/pipelock/internal/cli/guard"
	"github.com/luckyPipewrench/pipelock/internal/cli/hermes"
	"github.com/luckyPipewrench/pipelock/internal/cli/keys"
	"github.com/luckyPipewrench/pipelock/internal/cli/learn"
	"github.com/luckyPipewrench/pipelock/internal/cli/policy"
	"github.com/luckyPipewrench/pipelock/internal/cli/presets"
	"github.com/luckyPipewrench/pipelock/internal/cli/rules"
	"github.com/luckyPipewrench/pipelock/internal/cli/runtime"
	"github.com/luckyPipewrench/pipelock/internal/cli/scan"
	"github.com/luckyPipewrench/pipelock/internal/cli/selfupdate"
	"github.com/luckyPipewrench/pipelock/internal/cli/session"
	"github.com/luckyPipewrench/pipelock/internal/cli/setup"
	clisigning "github.com/luckyPipewrench/pipelock/internal/cli/signing"
	"github.com/luckyPipewrench/pipelock/internal/cli/support"
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

	// Route command results to stdout.
	//
	// cobra's Print, Printf, and Println all write to OutOrStderr(), which
	// returns the configured out writer if one is set and otherwise falls back
	// to stderr. Nothing set one, so every human-readable result in the CLI was
	// landing on stderr while `pipelock version > file` produced an empty file.
	// A test could not see it: SetOut in a test IS the writer OutOrStderr
	// returns, so the text appeared exactly where the test looked for it.
	//
	// Setting it here makes the split the code already encodes mean what it
	// reads as: Print* is a result and goes to stdout, PrintErr* is a
	// diagnostic and still goes to stderr. Subcommands inherit it through the
	// parent chain. Usage output is the one other consumer of this writer, and
	// SilenceUsage on this command keeps cobra from ever emitting it.
	cmd.SetOut(os.Stdout)

	cmd.PersistentFlags().StringVar(&cliutil.PipelockHome, "home", "",
		"pipelock home directory (default ~/.pipelock, or set PIPELOCK_HOME)")

	cmd.AddCommand(
		// External receipt anchoring
		anchor.Cmd(),
		// Assess
		assess.Cmd(),
		// Policy capture/replay
		policy.Cmd(),
		// Posture capsules
		postureCmd(),
		// Audit & reporting
		audit.Cmd(),
		// Canary tokens
		canary.Cmd(),
		audit.ReportCmd(),
		audit.SimulateCmd(),
		// Containment (workstation-tier)
		contain.Cmd(),
		// Private evidence commitment key lifecycle
		commitmentkeycmd.Cmd(),
		// Mediation envelope trust management
		clienvelope.Cmd(),
		// Evidence viewer (Free, single-agent)
		evidence.Cmd(),
		// Diagnostics
		diag.DoctorCmd(),
		diag.DiagnoseCmd(),
		diag.DiscoverCmd(),
		diag.PreflightCmd(),
		diag.CheckCmd(),
		diag.VerifyInstallCmd(),
		diag.TestCmd(),
		diag.DemoCmd(),
		diag.LogsCmd(),
		statusCmd(),
		support.Cmd(),
		// Generate
		generate.Cmd(),
		presets.Cmd(),
		// Git
		git.Cmd(),
		// Guard declaration and compiled-floor inspection
		cliguard.Cmd(),
		// Hermes Agent (Nous Research) integration
		hermes.Cmd(),
		// Signing-key inventory
		keys.Cmd(),
		// Learn-and-lock observation pipeline
		learn.Cmd(),
		// Rules
		rules.Cmd(),
		// Runtime
		runtime.RunCmd(),
		runtime.McpCmd(),
		runtime.SandboxCmd(),
		runtime.InternalRedirectCmd(),
		runtime.HealthcheckCmd(),
		// File injection scanning (invisible-Unicode / bidi)
		scan.Cmd(),
		skillScanCmd(),
		// Session admin (airlock recovery)
		session.AdaptiveCmd(),
		session.BaselineCmd(),
		session.Cmd(),
		// Setup (IDE integrations)
		setup.InitCmd(),
		setup.ClaudeCmd(),
		setup.ClineCmd(),
		setup.CursorCmd(),
		setup.VscodeCmd(),
		setup.JetbrainsCmd(),
		setup.CodexCmd(),
		setup.OpenCodeCmd(),
		setup.ZedCmd(),
		// Signing & integrity
		clisigning.IntegrityCmd(),
		clisigning.SignCmd(),
		clisigning.VerifyCmd(),
		clisigning.KeygenCmd(),
		clisigning.TrustCmd(),
		clisigning.TlsCmd(),
		clisigning.VerifyReceiptCmd(),
		clisigning.TranscriptRootCmd(),
		clisigning.SigningSubtreeCmd(),
		// Explain a URL verdict with per-scanner remediation.
		explainCmd(),
		quickstartCmd(),
		// Binary install helper for sidecar init containers.
		installCmd(),
		// Self-update (verified release install)
		selfupdate.Cmd(),
		// Version
		versionCmd(),
	)

	// Enterprise packages register extra commands via RegisterCommand().
	for _, extra := range extraCommands {
		cmd.AddCommand(extra)
	}

	guardGroupingCommands(cmd)

	return cmd
}

// guardGroupingCommands makes a command that only groups subcommands reject a
// subcommand it does not have, instead of reporting success.
//
// cobra checks for an unknown subcommand on the ROOT command only: legacyArgs
// returns its "unknown command" error solely when the command has no parent.
// Every nested group therefore accepted any word, fell through to the help
// path, and returned nil, so the process exited 0. `pipelock contain instal`
// printed help and reported success while nothing was installed, which in a
// setup script reads as containment being in place when it is not.
//
// Setting Args alone does not fix it. cobra returns flag.ErrHelp for a
// non-runnable command BEFORE it validates arguments (command.go, the
// `!c.Runnable()` check precedes ValidateArgs), so an argument constraint on a
// command with no action is never consulted. The group needs an action for the
// constraint to be reached, and printing help is the action it already had.
//
// Applied by walking the assembled tree rather than by annotating each command,
// so a group added later is covered without anyone remembering to.
func guardGroupingCommands(cmd *cobra.Command) {
	for _, sub := range cmd.Commands() {
		guardGroupingCommands(sub)
	}
	// A group is a command with children and no action of its own. Anything
	// runnable is left alone: it may legitimately take positional arguments.
	if cmd.Runnable() || !cmd.HasSubCommands() {
		return
	}
	cmd.Args = cobra.NoArgs
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		return c.Help()
	}
}
