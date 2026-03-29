// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package policy implements the "pipelock policy" command group, which
// provides subcommands for capturing live proxy verdicts to disk and replaying
// them against a candidate config to produce a diff report.
package policy

import "github.com/spf13/cobra"

// Cmd returns the "policy" subcommand group.
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Capture and replay policy verdicts",
		Long:  "Capture live proxy verdicts to disk and replay them against a candidate config to produce a diff report.",
	}
	cmd.AddCommand(captureCmd())
	cmd.AddCommand(replayCmd())
	return cmd
}
