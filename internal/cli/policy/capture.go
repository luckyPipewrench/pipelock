// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// captureCmd returns the "policy capture" subcommand.
func captureCmd() *cobra.Command {
	var (
		configFile         string
		outputDir          string
		duration           time.Duration
		sign               bool
		redact             bool
		rawEscrow          bool
		escrowPublicKey    string
		checkpointInterval int
		retentionDays      int
		maxEntriesPerFile  int
	)

	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Capture live proxy verdicts to a session directory",
		Long: `Start the pipelock proxy with capture enabled, writing all policy
verdicts to the specified output directory.

Captured sessions can later be replayed with "pipelock policy replay" to
compare behaviour against a candidate config.

Examples:
  pipelock policy capture --output ./sessions/ --duration 1h
  pipelock policy capture --output ./sessions/ --sign --redact
  pipelock policy capture --output ./sessions/ --raw-escrow --escrow-public-key <hex>`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if outputDir == "" {
				return fmt.Errorf("--output is required")
			}
			// v1 stub: capture runtime plumbing is wired via "pipelock run" flags.
			return fmt.Errorf("capture command is not yet fully implemented — see pipelock run with capture options")
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "pipelock config YAML")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "directory for capture session files (required)")
	cmd.Flags().DurationVar(&duration, "duration", 0, "capture duration (0 = until interrupted)")
	cmd.Flags().BoolVar(&sign, "sign", false, "sign checkpoints with Ed25519 key")
	cmd.Flags().BoolVar(&redact, "redact", false, "DLP-redact payloads before writing")
	cmd.Flags().BoolVar(&rawEscrow, "raw-escrow", false, "encrypt exact payloads into sidecar files")
	cmd.Flags().StringVar(&escrowPublicKey, "escrow-public-key", "", "X25519 hex public key for sidecar encryption")
	cmd.Flags().IntVar(&checkpointInterval, "checkpoint-interval", 0, "checkpoint every N entries (0 = recorder default)")
	cmd.Flags().IntVar(&retentionDays, "retention-days", 0, "delete session files older than N days (0 = no limit)")
	cmd.Flags().IntVar(&maxEntriesPerFile, "max-entries-per-file", 0, "rotate to a new file after N entries (0 = recorder default)")

	return cmd
}
