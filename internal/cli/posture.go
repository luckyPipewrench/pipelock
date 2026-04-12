// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"
)

func postureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "posture",
		Short: "Generate signed posture evidence",
	}

	cmd.AddCommand(postureEmitCmd())
	return cmd
}

func postureEmitCmd() *cobra.Command {
	var (
		configFile     string
		outputDir      string
		expirationDays int
	)

	cmd := &cobra.Command{
		Use:   "emit",
		Short: "Emit a signed posture capsule",
		Long: `Generate a signed posture capsule from the current config, discovery
state, simulated scanner coverage, and flight recorder receipts.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := cliutil.LoadConfigOrDefault(configFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			capsule, err := posturepkg.Emit(cfg, posturepkg.Options{
				ExpirationDays: expirationDays,
			})
			if err != nil {
				return fmt.Errorf("emit posture capsule: %w", err)
			}

			path, err := posturepkg.WriteProofJSON(outputDir, capsule)
			if err != nil {
				return fmt.Errorf("write posture capsule: %w", err)
			}

			// TODO: write proof.md once the human-readable posture summary lands.
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", path)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file (default: built-in defaults)")
	cmd.Flags().StringVarP(&outputDir, "output", "o", posturepkg.DefaultOutputDir, "output directory for posture artifacts")
	cmd.Flags().IntVar(&expirationDays, "expiration-days", 0, "days until the capsule expires (default 30)")
	return cmd
}
