// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/skillscan"
)

const (
	skillScanExitFindings = 1
	skillScanExitError    = 2
)

func skillScanCmd() *cobra.Command {
	var (
		lockFile      string
		allowlistFile string
		minSeverity   string
		baseline      bool
		update        bool
		includeDeps   bool
		jsonOutput    bool
		inventoryOnly bool
		noColor       bool
	)

	cmd := &cobra.Command{
		Use:   "skill-scan [path...]",
		Short: "Inventory skill files and flag lock drift or source-to-sink combinations",
		Long: `Inventory local agent skill files, compare them to an operator-owned
lock file, and flag conservative source-to-sink combinations with line evidence.

This is static defense-in-depth for files at rest. Runtime network and tool
enforcement remains Pipelock proper; a clean static scan is not a runtime allow.

Exit codes: 0 = no gated findings; 1 = findings at/above --min-severity;
2 = scan/config/IO error.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = noColor
			threshold := skillscan.Severity(minSeverity)
			if !skillscan.ValidateSeverity(threshold) {
				return cliutil.ExitCodeError(skillScanExitError,
					fmt.Errorf("invalid --min-severity %q (want high, medium, or low)", minSeverity))
			}
			opts := skillscan.Options{
				Paths:         args,
				LockFile:      lockFile,
				AllowlistFile: allowlistFile,
				Baseline:      baseline,
				Update:        update,
				IncludeDeps:   includeDeps,
				InventoryOnly: inventoryOnly,
			}
			res, err := skillscan.Scan(opts)
			if err != nil {
				return cliutil.ExitCodeError(skillScanExitError, err)
			}
			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				if encErr := enc.Encode(res); encErr != nil {
					return cliutil.ExitCodeError(skillScanExitError, encErr)
				}
			} else {
				res.WriteReport(cmd.OutOrStdout())
			}
			if gated := res.GatedFindings(threshold); len(gated) > 0 {
				return cliutil.ExitCodeError(skillScanExitFindings,
					fmt.Errorf("%w: %d at/above %s", skillscan.ErrFindings, len(gated), minSeverity))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&lockFile, "lock-file", "", "compare against this lock file")
	cmd.Flags().BoolVar(&baseline, "baseline", false, "write the current inventory to --lock-file, or ./pipelock-skill-lock.yaml when omitted")
	cmd.Flags().BoolVar(&update, "update", false, "rewrite the lock file after operator review")
	cmd.Flags().StringVar(&allowlistFile, "allowlist", "", "YAML file of exact combo fingerprints to suppress, each with a justification")
	cmd.Flags().StringVar(&minSeverity, "min-severity", string(skillscan.SeverityHigh), "minimum severity that causes a non-zero exit (high|medium|low); high gates on provable drift, tamper, direct transfers, and unscanned oversize files")
	cmd.Flags().BoolVar(&includeDeps, "include-deps", false, "include dependency install commands in the capability inventory")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "emit inventory and findings as JSON")
	cmd.Flags().BoolVar(&inventoryOnly, "inventory-only", false, "emit M1 capability inventory only; skip all findings")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "accepted for tooling compatibility; report output is not colorized")

	return cmd
}
