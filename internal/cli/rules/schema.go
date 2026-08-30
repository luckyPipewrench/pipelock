// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
)

func rulesSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Export the rule-bundle reader contract as JSON",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !cliutil.HasExactBuildIdentity() {
				return fmt.Errorf("export rule schema: exact build version and source revision are unavailable")
			}
			contract, err := domrules.BuildRuleSchemaContract(cliutil.Version, cliutil.GitCommit)
			if err != nil {
				return fmt.Errorf("export rule schema: %w", err)
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(contract); err != nil {
				return fmt.Errorf("encode rule schema: %w", err)
			}
			return nil
		},
	}
}
