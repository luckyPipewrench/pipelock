// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract/shadow"
)

func diffCmd() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "diff <shadow-a.json> <shadow-b.json>",
		Short: "Compare two shadow JSON reports",
		Long: `Compare two JSON reports written by 'pipelock learn shadow --out-json'.

The output is deterministic markdown summarizing per-rule changes in evaluation
volume and new-block rates between the two shadow runs.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(cmd, args[0], args[1], outPath)
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "", "write markdown to path instead of stdout")
	return cmd
}

func runDiff(cmd *cobra.Command, firstPath, secondPath, outPath string) error {
	first, err := readShadowReport(firstPath)
	if err != nil {
		return err
	}
	second, err := readShadowReport(secondPath)
	if err != nil {
		return err
	}
	rows := shadow.DiffReports(first, second)
	markdown := renderShadowDiff(first, second, rows)
	if outPath == "" {
		emitAuditEvent(cmd, auditEvent{
			Event:     "learn_diff",
			Candidate: filepath.Clean(firstPath),
			Inputs: []string{
				filepath.Clean(firstPath),
				filepath.Clean(secondPath),
			},
			NoOp: len(rows) == 0,
		})
		_, _ = fmt.Fprint(cmd.OutOrStdout(), markdown)
		return nil
	}
	dest, err := checkedWritePath(filepath.Clean(outPath))
	if err != nil {
		return err
	}
	if err := atomicfile.Write(dest, []byte(markdown), 0o600); err != nil {
		return fmt.Errorf("learn diff: write markdown: %w", err)
	}
	emitAuditEvent(cmd, auditEvent{
		Event:     "learn_diff",
		Candidate: filepath.Clean(firstPath),
		Inputs: []string{
			filepath.Clean(firstPath),
			filepath.Clean(secondPath),
		},
		Dest: dest,
		NoOp: len(rows) == 0,
	})
	return nil
}

func renderShadowDiff(first, second shadow.Report, rows []shadow.RuleStats) string {
	out := "# Shadow Diff\n\n"
	out += fmt.Sprintf("- first_contract_hash: `%s`\n", first.ContractHash)
	out += fmt.Sprintf("- second_contract_hash: `%s`\n", second.ContractHash)
	out += fmt.Sprintf("- records_delta: %+d\n", second.TotalRecords-first.TotalRecords)
	out += fmt.Sprintf("- new_blocks_delta: %+d\n", second.NewBlocks-first.NewBlocks)
	out += fmt.Sprintf("- quarantine_delta: %+d\n\n", len(second.Quarantines)-len(first.Quarantines))
	out += "| rule | evals_delta | new_blocks_delta | new_allows_delta | rate_delta |\n"
	out += "|---|---:|---:|---:|---:|\n"
	for _, row := range rows {
		out += fmt.Sprintf("| `%s` | %+d | %+d | %+d | %+.2f%% |\n",
			row.RuleID, row.Evaluations, row.NewBlocks, row.NewAllows, row.NewBlockRatePct)
	}
	return out
}
