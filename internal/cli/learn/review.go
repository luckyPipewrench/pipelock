// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/inference/aggregate"
	contractcompile "github.com/luckyPipewrench/pipelock/internal/contract/inference/compile"
)

func reviewCmd() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "review <candidate.yaml>",
		Short: "Generate deterministic markdown review for a candidate contract",
		Long: `Generate deterministic markdown review for a candidate contract.

This command reads only the signed candidate YAML. It can summarize rule
lifecycle, confidence, thin samples, and opportunity fields carried in the
contract. It cannot reconstruct classification-debt histograms or tail-coverage
state that only exists in the compile-time aggregate stream; use the review file
written by 'pipelock learn compile' for the full operator report.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReview(cmd, args[0], outPath)
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "", "write markdown to path instead of stdout")
	return cmd
}

func runReview(cmd *cobra.Command, candidatePath, outPath string) error {
	clean, doc, err := loadCandidate(candidatePath)
	if err != nil {
		return err
	}
	raw, err := yamlBytes(doc)
	if err != nil {
		return err
	}
	var env contract.ContractEnvelope
	if err := contract.DecodeStrictYAML(raw, &env); err != nil {
		return fmt.Errorf("learn review: decode candidate: %w", err)
	}
	review := contractcompile.ReviewMarkdown(env.Body, aggregate.Aggregates{
		Rules:                map[string]aggregate.RuleCounts{},
		Budgets:              map[string]aggregate.BudgetSamples{},
		HostPathFamilies:     map[string]map[string]int{},
		ActionClassHistogram: map[string]int{},
	}, contractcompile.CompileConfig{})

	if outPath == "" {
		emitAuditEvent(cmd, auditEvent{
			Event:     "learn_review",
			Candidate: clean,
			NoOp:      false,
		})
		_, _ = fmt.Fprint(cmd.OutOrStdout(), review)
		return nil
	}
	dest, err := checkedWritePath(filepath.Clean(outPath))
	if err != nil {
		return err
	}
	if err := atomicfile.Write(dest, []byte(review), 0o600); err != nil {
		return fmt.Errorf("learn review: write: %w", err)
	}
	emitAuditEvent(cmd, auditEvent{
		Event:     "learn_review",
		Candidate: clean,
		Dest:      dest,
		NoOp:      false,
	})
	return nil
}

func yamlBytes(doc *yaml.Node) ([]byte, error) {
	raw, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("learn review: marshal candidate: %w", err)
	}
	return raw, nil
}
