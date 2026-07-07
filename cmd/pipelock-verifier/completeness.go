// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/evidence/completeness"
	actionreceipt "github.com/luckyPipewrench/pipelock/internal/receipt"
)

type completenessOptions struct {
	signerKey     string
	sessionID     string
	jsonOutput    bool
	allowUnpinned bool
}

func newCompletenessCmd() *cobra.Command {
	var opts completenessOptions
	cmd := &cobra.Command{
		Use:   "completeness RUNDIR|FILE",
		Short: "Analyze bounded run-completeness evidence",
		Long: `Analyzes signed session lifecycle evidence in an action-receipt chain.
The best possible completeness result is LIMITED, never COMPLETE/PASS/OK:
Pipelock can bound mediated egress it observed, but cannot prove the agent had
no egress path outside that boundary.

Exit-code contract:
  0  analysis ran and the chain was not classified BROKEN; LIMITED and
     UNVERIFIED are successful analyses
  1  BROKEN chain/completeness evidence, unpinned non-empty chain without
     --allow-unpinned, or another verifier failure
  2  tool, IO, extraction, or key-resolution error
 64  command-line usage error`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCompleteness(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)
	cmd.Flags().StringVar(&opts.signerKey, "key", "", "expected signer public key (hex, public-key text, or file path)")
	cmd.Flags().StringVar(&opts.sessionID, "session", "proxy", "session ID inside an evidence directory")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON report on stdout")
	cmd.Flags().BoolVar(&opts.allowUnpinned, "allow-unpinned", false, "allow structural-only verification without a trusted signer key")
	return cmd
}

func runCompleteness(stdout, stderr io.Writer, target string, opts completenessOptions) error {
	keyHex, err := resolveSignerKey(strings.TrimSpace(opts.signerKey))
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve signer key: %w", err))
	}
	clean := filepath.Clean(target)
	receipts, label, err := extractCompletenessReceipts(clean, opts.sessionID)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	chainResult := actionreceipt.VerifyChain(receipts, keyHex)
	report := completeness.Analyze(receipts, chainResult)
	report.Path = label
	report.SignaturesVerified = chainResult.IntegrityVerified && keyHex != ""
	report.Unpinned = len(receipts) > 0 && chainResult.IntegrityVerified && keyHex == ""
	if report.Unpinned && !opts.allowUnpinned {
		// Append rather than overwrite: a report can be both Unpinned and
		// StatusBroken (integrity-valid chain with a completeness structural
		// violation), and the broken reason must survive so the exit-1 detail
		// below reports the real cause, not just the unpinned banner.
		if report.Error == "" {
			report.Error = unpinnedReceiptBanner
		} else {
			report.Error = report.Error + "; " + unpinnedReceiptBanner
		}
	}

	emitCompletenessReport(stdout, stderr, report, opts.jsonOutput)
	if report.Status == completeness.StatusBroken {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("completeness broken: %s", report.Error))
	}
	if report.Unpinned && !opts.allowUnpinned {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("completeness verification unpinned"))
	}
	return nil
}

func extractCompletenessReceipts(clean, sessionID string) ([]actionreceipt.Receipt, string, error) {
	info, err := os.Stat(clean)
	if err != nil {
		return nil, "", fmt.Errorf("stat %q: %w", clean, err)
	}
	if info.IsDir() {
		receipts, extractErr := actionreceipt.ExtractReceiptsFromSessionDir(clean, sessionID)
		if extractErr != nil {
			return nil, "", fmt.Errorf("extract receipts: %w", extractErr)
		}
		return receipts, fmt.Sprintf("%s (session %s)", clean, sessionID), nil
	}
	receipts, err := actionreceipt.ExtractReceipts(clean)
	if err != nil {
		return nil, "", fmt.Errorf("extract receipts: %w", err)
	}
	return receipts, clean, nil
}

func emitCompletenessReport(stdout, stderr io.Writer, report completeness.Report, jsonMode bool) {
	if jsonMode {
		writeJSON(stdout, report)
		return
	}
	if report.Unpinned {
		_, _ = fmt.Fprintf(stderr, "WARN: %s\n", unpinnedReceiptBanner)
	}
	_, _ = fmt.Fprintf(stdout, "completeness: %s (%s)\n", report.Status, report.Reason)
	_, _ = fmt.Fprintf(stdout, "path: %s\n", report.Path)
	_, _ = fmt.Fprintf(stdout, "receipts: %d\n", report.ReceiptCount)
	if report.FinalSeq != 0 || report.RootHash != "" {
		_, _ = fmt.Fprintf(stdout, "final_seq: %d\n", report.FinalSeq)
	}
	if report.RootHash != "" {
		_, _ = fmt.Fprintf(stdout, "root_hash: %s\n", report.RootHash)
	}
	if report.Error != "" {
		_, _ = fmt.Fprintf(stdout, "detail: %s\n", report.Error)
	}
	for _, run := range report.Runs {
		emitCompletenessRun(stdout, run)
	}
}

func emitCompletenessRun(stdout io.Writer, run completeness.RunReport) {
	_, _ = fmt.Fprintf(stdout, "\nrun_nonce: %s\n", run.RunNonce)
	_, _ = fmt.Fprintf(stdout, "  status: %s\n", run.Status)
	_, _ = fmt.Fprintf(stdout, "  reason: %s\n", run.Reason)
	_, _ = fmt.Fprintf(stdout, "  intents: %d\n", run.Intents)
	_, _ = fmt.Fprintf(stdout, "  outcomes: %d\n", run.Outcomes)
	_, _ = fmt.Fprintf(stdout, "  matched_pairs: %d\n", run.MatchedPairs)
	_, _ = fmt.Fprintf(stdout, "  unmatched_intents: %d\n", run.UnmatchedIntents)
	_, _ = fmt.Fprintf(stdout, "  heartbeats: %d\n", run.Heartbeats)
	_, _ = fmt.Fprintf(stdout, "  closed: %t\n", run.Closed)
	_, _ = fmt.Fprintf(stdout, "  durability_monotonic: %t\n", run.DurabilityMonotonic)
	_, _ = fmt.Fprintf(stdout, "  fsync_errors_gated: %d\n", run.FsyncErrorsGated)
	_, _ = fmt.Fprintf(stdout, "  durability_blocks: %d\n", run.DurabilityBlocks)
	if run.LastHeartbeat != nil {
		_, _ = fmt.Fprintf(stdout, "  last_heartbeat_fsync_errors_gated: %d\n", run.LastHeartbeat.FsyncErrorsGated)
		_, _ = fmt.Fprintf(stdout, "  last_heartbeat_durability_blocks: %d\n", run.LastHeartbeat.DurabilityBlocks)
	}
	if run.Close != nil {
		_, _ = fmt.Fprintf(stdout, "  close_fsync_errors_gated: %d\n", run.Close.FsyncErrorsGated)
		_, _ = fmt.Fprintf(stdout, "  close_durability_blocks: %d\n", run.Close.DurabilityBlocks)
	}
	if run.StructuralViolation != "" {
		_, _ = fmt.Fprintf(stdout, "  structural_violation: %s\n", run.StructuralViolation)
	}
}
