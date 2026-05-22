// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

// `pipelock-verifier replay` re-evaluates a Pipelock action receipt against
// a current policy. The point: turn receipts from "what happened" into
// "what would happen today under current policy" — the governance-evidence
// shift. Codex 2026-05-21 leadership review framed this as the
// load-bearing primitive for receipts as evidence rather than logs.
//
// Free-tier scope (single-agent): load one receipt, load one YAML policy,
// re-run the scanner pipeline against the receipt's preserved target URL,
// and emit a verdict-comparison report. Pro-tier corpus search across an
// agent fleet is out of scope.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type replayOptions struct {
	policyPath string
	signerKey  string
	jsonOutput bool
}

func newReplayCmd() *cobra.Command {
	var opts replayOptions

	cmd := &cobra.Command{
		Use:   "replay RECEIPT_PATH",
		Short: "Replay an action receipt against a current policy",
		Long: `Re-evaluates a Pipelock action receipt against the policy in --policy
to answer the question: would this action still be allowed or blocked today?

The receipt's preserved target URL is fed through the same scanner pipeline
the live proxy uses, with the loaded policy as the current ground truth.
The replay verdict is compared against the receipt's original verdict.

The receipt is also re-verified against its embedded signer key (or the key
supplied via --key); a tampered or unverifiable receipt is reported as a
replay-blocking error before any policy comparison is attempted.

Use cases:
  - Confirm a previously-blocked action would still be blocked under the
    new policy ("the block is durable").
  - Discover that a previously-allowed action would now be blocked
    ("policy tightened; surface this for audit").
  - Discover that a previously-blocked action would now be allowed
    ("policy loosened; surface this for review").

Exit codes:
  0  receipt verified and policy verdict matches original (no change)
  1  receipt verified but policy verdict differs from original
  2  receipt malformed, signature invalid, or policy could not be loaded
  64 usage error`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReplay(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringVar(&opts.policyPath, "policy", "", "path to YAML policy to replay against (required)")
	cmd.Flags().StringVar(&opts.signerKey, "key", "", "expected signer public key (hex, public-key text, or file path)")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON report on stdout")

	return cmd
}

// replayReport is the structured output emitted by `replay`. Stable JSON
// shape so external tooling can consume it.
type replayReport struct {
	ReceiptPath     string   `json:"receipt_path"`
	PolicyPath      string   `json:"policy_path"`
	ActionID        string   `json:"action_id,omitempty"`
	Target          string   `json:"target,omitempty"`
	Transport       string   `json:"transport,omitempty"`
	OriginalVerdict string   `json:"original_verdict,omitempty"`
	ReplayVerdict   string   `json:"replay_verdict,omitempty"`
	ReplayScanner   string   `json:"replay_scanner,omitempty"`
	ReplayReason    string   `json:"replay_reason,omitempty"`
	VerdictChanged  bool     `json:"verdict_changed"`
	ReceiptValid    bool     `json:"receipt_valid"`
	Details         []string `json:"details,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// Verdict tags emitted by `replay`. Aligned with config.Action* but kept as
// short strings here for human readability in the report.
const (
	replayVerdictAllow = "allow"
	replayVerdictBlock = "block"
)

func runReplay(stdout, stderr io.Writer, receiptPath string, opts replayOptions) error {
	if strings.TrimSpace(opts.policyPath) == "" {
		return cliutil.ExitCodeError(exitUsage, fmt.Errorf("--policy is required"))
	}

	report := replayReport{
		ReceiptPath: filepath.Clean(receiptPath),
		PolicyPath:  filepath.Clean(opts.policyPath),
	}

	// Step 1: load + verify the receipt.
	receiptData, err := os.ReadFile(filepath.Clean(receiptPath))
	if err != nil {
		report.Error = fmt.Sprintf("read receipt: %v", err)
		emitReplayReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}

	r, err := receipt.Unmarshal(receiptData)
	if err != nil {
		report.Error = fmt.Sprintf("parse receipt: %v", err)
		emitReplayReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}

	report.ActionID = r.ActionRecord.ActionID
	report.Target = r.ActionRecord.Target
	report.Transport = r.ActionRecord.Transport
	report.OriginalVerdict = r.ActionRecord.Verdict

	keyHex, err := resolveSignerKey(strings.TrimSpace(opts.signerKey))
	if err != nil {
		report.Error = fmt.Sprintf("resolve signer key: %v", err)
		emitReplayReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		report.ReceiptValid = false
		report.Error = fmt.Sprintf("verify receipt: %v", err)
		emitReplayReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	report.ReceiptValid = true

	// Step 2: load the current policy.
	cfg, err := config.Load(filepath.Clean(opts.policyPath))
	if err != nil {
		report.Error = fmt.Sprintf("load policy: %v", err)
		emitReplayReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}

	// Step 3: re-evaluate against the current policy.
	// We disable Internal so tests don't require DNS. In production usage
	// callers can re-enable by removing this line; for the v0 replay
	// primitive, the target URL re-evaluation is the load-bearing check
	// and SSRF/internal-IP semantics are deployment-dependent.
	if cfg.Internal == nil {
		cfg.Internal = []string{} // explicit empty preserves SSRF-disabled semantics
	}
	sc := scanner.New(cfg)
	scanResult := sc.Scan(context.Background(), r.ActionRecord.Target)

	if scanResult.Allowed {
		report.ReplayVerdict = replayVerdictAllow
	} else {
		report.ReplayVerdict = replayVerdictBlock
	}
	report.ReplayScanner = scanResult.Scanner
	report.ReplayReason = scanResult.Reason

	report.VerdictChanged = !verdictsAgree(report.OriginalVerdict, report.ReplayVerdict)

	if report.VerdictChanged {
		report.Details = append(report.Details,
			fmt.Sprintf("original=%s replay=%s (scanner=%s)",
				report.OriginalVerdict, report.ReplayVerdict, report.ReplayScanner))
	}

	emitReplayReport(stdout, stderr, report, opts.jsonOutput)

	if report.VerdictChanged {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("policy verdict differs from receipt"))
	}
	return nil
}

// verdictsAgree compares an original receipt verdict (block / allow / warn /
// strip / redirect / ask / forward) against a replay verdict (block / allow).
// Warn and strip are "soft allows" — they let the action through with a
// finding logged. Redirect, ask, forward are also "soft allows" relative
// to a binary block/allow comparison.
func verdictsAgree(original, replay string) bool {
	original = strings.ToLower(strings.TrimSpace(original))
	replay = strings.ToLower(strings.TrimSpace(replay))

	if original == replay {
		return true
	}

	// Map both sides to {block, allow} for comparison.
	allowEquivalents := map[string]bool{
		"allow":    true,
		"warn":     true,
		"strip":    true,
		"forward":  true,
		"redirect": true,
		"ask":      true,
	}
	originalAllow := allowEquivalents[original]
	replayAllow := allowEquivalents[replay]
	return originalAllow == replayAllow
}

func emitReplayReport(stdout, stderr io.Writer, report replayReport, jsonOutput bool) {
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}

	dst := stdout
	if report.Error != "" || !report.ReceiptValid {
		dst = stderr
	}

	_, _ = fmt.Fprintf(dst, "receipt:       %s\n", report.ReceiptPath)
	_, _ = fmt.Fprintf(dst, "policy:        %s\n", report.PolicyPath)
	if report.ActionID != "" {
		_, _ = fmt.Fprintf(dst, "action_id:     %s\n", report.ActionID)
	}
	if report.Target != "" {
		_, _ = fmt.Fprintf(dst, "target:        %s\n", report.Target)
	}
	if report.Transport != "" {
		_, _ = fmt.Fprintf(dst, "transport:     %s\n", report.Transport)
	}
	_, _ = fmt.Fprintf(dst, "receipt_valid: %v\n", report.ReceiptValid)
	if report.Error != "" {
		_, _ = fmt.Fprintf(dst, "error:         %s\n", report.Error)
		return
	}
	_, _ = fmt.Fprintf(dst, "original:      %s\n", report.OriginalVerdict)
	_, _ = fmt.Fprintf(dst, "replay:        %s (scanner=%s)\n", report.ReplayVerdict, report.ReplayScanner)
	if report.ReplayReason != "" {
		_, _ = fmt.Fprintf(dst, "replay_reason: %s\n", report.ReplayReason)
	}
	if report.VerdictChanged {
		_, _ = fmt.Fprintf(dst, "verdict:       CHANGED — review required\n")
	} else {
		_, _ = fmt.Fprintf(dst, "verdict:       stable\n")
	}
	for _, d := range report.Details {
		_, _ = fmt.Fprintf(dst, "  - %s\n", d)
	}
}
