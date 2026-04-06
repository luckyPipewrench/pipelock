// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// VerifyReceiptCmd returns the "verify-receipt" cobra command.
func VerifyReceiptCmd() *cobra.Command {
	var expectedKey string

	cmd := &cobra.Command{
		Use:   "verify-receipt <file>",
		Short: "Verify a signed action receipt or receipt chain",
		Long: `Verifies Ed25519 signatures on action receipts.

For a single receipt JSON file: verifies the signature and prints details.
For a flight recorder JSONL file: extracts all receipts and verifies the
full hash chain (prev_hash linkage, seq continuity, signatures).

Exit 0 = valid, exit 1 = invalid or malformed.

Examples:
  pipelock verify-receipt receipt.json
  pipelock verify-receipt evidence-proxy-0.jsonl
  pipelock verify-receipt receipt.json --key 70b991eb...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			out := cmd.OutOrStdout()

			// JSONL files: extract receipts and verify the full chain.
			if strings.HasSuffix(path, ".jsonl") {
				return verifyChainFromFile(out, path, expectedKey)
			}

			// Single receipt JSON file.
			return verifySingleReceipt(out, path, expectedKey)
		},
	}

	cmd.Flags().StringVar(&expectedKey, "key", "", "expected signer public key (hex)")
	return cmd
}

func verifySingleReceipt(out io.Writer, path, expectedKey string) error {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("reading receipt: %w", err)
	}

	r, err := receipt.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("parsing receipt: %w", err)
	}

	if err := receipt.VerifyWithKey(r, expectedKey); err != nil {
		_, _ = fmt.Fprintf(out, "FAILED: %s: %v\n", path, err)
		return fmt.Errorf("verification failed: %w", err)
	}

	_, _ = fmt.Fprintf(out, "OK: %s\n", path)
	printReceiptDetails(out, r)
	return nil
}

func verifyChainFromFile(out io.Writer, path, expectedKey string) error {
	receipts, err := receipt.ExtractReceipts(path)
	if err != nil {
		return fmt.Errorf("extracting receipts: %w", err)
	}

	if len(receipts) == 0 {
		_, _ = fmt.Fprintf(out, "No receipts found in %s\n", path)
		return fmt.Errorf("no receipts in %s", path)
	}

	result := receipt.VerifyChain(receipts, expectedKey)
	if !result.Valid {
		_, _ = fmt.Fprintf(out, "CHAIN BROKEN: %s\n", path)
		_, _ = fmt.Fprintf(out, "  Error:    %s\n", result.Error)
		_, _ = fmt.Fprintf(out, "  Broke at: seq %d\n", result.BrokenAtSeq)
		return fmt.Errorf("chain verification failed at seq %d: %s", result.BrokenAtSeq, result.Error)
	}

	_, _ = fmt.Fprintf(out, "CHAIN VALID: %s\n", path)
	_, _ = fmt.Fprintf(out, "  Receipts:  %d\n", result.ReceiptCount)
	_, _ = fmt.Fprintf(out, "  Final seq: %d\n", result.FinalSeq)
	_, _ = fmt.Fprintf(out, "  Root hash: %s\n", result.RootHash)
	_, _ = fmt.Fprintf(out, "  Start:     %s\n", result.StartTime.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(out, "  End:       %s\n", result.EndTime.Format("2006-01-02T15:04:05Z"))
	return nil
}

func printReceiptDetails(out io.Writer, r receipt.Receipt) {
	_, _ = fmt.Fprintf(out, "  Action ID:   %s\n", r.ActionRecord.ActionID)
	_, _ = fmt.Fprintf(out, "  Action Type: %s\n", r.ActionRecord.ActionType)
	_, _ = fmt.Fprintf(out, "  Verdict:     %s\n", r.ActionRecord.Verdict)
	_, _ = fmt.Fprintf(out, "  Target:      %s\n", r.ActionRecord.Target)
	_, _ = fmt.Fprintf(out, "  Transport:   %s\n", r.ActionRecord.Transport)
	_, _ = fmt.Fprintf(out, "  Timestamp:   %s\n", r.ActionRecord.Timestamp.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(out, "  Signer:      %s\n", r.SignerKey)
	_, _ = fmt.Fprintf(out, "  Chain seq:   %d\n", r.ActionRecord.ChainSeq)
	_, _ = fmt.Fprintf(out, "  Chain prev:  %s\n", r.ActionRecord.ChainPrevHash)

	if r.ActionRecord.Principal != "" {
		_, _ = fmt.Fprintf(out, "  Principal:   %s\n", r.ActionRecord.Principal)
	}
	if r.ActionRecord.Actor != "" {
		_, _ = fmt.Fprintf(out, "  Actor:       %s\n", r.ActionRecord.Actor)
	}
	if r.ActionRecord.PolicyHash != "" {
		_, _ = fmt.Fprintf(out, "  Policy Hash: %s\n", r.ActionRecord.PolicyHash)
	}

	if r.ActionRecord.Method != "" || r.ActionRecord.Layer != "" {
		pretty, err := json.MarshalIndent(r.ActionRecord, "  ", "  ")
		if err == nil {
			_, _ = fmt.Fprintf(out, "\n  Full record:\n  %s\n", string(pretty))
		}
	}
}

// TranscriptRootCmd returns the "transcript-root" cobra command.
func TranscriptRootCmd() *cobra.Command {
	var expectedKey string

	cmd := &cobra.Command{
		Use:   "transcript-root <file>",
		Short: "Compute and verify a transcript root from a receipt chain",
		Long: `Reads a flight recorder JSONL file, extracts all action receipts,
verifies the hash chain, and prints the transcript root.

The transcript root is the hash of the final receipt in the chain,
serving as a tamper-evident summary of the entire session.

Examples:
  pipelock transcript-root evidence-proxy-0.jsonl --key 70b991eb...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if expectedKey == "" {
				return fmt.Errorf("--key is required: transcript roots must be verified against a trusted signer key")
			}
			path := args[0]
			out := cmd.OutOrStdout()

			receipts, err := receipt.ExtractReceipts(path)
			if err != nil {
				return fmt.Errorf("extracting receipts: %w", err)
			}

			if len(receipts) == 0 {
				_, _ = fmt.Fprintf(out, "No receipts found in %s\n", path)
				return nil
			}

			root, err := receipt.ComputeTranscriptRoot("proxy", receipts, expectedKey)
			if err != nil {
				return fmt.Errorf("computing transcript root: %w", err)
			}

			_, _ = fmt.Fprintf(out, "Transcript Root: %s\n", path)
			_, _ = fmt.Fprintf(out, "  Session:       %s\n", root.SessionID)
			_, _ = fmt.Fprintf(out, "  Root hash:     %s\n", root.RootHash)
			_, _ = fmt.Fprintf(out, "  Receipt count: %d\n", root.ReceiptCount)
			_, _ = fmt.Fprintf(out, "  Final seq:     %d\n", root.FinalSeq)
			_, _ = fmt.Fprintf(out, "  Start:         %s\n", root.StartTime.Format("2006-01-02T15:04:05Z"))
			_, _ = fmt.Fprintf(out, "  End:           %s\n", root.EndTime.Format("2006-01-02T15:04:05Z"))
			return nil
		},
	}

	cmd.Flags().StringVar(&expectedKey, "key", "", "expected signer public key (hex)")
	return cmd
}
