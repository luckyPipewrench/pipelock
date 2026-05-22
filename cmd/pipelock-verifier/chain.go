// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// chainOptions holds resolved CLI flags for the chain subcommand.
type chainOptions struct {
	signerKey  string
	sessionID  string
	jsonOutput bool
	asDir      bool
}

func newChainCmd() *cobra.Command {
	var opts chainOptions

	cmd := &cobra.Command{
		Use:   "chain PATH",
		Short: "Verify a Pipelock receipt chain",
		Long: `Verifies the hash linkage and Ed25519 signatures of a Pipelock receipt
chain. PATH may be a single .jsonl evidence file or a session directory
when --dir is set.

Without --key the verifier confirms self-consistency: every receipt's
signer must match the first receipt's signer, and prev-hash linkage must
hold. Self-consistency does not prove provenance.

With --key the verifier requires every receipt to be signed by the named
key.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runChain(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringVar(&opts.signerKey, "key", "", "expected signer public key (hex, public-key text, or file path)")
	cmd.Flags().StringVar(&opts.sessionID, "session", "proxy", "session ID inside the evidence directory (--dir)")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON verdict on stdout")
	cmd.Flags().BoolVar(&opts.asDir, "dir", false, "treat PATH as a session directory rather than a single file")

	return cmd
}

// chainReport is the structured form emitted by --json on the chain
// subcommand.
type chainReport struct {
	Path         string `json:"path"`
	Valid        bool   `json:"valid"`
	ReceiptCount uint64 `json:"receipt_count"`
	FinalSeq     uint64 `json:"final_seq"`
	RootHash     string `json:"root_hash,omitempty"`
	Error        string `json:"error,omitempty"`
	BrokenAtSeq  uint64 `json:"broken_at_seq,omitempty"`
}

func runChain(stdout, stderr io.Writer, target string, opts chainOptions) error {
	keyHex, err := resolveSignerKey(strings.TrimSpace(opts.signerKey))
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve signer key: %w", err))
	}

	var (
		receipts []receipt.Receipt
		label    string
	)
	if opts.asDir {
		clean := filepath.Clean(target)
		receipts, err = receipt.ExtractReceiptsFromSessionDir(clean, opts.sessionID)
		if err != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("extract receipts: %w", err))
		}
		label = fmt.Sprintf("%s (session %s)", clean, opts.sessionID)
	} else {
		clean := filepath.Clean(target)
		info, statErr := os.Stat(clean)
		if statErr != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("stat %q: %w", target, statErr))
		}
		if info.IsDir() {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("%q is a directory; pass --dir to verify a session directory", target))
		}
		receipts, err = receipt.ExtractReceipts(clean)
		if err != nil {
			return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("extract receipts: %w", err))
		}
		label = clean
	}

	if len(receipts) == 0 {
		report := chainReport{Path: label, Valid: false, Error: "no receipts in chain"}
		emitChainReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("empty chain"))
	}

	res := receipt.VerifyChain(receipts, keyHex)
	report := chainReport{
		Path:         label,
		Valid:        res.Valid,
		ReceiptCount: res.ReceiptCount,
		FinalSeq:     res.FinalSeq,
		RootHash:     res.RootHash,
		Error:        res.Error,
		BrokenAtSeq:  res.BrokenAtSeq,
	}
	emitChainReport(stdout, stderr, report, opts.jsonOutput)
	if !res.Valid {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("chain rejected at seq %d: %s", res.BrokenAtSeq, res.Error))
	}
	return nil
}
