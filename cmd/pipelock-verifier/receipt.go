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
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type receiptOptions struct {
	signerKey  string
	jsonOutput bool
}

func newReceiptCmd() *cobra.Command {
	var opts receiptOptions

	cmd := &cobra.Command{
		Use:   "receipt PATH",
		Short: "Verify a single Pipelock action receipt",
		Long: `Verifies the Ed25519 signature on a single Pipelock action receipt
written as JSON. PATH must point at a JSON file holding one receipt
(version + action_record + signature + signer_key).

Without --key the verifier checks the receipt's embedded signer_key.
With --key it requires the receipt's signer to match the named key.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReceipt(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)

	cmd.Flags().StringVar(&opts.signerKey, "key", "", "expected signer public key (hex, public-key text, or file path)")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON verdict on stdout")

	return cmd
}

type receiptReport struct {
	Path       string `json:"path"`
	Valid      bool   `json:"valid"`
	ActionID   string `json:"action_id,omitempty"`
	Verdict    string `json:"verdict,omitempty"`
	Transport  string `json:"transport,omitempty"`
	SignerKey  string `json:"signer_key,omitempty"`
	PolicyHash string `json:"policy_hash,omitempty"`
	ChainSeq   uint64 `json:"chain_seq,omitempty"`
	Error      string `json:"error,omitempty"`
}

func runReceipt(stdout, stderr io.Writer, target string, opts receiptOptions) error {
	keyHex, err := resolveSignerKey(strings.TrimSpace(opts.signerKey))
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve signer key: %w", err))
	}

	clean := filepath.Clean(target)
	data, err := os.ReadFile(clean)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("read receipt: %w", err))
	}

	r, err := receipt.Unmarshal(data)
	if err != nil {
		report := receiptReport{Path: clean, Valid: false, Error: err.Error()}
		emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("parse receipt: %w", err))
	}

	report := receiptReport{
		Path:       clean,
		ActionID:   r.ActionRecord.ActionID,
		Verdict:    r.ActionRecord.Verdict,
		Transport:  r.ActionRecord.Transport,
		SignerKey:  r.SignerKey,
		PolicyHash: r.ActionRecord.PolicyHash,
		ChainSeq:   r.ActionRecord.ChainSeq,
	}

	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		report.Valid = false
		report.Error = err.Error()
		emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("verify: %w", err))
	}
	report.Valid = true
	emitReceiptReport(stdout, stderr, report, opts.jsonOutput)
	return nil
}
