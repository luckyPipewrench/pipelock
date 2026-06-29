// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type independentOptions struct {
	bundlePath string
	signerKeys []string
	logPath    string
	logID      string
	sessionID  string
	asDir      bool
	jsonOutput bool
}

func newIndependentCmd() *cobra.Command {
	var opts independentOptions
	cmd := &cobra.Command{
		Use:   "independent PATH",
		Short: "Verify an anchored receipt-chain checkpoint",
		Long: `Verifies a receipt chain against an anchor bundle and backend proof
material. The local backend is a deterministic test backend; it proves the
checkpoint/proof mechanics but is not an operator-independent witness.

Honest limit: anchoring does not prove real-time truth by whoever held the
receipt signing key. Rekor bundles fail closed until trusted Rekor SET and
inclusion-proof verification is implemented.`,
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIndependent(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0], opts)
		},
	}
	cmd.SetFlagErrorFunc(usageFlagError)
	cmd.Flags().StringVar(&opts.bundlePath, "bundle", "", "anchor bundle JSON path")
	cmd.Flags().StringArrayVar(&opts.signerKeys, "key", nil, "trusted signer public key (hex, public-key text, or file path); repeat for rotated chains")
	cmd.Flags().StringVar(&opts.logPath, "local-log", "", "local fake-log JSONL path")
	cmd.Flags().StringVar(&opts.logID, "log-id", anchor.DefaultLocalLogID, "local fake-log identifier")
	cmd.Flags().StringVar(&opts.sessionID, "session", "proxy", "session ID inside the evidence directory when --dir is set")
	cmd.Flags().BoolVar(&opts.asDir, "dir", false, "treat PATH as a session directory rather than a single evidence file")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "emit a structured JSON verdict on stdout")
	return cmd
}

func runIndependent(stdout, stderr io.Writer, target string, opts independentOptions) error {
	if strings.TrimSpace(opts.bundlePath) == "" {
		return cliutil.ExitCodeError(exitUsage, fmt.Errorf("--bundle is required"))
	}
	if len(opts.signerKeys) == 0 {
		return cliutil.ExitCodeError(exitUsage, fmt.Errorf("at least one --key is required"))
	}
	keyHexes, err := resolveSignerKeys(opts.signerKeys)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("resolve signer key: %w", err))
	}
	receipts, err := independentReceipts(target, opts)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("extract receipts: %w", err))
	}
	bundle, err := anchor.LoadBundle(opts.bundlePath)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, err)
	}
	backend, exitCode, err := independentBackend(bundle, opts)
	if err != nil {
		return cliutil.ExitCodeError(exitCode, err)
	}
	report := anchor.VerifyBundle(bundle, receipts, keyHexes, backend)
	emitIndependentReport(stdout, stderr, filepath.Clean(target), report, opts.jsonOutput)
	if !report.Valid {
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("independent verification failed: %s", report.Error))
	}
	return nil
}

func independentBackend(bundle anchor.Bundle, opts independentOptions) (anchor.Backend, int, error) {
	if bundle.Backend != bundle.Proof.Backend {
		return nil, cliutil.ExitConfig, fmt.Errorf("anchor bundle backend %q does not match proof backend %q", bundle.Backend, bundle.Proof.Backend)
	}
	switch bundle.Backend {
	case anchor.LocalBackend:
		if strings.TrimSpace(opts.logPath) == "" {
			return nil, exitUsage, fmt.Errorf("--local-log is required for local anchor verification")
		}
		return anchor.LocalLog{
			Path:  opts.logPath,
			LogID: opts.logID,
		}, cliutil.ExitOK, nil
	case anchor.RekorBackend:
		return anchor.RekorLog{}, cliutil.ExitOK, nil
	default:
		return nil, cliutil.ExitConfig, fmt.Errorf("unsupported anchor backend %q", bundle.Backend)
	}
}

func independentReceipts(target string, opts independentOptions) ([]receipt.Receipt, error) {
	if opts.asDir {
		return receipt.ExtractReceiptsFromSessionDir(target, opts.sessionID)
	}
	return receipt.ExtractReceipts(target)
}

func resolveSignerKeys(inputs []string) ([]string, error) {
	out := make([]string, 0, len(inputs))
	for _, input := range inputs {
		keyHex, err := resolveSignerKey(input)
		if err != nil {
			return nil, err
		}
		if keyHex != "" {
			out = append(out, keyHex)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one non-empty --key is required")
	}
	return out, nil
}

func emitIndependentReport(stdout, stderr io.Writer, path string, report anchor.VerifyReport, jsonMode bool) {
	if jsonMode {
		writeJSON(stdout, report)
		return
	}
	if report.Valid {
		_, _ = fmt.Fprintf(stdout, "INDEPENDENT VERIFY OK: %s\n", path)
		_, _ = fmt.Fprintf(stdout, "  Backend:       %s\n", report.Backend)
		_, _ = fmt.Fprintf(stdout, "  Session:       %s\n", report.SessionID)
		_, _ = fmt.Fprintf(stdout, "  Receipts:      %d\n", report.ReceiptCount)
		_, _ = fmt.Fprintf(stdout, "  Final seq:     %d\n", report.FinalSeq)
		_, _ = fmt.Fprintf(stdout, "  Root hash:     %s\n", report.RootHash)
		_, _ = fmt.Fprintf(stdout, "  Log index:     %d\n", report.Proof.LogIndex)
		for _, limit := range report.Limits {
			_, _ = fmt.Fprintf(stdout, "  Limit:         %s\n", limit)
		}
		return
	}
	_, _ = fmt.Fprintf(stderr, "INDEPENDENT VERIFY FAILED: %s\n", path)
	if report.Error != "" {
		_, _ = fmt.Fprintf(stderr, "  error: %s\n", report.Error)
	}
}
