// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	sigutil "github.com/luckyPipewrench/pipelock/internal/signing"
)

type receiptsOptions struct {
	keys      []string
	sessionID string
	asDir     bool
	logPath   string
	logID     string
	output    string
}

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "anchor",
		Short: "Anchor receipt-chain checkpoints",
		Long: `Anchors verified receipt-chain checkpoints to an append-only backend.

The local backend is a deterministic test backend. It exercises the same
checkpoint and proof plumbing used by real external logs, but it is not an
operator-independent witness.`,
	}
	cmd.AddCommand(receiptsCmd())
	return cmd
}

func receiptsCmd() *cobra.Command {
	var opts receiptsOptions
	cmd := &cobra.Command{
		Use:   "receipts PATH",
		Short: "Anchor a verified receipt chain checkpoint",
		Long: `Verifies a receipt chain with pinned signer keys, writes its chain head to
an anchor backend, and emits an anchor bundle for independent verification.

Honest limit: anchoring detects after-the-fact rewrite, delete, omit, and
equivocation against the anchored checkpoint. It does not prove real-time truth
by whoever held the receipt signing key. The local backend is for deterministic
tests and development; a real outside witness backend must replace it before
claiming operator-independent evidence.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReceipts(cmd.OutOrStdout(), args[0], opts)
		},
	}
	cmd.Flags().StringArrayVar(&opts.keys, "key", nil, "trusted signer public key (hex or file path); repeat for rotated chains")
	cmd.Flags().StringVar(&opts.sessionID, "session", "proxy", "session ID inside the evidence directory when --dir is set")
	cmd.Flags().BoolVar(&opts.asDir, "dir", false, "treat PATH as a session directory rather than a single evidence file")
	cmd.Flags().StringVar(&opts.logPath, "local-log", "", "local fake-log JSONL path (required for this backend)")
	cmd.Flags().StringVar(&opts.logID, "log-id", anchorpkg.DefaultLocalLogID, "local fake-log identifier")
	cmd.Flags().StringVar(&opts.output, "out", "", "anchor bundle output path")
	return cmd
}

func runReceipts(out io.Writer, target string, opts receiptsOptions) error {
	trustedKeys, err := resolveTrustedKeys(opts.keys)
	if err != nil {
		return err
	}
	if len(trustedKeys) == 0 {
		return fmt.Errorf("at least one --key is required to anchor a receipt chain")
	}
	if opts.logPath == "" {
		return fmt.Errorf("--local-log is required for the local anchor backend")
	}
	if opts.output == "" {
		return fmt.Errorf("--out is required")
	}

	receipts, sessionID, err := extractReceipts(target, opts)
	if err != nil {
		return err
	}
	checkpoint, err := anchorpkg.BuildCheckpoint(sessionID, receipts, trustedKeys)
	if err != nil {
		return err
	}
	proof, err := (anchorpkg.LocalLog{Path: opts.logPath, LogID: opts.logID}).Submit(checkpoint)
	if err != nil {
		return err
	}
	bundle := anchorpkg.NewBundle(checkpoint, proof)
	if err := anchorpkg.WriteBundle(opts.output, bundle); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "ANCHOR BUNDLE WRITTEN: %s\n", filepath.Clean(opts.output))
	_, _ = fmt.Fprintf(out, "  Backend:       %s\n", proof.Backend)
	_, _ = fmt.Fprintf(out, "  Log index:     %d\n", proof.LogIndex)
	_, _ = fmt.Fprintf(out, "  Session:       %s\n", checkpoint.SessionID)
	_, _ = fmt.Fprintf(out, "  Receipts:      %d\n", checkpoint.ReceiptCount)
	_, _ = fmt.Fprintf(out, "  Final seq:     %d\n", checkpoint.FinalSeq)
	_, _ = fmt.Fprintf(out, "  Root hash:     %s\n", checkpoint.RootHash)
	_, _ = fmt.Fprintln(out, "  Limit:         local backend is not an operator-independent witness")
	return nil
}

func extractReceipts(target string, opts receiptsOptions) ([]receipt.Receipt, string, error) {
	if opts.asDir {
		receipts, err := receipt.ExtractReceiptsFromSessionDir(target, opts.sessionID)
		return receipts, opts.sessionID, err
	}
	receipts, sessionID, err := receipt.ExtractReceiptsWithSessionID(target)
	if err == nil {
		if sessionID == "" {
			sessionID = "file"
		}
		return receipts, sessionID, nil
	}
	receipts, extractErr := receipt.ExtractReceipts(target)
	if extractErr != nil {
		return nil, "", extractErr
	}
	return receipts, "file", nil
}

func resolveTrustedKeys(keys []string) ([]string, error) {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("resolve --key: public key is empty")
		}
		pub, err := sigutil.LoadPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("resolve --key %q: %w", key, err)
		}
		out = append(out, hex.EncodeToString(pub))
	}
	return out, nil
}
