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
	backend   string
	logPath   string
	logID     string
	rekorURL  string
	rekorKey  string
	rekorYes  bool
	output    string
}

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "anchor",
		Short: "Anchor receipt-chain checkpoints",
		Long: `Anchors verified receipt-chain checkpoints to backend proof material.

The local backend is a deterministic test backend. It exercises the same
checkpoint and proof plumbing used by outside logs, but it is not an
operator-independent witness. The Rekor backend records a transparency-log
submission for later audit; independent Rekor verification requires a pinned
Rekor log public key.`,
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
an anchor backend, and emits an anchor bundle for verifier and audit tooling.

Honest limit: anchoring does not prove real-time truth by whoever held the
receipt signing key. The local backend is for deterministic tests and
development. Rekor submission is recorded for later transparency-log audit;
verify Rekor bundles with pipelock-verifier independent --rekor-log-key.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReceipts(cmd.OutOrStdout(), args[0], opts)
		},
	}
	cmd.Flags().StringArrayVar(&opts.keys, "key", nil, "trusted signer public key (hex or file path); repeat for rotated chains")
	cmd.Flags().StringVar(&opts.sessionID, "session", "proxy", "session ID inside the evidence directory when --dir is set")
	cmd.Flags().BoolVar(&opts.asDir, "dir", false, "treat PATH as a session directory rather than a single evidence file")
	cmd.Flags().StringVar(&opts.backend, "backend", anchorpkg.LocalBackend, "anchor backend: local or rekor")
	cmd.Flags().StringVar(&opts.logPath, "local-log", "", "local fake-log JSONL path (required for local backend)")
	cmd.Flags().StringVar(&opts.logID, "log-id", anchorpkg.DefaultLocalLogID, "local fake-log identifier")
	cmd.Flags().StringVar(&opts.rekorURL, "rekor-url", anchorpkg.DefaultRekorURL, "Rekor base URL")
	cmd.Flags().StringVar(&opts.rekorKey, "rekor-key", "", "Ed25519 private key file used to sign the Rekor checkpoint entry")
	cmd.Flags().BoolVar(&opts.rekorYes, "yes-send-to-remote-log", false, "acknowledge Rekor anchoring sends checkpoint material to the configured remote log")
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
	backend, err := resolveBackend(opts)
	if err != nil {
		return err
	}
	proof, err := backend.Submit(checkpoint)
	if err != nil {
		return err
	}
	bundle := anchorpkg.NewBundle(checkpoint, proof)
	if err := anchorpkg.WriteBundle(opts.output, bundle); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "ANCHOR BUNDLE WRITTEN: %s\n", filepath.Clean(opts.output))
	_, _ = fmt.Fprintf(out, "  Backend:       %s\n", proof.Backend)
	if proof.Rekor != nil {
		_, _ = fmt.Fprintf(out, "  Rekor URL:     %s\n", proof.Rekor.URL)
	}
	_, _ = fmt.Fprintf(out, "  Log index:     %d\n", proof.LogIndex)
	_, _ = fmt.Fprintf(out, "  Session:       %s\n", checkpoint.SessionID)
	_, _ = fmt.Fprintf(out, "  Receipts:      %d\n", checkpoint.ReceiptCount)
	_, _ = fmt.Fprintf(out, "  Final seq:     %d\n", checkpoint.FinalSeq)
	_, _ = fmt.Fprintf(out, "  Root hash:     %s\n", checkpoint.RootHash)
	for _, limit := range bundle.Limits {
		_, _ = fmt.Fprintf(out, "  Limit:         %s\n", limit)
	}
	return nil
}

func resolveBackend(opts receiptsOptions) (anchorpkg.Backend, error) {
	switch strings.TrimSpace(opts.backend) {
	case "", anchorpkg.LocalBackend:
		if opts.logPath == "" {
			return nil, fmt.Errorf("--local-log is required for the local anchor backend")
		}
		return anchorpkg.LocalLog{Path: opts.logPath, LogID: opts.logID}, nil
	case anchorpkg.RekorBackend:
		if strings.TrimSpace(opts.rekorKey) == "" {
			return nil, fmt.Errorf("--rekor-key is required for the rekor anchor backend")
		}
		if !opts.rekorYes {
			return nil, fmt.Errorf("--yes-send-to-remote-log is required for the rekor anchor backend")
		}
		key, err := anchorpkg.LoadRekorPrivateKey(opts.rekorKey)
		if err != nil {
			return nil, err
		}
		return anchorpkg.RekorLog{URL: opts.rekorURL, Signer: key}, nil
	default:
		return nil, fmt.Errorf("unsupported anchor backend %q", opts.backend)
	}
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
