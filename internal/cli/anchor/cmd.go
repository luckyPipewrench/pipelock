// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	rekorHash string
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
	cmd.Flags().StringVar(&opts.rekorURL, "rekor-url", "", "Rekor base URL (required for the rekor backend; no public default so receipt metadata stays in your trust boundary)")
	cmd.Flags().StringVar(&opts.rekorKey, "rekor-key", "", "Ed25519 private key file used to sign the Rekor checkpoint entry")
	cmd.Flags().StringVar(&opts.rekorHash, "rekor-hash-algorithm", anchorpkg.DefaultRekorHashAlgorithm, "hashedrekord data hash algorithm to submit (sha512 for Ed25519 Rekor v1)")
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
	output, err := resolveBundleOutput(target, opts)
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
	bundleBytes, err := anchorpkg.WriteBundleUnderDir(output.receiptDir, output.markerPath, bundle)
	if err != nil {
		return err
	}
	if err := writeAnchorStateMarker(output, checkpoint, proof, bundleBytes); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "ANCHOR BUNDLE WRITTEN: %s\n", output.bundlePath)
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

type bundleOutput struct {
	receiptDir string
	bundlePath string
	markerPath string
}

func resolveBundleOutput(target string, opts receiptsOptions) (bundleOutput, error) {
	receiptDir, err := receiptDirectory(target, opts.asDir)
	if err != nil {
		return bundleOutput{}, err
	}
	requested := filepath.Clean(opts.output)
	var bundlePath string
	if filepath.IsAbs(requested) {
		bundlePath = requested
	} else {
		bundlePath = filepath.Join(receiptDir, requested)
	}
	bundlePath, err = filepath.Abs(bundlePath)
	if err != nil {
		return bundleOutput{}, fmt.Errorf("resolve --out: %w", err)
	}
	rel, err := filepath.Rel(receiptDir, bundlePath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return bundleOutput{}, fmt.Errorf("--out must resolve under the receipt directory")
	}
	if rel == "." {
		return bundleOutput{}, fmt.Errorf("--out must name an anchor bundle file under the receipt directory")
	}
	if err := validateBundleOutputPath(receiptDir, bundlePath); err != nil {
		return bundleOutput{}, err
	}
	return bundleOutput{receiptDir: receiptDir, bundlePath: bundlePath, markerPath: filepath.ToSlash(rel)}, nil
}

func receiptDirectory(target string, asDir bool) (string, error) {
	cleanTarget, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return "", fmt.Errorf("resolve receipt directory: %w", err)
	}
	if !asDir {
		cleanTarget = filepath.Dir(cleanTarget)
	}
	resolved, err := filepath.EvalSymlinks(cleanTarget)
	if err != nil {
		return "", fmt.Errorf("resolve receipt directory: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect receipt directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("receipt directory is not a directory")
	}
	return resolved, nil
}

func validateBundleOutputPath(receiptDir, bundlePath string) error {
	if info, err := os.Lstat(bundlePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("--out must not be a symlink")
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("--out must be a regular file")
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect --out: %w", err)
	}
	parent := filepath.Dir(bundlePath)
	for {
		info, err := os.Lstat(parent)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("--out parent must not be a symlink")
			}
			if !info.IsDir() {
				return fmt.Errorf("--out parent is not a directory")
			}
			resolved, err := filepath.EvalSymlinks(parent)
			if err != nil {
				return fmt.Errorf("resolve --out parent: %w", err)
			}
			rel, err := filepath.Rel(receiptDir, resolved)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("--out parent resolves outside the receipt directory")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect --out parent: %w", err)
		}
		next := filepath.Dir(parent)
		if next == parent {
			return fmt.Errorf("resolve --out parent: no existing parent directory")
		}
		parent = next
	}
}

func writeAnchorStateMarker(output bundleOutput, checkpoint anchorpkg.Checkpoint, proof anchorpkg.Proof, bundleBytes []byte) error {
	sum := sha256.Sum256(bundleBytes)
	return anchorpkg.WriteStateMarker(output.receiptDir, anchorpkg.StateMarker{
		SessionID:    checkpoint.SessionID,
		FinalSeq:     checkpoint.FinalSeq,
		RootHash:     checkpoint.RootHash,
		Backend:      proof.Backend,
		LogIndex:     proof.LogIndex,
		AnchoredAt:   time.Now().UTC(),
		BundleSHA256: hex.EncodeToString(sum[:]),
		BundlePath:   output.markerPath,
	})
}

func resolveBackend(opts receiptsOptions) (anchorpkg.Backend, error) {
	switch strings.TrimSpace(opts.backend) {
	case "", anchorpkg.LocalBackend:
		if opts.logPath == "" {
			return nil, fmt.Errorf("--local-log is required for the local anchor backend")
		}
		return anchorpkg.LocalLog{Path: opts.logPath, LogID: opts.logID}, nil
	case anchorpkg.RekorBackend:
		if strings.TrimSpace(opts.rekorURL) == "" {
			return nil, fmt.Errorf("--rekor-url is required for the rekor anchor backend; " +
				"point it at your own transparency log (there is no public default, so receipt " +
				"metadata is never silently sent to a public log)")
		}
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
		return anchorpkg.RekorLog{URL: opts.rekorURL, Signer: key, HashAlgorithm: opts.rekorHash}, nil
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
