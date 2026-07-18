// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// replayCmd returns the "policy replay" subcommand.
func replayCmd() *cobra.Command {
	var (
		configFile     string
		sessionsDir    string
		reportPath     string
		reportJSONPath string
		contractPath   string
		contractKey    string
		escrowPrivKey  string
		allowUnsigned  bool
	)

	cmd := &cobra.Command{
		Use:   "replay",
		Short: "Replay captured sessions against a candidate config and produce a diff report",
		Long: `Load captured policy sessions and replay each verdict against the
candidate config. Produces an HTML and/or JSON diff report showing which
verdicts would change under the new config.

Examples:
  pipelock policy replay --config candidate.yaml --sessions ./sessions/
  pipelock policy replay --config candidate.yaml --sessions ./sessions/ --report diff.html
  pipelock policy replay --config candidate.yaml --sessions ./sessions/ --report diff.html --report-json diff.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if configFile == "" {
				return fmt.Errorf("--config is required")
			}
			if sessionsDir == "" {
				return fmt.Errorf("--sessions is required")
			}
			return runReplay(cmd, replayOpts{
				configFile:     configFile,
				sessionsDir:    sessionsDir,
				reportPath:     reportPath,
				reportJSONPath: reportJSONPath,
				contractPath:   contractPath,
				contractKey:    contractKey,
				escrowPrivKey:  escrowPrivKey,
				allowUnsigned:  allowUnsigned,
			})
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "candidate config YAML (required)")
	cmd.Flags().StringVarP(&sessionsDir, "sessions", "s", "", "capture sessions directory (required)")
	cmd.Flags().StringVar(&reportPath, "report", "", "HTML report output path")
	cmd.Flags().StringVar(&reportJSONPath, "report-json", "", "JSON report output path")
	cmd.Flags().StringVar(&contractPath, "contract", "", "signed candidate contract YAML for contract-aware URL replay")
	cmd.Flags().StringVar(&contractKey, "contract-key", "", "trusted Ed25519 public key (hex or file) used to verify --contract")
	cmd.Flags().StringVar(&escrowPrivKey, "escrow-private-key", "", "X25519 hex private key for sidecar decryption")
	cmd.Flags().BoolVar(&allowUnsigned, "allow-unsigned-contract-for-diagnostics", false, "allow unverified --contract input for diagnostics only (unsafe)")

	return cmd
}

type replayOpts struct {
	configFile     string
	sessionsDir    string
	reportPath     string
	reportJSONPath string
	contractPath   string
	contractKey    string
	escrowPrivKey  string
	allowUnsigned  bool
}

// runReplay is the testable core of the replay command.
func runReplay(cmd *cobra.Command, opts replayOpts) error {
	// Load and validate the candidate config.
	cfg, err := config.Load(opts.configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Disable SSRF and env-leak scanning: replay must not make DNS calls.
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false

	// Compute candidate config hash from raw file bytes.
	candidateHash, err := hashFile(opts.configFile)
	if err != nil {
		return fmt.Errorf("hashing config: %w", err)
	}

	escrowKey, err := decodeReplayEscrowPrivateKey(opts.escrowPrivKey)
	if err != nil {
		return err
	}
	replayContract, verifiedContract, err := loadReplayContract(opts.contractPath, opts.contractKey, opts.allowUnsigned)
	if err != nil {
		return err
	}
	if replayContract != nil && !verifiedContract {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: unverified contract accepted because --allow-unsigned-contract-for-diagnostics is set; replay is diagnostic only")
	}

	// Replay all captured sessions.
	replayOpts := capture.ReplayOptions{EscrowPrivateKey: escrowKey}
	if replayContract != nil {
		replayOpts.Contract = replayContract
	}
	records, dropped, skipped, originalHash, err := capture.LoadAndReplayWithOptions(cfg, opts.sessionsDir, replayOpts)
	if err != nil {
		return fmt.Errorf("replaying sessions: %w", err)
	}

	diff := capture.ComputeDiff(records, dropped, skipped, originalHash, candidateHash)

	// Print summary to stdout.
	w := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(w, "Records:       %d\n", diff.TotalRecords)
	_, _ = fmt.Fprintf(w, "Replayed:      %d\n", diff.Replayed)
	_, _ = fmt.Fprintf(w, "New blocks:    %d\n", diff.NewBlocks)
	_, _ = fmt.Fprintf(w, "New allows:    %d\n", diff.NewAllows)
	_, _ = fmt.Fprintf(w, "Unchanged:     %d\n", diff.Unchanged)
	_, _ = fmt.Fprintf(w, "Evidence-only: %d\n", diff.EvidenceOnly)
	_, _ = fmt.Fprintf(w, "Summary-only:  %d\n", diff.SummaryOnly)
	_, _ = fmt.Fprintf(w, "Dropped:       %d\n", diff.Dropped)
	_, _ = fmt.Fprintf(w, "Skipped:       %d\n", diff.Skipped)
	_, _ = fmt.Fprintf(w, "Original hash: %s\n", diff.OriginalConfigHash)
	_, _ = fmt.Fprintf(w, "Candidate hash:%s\n", diff.CandidateConfigHash)
	writeCaptureSurfaceStatus(w, diff)

	// Write HTML report if requested.
	if opts.reportPath != "" {
		if err := writeReport(opts.reportPath, diff, capture.RenderDiffHTML); err != nil {
			return fmt.Errorf("writing HTML report: %w", err)
		}
	}

	// Write JSON report if requested.
	if opts.reportJSONPath != "" {
		if err := writeReport(opts.reportJSONPath, diff, capture.RenderDiffJSON); err != nil {
			return fmt.Errorf("writing JSON report: %w", err)
		}
	}

	return nil
}

func loadReplayContract(path, publicKey string, allowUnsigned bool) (*contract.Contract, bool, error) {
	if path == "" {
		return nil, false, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, false, fmt.Errorf("loading contract: %w", err)
	}
	var env contract.ContractEnvelope
	if err := contract.DecodeStrictYAML(data, &env); err != nil {
		return nil, false, fmt.Errorf("loading contract: %w", err)
	}
	if err := env.Body.Validate(); err != nil {
		return nil, false, fmt.Errorf("validating contract: %w", err)
	}
	if publicKey == "" {
		if !allowUnsigned {
			return nil, false, fmt.Errorf("validating contract: --contract-key is required for --contract (or use --allow-unsigned-contract-for-diagnostics)")
		}
		return &env.Body, false, nil
	}
	pubKey, err := signing.LoadPublicKey(publicKey)
	if err != nil {
		return nil, false, fmt.Errorf("loading contract verification key: %w", err)
	}
	if err := verifyContractEnvelope(env, pubKey); err != nil {
		return nil, false, fmt.Errorf("verifying contract: %w", err)
	}
	return &env.Body, true, nil
}

func verifyContractEnvelope(env contract.ContractEnvelope, pubKey ed25519.PublicKey) error {
	if env.Body.KeyPurpose != signing.PurposeContractCompileSigning.String() {
		return fmt.Errorf("key_purpose must be %q, got %q", signing.PurposeContractCompileSigning.String(), env.Body.KeyPurpose)
	}
	if !strings.HasPrefix(env.Signature, "ed25519:") {
		return fmt.Errorf("signature must use ed25519:<hex>")
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(env.Signature, "ed25519:"))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature length=%d, want %d", len(sig), ed25519.SignatureSize)
	}
	preimage, err := env.Body.SignablePreimage()
	if err != nil {
		return fmt.Errorf("build preimage: %w", err)
	}
	if !ed25519.Verify(pubKey, preimage, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func decodeReplayEscrowPrivateKey(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid --escrow-private-key: must be hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid --escrow-private-key: must be 64 hex chars (32 bytes)")
	}
	return key, nil
}

func writeCaptureSurfaceStatus(w io.Writer, diff *capture.DiffReport) {
	if len(diff.CaptureSurfaces) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "Capture surfaces:")
	for _, surface := range capture.SortedCaptureSurfaces(diff.CaptureSurfaces) {
		status := diff.CaptureSurfaces[surface]
		value := status.Grade
		if status.Sidecar {
			value += " (sidecar)"
		}
		_, _ = fmt.Fprintf(w, "  %s: %s\n", surface, value)
	}
}

// writeReport renders into a private temporary file before atomically
// publishing the DiffReport.
type renderFunc func(w io.Writer, d *capture.DiffReport) error

func writeReport(path string, diff *capture.DiffReport, renderFn renderFunc) error {
	err := atomicfile.WriteFunc(filepath.Clean(path), 0o600, func(w io.Writer) error {
		return renderFn(w, diff)
	})
	if err != nil {
		return fmt.Errorf("opening report file: %w", err)
	}
	return nil
}

// hashFile returns the hex-encoded SHA-256 of the file at path.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
