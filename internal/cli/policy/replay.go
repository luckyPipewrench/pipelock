// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// replayCmd returns the "policy replay" subcommand.
func replayCmd() *cobra.Command {
	var (
		configFile     string
		sessionsDir    string
		reportPath     string
		reportJSONPath string
		escrowPrivKey  string
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
			return runReplay(cmd, configFile, sessionsDir, reportPath, reportJSONPath, escrowPrivKey)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "candidate config YAML (required)")
	cmd.Flags().StringVarP(&sessionsDir, "sessions", "s", "", "capture sessions directory (required)")
	cmd.Flags().StringVar(&reportPath, "report", "", "HTML report output path")
	cmd.Flags().StringVar(&reportJSONPath, "report-json", "", "JSON report output path")
	cmd.Flags().StringVar(&escrowPrivKey, "escrow-private-key", "", "X25519 hex private key for sidecar decryption")

	return cmd
}

// runReplay is the testable core of the replay command.
func runReplay(cmd *cobra.Command, configFile, sessionsDir, reportPath, reportJSONPath, _ string) error {
	// Load and validate the candidate config.
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Disable SSRF and env-leak scanning: replay must not make DNS calls.
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false

	// Compute candidate config hash from raw file bytes.
	candidateHash, err := hashFile(configFile)
	if err != nil {
		return fmt.Errorf("hashing config: %w", err)
	}

	// Replay all captured sessions.
	records, dropped, skipped, originalHash, err := capture.LoadAndReplay(cfg, sessionsDir)
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

	// Write HTML report if requested.
	if reportPath != "" {
		if err := writeReport(reportPath, diff, capture.RenderDiffHTML); err != nil {
			return fmt.Errorf("writing HTML report: %w", err)
		}
	}

	// Write JSON report if requested.
	if reportJSONPath != "" {
		if err := writeReport(reportJSONPath, diff, capture.RenderDiffJSON); err != nil {
			return fmt.Errorf("writing JSON report: %w", err)
		}
	}

	return nil
}

// writeReport opens path and calls renderFn to write the DiffReport.
type renderFunc func(w io.Writer, d *capture.DiffReport) error

func writeReport(path string, diff *capture.DiffReport, renderFn renderFunc) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("opening report file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return renderFn(f, diff)
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
