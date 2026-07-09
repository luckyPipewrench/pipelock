// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package evidence implements the free single-agent evidence viewer CLI
// command. It renders one agent's decision receipts as a static,
// self-contained, offline HTML report. No server, no persistence, no
// license check, single-agent only.
package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/coveragecertverify"
	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signingflag"
)

// Cmd returns the `pipelock evidence` command tree (Free tier).
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Offline evidence viewer for a single agent (Free)",
	}
	cmd.AddCommand(viewCmd())
	cmd.AddCommand(verifyCertCmd())
	return cmd
}

type viewOptions struct {
	receiptDir     string
	sessionID      string
	trustedSigners []string
	outFile        string
	title          string
}

func viewCmd() *cobra.Command {
	opts := viewOptions{}
	cmd := &cobra.Command{
		Use:   "view",
		Short: "Render a single agent's evidence as a self-contained HTML report",
		Long: `Read one agent's decision receipts from a flight-recorder evidence
directory and render a static, self-contained HTML report. The report
includes the four-line bounded scorecard, a receipt timeline, and
per-receipt decision explanations.

No server, no persistence, no license required. For the multi-agent
cross-agent evidence console, see the Pro/Enterprise dashboard.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runView(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "",
		"flight-recorder evidence directory holding action receipts")
	cmd.Flags().StringVar(&opts.sessionID, "session", "",
		"session ID to render; if omitted, uses the single or first session")
	cmd.Flags().StringArrayVar(&opts.trustedSigners, "trusted-signer", nil,
		"trusted receipt signing key as comma-separated kv pairs: "+
			"'(inline=HEX_OR_VERSIONED_PUBLIC_KEY|file=/path)[,source=LABEL]'; repeatable")
	cmd.Flags().StringVar(&opts.outFile, "out", "",
		"output file path; defaults to stdout")
	cmd.Flags().StringVar(&opts.title, "title", "Pipelock Evidence Report",
		"report title shown in the HTML output")
	_ = cmd.MarkFlagRequired("receipt-dir")
	return cmd
}

func runView(cmd *cobra.Command, opts viewOptions) error {
	cleanDir := filepath.Clean(opts.receiptDir)
	info, err := os.Stat(cleanDir)
	if err != nil {
		return fmt.Errorf("--receipt-dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--receipt-dir %q is not a directory", opts.receiptDir)
	}

	trusted, err := signingflag.ParseTrustedSigners(opts.trustedSigners)
	if err != nil {
		return err
	}

	sessionID, err := resolveSession(cmd, cleanDir, opts.sessionID)
	if err != nil {
		return err
	}

	receipts, readLimited, err := receipt.ExtractReceiptsFromSessionDirBounded(
		cleanDir, sessionID, evidenceview.DashboardReceiptReadLimit,
	)
	if err != nil {
		return fmt.Errorf("reading receipts for session %q: %w", sessionID, err)
	}

	ev := evidenceview.SessionEvidenceOf(
		sessionID, receipts, trusted,
		readLimited,
		evidenceview.DashboardReceiptReadLimit,
		evidenceview.DashboardTimelineLimit,
	)

	// Build a seq-to-receipt index so explanations match the timeline window.
	seqIndex := make(map[uint64]int, len(receipts))
	for i, r := range receipts {
		seqIndex[r.ActionRecord.ChainSeq] = i
	}
	explanations := make([]evidenceview.DecisionExplanation, len(ev.Timeline))
	for i, ti := range ev.Timeline {
		if idx, ok := seqIndex[ti.Seq]; ok {
			explanations[i] = evidenceview.ExplainReceipt(receipts[idx])
		}
	}

	renderOpts := evidenceview.RenderOptions{
		Title:       opts.title,
		GeneratedAt: time.Now(),
	}

	w := cmd.OutOrStdout()
	if opts.outFile != "" {
		cleanOut := filepath.Clean(opts.outFile)
		f, createErr := os.OpenFile(cleanOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if createErr != nil {
			return fmt.Errorf("--out: %w", createErr)
		}
		defer func() { _ = f.Close() }()
		w = f
	}

	return evidenceview.RenderSingleAgentHTML(w, ev, explanations, renderOpts)
}

// resolveSession picks the single session to render. If --session is set,
// use it. Otherwise list sessions: if exactly one, use it; if multiple,
// pick the first alphabetically and print a note that multi-agent console
// is available in Pro.
func resolveSession(cmd *cobra.Command, dir, explicit string) (string, error) {
	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		return "", fmt.Errorf("listing sessions: %w", err)
	}
	if explicit != "" {
		// Verify the requested session actually exists rather than silently
		// rendering an empty report for a typo'd or nonexistent session ID.
		for _, s := range sessions {
			if s == explicit {
				return explicit, nil
			}
		}
		return "", fmt.Errorf("session %q not found in %q", explicit, dir)
	}
	if len(sessions) == 0 {
		return "", fmt.Errorf("no sessions found in %q", dir)
	}
	if len(sessions) == 1 {
		return sessions[0], nil
	}
	// Multiple sessions: pick the first, note multi-agent is Pro.
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
		"pipelock: note: %d sessions found in the evidence directory; "+
			"rendering only session %q. The multi-agent cross-agent console "+
			"is available in Pipelock Pro.\n",
		len(sessions), sessions[0])
	return sessions[0], nil
}

// verify-cert subcommand: free offline verification of coverage certificates.

type verifyCertOptions struct {
	certFile       string
	trustedSigners []string
}

func verifyCertCmd() *cobra.Command {
	opts := verifyCertOptions{}
	cmd := &cobra.Command{
		Use:   "verify-cert",
		Short: "Verify a coverage certificate offline (Free)",
		Long: `Verify a coverage certificate's Ed25519 signature and check the signer
against the trusted-signer set. Re-derives aggregate counts from the
per-session data and flags any mismatch with the signed aggregates.

Fully offline: no license, no server, no network. The Free viewer
VERIFIES a Pro-issued certificate; only Pro issues one.

An untrusted signer is reported (never silently accepted). Non-zero exit
if the signature is invalid.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerifyCert(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.certFile, "cert", "", "coverage certificate JSON file")
	cmd.Flags().StringArrayVar(&opts.trustedSigners, "trusted-signer", nil,
		"trusted signing key as comma-separated kv pairs: "+
			"'(inline=HEX_OR_VERSIONED_PUBLIC_KEY|file=/path)[,source=LABEL]'; repeatable")
	_ = cmd.MarkFlagRequired("cert")
	return cmd
}

func runVerifyCert(cmd *cobra.Command, opts verifyCertOptions) error {
	return coveragecertverify.Run(coveragecertverify.Options{
		CertFile:       opts.certFile,
		TrustedSigners: opts.trustedSigners,
		Out:            cmd.OutOrStdout(),
		Err:            cmd.ErrOrStderr(),
	})
}
