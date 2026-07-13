// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package evidence implements the free single-agent evidence viewer CLI
// command. It renders one agent's decision receipts as a static,
// self-contained, offline HTML report. No server, no persistence, no
// license check, single-agent only.
package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	cmd.AddCommand(serveCmd())
	cmd.AddCommand(verifyCertCmd())
	return cmd
}

const (
	defaultEvidenceServeListen     = "127.0.0.1:0"
	evidenceServeCSP               = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'none'"
	evidenceServeReadHeaderTimeout = 5 * time.Second
	evidenceServeReadTimeout       = 30 * time.Second
	evidenceServeWriteTimeout      = 30 * time.Second
	evidenceServeShutdownTimeout   = 5 * time.Second
)

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
	cleanDir, err := validateReceiptDir(opts.receiptDir)
	if err != nil {
		return err
	}
	trusted, err := signingflag.ParseTrustedSigners(opts.trustedSigners)
	if err != nil {
		return err
	}
	sessionID, err := resolveSession(cmd, cleanDir, opts.sessionID)
	if err != nil {
		return err
	}
	html, err := renderSessionHTML(cleanDir, sessionID, trusted, opts.title)
	if err != nil {
		return err
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

	_, err = w.Write(html)
	return err
}

type serveOptions struct {
	receiptDir string
	sessionID  string
	listen     string
}

func serveCmd() *cobra.Command {
	opts := serveOptions{listen: defaultEvidenceServeListen}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve one agent's evidence as a read-only HTML report",
		Long: `Read one agent's decision receipts from a flight-recorder evidence
directory and serve a single-session, read-only HTML report at GET /.

No license required. The server binds exactly one session at startup and
does not expose any route or query parameter that can select another session.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "",
		"flight-recorder evidence directory holding action receipts")
	cmd.Flags().StringVar(&opts.sessionID, "session", "",
		"session ID to serve; required when the receipt directory contains multiple sessions")
	cmd.Flags().StringVar(&opts.listen, "listen", defaultEvidenceServeListen,
		"TCP listen address for the read-only evidence server")
	_ = cmd.MarkFlagRequired("receipt-dir")
	return cmd
}

func runServe(cmd *cobra.Command, opts serveOptions) error {
	cleanDir, err := validateReceiptDir(opts.receiptDir)
	if err != nil {
		return err
	}
	sessionID, err := resolveServeSession(cleanDir, opts.sessionID)
	if err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(cmd.Context(), "tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("--listen %q: %w", opts.listen, err)
	}
	defer func() { _ = ln.Close() }()

	srv := &http.Server{
		Handler:           evidenceServeHandler(cleanDir, sessionID),
		ReadHeaderTimeout: evidenceServeReadHeaderTimeout,
		ReadTimeout:       evidenceServeReadTimeout,
		WriteTimeout:      evidenceServeWriteTimeout,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock evidence serve listening on http://%s\n", ln.Addr().String())

	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-cmd.Context().Done():
		ctx, cancel := context.WithTimeout(context.Background(), evidenceServeShutdownTimeout)
		defer cancel()
		if shutdownErr := srv.Shutdown(ctx); shutdownErr != nil {
			return shutdownErr
		}
		err := <-errCh
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return cmd.Context().Err()
		}
		return err
	}
}

func evidenceServeHandler(dir, sessionID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", evidenceServeCSP)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		html, err := renderSessionHTML(dir, sessionID, nil, "Pipelock Evidence Report")
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "evidence serve: render evidence report: %v\n", err)
			http.Error(w, "render evidence report", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(html)
	})
}

func renderSessionHTML(
	dir string,
	sessionID string,
	trusted map[string]evidenceview.TrustedKey,
	title string,
) ([]byte, error) {
	receipts, readLimited, err := receipt.ExtractReceiptsFromSessionDirBounded(
		dir, sessionID, evidenceview.DashboardReceiptReadLimit,
	)
	if err != nil {
		return nil, fmt.Errorf("reading receipts for session %q: %w", sessionID, err)
	}
	if err := validateSingleActorReceipts(sessionID, receipts); err != nil {
		return nil, err
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

	var buf bytes.Buffer
	renderOpts := evidenceview.RenderOptions{
		Title:       title,
		GeneratedAt: time.Now(),
	}
	if err := evidenceview.RenderSingleAgentHTML(&buf, ev, explanations, renderOpts); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// anonymousActor is pipelock's default actor for unattributed requests (no agent
// identity supplied). It is not a distinct agent, so it must not trip the
// single-agent guard: a normal single-agent session routinely mixes its named
// agent's receipts with unattributed ("anonymous") traffic, and rejecting that
// would break the free view on legitimate real data. The guard rejects only when
// two or more DISTINCT NAMED actors appear (the real cross-agent leak).
const anonymousActor = "anonymous"

func validateSingleActorReceipts(sessionID string, receipts []receipt.Receipt) error {
	var boundActor string
	for _, r := range receipts {
		actor := strings.TrimSpace(r.ActionRecord.Actor)
		if actor == "" {
			actor = strings.TrimSpace(r.ActionRecord.SessionID)
		}
		if actor == "" {
			actor = sessionID
		}
		if actor == anonymousActor {
			continue
		}
		if boundActor == "" {
			boundActor = actor
			continue
		}
		if actor != boundActor {
			return fmt.Errorf(
				"session %q contains receipts for multiple named agents (%q and %q); use the Pro/Enterprise multi-agent evidence console",
				sessionID, boundActor, actor,
			)
		}
	}
	return nil
}

func validateReceiptDir(dir string) (string, error) {
	cleanDir := filepath.Clean(dir)
	info, err := os.Stat(cleanDir)
	if err != nil {
		return "", fmt.Errorf("--receipt-dir: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("--receipt-dir %q is not a directory", dir)
	}
	return cleanDir, nil
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

func resolveServeSession(dir, explicit string) (string, error) {
	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		return "", fmt.Errorf("listing sessions: %w", err)
	}
	if explicit != "" {
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
	return "", fmt.Errorf(
		"%d sessions found in %q; pass --session <id> to bind exactly one session",
		len(sessions), dir,
	)
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

Fails closed with a non-zero exit if the signature is invalid, the
aggregate counts do not match, or a trusted-signer set is supplied and the
certificate signer is not in it. With no trusted-signer set, verification is
structural-only and exits zero. The signer status is always reported.`,
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
	})
}
