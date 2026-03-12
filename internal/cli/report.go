// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/report"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Date layout for --since/--until when no time component is provided.
const dateLayout = "2006-01-02"

// Format constants for --format flag.
const (
	formatHTML   = "html"
	formatJSON   = "json"
	formatBundle = "bundle"
	formatText   = "text"
	formatSARIF  = "sarif"
)

func reportCmd() *cobra.Command {
	var (
		input       string
		format      string
		output      string
		days        int
		since       string
		until       string
		title       string
		maxEvidence int
		noRedact    bool
		sign        bool
		agent       string
		keystoreDir string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate an audit report from JSONL event logs",
		Long: `Reads a pipelock JSONL audit log and produces an HTML, JSON, or signed
bundle report with risk rating, event categories, timeline, and evidence.

Examples:
  pipelock report --input events.jsonl
  pipelock report --input events.jsonl --format json -o report.json
  pipelock report --input - < events.jsonl
  pipelock report --input events.jsonl --days 7
  pipelock report --input events.jsonl --since 2026-03-01 --until 2026-03-05
  pipelock report --input events.jsonl --format bundle -o ./report-bundle/
  pipelock report --input events.jsonl --format bundle -o ./bundle/ --sign --agent claude-code`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if input == "" {
				return fmt.Errorf("--input is required (file path or - for stdin)")
			}

			// Validate format.
			format = strings.ToLower(format)
			switch format {
			case formatHTML, formatJSON, formatBundle:
			default:
				return fmt.Errorf("unsupported format %q (use html, json, or bundle)", format)
			}

			// Signing requires bundle format.
			if sign && format != formatBundle {
				return fmt.Errorf("--sign requires --format bundle")
			}

			// Bundle requires --output.
			if format == formatBundle && output == "" {
				return fmt.Errorf("--format bundle requires --output directory")
			}

			// Open input.
			var reader io.Reader
			if input == "-" {
				reader = cmd.InOrStdin()
			} else {
				f, err := os.Open(filepath.Clean(input))
				if err != nil {
					return fmt.Errorf("opening input: %w", err)
				}
				defer func() { _ = f.Close() }()
				reader = f
			}

			// Build ParseOptions.
			var popts report.ParseOptions
			if days > 0 {
				popts.Since = time.Now().AddDate(0, 0, -days)
			}
			if since != "" {
				t, err := parseTimeFlag(since)
				if err != nil {
					return fmt.Errorf("parsing --since: %w", err)
				}
				popts.Since = t // --since overrides --days
			}
			if until != "" {
				t, err := parseTimeFlag(until)
				if err != nil {
					return fmt.Errorf("parsing --until: %w", err)
				}
				popts.Until = t
			}

			// Build Options.
			opts := report.Options{
				Title:       title,
				MaxEvidence: maxEvidence,
				Redact:      !noRedact,
			}

			// Generate report.
			rpt, err := report.Generate(reader, popts, opts)
			if err != nil {
				return fmt.Errorf("generating report: %w", err)
			}

			// Load signing key if requested.
			var privKey ed25519.PrivateKey
			if sign {
				agentName, err := resolveAgentName(agent)
				if err != nil {
					return err
				}
				dir, err := resolveKeystoreDir(keystoreDir)
				if err != nil {
					return err
				}
				ks := signing.NewKeystore(dir)
				privKey, err = ks.LoadPrivateKey(agentName)
				if err != nil {
					return fmt.Errorf("loading signing key for agent %q: %w", agentName, err)
				}
			}

			// Output.
			switch format {
			case formatHTML:
				if err := renderToTarget(cmd, output, rpt, report.RenderHTML); err != nil {
					return err
				}
			case formatJSON:
				if err := renderToTarget(cmd, output, rpt, report.RenderJSON); err != nil {
					return err
				}
			case formatBundle:
				if err := report.WriteBundle(output, rpt, privKey); err != nil {
					return fmt.Errorf("writing bundle: %w", err)
				}
			}

			// Summary to stderr.
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Report generated: %s risk, %d events, %d blocks\n",
				rpt.Risk, rpt.Summary.TotalEvents, rpt.Summary.Blocks)
			if rpt.Summary.SkippedLines > 0 {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: %d malformed line(s) skipped during parsing\n",
					rpt.Summary.SkippedLines)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "JSONL file path or - for stdin (required)")
	cmd.Flags().StringVar(&format, "format", formatHTML, "output format: html, json, or bundle")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file or directory (required for bundle)")
	cmd.Flags().IntVar(&days, "days", 0, "include events from last N days")
	cmd.Flags().StringVar(&since, "since", "", "include events after this date (YYYY-MM-DD or RFC3339)")
	cmd.Flags().StringVar(&until, "until", "", "include events before this date (YYYY-MM-DD or RFC3339)")
	cmd.Flags().StringVar(&title, "title", report.DefaultTitle, "report title")
	cmd.Flags().IntVar(&maxEvidence, "max-evidence", 100, "max evidence entries in appendix")
	cmd.Flags().BoolVar(&noRedact, "no-redact", false, "disable URL/IP redaction")
	cmd.Flags().BoolVar(&sign, "sign", false, "sign the bundle with an Ed25519 key")
	cmd.Flags().StringVar(&agent, "agent", "", "agent name for signing (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")

	return cmd
}

// renderToTarget renders a report to a file (if output is set) or to stdout.
func renderToTarget(cmd *cobra.Command, output string, rpt *report.Report, renderFn func(io.Writer, *report.Report) error) error {
	if output != "" {
		f, err := os.OpenFile(filepath.Clean(output), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		return renderFn(f, rpt)
	}
	return renderFn(cmd.OutOrStdout(), rpt)
}

// parseTimeFlag parses a date string as RFC3339 first, then as YYYY-MM-DD.
func parseTimeFlag(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected RFC3339 or YYYY-MM-DD, got %q", s)
	}
	return t.UTC(), nil
}
