// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// errExplainResponseScan is returned when the offline response scanner could
// not complete. It is an input/runtime error (exit 2), not an injection block.
var errExplainResponseScan = errors.New("response scan failed")

// errExplainResponseTooLarge is returned when stdin exceeds every live
// response-scan ceiling in the loaded config. The body is not scanned.
var errExplainResponseTooLarge = errors.New("response body exceeds explain read cap")

// errExplainResponseBlocked is returned when the offline scan matches and
// runtime would not forward the original body. It must not reuse
// errExplainBlocked ("url blocked"): main prints the sentinel on stderr.
var errExplainResponseBlocked = errors.New("response blocked")

// responseExplainReport is an offline explanation of the raw HTTP response
// body that an operator saved after a response-scan block. Match values are
// deliberately fingerprints, not attacker-controlled text: explain output is
// commonly copied into terminals, logs, and agent-visible incident channels.
type responseExplainReport struct {
	ConfigFile string                 `json:"config_file"`
	Mode       string                 `json:"mode"`
	Version    string                 `json:"version"`
	Allowed    bool                   `json:"allowed"`
	Action     string                 `json:"action"`
	BodySHA256 string                 `json:"body_sha256"`
	Matches    []responseExplainMatch `json:"matches,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Notes      []string               `json:"notes,omitempty"`
}

// responseExplainMatch identifies the exact scanner view and byte range that
// matched. Position and Length index View, not the raw stdin bytes.
// MatchSHA256 is SHA-256 of the scanner's retained match text (truncated to
// 100 runes), not of the raw stdin slice at Position:Length.
type responseExplainMatch struct {
	PatternName   string `json:"pattern_name"`
	Position      int    `json:"position"`
	Length        int    `json:"length"`
	View          string `json:"view"`
	MatchSHA256   string `json:"match_sha256"`
	Bundle        string `json:"bundle,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`
}

func explainResponseCmd() *cobra.Command {
	var configFile string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "response",
		Short: "Explain an HTTP response-body prompt-injection block",
		Long: `Read a saved HTTP response body from stdin and run ScanResponseBodyWithSuppress, the raw-body scanner used by intercept, forward, reverse, and non-HTML fetch. The report names every matching pattern and gives the matching scanner view, byte offset, length, and fingerprints for the body and match.

This is not a replay of a live fetch HTML block. Fetch HTML is scanned after hidden-content extraction and readability, using the final response URL for destination-scoped suppress entries. Piping a saved HTML document can therefore disagree with a live fetch verdict. Reconstruct the extracted scan input when diagnosing a fetch HTML block.

Offsets, lengths, and match fingerprints index the named scanner view, not the raw stdin bytes. Match SHA-256 is over the scanner's retained match text (truncated to 100 runes). Slice that named view, not the saved file, when comparing fingerprints.

The command never fetches a URL and never prints matched response text. A match can contain attacker-controlled instructions or credentials; emitting it into a terminal, log, or agent-visible incident channel would create a new injection or disclosure path. Inspect the saved body only in an isolated viewer.

Example:
  pipelock explain response --config pipelock.yaml < saved-response.bin`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgLabel, err := explainLoadConfig(configFile)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			limit := explainResponseReadLimit(cfg)
			body, err := readExplainResponseBody(cmd.Context(), cmd.InOrStdin(), limit)
			if err != nil {
				if errors.Is(err, errExplainResponseTooLarge) {
					report := newResponseExplainReport(cfg, cfgLabel, nil)
					report.Allowed = false
					report.Error = fmt.Sprintf("response body exceeds explain read cap of %d bytes", limit)
					return emitResponseExplainReport(cmd, report, jsonOutput, errExplainResponseTooLarge)
				}
				return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("read response body from stdin: %w", err))
			}
			report, err := buildResponseExplainReport(cmd.Context(), cfg, cfgLabel, body)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			return emitResponseExplainReport(cmd, report, jsonOutput, nil)
		},
	}
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (default: built-in defaults)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output report as JSON")
	return cmd
}

func newResponseExplainReport(cfg *config.Config, cfgLabel string, body []byte) responseExplainReport {
	report := responseExplainReport{
		ConfigFile: cfgLabel,
		Mode:       cfg.Mode,
		Version:    cliutil.Version,
		Allowed:    true,
		Action:     cfg.ResponseScanning.Action,
		Notes: []string{
			"matched text is intentionally omitted",
			"position, length, and match SHA-256 index the named scanner view, not the raw stdin bytes; match SHA-256 is over the scanner's retained match text (truncated to 100 runes)",
			"this command scans raw stdin with ScanResponseBodyWithSuppress (intercept/forward/reverse/non-HTML fetch). Fetch HTML is scanned after hidden-content extraction and readability, so a saved HTML document can disagree with a live fetch block",
		},
	}
	if body != nil {
		report.BodySHA256 = sha256Hex(body)
	}
	if len(cfg.Suppress) > 0 {
		report.Notes = append(report.Notes, "destination-scoped suppress entries were not applied; this command has no request URL and cannot prove the live final URL")
	}
	if cfg.AdaptiveEnforcement.Enabled {
		report.Notes = append(report.Notes, "adaptive enforcement uses live session state and did not run; it can upgrade this scanner action at runtime")
	}
	if !cfg.ResponseScanning.Enabled {
		report.Notes = append(report.Notes, "response_scanning.enabled is false; only the immutable core response floor ran, and runtime treats those hits as block")
	}
	return report
}

func buildResponseExplainReport(ctx context.Context, cfg *config.Config, cfgLabel string, body []byte) (responseExplainReport, error) {
	report := newResponseExplainReport(cfg, cfgLabel, body)
	bundleResult := rules.MergeIntoConfig(cfg, cliutil.Version)
	for _, e := range bundleResult.Errors {
		// Bundle-sourced text reaches a terminal exactly like the scan error
		// does, so it gets the same escaping. Escaping one of these and not its
		// siblings was the gap this closes.
		report.Notes = append(report.Notes, escapeExplainEventTerminalControls(
			fmt.Sprintf("rule bundle %s skipped: %s", e.Name, e.Reason)))
	}
	for _, w := range bundleResult.Warnings {
		report.Notes = append(report.Notes, escapeExplainEventTerminalControls("rule bundle warning: "+w))
	}
	cfg.Internal = nil
	sc, err := scanner.New(cfg)
	if err != nil {
		return report, fmt.Errorf("create scanner: %w", err)
	}
	defer sc.Close()
	result := sc.ScanResponseBodyWithSuppress(ctx, body, "", nil)
	// Runtime intercept/forward/reverse consult Scanner.ResponseAction(), not
	// the raw YAML field. When response_scanning.enabled is false, that method
	// returns block for core-floor hits even if the file still says warn.
	report.Action = sc.ResponseAction()
	if result.Failed() {
		report.Allowed = false
		// The scan error reaches a terminal and a JSON consumer. Two of its
		// three sources are fixed context-error text, but an image-metadata
		// decode error is shaped by the body, so it goes through the same
		// control-character escaping the event explainer already uses rather
		// than being trusted because its usual value is benign.
		report.Error = escapeExplainEventTerminalControls(result.ScanError)
		return report, nil
	}
	if result.Clean {
		return report, nil
	}
	report.Allowed = report.Action == config.ActionWarn
	switch report.Action {
	case config.ActionWarn:
		report.Notes = append(report.Notes, "response_scanning.action is warn, so runtime forwards this response and logs the finding")
	case config.ActionStrip:
		report.Notes = append(report.Notes, "response_scanning.action is strip; runtime redacts matches when transformation is possible, otherwise blocks")
	case config.ActionAsk:
		report.Notes = append(report.Notes, "response_scanning.action is ask; runtime prompts an approver before releasing the response, and hard-blocks when none is configured, which is the verdict shown here")
	}
	for _, match := range result.Matches {
		span := match.Span()
		report.Matches = append(report.Matches, responseExplainMatch{
			PatternName:   escapeExplainEventTerminalControls(match.PatternName),
			Position:      match.Position,
			Length:        span.ByteEnd - span.ByteStart,
			View:          span.ViewLabel,
			MatchSHA256:   sha256Hex([]byte(match.MatchText)),
			Bundle:        escapeExplainEventTerminalControls(match.Bundle),
			BundleVersion: escapeExplainEventTerminalControls(match.BundleVersion),
		})
	}
	return report, nil
}

// explainResponseMaxReadBytes bounds the read no matter how large the configured
// ceilings are. The derived limit comes from operator configuration, and
// `size_exempt_scan_max_bytes` is only validated as positive, so a large value
// would otherwise have io.ReadAll allocate that much from stdin in one piece.
// This is a diagnostic command; refusing an enormous body with a clear reason
// beats exhausting memory on the operator's workstation.
const explainResponseMaxReadBytes = 256 << 20

func explainResponseReadLimit(cfg *config.Config) int {
	if cfg == nil {
		return explainFileReadLimitBytes
	}
	limit := 0
	// Multiply in int64 and reject the overflow rather than wrapping to a small
	// or negative limit, which would silently truncate the body and report a
	// clean scan of the part that fit.
	if mb := int64(cfg.FetchProxy.MaxResponseMB); mb > 0 && mb <= explainResponseMaxReadBytes/(1024*1024) {
		limit = int(mb * 1024 * 1024)
	} else if mb > 0 {
		limit = explainResponseMaxReadBytes
	}
	if n := cfg.TLSInterception.MaxResponseBytes; n > int64(limit) {
		limit = clampExplainResponseLimit(n)
	}
	if n := int64(cfg.ResponseScanning.SizeExemptScanMaxBytes); n > int64(limit) {
		limit = clampExplainResponseLimit(n)
	}
	if limit <= 0 {
		return explainFileReadLimitBytes
	}
	return limit
}

func clampExplainResponseLimit(n int64) int {
	if n > explainResponseMaxReadBytes {
		return explainResponseMaxReadBytes
	}
	return int(n)
}

// readExplainResponseBody reads stdin under the command's context. io.ReadAll on
// a terminal or a pipe nobody closes blocks forever, so without the select below
// cancellation is only observed AFTER the read returns, which is exactly when it
// no longer matters.
//
// On cancellation the reader is CLOSED when it can be, which unblocks the
// in-flight read, and the goroutine is then waited for. The buffered channel
// only stops that goroutine blocking on its send; it does NOT stop it blocking
// inside the read, so it is not what bounds the goroutine and this comment no
// longer claims it is. A reader that cannot be closed and never returns leaves
// one goroutine parked for the remaining life of the process, which is stated
// here rather than implied to be handled.
func readExplainResponseBody(ctx context.Context, r io.Reader, limit int) ([]byte, error) {
	if limit <= 0 {
		limit = explainFileReadLimitBytes
	}
	if limit > explainResponseMaxReadBytes {
		limit = explainResponseMaxReadBytes
	}
	type readResult struct {
		body []byte
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		body, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
		done <- readResult{body: body, err: err}
	}()
	var body []byte
	select {
	case <-ctx.Done():
		if closer, ok := r.(io.Closer); ok {
			// Close, then take the result only if it is already there. Waiting
			// unconditionally hangs forever on a reader whose Close does
			// nothing: io.NopCloser around a blocking reader satisfies
			// io.Closer and unblocks nothing, so the previous wait meant the
			// command could not report cancellation at all. A goroutine still
			// parked in the read is the unavoidable part, because io.Reader has
			// no cancellation contract; the buffered channel is what lets it
			// finish its send later instead of blocking forever.
			_ = closer.Close()
			select {
			case <-done:
			default:
			}
		}
		return nil, ctx.Err()
	case res := <-done:
		body = res.body
		if res.err != nil {
			return nil, res.err
		}
	}
	if len(body) > limit {
		return nil, errExplainResponseTooLarge
	}
	return body, nil
}

func emitResponseExplainReport(cmd *cobra.Command, report responseExplainReport, jsonOutput bool, cause error) error {
	if jsonOutput {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return fmt.Errorf("encode response explain report JSON: %w", err)
		}
	} else if err := printResponseExplainReport(cmd.OutOrStdout(), report); err != nil {
		// The JSON branch already propagates its encode error. A silent failure
		// here returned success with partial or absent output, so an operator
		// piping this into a file saw an empty result and a zero exit.
		return fmt.Errorf("write response explain report: %w", err)
	}
	if report.Error != "" {
		// The cause is carried from the caller that KNEW it, never re-derived by
		// matching the rendered message. report.Error can hold scanner text that
		// an image-metadata failure shapes from the body, so a substring check
		// here would let that text choose the sentinel and mislead anything
		// scripting the exit code.
		if cause == nil {
			cause = errExplainResponseScan
		}
		return cliutil.ExitCodeError(cliutil.ExitConfig, cause)
	}
	if !report.Allowed {
		return cliutil.ExitCodeError(cliutil.ExitSecurity, errExplainResponseBlocked)
	}
	return nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// printResponseExplainReport returns the first write error rather than dropping
// it. A partial report that exits zero is worse than a loud failure: the
// operator reads the lines that made it out and takes the missing ones as absent
// findings.
func printResponseExplainReport(w io.Writer, report responseExplainReport) error {
	verdict := "BLOCKED"
	switch {
	case report.Error != "":
		verdict = "ERROR"
	case report.Allowed:
		verdict = "ALLOWED"
	}
	if _, err := fmt.Fprintln(w, verdict); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Action: %s\nBody SHA-256: %s\n", report.Action, report.BodySHA256); err != nil {
		return err
	}
	for _, match := range report.Matches {
		if _, err := fmt.Fprintf(w, "Pattern: %s\nView: %s\nPosition: %d\nLength: %d\nMatch SHA-256: %s\n", match.PatternName, match.View, match.Position, match.Length, match.MatchSHA256); err != nil {
			return err
		}
	}
	if report.Error != "" {
		if _, err := fmt.Fprintf(w, "Error: %s\n", report.Error); err != nil {
			return err
		}
	}
	for _, note := range report.Notes {
		if _, err := fmt.Fprintf(w, "Note: %s\n", note); err != nil {
			return err
		}
	}
	return nil
}
