// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	explainEventIDRequest = "request_id"
	explainEventIDEvent   = "event_id"
	explainEventIDGeneric = "id"

	explainEventOutcomeAllowed = "allowed"
	explainEventOutcomeBlocked = "blocked"
	explainEventRedacted       = "[redacted]"
	explainEventRedactedValue  = "[redacted-value]"
)

var explainEventSecretAssignmentRe = regexp.MustCompile(`(?i)\b(?:token|access_token|api_key|apikey|secret|password|passwd|authorization|client_secret|bearer)\b\s*[:=]\s*[^,\s;&]+`)

type explainEventReport struct {
	ID              string   `json:"id"`
	MatchedField    string   `json:"matched_field"`
	ConfigFile      string   `json:"config_file"`
	AuditLog        string   `json:"audit_log"`
	Version         string   `json:"version"`
	Time            string   `json:"time,omitempty"`
	Event           string   `json:"event,omitempty"`
	Outcome         string   `json:"outcome,omitempty"`
	Method          string   `json:"method,omitempty"`
	Target          string   `json:"target,omitempty"`
	TargetView      string   `json:"target_view,omitempty"`
	Scanner         string   `json:"scanner,omitempty"`
	Layer           string   `json:"layer,omitempty"`
	PatternName     string   `json:"pattern_name,omitempty"`
	Reason          string   `json:"reason,omitempty"`
	StatusCode      string   `json:"status_code,omitempty"`
	RemediationHint string   `json:"remediation_hint,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

type explainEventLookup struct {
	report       explainEventReport
	found        bool
	skippedLines int
}

func explainEventCmd() *cobra.Command {
	var configFile string
	var auditLog string
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "event <id>",
		Short: "Explain a past audit-log event by id",
		Long: `Look up a past decision event in a Pipelock JSON audit log and explain
the operator-facing reason. The lookup matches request_id first, then event_id
and id for adjacent JSONL event streams. For blocks, the report uses the
audit event's remediation_hint when present and falls back to the same scanner
remediation table used by pipelock explain.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgLabel, err := explainLoadConfig(configFile)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			logPath, err := resolveExplainEventLogPath(cfg, auditLog)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}

			lookup, err := lookupExplainEvent(logPath, args[0])
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if !lookup.found {
				return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("audit event %q not found in %s", args[0], logPath))
			}
			report := lookup.report
			report.ConfigFile = cfgLabel
			report.AuditLog = logPath
			report.Version = cliutil.Version
			if lookup.skippedLines > 0 {
				report.Notes = append(report.Notes, fmt.Sprintf("%d malformed audit log line(s) skipped", lookup.skippedLines))
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return fmt.Errorf("encode explain event report JSON: %w", err)
				}
				return nil
			}
			printExplainEventReport(cmd.OutOrStdout(), report)
			return nil
		},
	}
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path (default: built-in defaults)")
	cmd.Flags().StringVar(&auditLog, "log", "", "audit JSONL log path (default: logging.file from config when output is file or both)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output report as JSON")
	return cmd
}

func resolveExplainEventLogPath(cfg *config.Config, auditLog string) (string, error) {
	if strings.TrimSpace(auditLog) != "" {
		return filepath.Clean(auditLog), nil
	}
	if cfg.Logging.File != "" && (cfg.Logging.Output == config.OutputFile || cfg.Logging.Output == config.OutputBoth) {
		return filepath.Clean(cfg.Logging.File), nil
	}
	return "", errors.New("audit log path required: pass --log or set logging.output to file/both with logging.file")
}

func lookupExplainEvent(path, id string) (explainEventLookup, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return explainEventLookup{}, fmt.Errorf("open audit log %s: %w", cleanPath, err)
	}
	defer func() {
		_ = f.Close()
	}()
	return scanExplainEvent(f, strings.TrimSpace(id))
}

func scanExplainEvent(r io.Reader, id string) (explainEventLookup, error) {
	var out explainEventLookup
	if id == "" {
		return out, errors.New("event id cannot be empty")
	}

	const maxAuditLineBytes = 1 << 20
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		lineBytes, tooLong, err := readExplainEventAuditLine(br, maxAuditLineBytes)
		if tooLong {
			out.skippedLines++
			if err != nil {
				return out, err
			}
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, fmt.Errorf("scan audit log: %w", err)
		}
		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			out.skippedLines++
			continue
		}
		matchedField := matchedExplainEventID(raw, id)
		if matchedField == "" {
			continue
		}
		out.report = buildExplainEventReport(raw, id, matchedField)
		out.found = true
		return out, nil
	}
}

func readExplainEventAuditLine(r *bufio.Reader, maxBytes int) ([]byte, bool, error) {
	line := make([]byte, 0, 4096)
	for {
		frag, err := r.ReadSlice('\n')
		if len(line)+len(frag) > maxBytes {
			if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
				return nil, true, fmt.Errorf("scan audit log: %w", err)
			}
			if err == nil || errors.Is(err, io.EOF) {
				return nil, true, nil
			}
			if discardErr := discardExplainEventAuditLineRemainder(r); discardErr != nil {
				return nil, true, discardErr
			}
			return nil, true, nil
		}
		line = append(line, frag...)
		switch {
		case err == nil:
			return line, false, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(line) == 0 {
				return nil, false, io.EOF
			}
			return line, false, nil
		default:
			return nil, false, err
		}
	}
}

func discardExplainEventAuditLineRemainder(r *bufio.Reader) error {
	for {
		_, err := r.ReadSlice('\n')
		switch {
		case err == nil:
			return nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return nil
		default:
			return fmt.Errorf("scan audit log: %w", err)
		}
	}
}

func matchedExplainEventID(raw map[string]any, id string) string {
	for _, field := range []string{explainEventIDRequest, explainEventIDEvent, explainEventIDGeneric, "action_id", "defer_id"} {
		if eventFieldString(raw, field) == id {
			return field
		}
	}
	return ""
}

func buildExplainEventReport(raw map[string]any, id, matchedField string) explainEventReport {
	sanitizer := newExplainEventSanitizer()
	eventName := eventFieldString(raw, "event")
	reason := eventFieldString(raw, "reason")
	scannerName := eventFieldString(raw, "scanner")
	target := firstEventField(raw, "url", "target", "resource", "endpoint", "tool", "session")
	report := explainEventReport{
		ID:              id,
		MatchedField:    matchedField,
		Time:            sanitizer.field(eventFieldString(raw, "time")),
		Event:           sanitizer.field(eventName),
		Outcome:         explainEventOutcome(eventName, eventFieldString(raw, "action")),
		Method:          sanitizer.field(eventFieldString(raw, "method")),
		Target:          sanitizer.target(target),
		TargetView:      explainEventTargetView(scannerName, reason, target, raw),
		Scanner:         sanitizer.field(scannerName),
		Layer:           sanitizer.field(scannerName),
		PatternName:     sanitizer.field(firstEventField(raw, "pattern_name", "pattern", "display_label")),
		Reason:          sanitizer.field(reason),
		StatusCode:      sanitizer.field(eventFieldString(raw, "status_code")),
		RemediationHint: sanitizer.field(eventFieldString(raw, "remediation_hint")),
	}
	if report.RemediationHint == "" && scannerName != "" {
		report.RemediationHint = scanner.OperatorHintForResult(scannerName, reason)
	}
	if report.Outcome == "" {
		report.Notes = append(report.Notes, "event type is not a standard allowed/blocked decision; fields shown are the available audit evidence")
	}
	return report
}

func explainEventOutcome(eventName, action string) string {
	switch {
	case eventName == explainEventOutcomeAllowed || action == config.ActionAllow || action == config.ActionForward:
		return explainEventOutcomeAllowed
	case eventName == explainEventOutcomeBlocked || action == config.ActionBlock:
		return explainEventOutcomeBlocked
	default:
		return ""
	}
}

func explainEventTargetView(scannerName, reason, target string, raw map[string]any) string {
	switch {
	case target == "":
		return ""
	case eventFieldString(raw, "tool") != "":
		return explainSurfaceTool
	case eventFieldString(raw, "resource") != "":
		return "resource"
	case eventFieldString(raw, "session") != "":
		return "session"
	}
	if strings.Contains(target, "://") {
		return explainTargetView(scanner.Result{Scanner: scannerName, Reason: reason}, target)
	}
	if strings.Contains(target, "/") {
		return explainViewPath
	}
	return explainViewHost
}

func firstEventField(raw map[string]any, fields ...string) string {
	for _, field := range fields {
		if value := eventFieldString(raw, field); value != "" {
			return value
		}
	}
	return ""
}

func eventFieldString(raw map[string]any, field string) string {
	v, ok := raw[field]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

type explainEventSanitizer struct {
	scanner *scanner.Scanner
}

func newExplainEventSanitizer() explainEventSanitizer {
	return explainEventSanitizer{scanner: scanner.New(config.Defaults())}
}

func (s explainEventSanitizer) clean(value string) bool {
	if value == "" {
		return true
	}
	return s.scanner.ScanTextForDLPQuiet(context.Background(), value).Clean
}

func (s explainEventSanitizer) field(value string) string {
	value = redactExplainEventSecretAssignments(value)
	if s.clean(value) {
		return value
	}
	return explainEventRedacted
}

func (s explainEventSanitizer) target(value string) string {
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			parsed.User = nil
			parsed.Fragment = ""
			parsed.RawFragment = ""
			query := parsed.Query()
			for key := range query {
				if explainEventSecretQueryParam(key) {
					query.Set(key, explainEventRedactedValue)
				}
			}
			parsed.RawQuery = query.Encode()
			value = parsed.String()
		}
	}
	value = receipt.SanitizeTarget(value, s.clean)
	return s.field(value)
}

func redactExplainEventSecretAssignments(value string) string {
	return explainEventSecretAssignmentRe.ReplaceAllStringFunc(value, func(match string) string {
		idx := strings.IndexAny(match, ":=")
		if idx < 0 {
			return explainEventRedacted
		}
		return strings.TrimRight(match[:idx+1], " \t") + explainEventRedactedValue
	})
}

func explainEventSecretQueryParam(key string) bool {
	switch strings.ToLower(key) {
	case "token", "access_token", "api_key", "apikey", "secret", "password", "passwd", "key",
		"auth", "authorization", "client_secret", "client_id", "sig", "signature":
		return true
	default:
		return false
	}
}

func printExplainEventReport(w io.Writer, report explainEventReport) {
	_, _ = fmt.Fprintln(w, "Pipelock Explain Event")
	_, _ = fmt.Fprintln(w, "======================")
	_, _ = fmt.Fprintf(w, "ID:      %s (%s)\n", terminalDisplay(report.ID), terminalDisplay(report.MatchedField))
	_, _ = fmt.Fprintf(w, "Config:  %s\n", terminalDisplay(report.ConfigFile))
	_, _ = fmt.Fprintf(w, "Log:     %s\n", terminalDisplay(report.AuditLog))
	if report.Time != "" {
		_, _ = fmt.Fprintf(w, "Time:    %s\n", terminalDisplay(report.Time))
	}
	if report.Event != "" {
		_, _ = fmt.Fprintf(w, "Event:   %s\n", terminalDisplay(report.Event))
	}
	if report.Outcome != "" {
		_, _ = fmt.Fprintf(w, "Verdict: %s\n", terminalDisplay(strings.ToUpper(report.Outcome)))
	}
	if report.Method != "" {
		_, _ = fmt.Fprintf(w, "Method:  %s\n", terminalDisplay(report.Method))
	}
	if report.Target != "" {
		_, _ = fmt.Fprintf(w, "Target:  %s\n", terminalDisplay(report.Target))
	}
	if report.TargetView != "" {
		_, _ = fmt.Fprintf(w, "View:    %s\n", terminalDisplay(report.TargetView))
	}
	if report.Scanner != "" {
		_, _ = fmt.Fprintf(w, "Scanner: %s\n", terminalDisplay(report.Scanner))
		_, _ = fmt.Fprintf(w, "Layer:   %s\n", terminalDisplay(report.Layer))
	}
	if report.PatternName != "" {
		_, _ = fmt.Fprintf(w, "Pattern: %s\n", terminalDisplay(report.PatternName))
	}
	if report.Reason != "" {
		_, _ = fmt.Fprintf(w, "Why:     %s\n", terminalDisplay(report.Reason))
	} else if report.Outcome == explainEventOutcomeAllowed {
		_, _ = fmt.Fprintln(w, "Why:     request completed without a blocking scanner verdict")
	}
	if report.StatusCode != "" {
		_, _ = fmt.Fprintf(w, "Status:  %s\n", terminalDisplay(report.StatusCode))
	}
	if report.RemediationHint != "" {
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "Remediation:")
		_, _ = fmt.Fprintf(w, "  %s\n", terminalDisplay(report.RemediationHint))
	}
	for _, note := range report.Notes {
		_, _ = fmt.Fprintf(w, "note: %s\n", terminalDisplay(note))
	}
}

func terminalDisplay(value string) string {
	if value == "" || !needsTerminalQuoting(value) {
		return value
	}
	return strconv.QuoteToASCII(value)
}

func needsTerminalQuoting(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}
