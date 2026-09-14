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
	"math"
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

	explainEventOutcomeAllowed  = "allowed"
	explainEventOutcomeBlocked  = "blocked"
	explainEventOutcomeWarned   = "warned"
	explainEventOutcomeModified = "modified"
	explainEventOutcomePartial  = "partial"
	explainEventRedacted        = "[redacted]"
	explainEventRedactedValue   = "[redacted-value]"
)

var (
	explainEventAuthorizationAssignmentRe = regexp.MustCompile(`(?i)\bauthorization\b\s*[:=]\s*(?:bearer\s+)?[^,\s;&]+`)
	explainEventBearerValueRe             = regexp.MustCompile(`(?i)\bbearer\s+[^,\s;&]+`)
	explainEventSecretAssignmentRe        = regexp.MustCompile(`(?i)\b(?:token|access_token|api_key|apikey|secret|password|passwd|client_secret)\b\s*[:=]\s*[^,\s;&]+`)
)

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

			sanitizer, err := newExplainEventSanitizer(cfg)
			if err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			lookup, err := lookupExplainEvent(logPath, args[0], sanitizer)
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

func lookupExplainEvent(path, id string, sanitizer explainEventSanitizer) (explainEventLookup, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return explainEventLookup{}, fmt.Errorf("open audit log %s: %w", cleanPath, err)
	}
	defer func() {
		_ = f.Close()
	}()
	return scanExplainEventWithSanitizer(f, strings.TrimSpace(id), sanitizer)
}

func scanExplainEvent(r io.Reader, id string) (explainEventLookup, error) {
	sanitizer, err := newExplainEventSanitizer(nil)
	if err != nil {
		return explainEventLookup{}, err
	}
	return scanExplainEventWithSanitizer(r, id, sanitizer)
}

func scanExplainEventWithSanitizer(r io.Reader, id string, sanitizer explainEventSanitizer) (explainEventLookup, error) {
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
		if eventFieldString(raw, explainEventIDRequest) == id {
			out.report = buildExplainEventReport(raw, id, explainEventIDRequest, sanitizer)
			out.found = true
			return out, nil
		}
		matchedField := matchedExplainEventFallbackID(raw, id)
		if matchedField == "" {
			continue
		}
		if out.found {
			continue
		}
		out.report = buildExplainEventReport(raw, id, matchedField, sanitizer)
		out.found = true
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

func matchedExplainEventFallbackID(raw map[string]any, id string) string {
	for _, field := range []string{explainEventIDEvent, explainEventIDGeneric, "action_id", "defer_id"} {
		if eventFieldString(raw, field) == id {
			return field
		}
	}
	return ""
}

func buildExplainEventReport(raw map[string]any, id, matchedField string, sanitizer explainEventSanitizer) explainEventReport {
	eventName := eventFieldString(raw, "event")
	reason := firstEventField(raw, "reason", "pattern")
	scannerName := firstEventField(raw, "scanner", "layer")
	target := firstEventField(raw, "url", "target", "resource", "endpoint", "tool", "session")
	report := explainEventReport{
		ID:              id,
		MatchedField:    matchedField,
		Time:            sanitizer.field(eventFieldString(raw, "time")),
		Event:           sanitizer.field(eventName),
		Outcome:         explainEventOutcome(eventName, firstEventField(raw, "action", "verdict"), raw),
		Method:          sanitizer.field(eventFieldString(raw, "method")),
		Target:          sanitizer.target(target),
		TargetView:      explainEventTargetView(scannerName, reason, target, raw),
		Scanner:         sanitizer.field(scannerName),
		Layer:           sanitizer.field(scannerName),
		PatternName:     sanitizer.field(explainEventPatternName(raw)),
		Reason:          sanitizer.field(reason),
		StatusCode:      sanitizer.field(eventFieldString(raw, "status_code")),
		RemediationHint: sanitizer.field(eventFieldString(raw, "remediation_hint")),
	}
	if report.RemediationHint == "" && scannerName != "" {
		report.RemediationHint = sanitizer.field(scanner.OperatorHintForResult(scannerName, reason))
	}
	for _, note := range explainEventOutcomeNotes(raw, report.Outcome) {
		report.Notes = append(report.Notes, sanitizer.field(note))
	}
	return report
}

func explainEventOutcome(eventName, action string, raw map[string]any) string {
	if eventName == explainEventOutcomeBlocked || action == config.ActionBlock {
		return explainEventOutcomeBlocked
	}
	if explainEventMalformedPartialEvidence(raw, eventName) {
		return ""
	}
	if explainEventPartialResponse(raw, eventName, action) {
		return explainEventOutcomePartial
	}
	switch {
	case eventName == explainEventOutcomeAllowed || action == config.ActionAllow || action == config.ActionForward || action == "ask:allow":
		return explainEventOutcomeAllowed
	case action == config.ActionWarn:
		return explainEventOutcomeWarned
	case action == config.ActionStrip || action == "ask:strip" || eventName == "shield_rewrite":
		return explainEventOutcomeModified
	default:
		return ""
	}
}

func explainEventMalformedPartialEvidence(raw map[string]any, eventName string) bool {
	if shieldValue, ok := raw["shield"]; ok {
		shieldFields, ok := shieldValue.(map[string]any)
		if !ok {
			return true
		}
		if partial, ok := shieldFields["partial"]; ok {
			if _, ok := partial.(bool); !ok {
				return true
			}
		}
		for _, field := range []string{"body_bytes", "scanned_bytes"} {
			if value, present := shieldFields[field]; present {
				n, ok := value.(float64)
				if !ok || n < 0 || n > 1<<53-1 || n != math.Trunc(n) {
					return true
				}
			}
		}
		body, bodyOK := shieldFields["body_bytes"].(float64)
		scanned, scannedOK := shieldFields["scanned_bytes"].(float64)
		if bodyOK && scannedOK && scanned > body {
			return true
		}
	}
	if eventName != "response_scan_exempt" {
		return false
	}
	if effect, ok := raw["effect"]; ok {
		_, ok := effect.(string)
		return !ok
	}
	return false
}

func explainEventPartialResponse(raw map[string]any, eventName, action string) bool {
	if nestedEventBool(raw, "shield", "partial") {
		return true
	}
	if strings.Contains(strings.ToLower(eventFieldString(raw, "effect")), "stream unscanned") {
		return true
	}
	return eventName == "anomaly" && action == "" &&
		strings.EqualFold(eventFieldString(raw, "scanner"), "shield_oversize_scan_head")
}

func explainEventOutcomeNotes(raw map[string]any, outcome string) []string {
	switch outcome {
	case explainEventOutcomeAllowed:
		if eventFieldString(raw, "action") == "ask:allow" {
			return []string{"an operator allowed the response after a finding; this is not a clean scan verdict"}
		}
		return nil
	case explainEventOutcomePartial:
		bodyBytes := nestedEventFieldString(raw, "shield", "body_bytes")
		scannedBytes := nestedEventFieldString(raw, "shield", "scanned_bytes")
		if bodyBytes != "" && scannedBytes != "" {
			return []string{fmt.Sprintf("response handling was partial: %s of %s recorded bytes were scanned; this is not a clean full-response verdict", scannedBytes, bodyBytes)}
		}
		return []string{"response handling was partial; this record does not establish that the full response was scanned"}
	case explainEventOutcomeWarned:
		return []string{"a finding was recorded with action warn; this event does not show a block"}
	case explainEventOutcomeModified:
		return []string{"response content was modified before forwarding; this is not a clean full-response verdict"}
	case "":
		return []string{"recorded outcome is unknown; fields shown are the available audit evidence"}
	default:
		return nil
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

func explainEventPatternName(raw map[string]any) string {
	if value := firstEventField(raw, "pattern_name", "pattern", "display_label"); value != "" {
		return value
	}
	values, ok := raw["patterns"].([]any)
	if !ok {
		return ""
	}
	patterns := make([]string, 0, len(values))
	for _, value := range values {
		pattern, ok := value.(string)
		if !ok || strings.TrimSpace(pattern) == "" {
			continue
		}
		patterns = append(patterns, strings.TrimSpace(pattern))
	}
	return strings.Join(patterns, ", ")
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

func nestedEventFieldString(raw map[string]any, parent, field string) string {
	v, ok := raw[parent].(map[string]any)
	if !ok {
		return ""
	}
	return eventFieldString(v, field)
}

func nestedEventBool(raw map[string]any, parent, field string) bool {
	v, ok := raw[parent].(map[string]any)
	if !ok {
		return false
	}
	b, ok := v[field].(bool)
	return ok && b
}

type explainEventSanitizer struct {
	scanner *scanner.Scanner
}

func newExplainEventSanitizer(cfg *config.Config) (explainEventSanitizer, error) {
	if cfg == nil {
		cfg = config.Defaults()
	}
	sc, err := scanner.New(cfg)
	if err != nil {
		return explainEventSanitizer{}, fmt.Errorf("create scanner: %w", err)
	}
	return explainEventSanitizer{scanner: sc}, nil
}

func (s explainEventSanitizer) clean(value string) bool {
	if value == "" {
		return true
	}
	return s.scanner.ScanTextForDLPQuiet(context.Background(), value).Clean
}

func (s explainEventSanitizer) field(value string) string {
	if explainEventAmbiguousCredentialText(value) {
		return explainEventRedacted
	}
	if !s.clean(value) {
		return explainEventRedacted
	}
	return escapeExplainEventTerminalControls(value)
}

func (s explainEventSanitizer) target(value string) string {
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") || strings.ContainsAny(value, "?#") {
		if parsed, err := url.Parse(value); err == nil {
			parsed.User = nil
			parsed.Fragment = ""
			parsed.RawFragment = ""
			if parsed.RawQuery != "" {
				query := parsed.Query()
				for key := range query {
					if explainEventSecretQueryParam(key) {
						query.Set(key, explainEventRedactedValue)
					}
				}
				parsed.RawQuery = query.Encode()
			}
			value = parsed.String()
		}
	}
	value = receipt.SanitizeTarget(value, s.clean)
	if !s.clean(value) {
		return explainEventRedacted
	}
	return escapeExplainEventTerminalControls(value)
}

func explainEventAmbiguousCredentialText(value string) bool {
	return explainEventAuthorizationAssignmentRe.MatchString(value) ||
		explainEventBearerValueRe.MatchString(value) ||
		explainEventSecretAssignmentRe.MatchString(value)
}

func explainEventSecretQueryParam(key string) bool {
	normalized := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(key))
	if strings.Contains(normalized, "token") || strings.Contains(normalized, "credential") {
		return true
	}
	switch normalized {
	case "token", "access_token", "api_key", "apikey", "secret", "password", "passwd", "key",
		"auth", "authorization", "client_secret", "client_id", "sig", "signature", "code":
		return true
	default:
		return false
	}
}

func escapeExplainEventTerminalControls(value string) string {
	var b strings.Builder
	changed := false
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			changed = true
			quoted := strconv.QuoteToASCII(string(r))
			b.WriteString(strings.Trim(quoted, `"`))
			continue
		}
		b.WriteRune(r)
	}
	if !changed {
		return value
	}
	return b.String()
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
