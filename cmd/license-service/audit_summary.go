//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/licenseservice"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const maxAuditSummaryLine = 1 << 20

var summaryEvents = map[string]bool{
	licenseservice.AuditWebhookReceived:        true,
	licenseservice.AuditLicenseIssued:          true,
	licenseservice.AuditEmailSent:              true,
	licenseservice.AuditEmailFailed:            true,
	licenseservice.AuditRefreshIssued:          true,
	licenseservice.AuditSubscriptionEnd:        true,
	licenseservice.AuditLicenseRevoked:         true,
	licenseservice.AuditIntermediateRevoked:    true,
	licenseservice.AuditIssuanceImported:       true,
	licenseservice.AuditFoundingCapHit:         true,
	licenseservice.AuditError:                  true,
	licenseservice.AuditEvalMinted:             true,
	licenseservice.AuditEvalRefundRevoked:      true,
	licenseservice.AuditTrialRefundRevoked:     true,
	licenseservice.AuditEvalRejected:           true,
	licenseservice.AuditTrialResendRequested:   true,
	licenseservice.AuditTrialRevokeRequested:   true,
	licenseservice.AuditTrialResent:            true,
	licenseservice.AuditTrialRevoked:           true,
	licenseservice.AuditLicenseResendRequested: true,
	licenseservice.AuditLicenseResent:          true,
	licenseservice.AuditLicenseResendThrottled: true,
}

type auditSummary struct {
	Since         string         `json:"since,omitempty"`
	Until         string         `json:"until,omitempty"`
	Total         int            `json:"total"`
	Counts        map[string]int `json:"counts"`
	UnknownEvents int            `json:"unknown_events"`
	ErrorEvents   int            `json:"error_events"`
}

func runAuditSummary(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit-summary", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	ledgerPath := fs.String("ledger", "", "existing audit JSONL path (required)")
	sinceValue := fs.String("since", "", "include entries at or after RFC3339 time")
	untilValue := fs.String("until", "", "exclude entries at or after RFC3339 time")
	format := fs.String("format", "text", "text or json")
	failOnErrors := fs.Bool("fail-on-errors", false, "exit nonzero when error or email_failed events occur")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Usage: license-service audit-summary --ledger PATH [options]")
		_, _ = fmt.Fprintln(fs.Output(), "Counts entries in an unsigned local ledger. An empty window does not establish service health.")
		_, _ = fmt.Fprintln(fs.Output(), "Each ledger line is limited to 1 MiB. For a torn tail, use a stable, complete copy of the ledger.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(out)
			fs.Usage()
			return nil
		}
		return fmt.Errorf("parse audit-summary options: %w", err)
	}
	if fs.NArg() != 0 || strings.TrimSpace(*ledgerPath) == "" {
		return errors.New("audit-summary requires --ledger and no positional arguments")
	}
	if *format != "text" && *format != "json" {
		return errors.New("audit-summary --format must be text or json")
	}
	since, err := parseSummaryTime("--since", *sinceValue)
	if err != nil {
		return err
	}
	until, err := parseSummaryTime("--until", *untilValue)
	if err != nil {
		return err
	}
	if !since.IsZero() && !until.IsZero() && !since.Before(until) {
		return errors.New("audit-summary --since must be before --until")
	}
	summary, err := readAuditSummary(*ledgerPath, since, until)
	if err != nil {
		return err
	}
	if *format == "json" {
		if err := json.NewEncoder(out).Encode(summary); err != nil {
			return fmt.Errorf("write audit summary: %w", err)
		}
	} else if err := writeAuditSummaryText(out, summary); err != nil {
		return fmt.Errorf("write audit summary: %w", err)
	}
	if *failOnErrors && summary.ErrorEvents > 0 {
		return errors.New("audit summary contains error events")
	}
	return nil
}

func parseSummaryTime(label, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("audit-summary %s must be RFC3339: %w", label, err)
	}
	return parsed.UTC(), nil
}

func readAuditSummary(path string, since, until time.Time) (auditSummary, error) {
	result := auditSummary{Counts: make(map[string]int)}
	if !since.IsZero() {
		result.Since = since.Format(time.RFC3339Nano)
	}
	if !until.IsZero() {
		result.Until = until.Format(time.RFC3339Nano)
	}
	cleanPath := filepath.Clean(path)
	info, err := os.Lstat(cleanPath)
	if err != nil {
		return result, fmt.Errorf("stat audit ledger: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("audit ledger must be a regular file")
	}
	file, err := os.Open(cleanPath) // #nosec G304 -- explicit operator-supplied offline ledger path
	if err != nil {
		return result, fmt.Errorf("open audit ledger: %w", err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return result, fmt.Errorf("stat opened audit ledger: %w", err)
	}
	if !opened.Mode().IsRegular() {
		return result, errors.New("opened audit ledger must be a regular file")
	}
	return summarizeAuditSnapshot(file, opened.Size(), since, until, result)
}

func summarizeAuditSnapshot(source io.Reader, size int64, since, until time.Time, result auditSummary) (auditSummary, error) {
	snapshot := &io.LimitedReader{R: source, N: size}
	reader := bufio.NewReaderSize(snapshot, maxAuditSummaryLine)
	for lineNumber := 1; ; lineNumber++ {
		line, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, io.EOF) && len(line) == 0 {
			if snapshot.N != 0 {
				return result, errors.New("audit ledger became shorter than its observed size; use a stable, complete copy")
			}
			break
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			return result, fmt.Errorf("audit ledger line %d exceeds size limit", lineNumber)
		}
		if errors.Is(readErr, io.EOF) {
			return result, fmt.Errorf("audit ledger line %d has a torn tail", lineNumber)
		}
		if readErr != nil {
			return result, fmt.Errorf("read audit ledger line %d: %w", lineNumber, readErr)
		}
		line = line[:len(line)-1]
		if len(line) == 0 {
			return result, fmt.Errorf("audit ledger line %d is blank", lineNumber)
		}
		if !json.Valid(line) {
			return result, fmt.Errorf("audit ledger line %d is malformed JSON", lineNumber)
		}
		if err := jsonscan.RejectDuplicateKeys(line); err != nil {
			return result, fmt.Errorf("audit ledger line %d has duplicate keys", lineNumber)
		}
		var entry licenseservice.AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return result, fmt.Errorf("audit ledger line %d is malformed", lineNumber)
		}
		if entry.Event == "" || entry.Timestamp.IsZero() {
			return result, fmt.Errorf("audit ledger line %d lacks event or timestamp", lineNumber)
		}
		if (!since.IsZero() && entry.Timestamp.Before(since)) || (!until.IsZero() && !entry.Timestamp.Before(until)) {
			continue
		}
		result.Total++
		if !summaryEvents[entry.Event] {
			result.UnknownEvents++
			continue
		}
		result.Counts[entry.Event]++
		if entry.Event == licenseservice.AuditError || entry.Event == licenseservice.AuditEmailFailed {
			result.ErrorEvents++
		}
	}
	return result, nil
}

func writeAuditSummaryText(out io.Writer, summary auditSummary) error {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "audit entries: %d\n", summary.Total)
	if summary.Since != "" {
		_, _ = fmt.Fprintf(&b, "since: %s\n", summary.Since)
	}
	if summary.Until != "" {
		_, _ = fmt.Fprintf(&b, "until: %s\n", summary.Until)
	}
	keys := make([]string, 0, len(summary.Counts))
	for key := range summary.Counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		_, _ = fmt.Fprintf(&b, "%s: %d\n", key, summary.Counts[key])
	}
	_, _ = fmt.Fprintf(&b, "unknown_events: %d\nerror_events: %d\n", summary.UnknownEvents, summary.ErrorEvents)
	_, err := io.WriteString(out, b.String())
	return err
}
