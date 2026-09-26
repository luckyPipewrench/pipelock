//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/licenseservice"
)

type brokenSummaryWriter struct{}

func (brokenSummaryWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func testSummaryLedger(t *testing.T, entries ...licenseservice.AuditEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ledger, err := licenseservice.OpenAuditLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := ledger.Log(entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAuditSummaryRealLedgerWindowAndPrivacy(t *testing.T) {
	date := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	path := testSummaryLedger(t,
		licenseservice.AuditEntry{Timestamp: date.Add(-time.Second), Event: licenseservice.AuditEmailFailed, CustomerEmail: "outside@example.com"},
		licenseservice.AuditEntry{Timestamp: date, Event: licenseservice.AuditLicenseIssued, CustomerEmail: "private@example.com", SubscriptionID: "sub_private", Detail: "private detail"},
		licenseservice.AuditEntry{Timestamp: date.Add(time.Hour), Event: licenseservice.AuditError, Error: "private error"},
		licenseservice.AuditEntry{Timestamp: date.Add(2 * time.Hour), Event: licenseservice.AuditEmailFailed, CustomerEmail: "failure@example.com"},
		licenseservice.AuditEntry{Timestamp: date.Add(3 * time.Hour), Event: "private@example.com"},
		licenseservice.AuditEntry{Timestamp: date.Add(24 * time.Hour), Event: licenseservice.AuditEmailSent},
	)
	before, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--ledger", path, "--since", date.Format(time.RFC3339), "--until", date.Add(24 * time.Hour).Format(time.RFC3339)}
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			if err := runAuditSummary(append(append([]string{}, args...), "--format", format), &out); err != nil {
				t.Fatal(err)
			}
			for _, sensitive := range []string{"private@example.com", "failure@example.com", "sub_private", "private detail", "private error"} {
				if strings.Contains(out.String(), sensitive) {
					t.Fatalf("aggregate leaked %q: %s", sensitive, out.String())
				}
			}
			if format == "json" {
				var got auditSummary
				if err := json.Unmarshal(out.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if got.Total != 4 || got.ErrorEvents != 2 || got.UnknownEvents != 1 || got.Counts[licenseservice.AuditLicenseIssued] != 1 {
					t.Fatalf("summary = %+v", got)
				}
			} else if !strings.Contains(out.String(), "error_events: 2") || !strings.Contains(out.String(), "unknown_events: 1") {
				t.Fatalf("text summary = %s", out.String())
			}
		})
	}
	var out bytes.Buffer
	if err := runAuditSummary(append(args, "--fail-on-errors"), &out); err == nil || !strings.Contains(err.Error(), "error events") || out.Len() == 0 {
		t.Fatalf("monitoring result = %v, output = %q", err, out.String())
	}
	after, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only summary modified source ledger")
	}
}

func TestAuditSummaryAllKnownAndEmpty(t *testing.T) {
	date := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	entries := make([]licenseservice.AuditEntry, 0, len(summaryEvents))
	for event := range summaryEvents {
		entries = append(entries, licenseservice.AuditEntry{Timestamp: date, Event: event})
	}
	path := testSummaryLedger(t, entries...)
	got, err := readAuditSummary(path, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != len(summaryEvents) || got.UnknownEvents != 0 || len(got.Counts) != len(summaryEvents) {
		t.Fatalf("all-category summary = %+v", got)
	}
	for event := range summaryEvents {
		if got.Counts[event] != 1 {
			t.Errorf("count %s = %d", event, got.Counts[event])
		}
	}
	if got.Counts[licenseservice.AuditError] != 1 || got.Counts[licenseservice.AuditEmailFailed] != 1 || got.ErrorEvents != 2 {
		t.Fatalf("error categories = %+v", got)
	}
	empty := testSummaryLedger(t)
	var textOutput bytes.Buffer
	if err := runAuditSummary([]string{"--ledger", empty}, &textOutput); err != nil || !strings.Contains(textOutput.String(), "audit entries: 0") {
		t.Fatalf("empty text report = %v, %q", err, textOutput.String())
	}
	got, err = readAuditSummary(empty, time.Time{}, time.Time{})
	if err != nil || got.Total != 0 || !reflect.DeepEqual(got.Counts, map[string]int{}) {
		t.Fatalf("empty summary = %+v, %v", got, err)
	}
}

func TestAuditSummaryEventConstantsMatchProducerSource(t *testing.T) {
	files, err := filepath.Glob("../../enterprise/licenseservice/*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no license-service producer source found")
	}
	produced := make(map[string]bool)
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			decl, ok := node.(*ast.GenDecl)
			if !ok || decl.Tok != token.CONST {
				return true
			}
			for _, spec := range decl.Specs {
				valueSpec, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range valueSpec.Names {
					if !strings.HasPrefix(name.Name, "Audit") || !name.IsExported() {
						continue
					}
					if i >= len(valueSpec.Values) {
						t.Errorf("%s has no explicit event value", name.Name)
						continue
					}
					literal, ok := valueSpec.Values[i].(*ast.BasicLit)
					if !ok || literal.Kind != token.STRING {
						t.Errorf("%s has unsupported event value", name.Name)
						continue
					}
					value, err := strconv.Unquote(literal.Value)
					if err != nil {
						t.Errorf("%s: %v", name.Name, err)
						continue
					}
					produced[value] = true
				}
			}
			return false
		})
	}
	if !reflect.DeepEqual(produced, summaryEvents) {
		t.Fatalf("producer event constants = %v; summary events = %v", produced, summaryEvents)
	}
}

func TestAuditSummarySnapshotByteBoundary(t *testing.T) {
	first := `{"ts":"2026-09-26T00:00:00Z","event":"license_issued"}` + "\n"
	appended := `{"ts":"2026-09-26T00:01:00Z","event":"error"}` + "\n"
	for _, tc := range []struct {
		name string
		size int64
		want string
	}{
		{"complete snapshot ignores later append", int64(len(first)), ""},
		{"partial snapshot rejects torn tail", int64(len(first) - 1), "torn tail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := summarizeAuditSnapshot(strings.NewReader(first+appended), tc.size, time.Time{}, time.Time{}, auditSummary{Counts: map[string]int{}})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("snapshot error = %v; want %q", err, tc.want)
				}
				return
			}
			if err != nil || got.Total != 1 || got.Counts[licenseservice.AuditLicenseIssued] != 1 || got.ErrorEvents != 0 {
				t.Fatalf("bounded snapshot = %+v, %v", got, err)
			}
		})
	}
}

func TestAuditSummaryTruncatedSnapshot(t *testing.T) {
	line := `{"ts":"2026-09-26T00:00:00Z","event":"license_issued"}` + "\n"
	for _, source := range []string{"", line} {
		_, err := summarizeAuditSnapshot(strings.NewReader(source), int64(len(line)*2), time.Time{}, time.Time{}, auditSummary{Counts: map[string]int{}})
		if err == nil || !strings.Contains(err.Error(), "shorter than its observed size") {
			t.Fatalf("truncated snapshot of %d bytes: got %v", len(source), err)
		}
	}
}

func TestDispatchAuditSummaryWithoutServiceEnvironment(t *testing.T) {
	clearLicenseServiceEnv(t)
	path := testSummaryLedger(t, licenseservice.AuditEntry{Event: licenseservice.AuditLicenseIssued})
	oldArgs, oldStdout := os.Args, os.Stdout
	t.Cleanup(func() { os.Args, os.Stdout = oldArgs, oldStdout })
	os.Args = []string{"license-service", "audit-summary", "--ledger", path, "--format", "json"}
	outputPath := filepath.Join(t.TempDir(), "output.json")
	output, err := os.OpenFile(filepath.Clean(outputPath), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close() })
	os.Stdout = output
	handled, err := dispatchAdmin(discardLog())
	if !handled || err != nil {
		t.Fatalf("offline dispatch = %v, %v", handled, err)
	}
	content, err := os.ReadFile(filepath.Clean(outputPath))
	if err != nil {
		t.Fatal(err)
	}
	var got auditSummary
	if err := json.Unmarshal(content, &got); err != nil || got.Total != 1 || got.Counts[licenseservice.AuditLicenseIssued] != 1 {
		t.Fatalf("offline dispatch report = %+v, %v", got, err)
	}
}

func TestAuditSummaryWriterErrorEventsAndFractionalWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ledger, err := licenseservice.OpenAuditLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.LogEmailFailed("sub_private", "private@example.com", errors.New("mailbox private")); err != nil {
		t.Fatal(err)
	}
	if err := ledger.LogError("sub_private", "private detail", errors.New("error private")); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runAuditSummary([]string{"--ledger", path, "--format", "json"}, &out); err != nil {
		t.Fatal(err)
	}
	var got auditSummary
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 2 || got.ErrorEvents != 2 || got.Counts[licenseservice.AuditError] != 1 || got.Counts[licenseservice.AuditEmailFailed] != 1 || strings.Contains(out.String(), "private") {
		t.Fatalf("writer-event summary = %+v, %q", got, out.String())
	}
	boundary := time.Date(2026, 9, 26, 0, 0, 0, 123456789, time.UTC)
	windowPath := testSummaryLedger(t, licenseservice.AuditEntry{Timestamp: boundary, Event: licenseservice.AuditLicenseIssued})
	out.Reset()
	if err := runAuditSummary([]string{"--ledger", windowPath, "--since", boundary.Format(time.RFC3339Nano), "--format", "json"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Since != boundary.Format(time.RFC3339Nano) || got.Total != 1 {
		t.Fatalf("fractional-window summary = %+v", got)
	}
}

func TestAuditSummaryRejectsBrokenEvidenceAndOptions(t *testing.T) {
	valid := `{"ts":"2026-09-26T00:00:00Z","event":"license_issued"}` + "\n"
	for _, tc := range []struct {
		name, content, want string
	}{
		{"malformed JSON", "{\n", "malformed"},
		{"missing timestamp", `{"event":"license_issued"}` + "\n", "lacks event or timestamp"},
		{"null timestamp", `{"ts":null,"event":"license_issued"}` + "\n", "lacks event or timestamp"},
		{"malformed timestamp", `{"ts":"yesterday","event":"license_issued"}` + "\n", "malformed"},
		{"missing event", `{"ts":"2026-09-26T00:00:00Z"}` + "\n", "lacks event or timestamp"},
		{"duplicate event", `{"ts":"2026-09-26T00:00:00Z","event":"error","event":"license_issued"}` + "\n", "duplicate keys"},
		{"blank line", valid + "\n", "blank"},
		{"torn tail", strings.TrimSuffix(valid, "\n"), "torn tail"},
		{"partial tail after valid", valid + "{", "torn tail"},
		{"malformed outside window", valid + "{\n", "malformed"},
		{"oversized line", strings.Repeat("x", maxAuditSummaryLine+1) + "\n", "size limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := runAuditSummary([]string{"--ledger", path, "--since", "2026-09-27T00:00:00Z"}, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) || out.Len() != 0 {
				t.Fatalf("error = %v, output = %q; want %q with no summary", err, out.String(), tc.want)
			}
		})
	}
	missing := filepath.Join(t.TempDir(), "missing.jsonl")
	nonregular := t.TempDir()
	for _, args := range [][]string{
		{},
		{"--ledger", missing},
		{"--ledger", nonregular},
		{"--ledger", missing, "--since", "bad"},
		{"--ledger", missing, "--until", "bad"},
		{"--ledger", missing, "--format", "yaml"},
		{"--ledger", missing, "--since", "2026-09-27T00:00:00Z", "--until", "2026-09-26T00:00:00Z"},
		{"--ledger", missing, "extra"},
	} {
		var out bytes.Buffer
		if err := runAuditSummary(args, &out); err == nil || out.Len() != 0 {
			t.Errorf("options %v: error = %v, output = %q", args, err, out.String())
		}
	}
	path := testSummaryLedger(t, licenseservice.AuditEntry{Timestamp: time.Now().UTC(), Event: licenseservice.AuditLicenseIssued})
	for _, format := range []string{"text", "json"} {
		err := runAuditSummary([]string{"--ledger", path, "--format", format}, brokenSummaryWriter{})
		if err == nil || !strings.Contains(err.Error(), "write audit summary") {
			t.Errorf("%s writer error = %v", format, err)
		}
	}
	for _, arg := range []string{"-h", "-help", "--help", "--help=true", "-h=1"} {
		var help bytes.Buffer
		if err := runAuditSummary([]string{arg}, &help); err != nil || !strings.Contains(help.String(), "-ledger") {
			t.Fatalf("offline help %s = %v, %q", arg, err, help.String())
		}
	}
}
