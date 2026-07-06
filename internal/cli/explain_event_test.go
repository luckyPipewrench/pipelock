// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestExplainEventCmd_LooksUpBlockedRequestID(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	line := `{"level":"warn","time":"2026-07-06T01:02:03Z","event":"blocked","method":"GET","url":"https://api.vendor.example/path?sig=abc","request_id":"req-123","scanner":"entropy","reason":"high entropy query param \"sig\"","remediation_hint":"Add a narrow query entropy exemption."}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	out, err := runExplainCmd(t, "event", "req-123", "--log", logPath)
	if err != nil {
		t.Fatalf("explain event failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"Pipelock Explain Event",
		"Verdict: BLOCKED",
		"Scanner: entropy",
		"View:    url_query",
		"Why:     high entropy query param \"sig\"",
		"Add a narrow query entropy exemption.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestExplainEventCmd_JSONFallbackRemediation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	line := `{"event":"blocked","request_id":"req-456","url":"https://api.vendor.example/?token=redacted","scanner":"dlp","reason":"DLP match: test (critical)"}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	out, err := runExplainCmd(t, "event", "req-456", "--log", logPath, "--json")
	if err != nil {
		t.Fatalf("explain event JSON failed: %v\n%s", err, out)
	}
	var report explainEventReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, out)
	}
	if report.RemediationHint == "" {
		t.Fatalf("expected fallback remediation hint: %+v", report)
	}
	if report.Scanner != scanner.ScannerDLP {
		t.Fatalf("scanner = %q, want %q", report.Scanner, scanner.ScannerDLP)
	}
}

func TestExplainEventCmd_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		logBody string
		wantErr string
	}{
		{
			name:    "missing log flag",
			args:    []string{"event", "req-1"},
			wantErr: "audit log path required",
		},
		{
			name:    "not found",
			args:    []string{"event", "req-missing"},
			logBody: `{"event":"allowed","request_id":"req-present"}` + "\n",
			wantErr: "not found",
		},
		{
			name:    "empty id",
			args:    []string{"event", " "},
			logBody: `{"event":"allowed","request_id":"req-present"}` + "\n",
			wantErr: "event id cannot be empty",
		},
		{
			name:    "malformed skipped then found",
			args:    []string{"event", "req-ok"},
			logBody: "{not-json}\n" + `{"event":"allowed","request_id":"req-ok","status_code":200}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string(nil), tt.args...)
			if tt.logBody != "" {
				logPath := filepath.Join(t.TempDir(), "audit.log")
				if err := os.WriteFile(logPath, []byte(tt.logBody), 0o600); err != nil {
					t.Fatalf("write audit log: %v", err)
				}
				args = append(args, "--log", logPath)
			}
			out, err := runExplainCmd(t, args...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v\n%s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q\nout=%s", err, tt.wantErr, out)
			}
		})
	}
}

func TestScanExplainEvent_BoundaryLongLineFailsClosedAsSkipped(t *testing.T) {
	longLine := strings.Repeat("x", 1<<20+1)
	lookup, err := scanExplainEvent(strings.NewReader(longLine), "req-1")
	if err != nil {
		t.Fatalf("scanExplainEvent long line returned hard error: %v", err)
	}
	if lookup.found {
		t.Fatal("oversized malformed line must not match an event")
	}
	if lookup.skippedLines != 1 {
		t.Fatalf("skippedLines = %d, want 1", lookup.skippedLines)
	}
}

func TestQuickstartCmd_PrintsConcreteCommands(t *testing.T) {
	cmd := quickstartCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("quickstart failed: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"pipelock install /usr/local/bin/pipelock",
		"pipelock run --config configs/balanced.yaml",
		"export HTTPS_PROXY=http://127.0.0.1:8888",
		"pipelock mcp proxy --config configs/balanced.yaml",
		"pipelock status --config configs/balanced.yaml",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("quickstart output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "<") || strings.Contains(got, ">") {
		t.Fatalf("quickstart must not contain angle-bracket placeholders:\n%s", got)
	}
}
