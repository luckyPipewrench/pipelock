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

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestNewExplainEventSanitizerRejectsInvalidScannerConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:  "invalid",
		Regex: "[",
	})

	if _, err := newExplainEventSanitizer(cfg); err == nil || !strings.Contains(err.Error(), "create scanner") {
		t.Fatalf("newExplainEventSanitizer() error = %v, want create scanner error", err)
	}
}

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
	line := `{"event":"blocked","request_id":"req-456","url":"https://api.vendor.example/?ref=example","scanner":"dlp","reason":"DLP match: test (critical)"}` + "\n"
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

func TestExplainEventCmd_JSONFallbackRemediationUsesSanitizer(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	line := `{"event":"blocked","request_id":"req-sanitize-hint","url":"https://api.vendor.example/?ref=example","scanner":"dlp","reason":"DLP match: test (critical)"}` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	cfgPath := writeConfig(t, `
mode: balanced
dlp:
  patterns:
    - name: Fallback Hint Redaction Guard
      regex: "Add the destination host"
      severity: critical
`)

	out, err := runExplainCmd(t, "event", "req-sanitize-hint", "--config", cfgPath, "--log", logPath, "--json")
	if err != nil {
		t.Fatalf("explain event JSON failed: %v\n%s", err, out)
	}
	var report explainEventReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode JSON: %v\n%s", err, out)
	}
	if report.RemediationHint != explainEventRedacted {
		t.Fatalf("fallback remediation hint = %q, want %q", report.RemediationHint, explainEventRedacted)
	}
	if strings.Contains(out, "Add the destination host") {
		t.Fatalf("JSON output leaked unsanitized fallback hint:\n%s", out)
	}
}

func TestExplainEventCmd_RedactsSecretBearingAuditFields(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	secret := fakeExplainEventGitHubToken()
	line := map[string]any{
		"event":            "blocked",
		"request_id":       "req-secret",
		"url":              "https://user:pass@api.vendor.example/v1/keys?model=ok&token=" + secret + "#fragment",
		"scanner":          "dlp",
		"reason":           "DLP match leaked " + secret,
		"pattern_name":     secret,
		"remediation_hint": "rotate " + secret,
	}
	data, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal audit line: %v", err)
	}
	if err := os.WriteFile(logPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	out, err := runExplainCmd(t, "event", "req-secret", "--log", logPath)
	if err != nil {
		t.Fatalf("explain event failed: %v\n%s", err, out)
	}
	for _, leaked := range []string{secret, "user:pass", "#fragment"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("text output leaked %q:\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "[redacted") {
		t.Fatalf("text output did not show redaction marker:\n%s", out)
	}

	out, err = runExplainCmd(t, "event", "req-secret", "--log", logPath, "--json")
	if err != nil {
		t.Fatalf("explain event JSON failed: %v\n%s", err, out)
	}
	for _, leaked := range []string{secret, "user:pass", "#fragment"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("JSON output leaked %q:\n%s", leaked, out)
		}
	}
}

func TestExplainEventCmd_RedactsUsingActiveConfigDLPPatterns(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	cfgPath := writeConfig(t, `
mode: balanced
dlp:
  patterns:
    - name: Custom Audit Token
      regex: "custom-leak-[a-z]{8}"
      severity: critical
`)
	secret := "custom-leak-abcdefgh"
	line := map[string]any{
		"event":            "blocked",
		"request_id":       "req-custom-dlp",
		"url":              "https://api.vendor.example/callback?note=" + secret + "&state=public",
		"scanner":          "dlp",
		"reason":           "DLP match leaked " + secret,
		"display_label":    secret,
		"remediation_hint": "rotate " + secret,
	}
	data, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal audit line: %v", err)
	}
	if err := os.WriteFile(logPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	for _, args := range [][]string{
		{"event", "req-custom-dlp", "--config", cfgPath, "--log", logPath},
		{"event", "req-custom-dlp", "--config", cfgPath, "--log", logPath, "--json"},
	} {
		out, err := runExplainCmd(t, args...)
		if err != nil {
			t.Fatalf("explain event failed for args %v: %v\n%s", args, err, out)
		}
		if strings.Contains(out, secret) {
			t.Fatalf("output leaked active-config DLP value for args %v:\n%s", args, out)
		}
		if !strings.Contains(out, "state=public") {
			t.Fatalf("output should preserve non-sensitive query context for args %v:\n%s", args, out)
		}
	}
}

func TestExplainEventCmd_RedactsTokenFamilyQueryParams(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	refreshValue := "short-refresh-" + "value"
	idValue := "short-id-" + "value"
	line := map[string]any{
		"event":      "blocked",
		"request_id": "req-token-family",
		"url":        "https://api.vendor.example/oauth/callback?refresh_token=" + refreshValue + "&id_token=" + idValue + "&state=public",
		"scanner":    "allowlist",
		"reason":     "domain blocked",
	}
	data, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal audit line: %v", err)
	}
	if err := os.WriteFile(logPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	out, err := runExplainCmd(t, "event", "req-token-family", "--log", logPath)
	if err != nil {
		t.Fatalf("explain event failed: %v\n%s", err, out)
	}
	for _, leaked := range []string{refreshValue, idValue} {
		if strings.Contains(out, leaked) {
			t.Fatalf("text output leaked token-family query value %q:\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "state=public") {
		t.Fatalf("text output should preserve non-sensitive query context:\n%s", out)
	}

	out, err = runExplainCmd(t, "event", "req-token-family", "--log", logPath, "--json")
	if err != nil {
		t.Fatalf("explain event JSON failed: %v\n%s", err, out)
	}
	for _, leaked := range []string{refreshValue, idValue} {
		if strings.Contains(out, leaked) {
			t.Fatalf("JSON output leaked token-family query value %q:\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, "state=public") {
		t.Fatalf("JSON output should preserve non-sensitive query context:\n%s", out)
	}
}

func TestExplainEventCmd_RedactsShortAuthorizationBearerAssignments(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	privateValue := "short-" + "bearer-" + "value"
	line := map[string]any{
		"event":            "blocked",
		"request_id":       "req-short-bearer",
		"scanner":          "dlp",
		"reason":           "blocked upstream header Authorization: Bearer " + privateValue,
		"remediation_hint": "rotate Bearer " + privateValue,
	}
	data, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal audit line: %v", err)
	}
	if err := os.WriteFile(logPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	out, err := runExplainCmd(t, "event", "req-short-bearer", "--log", logPath)
	if err != nil {
		t.Fatalf("explain event failed: %v\n%s", err, out)
	}
	if strings.Contains(out, privateValue) {
		t.Fatalf("text output leaked short bearer value:\n%s", out)
	}

	out, err = runExplainCmd(t, "event", "req-short-bearer", "--log", logPath, "--json")
	if err != nil {
		t.Fatalf("explain event JSON failed: %v\n%s", err, out)
	}
	if strings.Contains(out, privateValue) {
		t.Fatalf("JSON output leaked short bearer value:\n%s", out)
	}
}

func TestExplainEventCmd_RedactsRelativeTargetSecretQueryParams(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	privateValue := "short-" + "access-" + "value"
	line := map[string]any{
		"event":      "blocked",
		"request_id": "req-relative-target",
		"target":     "/oauth/callback?access_token=" + privateValue + "&state=public",
		"scanner":    "allowlist",
		"reason":     "domain blocked",
	}
	data, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal audit line: %v", err)
	}
	if err := os.WriteFile(logPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	out, err := runExplainCmd(t, "event", "req-relative-target", "--log", logPath)
	if err != nil {
		t.Fatalf("explain event failed: %v\n%s", err, out)
	}
	if strings.Contains(out, privateValue) {
		t.Fatalf("text output leaked relative target query value:\n%s", out)
	}
	if !strings.Contains(out, "state=public") {
		t.Fatalf("text output should preserve non-sensitive query context:\n%s", out)
	}

	out, err = runExplainCmd(t, "event", "req-relative-target", "--log", logPath, "--json")
	if err != nil {
		t.Fatalf("explain event JSON failed: %v\n%s", err, out)
	}
	if strings.Contains(out, privateValue) {
		t.Fatalf("JSON output leaked relative target query value:\n%s", out)
	}
	if !strings.Contains(out, "state=public") {
		t.Fatalf("JSON output should preserve non-sensitive query context:\n%s", out)
	}
}

func TestExplainEventCmd_TextEscapesControlCharacters(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	line := map[string]any{
		"event":      "blocked",
		"request_id": "req-control",
		"scanner":    "dlp",
		"reason":     "real reason\nFAKE: allowed\r\x1b[31mred",
	}
	data, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal audit line: %v", err)
	}
	if err := os.WriteFile(logPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	out, err := runExplainCmd(t, "event", "req-control", "--log", logPath)
	if err != nil {
		t.Fatalf("explain event failed: %v\n%s", err, out)
	}
	for _, raw := range []string{"\nFAKE: allowed", "\r", "\x1b"} {
		if strings.Contains(out, raw) {
			t.Fatalf("text output contained raw control sequence %q:\n%q", raw, out)
		}
	}
	if !strings.Contains(out, `\nFAKE: allowed`) || !strings.Contains(out, `\x1b`) {
		t.Fatalf("text output did not render controls as escaped text:\n%q", out)
	}
}

func TestExplainEventCmd_JSONEscapesUnicodeFormatControls(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	line := map[string]any{
		"event":      "blocked",
		"request_id": "req-bidi",
		"scanner":    "dlp",
		"reason":     "blocked \u202Eallowed",
	}
	data, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("marshal audit line: %v", err)
	}
	if err := os.WriteFile(logPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}

	out, err := runExplainCmd(t, "event", "req-bidi", "--log", logPath, "--json")
	if err != nil {
		t.Fatalf("explain event JSON failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "\u202E") {
		t.Fatalf("JSON output contained raw Unicode format control:\n%q", out)
	}
	if !strings.Contains(out, `\u202e`) {
		t.Fatalf("JSON output did not render Unicode format control as escaped text:\n%q", out)
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
			name:    "unreadable log path",
			args:    []string{"event", "req-1", "--log", filepath.Join(t.TempDir(), "does-not-exist.log")},
			wantErr: "open audit log",
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

func TestScanExplainEvent_OversizedLineSkippedThenFound(t *testing.T) {
	longLine := strings.Repeat("x", 1<<20+1)
	body := longLine + "\n" + `{"event":"allowed","request_id":"req-after","status_code":200}` + "\n"
	lookup, err := scanExplainEvent(strings.NewReader(body), "req-after")
	if err != nil {
		t.Fatalf("scanExplainEvent returned error: %v", err)
	}
	if !lookup.found {
		t.Fatal("oversized malformed line must not hide later valid events")
	}
	if lookup.skippedLines != 1 {
		t.Fatalf("skippedLines = %d, want 1", lookup.skippedLines)
	}
}

func TestScanExplainEvent_PrefersRequestIDAcrossWholeLog(t *testing.T) {
	body := strings.Join([]string{
		`{"event":"blocked","event_id":"collision","scanner":"allowlist","reason":"wrong lower-priority event"}`,
		`{"event":"blocked","request_id":"collision","scanner":"dlp","reason":"right request event"}`,
		"",
	}, "\n")
	lookup, err := scanExplainEvent(strings.NewReader(body), "collision")
	if err != nil {
		t.Fatalf("scanExplainEvent returned error: %v", err)
	}
	if !lookup.found {
		t.Fatal("expected event match")
	}
	if lookup.report.MatchedField != explainEventIDRequest {
		t.Fatalf("matched field = %q, want %q", lookup.report.MatchedField, explainEventIDRequest)
	}
	if lookup.report.Reason != "right request event" {
		t.Fatalf("reason = %q, want request_id event", lookup.report.Reason)
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

func fakeExplainEventGitHubToken() string {
	return "ghp_" + strings.Repeat("A", 36)
}
