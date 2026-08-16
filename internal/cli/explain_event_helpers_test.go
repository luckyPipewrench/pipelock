// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestResolveExplainEventLogPathRejectsMissingFile(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.Logging.Output = config.DefaultLogOutput
	cfg.Logging.File = ""
	_, err := resolveExplainEventLogPath(cfg, "")
	if err == nil || !strings.Contains(err.Error(), "audit log path required") {
		t.Fatalf("missing log path err = %v", err)
	}

	got, err := resolveExplainEventLogPath(cfg, "/tmp/audit.log")
	if err != nil {
		t.Fatalf("explicit log path: %v", err)
	}
	if got != "/tmp/audit.log" {
		t.Fatalf("explicit path = %q", got)
	}

	cfg.Logging.Output = config.OutputFile
	cfg.Logging.File = "/var/log/pipelock/audit.log"
	got, err = resolveExplainEventLogPath(cfg, "")
	if err != nil {
		t.Fatalf("configured file output: %v", err)
	}
	if got != "/var/log/pipelock/audit.log" {
		t.Fatalf("configured path = %q", got)
	}
}

func TestExplainEventSecretQueryParam(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"token", "access-token", "api.key", "client_secret", "authorization", "session_credential"} {
		if !explainEventSecretQueryParam(key) {
			t.Fatalf("secret query key %q was not flagged", key)
		}
	}
	if explainEventSecretQueryParam("ref") || explainEventSecretQueryParam("page") {
		t.Fatal("benign query key was flagged as secret")
	}
}

func TestExplainEventAmbiguousCredentialText(t *testing.T) {
	t.Parallel()

	if !explainEventAmbiguousCredentialText("Authorization: Bearer abcdef") {
		t.Fatal("authorization assignment was not redacted")
	}
	if !explainEventAmbiguousCredentialText("api_key=abcdef") {
		t.Fatal("api_key assignment was not redacted")
	}
	if explainEventAmbiguousCredentialText("blocked private ip 10.0.0.1") {
		t.Fatal("plain block reason treated as a credential")
	}
}

func TestExplainEventSanitizerTargetRedactsSecretQuery(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	s, err := newExplainEventSanitizer(cfg)
	if err != nil {
		t.Fatalf("newExplainEventSanitizer: %v", err)
	}

	got := s.target("https://api.vendor.example/v1?page=2&access_token=abc&ref=ok")
	if strings.Contains(got, "abc") {
		t.Fatalf("secret query value leaked: %q", got)
	}
	if !strings.Contains(got, explainEventRedactedValue) && !strings.Contains(got, "%5Bredacted-value%5D") {
		t.Fatalf("secret query was not replaced: %q", got)
	}
	if !strings.Contains(got, "page=2") || !strings.Contains(got, "ref=ok") {
		t.Fatalf("benign query params were dropped: %q", got)
	}
	if s.target("") != "" {
		t.Fatal("empty target was rewritten")
	}
}

func TestEscapeExplainEventTerminalControls(t *testing.T) {
	t.Parallel()

	if got := escapeExplainEventTerminalControls("clean-host"); got != "clean-host" {
		t.Fatalf("clean = %q", got)
	}
	got := escapeExplainEventTerminalControls("bad\x1b[31mhost")
	if strings.Contains(got, "\x1b") {
		t.Fatalf("ESC survived: %q", got)
	}
	if got == "bad\x1b[31mhost" {
		t.Fatal("control runes were not escaped")
	}
}

func TestTerminalDisplayQuotesControls(t *testing.T) {
	t.Parallel()

	if got := terminalDisplay("plain"); got != "plain" {
		t.Fatalf("plain = %q", got)
	}
	if got := terminalDisplay("x\ny"); !strings.Contains(got, `\n`) {
		t.Fatalf("control display = %q, want quoted newline", got)
	}
	if needsTerminalQuoting("plain") {
		t.Fatal("plain text required quoting")
	}
	if !needsTerminalQuoting("x\ny") {
		t.Fatal("newline did not require quoting")
	}
}

func TestMatchedExplainEventFallbackID(t *testing.T) {
	t.Parallel()

	raw := map[string]any{"event_id": "evt-1", "action_id": "act-1", "defer_id": "def-1"}
	if got := matchedExplainEventFallbackID(raw, "evt-1"); got != explainEventIDEvent {
		t.Fatalf("event_id field = %q", got)
	}
	if got := matchedExplainEventFallbackID(raw, "act-1"); got != "action_id" {
		t.Fatalf("action_id field = %q", got)
	}
	if got := matchedExplainEventFallbackID(raw, "missing"); got != "" {
		t.Fatalf("unknown id = %q, want empty", got)
	}
}

func TestEventFieldStringTypes(t *testing.T) {
	t.Parallel()

	raw := map[string]any{
		"s":   "  hello  ",
		"n":   float64(42),
		"b":   true,
		"obj": map[string]any{"x": 1},
	}
	if got := eventFieldString(raw, "s"); got != "hello" {
		t.Fatalf("string = %q", got)
	}
	if got := eventFieldString(raw, "n"); got != "42" {
		t.Fatalf("number = %q", got)
	}
	if got := eventFieldString(raw, "b"); got != "true" {
		t.Fatalf("bool = %q", got)
	}
	if got := eventFieldString(raw, "obj"); got != "" {
		t.Fatalf("object = %q, want empty", got)
	}
	if got := eventFieldString(raw, "missing"); got != "" {
		t.Fatalf("missing = %q", got)
	}
	if got := firstEventField(raw, "missing", "s"); got != "hello" {
		t.Fatalf("firstEventField = %q", got)
	}
}

func TestExplainDisplayHostFallback(t *testing.T) {
	t.Parallel()

	if got := explainDisplayHost("https://api.vendor.example/v1"); got != "api.vendor.example" {
		t.Fatalf("url host = %q", got)
	}
	if got := explainDisplayHost("xn--nxasmq6b"); got != "xn--nxasmq6b" {
		t.Fatalf("punycode token = %q", got)
	}
	if got := explainDisplayHost("noperiod"); got != "" {
		t.Fatalf("bare token = %q, want empty", got)
	}
}

func TestPrintExplainEventReportAllowedWithoutReason(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	printExplainEventReport(&buf, explainEventReport{
		ID:           "req-1",
		MatchedField: explainEventIDRequest,
		Outcome:      explainEventOutcomeAllowed,
	})
	if !strings.Contains(buf.String(), "request completed without a blocking scanner verdict") {
		t.Fatalf("allowed fallback missing:\n%s", buf.String())
	}
}
