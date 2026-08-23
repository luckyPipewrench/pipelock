// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

func TestNewAuthorityVerificationReasonFallback(t *testing.T) {
	t.Parallel()
	verification := NewAuthorityVerification("mcp_http", "invalid", "", "issuer", "reference", errors.New("invalid verifier result"))
	if verification.Transport != "mcp_http" || verification.Decision != "invalid" || verification.Reason != "invalid verifier result" || verification.Issuer != "issuer" || verification.Reference != "reference" {
		t.Fatalf("verification = %+v", verification)
	}
	preserved := NewAuthorityVerification("fetch", "deny", "action_mismatch", "", "", errors.New("ignored fallback"))
	if preserved.Reason != "action_mismatch" {
		t.Fatalf("reason = %q, want verifier reason", preserved.Reason)
	}
}

func TestLogAuthorityVerificationUsesValidatedIdentifierOnly(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger, err := New("json", "custom", "", true, true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.zl = logger.zl.Output(&buf)
	ctx, err := NewHTTPLogContext("GET", "https://service.example/path", "192.0.2.1", "req-1", "agent-a")
	if err != nil {
		t.Fatalf("NewHTTPLogContext: %v", err)
	}
	logger.LogAuthorityVerification(ctx, AuthorityVerification{
		Transport: "fetch",
		Decision:  "allow",
		Reason:    "matched",
		Issuer:    "issuer-a",
		Reference: "validated-ref-1",
	})

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry); err != nil {
		t.Fatalf("decode audit event: %v", err)
	}
	for key, want := range map[string]string{
		"event":     string(EventAuthorityVerification),
		"transport": "fetch",
		"action":    "allow",
		"decision":  "allow",
		"reason":    "matched",
		"issuer":    "issuer-a",
		"reference": "validated-ref-1",
	} {
		if got := entry[key]; got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
	if _, exists := entry["authority_ref"]; exists {
		t.Fatal("opaque authority_ref appeared in audit event")
	}
}

func TestLogAuthorityVerificationDenialExportsBlockAction(t *testing.T) {
	t.Parallel()
	logger, sink := newLoggerWithEmitter(t)
	defer logger.Close()
	logger.LogAuthorityVerification(NewMethodLogContext("MCP"), AuthorityVerification{
		Transport: "mcp-stdio",
		Decision:  "indeterminate",
		Reason:    "timeout",
	})
	event := sink.onlyEvent(t)
	if got := event.Fields["action"]; got != "block" {
		t.Fatalf("exported action = %v, want block", got)
	}
}

func TestLogAuthorityVerificationEmitsDecisionSeverity(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		decision string
		severity emit.Severity
	}{
		{decision: "allow", severity: emit.SeverityInfo},
		{decision: "deny", severity: emit.SeverityWarn},
	} {
		t.Run(tc.decision, func(t *testing.T) {
			logger, sink := newLoggerWithEmitter(t)
			defer logger.Close()
			logger.LogAuthorityVerification(NewMethodLogContext("MCP"), AuthorityVerification{
				Transport: "mcp-stdio",
				Decision:  tc.decision,
			})
			event := sink.onlyEvent(t)
			if event.Type != string(EventAuthorityVerification) || event.Severity != tc.severity {
				t.Fatalf("event type/severity = %q/%v, want %q/%v", event.Type, event.Severity, EventAuthorityVerification, tc.severity)
			}
		})
	}
}
