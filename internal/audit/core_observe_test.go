// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestLogCoreResponseObserved_NamesTheAuthorization pins what separates an
// operator-declared floor observation from an ordinary suppression. Ordinary
// suppression cannot reach the immutable core patterns at all, so an audit
// trail that rendered the two identically would leave an auditor unable to
// tell which approval allowed a core finding through, or when it lapses.
func TestLogCoreResponseObserved_NamesTheAuthorization(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New("json", "custom", "", true, true)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	logger.zl = logger.zl.Output(&buf)

	ctx, ctxErr := NewHTTPLogContext("GET", "https://docs.vendor.example/guide", "10.0.0.1", "req-7", "test-agent")
	if ctxErr != nil {
		t.Fatalf("NewHTTPLogContext: %v", ctxErr)
	}

	logger.LogCoreResponseObserved(ctx, "Prompt Injection", "forward", CoreObserveAuthorization{
		Host:    "docs.vendor.example",
		Reason:  "vendor security documentation",
		Owner:   "security-team",
		Expires: "2099-01-01",
	})

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("parse audit line %q: %v", buf.String(), err)
	}

	for field, want := range map[string]string{
		"pattern":         "Prompt Injection",
		"surface":         "forward",
		"reason":          "core_observed",
		"observe_host":    "docs.vendor.example",
		"observe_owner":   "security-team",
		"observe_expires": "2099-01-01",
		"observe_reason":  "vendor security documentation",
	} {
		if got, _ := entry[field].(string); got != want {
			t.Errorf("field %s = %q, want %q", field, got, want)
		}
	}
}

// TestLogCoreResponseObserved_OmitsAbsentAuthorizationFields proves the
// optional fields stay absent rather than emitting empty strings, so a
// downstream consumer can tell "not recorded" from "recorded as blank".
func TestLogCoreResponseObserved_OmitsAbsentAuthorizationFields(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New("json", "custom", "", true, true)
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}
	logger.zl = logger.zl.Output(&buf)

	ctx, ctxErr := NewHTTPLogContext("GET", "https://docs.vendor.example/guide", "10.0.0.1", "req-8", "test-agent")
	if ctxErr != nil {
		t.Fatalf("NewHTTPLogContext: %v", ctxErr)
	}

	logger.LogCoreResponseObserved(ctx, "Prompt Injection", "mcp_stdio", CoreObserveAuthorization{})

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("parse audit line %q: %v", buf.String(), err)
	}
	for _, field := range []string{"observe_host", "observe_owner", "observe_expires", "observe_reason"} {
		if _, present := entry[field]; present {
			t.Errorf("field %s was emitted despite being unset", field)
		}
	}
	// The classification must still be present, or the record is
	// indistinguishable from an ordinary suppression.
	if got, _ := entry["reason"].(string); got != "core_observed" {
		t.Errorf("reason = %q, want core_observed", got)
	}
}
