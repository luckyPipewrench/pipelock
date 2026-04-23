// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func TestApplyMCPToolCallRedaction_PreservesWhitespace(t *testing.T) {
	secret := mcpRedactionSecret()
	line := []byte("  " +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"prompt":"use ` +
		secret + ` to deploy"}}}` + "\n")

	rewritten, report, err := applyMCPToolCallRedaction(line, MCPProxyOpts{
		RedactMatcher: testRedactionMatcher(),
		RedactLimits:  redact.DefaultLimits().ToLimits(),
	})
	if err != nil {
		t.Fatalf("applyMCPToolCallRedaction: %v", err)
	}
	if !bytes.HasPrefix(rewritten, []byte("  ")) {
		t.Fatalf("rewritten line lost leading whitespace: %q", string(rewritten))
	}
	if !bytes.HasSuffix(rewritten, []byte("\n")) {
		t.Fatalf("rewritten line lost trailing newline: %q", string(rewritten))
	}
	if bytes.Contains(rewritten, []byte(secret)) {
		t.Fatalf("rewritten line leaked secret: %s", rewritten)
	}
	if !bytes.Contains(rewritten, []byte(mcpPlaceholderAWS)) {
		t.Fatalf("rewritten line missing placeholder: %s", rewritten)
	}
	if reportTotal(report) != 1 {
		t.Fatalf("report total = %d, want 1", reportTotal(report))
	}
}

func TestApplyMCPToolCallRedaction_NonToolsCallBypasses(t *testing.T) {
	line := []byte(" " + jsonToolsList + "\n")

	rewritten, report, err := applyMCPToolCallRedaction(line, MCPProxyOpts{
		RedactMatcher: testRedactionMatcher(),
		RedactLimits:  redact.DefaultLimits().ToLimits(),
	})
	if err != nil {
		t.Fatalf("applyMCPToolCallRedaction: %v", err)
	}
	if !bytes.Equal(rewritten, line) {
		t.Fatalf("non-tools/call message should pass through unchanged\ngot:  %q\nwant: %q", rewritten, line)
	}
	if report != nil {
		t.Fatalf("report should be nil for bypassed message, got %+v", report)
	}
}

func TestApplyMCPToolCallRedaction_MethodMustBeStringBypasses(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":{}}`)

	rewritten, report, err := applyMCPToolCallRedaction(line, MCPProxyOpts{
		RedactMatcher: testRedactionMatcher(),
		RedactLimits:  redact.DefaultLimits().ToLimits(),
	})
	if err != nil {
		t.Fatalf("applyMCPToolCallRedaction: %v", err)
	}
	if !bytes.Equal(rewritten, line) {
		t.Fatalf("non-string method should pass through unchanged\ngot:  %q\nwant: %q", rewritten, line)
	}
	if report != nil {
		t.Fatalf("report should be nil for bypassed malformed method, got %+v", report)
	}
}

func TestApplyMCPToolCallRedaction_MethodNullBypasses(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":null}`)

	rewritten, report, err := applyMCPToolCallRedaction(line, MCPProxyOpts{
		RedactMatcher: testRedactionMatcher(),
		RedactLimits:  redact.DefaultLimits().ToLimits(),
	})
	if err != nil {
		t.Fatalf("applyMCPToolCallRedaction: %v", err)
	}
	if !bytes.Equal(rewritten, line) {
		t.Fatalf("null method should pass through unchanged\ngot:  %q\nwant: %q", rewritten, line)
	}
	if report != nil {
		t.Fatalf("report should be nil for bypassed null method, got %+v", report)
	}
}

func TestApplyMCPToolCallRedaction_ToolsCallWithInvalidParamsBlocks(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"oops"}`)

	_, _, err := applyMCPToolCallRedaction(line, MCPProxyOpts{
		RedactMatcher: testRedactionMatcher(),
		RedactLimits:  redact.DefaultLimits().ToLimits(),
	})
	if err == nil {
		t.Fatal("expected block error")
	}
	var blockErr *redact.BlockError
	if !errors.As(err, &blockErr) {
		t.Fatalf("expected BlockError, got %T", err)
	}
	if blockErr.Reason != redact.ReasonBodyUnparseable {
		t.Fatalf("reason = %q, want %q", blockErr.Reason, redact.ReasonBodyUnparseable)
	}
}

func TestApplyMCPToolCallRedaction_RequiredWithoutMatcherBlocks(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"prompt":"hi"}}}`)

	_, _, err := applyMCPToolCallRedactionWithConfig(line, MCPRedactionConfig{
		Required: true,
	})
	if err == nil {
		t.Fatal("expected block error")
	}
	var blockErr *redact.BlockError
	if !errors.As(err, &blockErr) {
		t.Fatalf("expected BlockError, got %T", err)
	}
	if blockErr.Reason != redact.ReasonInternalError {
		t.Fatalf("reason = %q, want %q", blockErr.Reason, redact.ReasonInternalError)
	}
}

func TestApplyMCPToolCallRedaction_NoArgumentsBypasses(t *testing.T) {
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`)

	rewritten, report, err := applyMCPToolCallRedaction(line, MCPProxyOpts{
		RedactMatcher: testRedactionMatcher(),
		RedactLimits:  redact.DefaultLimits().ToLimits(),
	})
	if err != nil {
		t.Fatalf("applyMCPToolCallRedaction: %v", err)
	}
	if string(rewritten) != string(line) {
		t.Fatalf("tools/call without arguments should pass through unchanged\ngot:  %s\nwant: %s", rewritten, line)
	}
	if report != nil {
		t.Fatalf("report should be nil when arguments are absent, got %+v", report)
	}
}

func TestApplyMCPToolCallRedaction_InvalidArgumentsBypass(t *testing.T) {
	tests := []struct {
		name string
		line []byte
	}{
		{
			name: "null",
			line: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":null}}`),
		},
		{
			name: "string",
			line: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":"oops"}}`),
		},
		{
			name: "array",
			line: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":[]}}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rewritten, report, err := applyMCPToolCallRedaction(tt.line, MCPProxyOpts{
				RedactMatcher: testRedactionMatcher(),
				RedactLimits:  redact.DefaultLimits().ToLimits(),
			})
			if err != nil {
				t.Fatalf("applyMCPToolCallRedaction: %v", err)
			}
			if !bytes.Equal(rewritten, tt.line) {
				t.Fatalf("invalid arguments should pass through unchanged\ngot:  %s\nwant: %s", rewritten, tt.line)
			}
			if report != nil {
				t.Fatalf("report should be nil for invalid arguments, got %+v", report)
			}
		})
	}
}

func TestReportTotal(t *testing.T) {
	if got := reportTotal(nil); got != 0 {
		t.Fatalf("reportTotal(nil) = %d, want 0", got)
	}
	report := &redact.Report{
		Applied:         true,
		TotalRedactions: 2,
	}
	if got := reportTotal(report); got != 2 {
		t.Fatalf("reportTotal(report) = %d, want 2", got)
	}
	if strings.Contains(mcpPlaceholderAWS, " ") {
		t.Fatal("placeholder constant unexpectedly contains whitespace")
	}
}
