// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"strings"
	"testing"
)

// dupkeyFakeAWSKey is split at build time so gosec G101 and the pipelock self-scan
// see no embedded credential shape. The test fixture targets pipelock's own
// AWS Access Key DLP pattern.
const dupkeyFakeAWSKey = "AKIA" + "IOSFODNN7EXAMPLE"

// TestParseMCPFrame_DuplicateMethodFailsClosed locks down the duplicate-key
// gate-evaluation path. The attacker payload pairs a
// secret-bearing tools/call with a benign duplicate `method`/`params`;
// Go's last-wins decode would otherwise route this as `ping` while a
// first-wins upstream parser still sees `tools/call` with the secret.
// ParseMCPFrame must fail closed on the duplicate before any structural
// parse runs.
func TestParseMCPFrame_DuplicateMethodFailsClosed(t *testing.T) {
	payload := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}},"method":"ping","params":{}}`, dupkeyFakeAWSKey))
	frame := ParseMCPFrame(payload)
	if frame.ParseErr == nil {
		t.Fatalf("expected ParseErr for duplicate method key, got nil; frame=%+v", frame)
	}
	if !strings.Contains(strings.ToLower(frame.ParseErr.Error()), "duplicate") {
		t.Fatalf("expected ParseErr to mention duplicate, got %v", frame.ParseErr)
	}
}

// TestParseMCPFrame_DuplicateParamsFailsClosed covers the same class
// at the params nesting level: a non-tools/call last-wins method paired
// with a tools/call-shaped params first-wins block.
func TestParseMCPFrame_DuplicateParamsFailsClosed(t *testing.T) {
	payload := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x","arguments":{"k":"v"}},"params":{"name":"y","arguments":{"k":%q}}}`, dupkeyFakeAWSKey))
	frame := ParseMCPFrame(payload)
	if frame.ParseErr == nil {
		t.Fatalf("expected ParseErr for duplicate params key, got nil; frame=%+v", frame)
	}
}

// TestApplyMCPToolCallRedaction_DuplicateMethodEnvelopeFailsClosed locks
// down the redaction-engine path. A duplicate-method envelope must not
// be forwarded as the (last-wins) non-tools/call shape; redaction has
// to fail closed at the envelope level before its own RewriteJSON guard.
func TestApplyMCPToolCallRedaction_DuplicateMethodEnvelopeFailsClosed(t *testing.T) {
	payload := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}},"method":"ping","params":{}}`, dupkeyFakeAWSKey))
	cfg := MCPRedactionConfig{Matcher: redactNewDefaultForParity(), Required: true}
	out, _, err := applyMCPToolCallRedactionWithConfig(payload, cfg)
	if err == nil {
		t.Fatalf("expected duplicate-key block, got nil and out=%q", string(out))
	}
	if !isDuplicateKeyBlock(err) {
		t.Fatalf("expected duplicate-key BlockError, got %v", err)
	}
}

// TestApplyMCPToolCallRedaction_DuplicateParamsFailsClosed covers the
// nested params variant.
func TestApplyMCPToolCallRedaction_DuplicateParamsFailsClosed(t *testing.T) {
	payload := []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x","arguments":{"k":"v"},"arguments":{"k":%q}}}`, dupkeyFakeAWSKey))
	cfg := MCPRedactionConfig{Matcher: redactNewDefaultForParity(), Required: true}
	out, _, err := applyMCPToolCallRedactionWithConfig(payload, cfg)
	if err == nil {
		t.Fatalf("expected duplicate-key block, got nil and out=%q", string(out))
	}
	if !isDuplicateKeyBlock(err) {
		t.Fatalf("expected duplicate-key BlockError, got %v", err)
	}
}
