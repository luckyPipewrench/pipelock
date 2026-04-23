// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseMCPFrame_RequestIDVariants(t *testing.T) {
	tests := []struct {
		name        string
		msg         string
		wantID      string
		wantMethod  string
		wantRequest bool
	}{
		{
			name:        "numeric id",
			msg:         `{"jsonrpc":"2.0","id":1,"method":"ping"}`,
			wantID:      `1`,
			wantMethod:  "ping",
			wantRequest: true,
		},
		{
			name:        "string id",
			msg:         `{"jsonrpc":"2.0","id":"req-42","method":"ping"}`,
			wantID:      `"req-42"`,
			wantMethod:  "ping",
			wantRequest: true,
		},
		{
			// Matches extractRPCID's historical normalisation: a
			// literal "null" id becomes nil, not json.RawMessage("null").
			// Callers that compare the raw ID bytes directly must not
			// see a divergent representation.
			name:        "null id is notification",
			msg:         `{"jsonrpc":"2.0","id":null,"method":"ping"}`,
			wantID:      ``,
			wantMethod:  "ping",
			wantRequest: false,
		},
		{
			name:        "missing id is notification",
			msg:         `{"jsonrpc":"2.0","method":"ping"}`,
			wantID:      ``,
			wantMethod:  "ping",
			wantRequest: false,
		},
		{
			name:        "zero numeric id",
			msg:         `{"jsonrpc":"2.0","id":0,"method":"ping"}`,
			wantID:      `0`,
			wantMethod:  "ping",
			wantRequest: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := ParseMCPFrame([]byte(tt.msg))
			if frame.ParseErr != nil {
				t.Fatalf("ParseErr = %v, want nil", frame.ParseErr)
			}
			if got := string(frame.ID); got != tt.wantID {
				t.Errorf("ID = %q, want %q", got, tt.wantID)
			}
			if frame.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", frame.Method, tt.wantMethod)
			}
			if got := frame.IsRequest(); got != tt.wantRequest {
				t.Errorf("IsRequest() = %v, want %v", got, tt.wantRequest)
			}
		})
	}
}

func TestParseMCPFrame_ToolsCallExtraction(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://example.com"}}}`
	frame := ParseMCPFrame([]byte(msg))
	if frame.ParseErr != nil {
		t.Fatalf("ParseErr = %v", frame.ParseErr)
	}
	if !frame.IsToolsCall() {
		t.Error("IsToolsCall() = false, want true")
	}
	if frame.ToolCallName != "fetch_url" {
		t.Errorf("ToolCallName = %q, want fetch_url", frame.ToolCallName)
	}
	if string(frame.Args) != `{"url":"https://example.com"}` {
		t.Errorf("Args = %q, want the arguments object", string(frame.Args))
	}
}

func TestParseMCPFrame_ToolsCallMissingArgs(t *testing.T) {
	// tools/call without "arguments" — Args must be nil (not a valid
	// empty RawMessage) so the downstream "no arguments" check passes.
	msg := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo"}}`
	frame := ParseMCPFrame([]byte(msg))
	if frame.ParseErr != nil {
		t.Fatalf("ParseErr = %v", frame.ParseErr)
	}
	if frame.ToolCallName != "echo" {
		t.Errorf("ToolCallName = %q, want echo", frame.ToolCallName)
	}
	if frame.Args != nil {
		t.Errorf("Args = %q, want nil when arguments absent", string(frame.Args))
	}
}

func TestParseMCPFrame_ToolsCallNullArgs(t *testing.T) {
	// tools/call with explicit "arguments": null — Args must be
	// normalised to nil rather than json.RawMessage("null"). This
	// mirrors extractToolCallArgs's historical behaviour so downstream
	// scanners don't treat the literal string "null" as user input.
	msg := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":null}}`
	frame := ParseMCPFrame([]byte(msg))
	if frame.ParseErr != nil {
		t.Fatalf("ParseErr = %v", frame.ParseErr)
	}
	if frame.ToolCallName != "echo" {
		t.Errorf("ToolCallName = %q, want echo", frame.ToolCallName)
	}
	if frame.Args != nil {
		t.Errorf("Args = %q, want nil for explicit null", string(frame.Args))
	}
}

func TestParseMCPFrame_ToolsCallMalformedParamsKeepsMethodAndID(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{
			name: "params array",
			msg:  `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":["not","object"]}`,
		},
		{
			name: "params string",
			msg:  `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":"not-object"}`,
		},
		{
			name: "non-string tool name",
			msg:  `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":42,"arguments":{"q":"x"}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := ParseMCPFrame([]byte(tt.msg))
			if frame.ParseErr != nil {
				t.Fatalf("ParseErr = %v, want nil", frame.ParseErr)
			}
			if frame.ID == nil {
				t.Fatal("ID = nil, want preserved request ID")
			}
			if frame.Method != methodToolsCall {
				t.Fatalf("Method = %q, want %q", frame.Method, methodToolsCall)
			}
			if frame.ToolCallName != "" {
				t.Errorf("ToolCallName = %q, want empty for malformed params", frame.ToolCallName)
			}
			if frame.Args != nil {
				t.Errorf("Args = %q, want nil for malformed params", string(frame.Args))
			}
		})
	}
}

func TestParseMCPFrame_InvalidMethodPreservesID(t *testing.T) {
	tests := []struct {
		name       string
		msg        string
		wantErrIs  error
		matchExact bool
	}{
		{
			name: "numeric method",
			msg:  `{"jsonrpc":"2.0","id":"client-id","method":42}`,
		},
		{
			name:       "null method",
			msg:        `{"jsonrpc":"2.0","id":"client-id","method":null}`,
			wantErrIs:  ErrInvalidMethodType,
			matchExact: true,
		},
		{
			name: "boolean method",
			msg:  `{"jsonrpc":"2.0","id":"client-id","method":true}`,
		},
		{
			name: "array method",
			msg:  `{"jsonrpc":"2.0","id":"client-id","method":["a","b"]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := ParseMCPFrame([]byte(tt.msg))
			if frame.ParseErr == nil {
				t.Fatal("ParseErr = nil, want error for non-string method")
			}
			if tt.matchExact && !errors.Is(frame.ParseErr, tt.wantErrIs) {
				t.Fatalf("ParseErr = %v, want errors.Is(%v)", frame.ParseErr, tt.wantErrIs)
			}
			if string(frame.ID) != `"client-id"` {
				t.Fatalf("ID = %q, want client ID preserved after second-pass failure", string(frame.ID))
			}
			if frame.Method != "" {
				t.Fatalf("Method = %q, want empty after invalid method", frame.Method)
			}
		})
	}
}

func TestParseMCPFrame_NonToolsCallLeavesToolFieldsEmpty(t *testing.T) {
	// tools/list and friends: ToolCallName and Args must stay zero so
	// callers can use empty-ness as the "not a tools/call" gate.
	tests := []string{
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"capabilities":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"notifications/progress","params":{"progressToken":"x"}}`,
	}
	for _, msg := range tests {
		frame := ParseMCPFrame([]byte(msg))
		if frame.ParseErr != nil {
			t.Errorf("unexpected ParseErr on %q: %v", msg, frame.ParseErr)
		}
		if frame.ToolCallName != "" {
			t.Errorf("ToolCallName on %q = %q, want empty", msg, frame.ToolCallName)
		}
		if frame.Args != nil {
			t.Errorf("Args on %q = %q, want nil", msg, string(frame.Args))
		}
		if frame.IsToolsCall() {
			t.Errorf("IsToolsCall() = true on non-tools/call %q", msg)
		}
	}
}

func TestParseMCPFrame_Batch(t *testing.T) {
	// Batch detection must fire on leading '[' even before any JSON
	// parse attempt. Batches are rejected unconditionally on the
	// inbound MCP path, so this is the first-class signal callers
	// short-circuit on.
	msg := `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`
	frame := ParseMCPFrame([]byte(msg))
	if !frame.IsBatch {
		t.Error("IsBatch = false, want true for '[' prefix")
	}
	// Method / ID are not extracted for batches (the caller short-circuits).
	if frame.Method != "" {
		t.Errorf("Method = %q, want empty for batch", frame.Method)
	}
	if frame.ID != nil {
		t.Errorf("ID = %q, want nil for batch", string(frame.ID))
	}
	// Leading whitespace before '[' must still trigger batch detection.
	frame = ParseMCPFrame([]byte("  \t\n[{}]"))
	if !frame.IsBatch {
		t.Error("IsBatch must strip leading whitespace")
	}
}

func TestParseMCPFrame_MalformedJSONSurfacesParseErr(t *testing.T) {
	// Missing closing brace. Callers must fail-closed on ParseErr.
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{`
	frame := ParseMCPFrame([]byte(msg))
	if frame.ParseErr == nil {
		t.Fatal("ParseErr = nil on malformed JSON, want error")
	}
	// Raw is preserved so a caller that wants to fall back to a
	// raw-bytes scan still has the original message.
	if !bytes.Equal(frame.Raw, []byte(msg)) {
		t.Error("Raw not preserved on parse error")
	}
	if frame.Method != "" {
		t.Errorf("Method = %q on parse error, want empty", frame.Method)
	}
	if frame.ToolCallName != "" {
		t.Errorf("ToolCallName = %q on parse error, want empty", frame.ToolCallName)
	}
}

func TestParseMCPFrame_EmptyAndNilInput(t *testing.T) {
	// Nil and empty-slice inputs must not panic.
	for _, msg := range [][]byte{nil, {}, []byte("   \t\n")} {
		frame := ParseMCPFrame(msg)
		if frame.ParseErr == nil && len(msg) > 0 {
			// Whitespace-only is not batch, is not parseable — should
			// surface the json.Unmarshal error.
			t.Errorf("whitespace-only input should surface ParseErr, got nil")
		}
		if frame.IsBatch {
			t.Errorf("IsBatch = true on %q, want false", string(msg))
		}
	}
}

func TestParseMCPFrame_ParityWithLegacyExtractors(t *testing.T) {
	// Sanity check: for every message variant a caller cares about,
	// ParseMCPFrame returns the same ID / tool name / args as the
	// legacy extract* helpers did. If this ever drifts, the migration
	// in commit 2 would silently break callers that still route
	// through the old helpers during rollback.
	tests := []struct {
		name string
		msg  string
	}{
		{"tools/call with args", `{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"x"}}}`},
		{"tools/call no args", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}`},
		{"tools/list", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		{"null id", `{"jsonrpc":"2.0","id":null,"method":"ping"}`},
		{"response, no method", `{"jsonrpc":"2.0","id":9,"result":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := ParseMCPFrame([]byte(tt.msg))
			if frame.ParseErr != nil {
				t.Fatalf("ParseErr = %v", frame.ParseErr)
			}

			legacyID := extractRPCID([]byte(tt.msg))
			if string(frame.ID) != string(legacyID) {
				t.Errorf("ID drift: frame = %q, legacy = %q", string(frame.ID), string(legacyID))
			}

			legacyName := extractToolCallName([]byte(tt.msg))
			if frame.ToolCallName != legacyName {
				t.Errorf("ToolCallName drift: frame = %q, legacy = %q", frame.ToolCallName, legacyName)
			}

			legacyArgs := extractToolCallArgs([]byte(tt.msg))
			// The legacy helper returns "" when args are absent; Frame
			// returns nil. Normalise to the same thing for comparison.
			var frameArgs string
			if frame.Args != nil {
				frameArgs = string(frame.Args)
			}
			if frameArgs != legacyArgs {
				t.Errorf("Args drift: frame = %q, legacy = %q", frameArgs, legacyArgs)
			}
		})
	}
}
