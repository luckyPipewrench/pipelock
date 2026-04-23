// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

// MCPFrame is a structural parse of a JSON-RPC 2.0 message
// received on an MCP transport. Callers that previously invoked
// extractRPCID, extractToolCallName, and extractToolCallArgs separately
// can read every field from the Frame instead.
//
// The zero value is a valid "nothing-parsed-yet" frame. Downstream
// callers must check ParseErr before trusting Method or ToolCallName:
// when ParseErr is non-nil the fields may be unset even if the
// underlying bytes contained recognisable substrings. Fail-closed on
// ParseErr — the existing input-scanner already does this via the
// onParseError knob, and the Frame preserves that contract by surfacing
// the error rather than swallowing it.
//
// Raw is retained so downstream scanning paths (ForwardScannedInput,
// scanHTTPInputDecision, ForwardScanned) that operate on the raw bytes
// (DLP scan, redaction rewrite, envelope injection) do not have to
// re-carry them separately.
type MCPFrame struct {
	// Raw is the original bytes as passed to ParseMCPFrame.
	Raw []byte

	// ID is the JSON-RPC "id" field, verbatim from the wire.
	//
	//  - nil when the "id" key is absent or explicitly null.
	//  - the raw numeric or string form otherwise (do not coerce; the
	//    wire format must flow through untouched for response
	//    correlation).
	ID json.RawMessage

	// Method is the JSON-RPC "method" field. Empty string for response
	// messages (no "method" key) and for any message that failed to
	// parse.
	Method string

	// ToolCallName is populated with params.name when Method is exactly
	// "tools/call". Empty otherwise so callers can use the empty-string
	// check as a "not a tools/call" gate without re-parsing.
	ToolCallName string

	// Args is the raw params.arguments JSON for tools/call messages.
	// nil for non-tools/call methods and when arguments are absent.
	// Kept as json.RawMessage so callers that need to re-emit the
	// arguments (redaction, envelope injection) can do so without
	// round-tripping through a typed value.
	Args json.RawMessage

	// IsBatch is true when Raw (after whitespace trimming) begins with
	// '[' — a JSON-RPC batch array. Batches are rejected unconditionally
	// on the inbound MCP path; callers short-circuit on this flag
	// before attempting field access.
	IsBatch bool

	// ParseErr is non-nil when json.Unmarshal failed on Raw. Most
	// fields are zero-valued in this case; Raw and IsBatch are still
	// populated because they derive from the bytes directly.
	ParseErr error
}

// IsRequest reports whether the frame carries a JSON-RPC request ID
// (numeric or string). Notifications (missing or null ID) return false.
// Responses with an ID also return true, so callers that need to
// distinguish requests from responses must check Method separately.
func (f MCPFrame) IsRequest() bool {
	return !isRPCNotification(f.ID)
}

// IsToolsCall reports whether this frame is a request for the MCP
// "tools/call" method. Saves the repeated `frame.Method == methodToolsCall`
// check at callsites.
func (f MCPFrame) IsToolsCall() bool {
	return f.Method == methodToolsCall
}

// ParseMCPFrame decodes msg into the fields needed by the MCP pipeline.
// The returned Frame is always usable: even on parse failure the caller
// gets back a populated Raw and a set ParseErr so fail-closed handling
// can run.
//
// This function is intentionally tolerant: it does not enforce the
// jsonrpc 2.0 marker or any other validation. Those are policy
// decisions the downstream scanner and policy engine make with their
// own fail-closed semantics. ParseMCPFrame only performs the structural
// extraction so every callsite sees the same fields without re-parsing.
func ParseMCPFrame(msg []byte) MCPFrame {
	frame := MCPFrame{Raw: msg}

	trimmed := bytes.TrimSpace(msg)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		frame.IsBatch = true
		return frame
	}

	// First pass: extract the ID only. This succeeds for any valid
	// JSON object even if method or params are the wrong type. Keeping
	// ID extraction resilient matters because the HTTP listener returns
	// an invalid-request response that must include the client's id
	// verbatim, even when the structural validator rejects the rest of
	// the message (e.g., non-string method).
	var idOnly struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(msg, &idOnly); err != nil {
		frame.ParseErr = err
		return frame
	}
	// Normalise the ID to match the legacy extractRPCID semantics: an
	// explicit "null" literal or an empty RawMessage becomes nil.
	if len(idOnly.ID) > 0 && string(idOnly.ID) != jsonrpc.Null {
		frame.ID = idOnly.ID
	}

	// Second pass: extract method and raw params. May fail when method is a
	// non-string; in that case the frame keeps the ID from the first pass
	// and surfaces ParseErr so downstream validators still fail closed.
	var decoded struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(msg, &decoded); err != nil {
		frame.ParseErr = err
		return frame
	}
	frame.Method = decoded.Method
	if decoded.Method == methodToolsCall {
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(decoded.Params, &params); err != nil {
			return frame
		}
		frame.ToolCallName = params.Name
		// Only retain a non-null, non-empty Arguments slice. A
		// json.RawMessage of "null" is non-nil in Go but semantically
		// absent; normalising to nil here lets callers rely on a plain
		// len() == 0 check without the jsonrpc.Null-literal dance.
		if len(params.Arguments) > 0 && string(params.Arguments) != jsonrpc.Null {
			frame.Args = params.Arguments
		}
	}
	return frame
}
