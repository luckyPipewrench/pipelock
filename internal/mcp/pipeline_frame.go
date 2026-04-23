// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

// MCPFrame is a single-pass structural parse of a JSON-RPC 2.0 message
// received on an MCP transport. Callers that previously invoked
// extractRPCID, extractToolCallName, and extractToolCallArgs separately
// (each re-running json.Unmarshal on the same bytes) can parse once and
// read every field from the Frame.
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
	//  - nil when the "id" key is absent (a notification).
	//  - json.RawMessage("null") for explicit-null IDs (also treated
	//    as notification per isRPCNotification).
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
// Responses (no Method) also return false — callers should check Method
// separately when they need to distinguish request from response.
func (f MCPFrame) IsRequest() bool {
	return !isRPCNotification(f.ID)
}

// IsToolsCall reports whether this frame is a request for the MCP
// "tools/call" method. Saves the repeated `frame.Method == methodToolsCall`
// check at callsites.
func (f MCPFrame) IsToolsCall() bool {
	return f.Method == methodToolsCall
}

// ParseMCPFrame decodes msg in a single pass. The returned Frame is
// always usable: even on parse failure the caller gets back a populated
// Raw and a set ParseErr so fail-closed handling can run.
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

	// Single struct captures every field any MCP call path needs.
	// Keeping this layout stable matters: adding optional fields here
	// is safe, removing or renaming them breaks every caller.
	var decoded struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(msg, &decoded); err != nil {
		frame.ParseErr = err
		return frame
	}

	// Normalise the ID to match the legacy extractRPCID semantics: an
	// explicit "null" literal or an empty RawMessage becomes nil. This
	// keeps downstream notification checks and direct ID comparisons
	// behaving identically during the migration off the legacy
	// extractors.
	if len(decoded.ID) > 0 && string(decoded.ID) != jsonrpc.Null {
		frame.ID = decoded.ID
	}
	frame.Method = decoded.Method
	if decoded.Method == methodToolsCall {
		frame.ToolCallName = decoded.Params.Name
		// Only retain a non-null, non-empty Arguments slice. A
		// json.RawMessage of "null" is non-nil in Go but semantically
		// absent; normalising to nil here lets callers rely on a plain
		// len() == 0 check without the jsonrpc.Null-literal dance.
		if len(decoded.Params.Arguments) > 0 && string(decoded.Params.Arguments) != jsonrpc.Null {
			frame.Args = decoded.Params.Arguments
		}
	}
	return frame
}
