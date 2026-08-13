// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// ErrInvalidMethodType is surfaced via MCPFrame.ParseErr when a
// JSON-RPC message has a non-string "method" field (including the
// explicit JSON null literal). The HTTP listener's validateRPCStructure
// already rejects these before they reach the frame parser on that
// transport; the explicit error here fails closed on the stdio and
// HTTP upstream paths where no pre-validator runs.
var ErrInvalidMethodType = errors.New("mcp: method must be a string")

const methodPromptsGet = "prompts/get"

// MCPFrame is a structural parse of a JSON-RPC 2.0 message
// received on an MCP transport. Callers that previously invoked
// extractRPCID, extractToolCallName, and extractToolCallArgs separately
// can read every field from the Frame instead.
//
// The zero value is a valid "nothing-parsed-yet" frame. Downstream
// callers must check ParseErr before trusting Method or ToolCallName:
// when ParseErr is non-nil the fields may be unset even if the
// underlying bytes contained recognisable substrings. Fail-closed on
// ParseErr - the existing input-scanner already does this via the
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

	// RoutingName is the entity selected by methods whose 2026-07-28 HTTP
	// routing contract requires Mcp-Name. It is the tool name, resource URI, or
	// prompt name, depending on Method.
	RoutingName string
	// RoutingNamePresent distinguishes an absent body field from an explicitly
	// present empty string. RoutingNameErr records a non-string or malformed
	// params shape without turning otherwise valid legacy traffic into a global
	// parse failure. HTTP routing-header validation uses both fields to refuse a
	// header that has no trustworthy body value to mirror.
	RoutingNamePresent bool
	RoutingNameErr     error

	// ProtocolVersion and ClientCapabilitiesPresent come from the standard
	// request metadata added by protocol revision 2026-07-28. ClientInfo is
	// deliberately not retained because it is self-declared and is never an
	// authentication input.
	ProtocolVersion           string
	ProtocolVersionPresent    bool
	ClientCapabilitiesPresent bool

	// Args is the raw params.arguments JSON for tools/call messages.
	// nil for non-tools/call methods and when arguments are absent.
	// Kept as json.RawMessage so callers that need to re-emit the
	// arguments (redaction, envelope injection) can do so without
	// round-tripping through a typed value.
	Args json.RawMessage

	// IsBatch is true when Raw (after whitespace trimming) begins with
	// '[' - a JSON-RPC batch array. Batches are rejected unconditionally
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
	frame.ID = recoverTopLevelJSONRPCID(trimmed)

	// Fail closed on duplicate envelope keys before json.Unmarshal would
	// silently collapse them. A duplicate `method` would let an attacker
	// hide a tools/call behind a benign sibling that wins last-wins,
	// while upstream first-wins parsers still see the real attack.
	// ParseMCPFrame is the single entry point for HTTP + stdio input
	// gates, so blocking here covers the gate-evaluation path. external review C-1.
	// Only fail-closed on actual duplicate-key matches; let malformed-
	// JSON errors flow through to the existing structural parse path.
	if err := redact.NoDuplicateJSONKeys(trimmed); err != nil && redact.IsDuplicateKeyBlock(err) {
		frame.ParseErr = err
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
	// Method is read as json.RawMessage so we can distinguish three cases
	// the Go json package would otherwise conflate: absent (zero len),
	// explicit null literal (surfaces ErrInvalidMethodType per the
	// fail-closed default), and a real string.
	var decoded struct {
		Method json.RawMessage `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(msg, &decoded); err != nil {
		frame.ParseErr = err
		return frame
	}
	if len(decoded.Method) > 0 {
		if string(decoded.Method) == jsonrpc.Null {
			frame.ParseErr = ErrInvalidMethodType
			return frame
		}
		if err := json.Unmarshal(decoded.Method, &frame.Method); err != nil {
			frame.ParseErr = fmt.Errorf("%w: %w", ErrInvalidMethodType, err)
			return frame
		}
	}
	if frame.Method == methodToolsCall {
		var params struct {
			Name      json.RawMessage `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(decoded.Params, &params); err != nil {
			frame.RoutingNameErr = err
			frame.ParseErr = err
			return frame
		}
		if len(params.Name) > 0 {
			frame.RoutingNamePresent = true
			if err := json.Unmarshal(params.Name, &frame.RoutingName); err != nil {
				frame.RoutingNameErr = err
				frame.ParseErr = err
				return frame
			}
			frame.ToolCallName = frame.RoutingName
		}
		// Only retain a non-null, non-empty Arguments slice. A
		// json.RawMessage of "null" is non-nil in Go but semantically
		// absent; normalising to nil here lets callers rely on a plain
		// len() == 0 check without the jsonrpc.Null-literal dance.
		if len(params.Arguments) > 0 && string(params.Arguments) != jsonrpc.Null {
			frame.Args = params.Arguments
		}
	}
	if field := routingFieldForMethod(frame.Method); field != "" {
		var params map[string]json.RawMessage
		if err := json.Unmarshal(decoded.Params, &params); err != nil {
			frame.RoutingNameErr = err
			frame.ParseErr = err
			return frame
		}
		if raw, ok := params[field]; ok && len(raw) > 0 {
			frame.RoutingNamePresent = true
			if err := json.Unmarshal(raw, &frame.RoutingName); err != nil {
				frame.RoutingNameErr = err
				frame.ParseErr = err
				return frame
			}
		}
	}
	var paramsMeta struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(decoded.Params, &paramsMeta) == nil && paramsMeta.Meta != nil {
		if raw, ok := paramsMeta.Meta["io.modelcontextprotocol/protocolVersion"]; ok {
			// A JSON null unmarshals into a string without error and leaves it
			// empty, so success alone would mark a null version present. The flag
			// gates current-wire validation, so it must mean "a version string
			// arrived", not "the key was there".
			frame.ProtocolVersionPresent = json.Unmarshal(raw, &frame.ProtocolVersion) == nil && frame.ProtocolVersion != ""
		}
		if raw, ok := paramsMeta.Meta["io.modelcontextprotocol/clientCapabilities"]; ok {
			var capabilities map[string]json.RawMessage
			frame.ClientCapabilitiesPresent = json.Unmarshal(raw, &capabilities) == nil && capabilities != nil
		}
	}
	return frame
}

func routingFieldForMethod(method string) string {
	switch method {
	case methodResourcesRead:
		return "uri"
	case methodPromptsGet:
		return "name"
	default:
		return ""
	}
}

// recoverTopLevelJSONRPCID reads a top-level JSON-RPC id without requiring the
// whole frame to unmarshal successfully.
func recoverTopLevelJSONRPCID(msg []byte) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(msg))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil
		}
		if key == "id" {
			return readTopLevelIDValue(dec)
		}
		if err := skipTopLevelJSONValue(dec); err != nil {
			return nil
		}
	}
	return nil
}

// readTopLevelIDValue returns the next decoder value when it is a scalar
// JSON-RPC id type.
func readTopLevelIDValue(dec *json.Decoder) json.RawMessage {
	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	switch v := tok.(type) {
	case nil:
		return nil
	case string:
		data, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return data
	case json.Number:
		return json.RawMessage(v.String())
	case bool:
		data, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return data
	default:
		return nil
	}
}

// skipTopLevelJSONValue consumes the next JSON value from dec.
func skipTopLevelJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		for dec.More() {
			if _, err := dec.Token(); err != nil {
				return err
			}
			if err := skipTopLevelJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := skipTopLevelJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return nil
	}
}
