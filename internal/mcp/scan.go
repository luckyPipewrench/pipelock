// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package mcp provides scanning of MCP (Model Context Protocol) JSON-RPC 2.0
// responses for prompt injection and inbound generic credentials. It extracts
// text content from tool result blocks and runs the response and inbound-DLP
// scanners for pattern matching.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/provenance"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ResponseScanOptions carries per-server suppression context for stdio MCP
// response scanning. It mirrors GenericSSEScanOptions (the SSE transport) so
// the stdio transport reaches suppression parity: an operator can suppress a
// named response-scan pattern for a specific MCP server's responses without
// weakening scanning for any other server. The zero value preserves prior
// (no-suppression) behavior, so existing callers are unaffected.
type ResponseScanOptions struct {
	// Target identifies the MCP server's response surface for suppress-rule
	// matching, e.g. "mcp://code-assistant/response". Empty disables target-scoped
	// suppression (an empty target matches no path-scoped suppress entry).
	Target string
	// Suppress holds the operator's suppress rules (config Suppress list).
	Suppress []config.SuppressEntry
	// ActionOverride is the effective MCP response-scan action for this server.
	// Empty preserves scanner.ResponseAction() for diagnostic callers; the
	// runtime proxy sets this from the fail-closed trust class decision.
	ActionOverride string
	// TrustClass is the effective response trust class used for operator logs.
	// Empty is treated as untrusted.
	TrustClass string
}

// ScanResponse parses a single JSON-RPC 2.0 response and scans its text
// content for prompt injection and enforceable inbound DLP. Parse errors produce
// a verdict with Clean=false and the Error field set. Both result content and
// error messages are scanned. Server notifications (method+params, no id) are
// also scanned. Batch responses (JSON arrays) are detected and each element
// scanned individually.
func ScanResponse(line []byte, sc *scanner.Scanner) jsonrpc.ScanVerdict {
	return ScanResponseOpts(line, sc, ResponseScanOptions{})
}

// ScanResponseInjection parses an MCP response and scans only for prompt
// injection. Callers that separately scan outbound DLP with a contextual warn
// hook use this to avoid emitting an unscoped duplicate DLP warning.
func ScanResponseInjection(line []byte, sc *scanner.Scanner) jsonrpc.ScanVerdict {
	return scanResponseOpts(line, sc, ResponseScanOptions{}, false)
}

// ScanResponseOpts is ScanResponse with per-server suppression context. The
// stdio MCP forwarding path passes the server's Target and the operator's
// Suppress rules so a response-scan false positive can be remediated for one
// server without a global config change. ScanResponse delegates here with an
// empty options value (no suppression).
func ScanResponseOpts(line []byte, sc *scanner.Scanner, opts ResponseScanOptions) jsonrpc.ScanVerdict {
	return scanResponseOpts(line, sc, opts, true)
}

func scanResponseOpts(line []byte, sc *scanner.Scanner, opts ResponseScanOptions, includeDLP bool) jsonrpc.ScanVerdict {
	trimmed := bytes.TrimSpace(line)
	// Detect batch response (JSON-RPC 2.0 batch = JSON array).
	if len(trimmed) > 0 && trimmed[0] == '[' {
		verdict, _ := scanBatch(trimmed, sc, opts, includeDLP)
		return verdict
	}
	if err := redact.NoDuplicateJSONKeys(trimmed); err != nil && redact.IsDuplicateKeyBlock(err) {
		return jsonrpc.ScanVerdict{
			ID:    recoverTopLevelJSONRPCID(trimmed),
			Clean: false,
			Error: fmt.Sprintf("duplicate JSON object key: %v", err),
		}
	}

	var rpc jsonrpc.RPCResponse
	if err := json.Unmarshal(trimmed, &rpc); err != nil {
		return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonrpc.Version {
		return jsonrpc.ScanVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 response: jsonrpc=%q", rpc.JSONRPC),
		}
	}

	// Extract text from result (handles standard ToolResult and arbitrary shapes).
	textResult := jsonrpc.ExtractTextResult(rpc.Result)
	if textResult.Truncated {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
	}
	text := textResult.Text

	// Also scan error messages for prompt injection.
	// Attackers can inject via error.message and error.data returned by malicious
	// tool servers. Falls back to recursive string extraction for non-standard
	// error shapes (e.g., plain string error), matching the Result field pattern.
	if len(rpc.Error) > 0 && string(rpc.Error) != jsonrpc.Null {
		var rpcErr jsonrpc.RPCError
		if err := json.Unmarshal(rpc.Error, &rpcErr); err == nil && rpcErr.Message != "" {
			if text != "" {
				text += "\n"
			}
			text += rpcErr.Message
			// Also scan error.data if present.
			errData := jsonrpc.ExtractTextResult(rpcErr.Data)
			if errData.Truncated {
				return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
			}
			if errData.Text != "" {
				text += "\n" + errData.Text
			}
		} else {
			// Fallback: extract all strings from non-standard error shapes.
			errText := jsonrpc.ExtractTextResult(rpc.Error)
			if errText.Truncated {
				return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
			}
			if errText.Text != "" {
				if text != "" {
					text += "\n"
				}
				text += errText.Text
			}
		}
	}

	// Scan notification params for injection content.
	// MCP server notifications (method+params, no id) can carry payloads.
	if len(rpc.Params) > 0 && string(rpc.Params) != jsonrpc.Null {
		paramsText := jsonrpc.ExtractTextResult(rpc.Params)
		if paramsText.Truncated {
			return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
		}
		if paramsText.Text != "" {
			if text != "" {
				text += "\n"
			}
			text += paramsText.Text
		}
	}

	if text == "" {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}
	}

	result := sc.ScanResponseWithSuppress(context.Background(), text, opts.Target, opts.Suppress)
	var dlpMatches []scanner.TextDLPMatch
	if includeDLP {
		dlpMatches = scanner.EnforceableInboundTextDLPMatches(text, sc.ScanTextForDLPInbound(context.Background(), text).Matches)
	}
	if result.Clean && len(dlpMatches) == 0 {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}
	}

	return jsonrpc.ScanVerdict{
		ID:         rpc.ID,
		Clean:      false,
		Action:     responseScanAction(sc, opts),
		Matches:    result.Matches,
		DLPMatches: dlpMatches,
	}
}

// responseScanAction resolves the effective response-scan action. A per-server
// trust override may only make scanning stricter than the section action, never
// weaker, so the override is clamped against it rather than replacing it. The
// callers that build the override clamp it too; this is the enforcement-side
// backstop, and clamping twice is idempotent.
func responseScanAction(sc *scanner.Scanner, opts ResponseScanOptions) string {
	sectionAction := sc.ResponseAction()
	if opts.ActionOverride == "" {
		return sectionAction
	}
	return config.StricterAction(opts.ActionOverride, sectionAction)
}

func responseScanTrustClass(opts ResponseScanOptions) string {
	if opts.TrustClass != "" {
		return opts.TrustClass
	}
	return config.ResponseTrustUntrusted
}

// ScanResponseDispatch scans an MCP response the way ForwardScanned does, so a
// diagnostic caller (pipelock explain mcp-response) reports the same verdict the
// runtime proxy would. When tool scanning is enabled and the response is a
// tools/list payload, the tool-description fields are scanned by the dedicated
// tool scanner (not the injection scanner), so only the non-tool sibling fields
// go through response scanning here; otherwise the full response is scanned.
// Per-server suppression applies in both paths. ForwardScanned implements the
// equivalent dispatch inline (it computes isToolsList via tools.ScanTools, which
// also drives provenance/baseline side effects this read-only path omits).
func ScanResponseDispatch(line []byte, sc *scanner.Scanner, toolScanning bool, opts ResponseScanOptions) jsonrpc.ScanVerdict {
	if toolScanning && isToolsListResponse(line) {
		return scanToolsListNonToolFields(line, sc, opts)
	}
	return ScanResponseOpts(line, sc, opts)
}

// isToolsListResponse reports whether line is a JSON-RPC response whose result
// carries a non-empty "tools" array (the tools/list shape). It mirrors the
// shape detection in internal/mcp/tools (isToolsListResult); kept here as a
// lightweight check so the explain path need not run the full tool scanner.
func isToolsListResponse(line []byte) bool {
	var rpc jsonrpc.RPCResponse
	if json.Unmarshal(line, &rpc) != nil || len(rpc.Result) == 0 || string(rpc.Result) == jsonrpc.Null {
		return false
	}
	var probe struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(rpc.Result, &probe) != nil {
		return false
	}
	return len(probe.Tools) > 0
}

// scanToolsListNonToolFields scans a tools/list response for injection in
// non-tool fields (error, params, and any sibling keys in result besides "tools").
// Tool descriptions are scanned separately by the dedicated tool scanning
// subsystem (internal/mcp/tools), so injection scanning skips result.tools to
// avoid FPs from instructional text. Inbound DLP still scans result.tools:
// credential patterns do not share that instructional-text false-positive class.
// A malicious server can also inject into sibling fields like result.note or
// result.cursor, so those remain in both scan inputs.
func scanToolsListNonToolFields(line []byte, sc *scanner.Scanner, opts ResponseScanOptions) jsonrpc.ScanVerdict {
	trimmed := bytes.TrimSpace(line)
	if err := redact.NoDuplicateJSONKeys(trimmed); err != nil && redact.IsDuplicateKeyBlock(err) {
		return jsonrpc.ScanVerdict{
			ID:    recoverTopLevelJSONRPCID(trimmed),
			Clean: false,
			Error: fmt.Sprintf("duplicate JSON object key: %v", err),
		}
	}

	var rpc jsonrpc.RPCResponse
	if err := json.Unmarshal(trimmed, &rpc); err != nil {
		return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonrpc.Version {
		return jsonrpc.ScanVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 response: jsonrpc=%q", rpc.JSONRPC),
		}
	}

	var text, toolText string

	// Scan non-"tools" sibling fields in the result object.
	// A malicious server can include extra fields alongside tools[].
	// Keys are sorted for deterministic concatenation order.
	if len(rpc.Result) > 0 && string(rpc.Result) != jsonrpc.Null {
		var resultMap map[string]json.RawMessage
		if json.Unmarshal(rpc.Result, &resultMap) == nil {
			keys := make([]string, 0, len(resultMap))
			for k := range resultMap {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if key == "tools" {
					extracted := jsonrpc.ExtractTextResult(resultMap[key])
					if extracted.Truncated {
						return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
					}
					toolText = extracted.Text
					continue
				}
				siblingText := jsonrpc.ExtractTextResult(resultMap[key])
				if siblingText.Truncated {
					return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
				}
				if siblingText.Text != "" {
					if text != "" {
						text += "\n"
					}
					text += siblingText.Text
				}
			}
		}
	}

	// Scan error field (injection can hide in error messages).
	if len(rpc.Error) > 0 && string(rpc.Error) != jsonrpc.Null {
		var rpcErr jsonrpc.RPCError
		if err := json.Unmarshal(rpc.Error, &rpcErr); err == nil && rpcErr.Message != "" {
			if text != "" {
				text += "\n"
			}
			text += rpcErr.Message
			errData := jsonrpc.ExtractTextResult(rpcErr.Data)
			if errData.Truncated {
				return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
			}
			if errData.Text != "" {
				text += "\n" + errData.Text
			}
		} else {
			errText := jsonrpc.ExtractTextResult(rpc.Error)
			if errText.Truncated {
				return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
			}
			if errText.Text != "" {
				if text != "" {
					text += "\n"
				}
				text += errText.Text
			}
		}
	}

	// Scan params (server notifications can carry payloads).
	if len(rpc.Params) > 0 && string(rpc.Params) != jsonrpc.Null {
		paramsText := jsonrpc.ExtractTextResult(rpc.Params)
		if paramsText.Truncated {
			return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: false, Error: uninspectableJSONDepthReason}
		}
		if paramsText.Text != "" {
			if text != "" {
				text += "\n"
			}
			text += paramsText.Text
		}
	}

	dlpText := text
	if toolText != "" {
		if dlpText != "" {
			dlpText += "\n"
		}
		dlpText += toolText
	}

	if text == "" && dlpText == "" {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}
	}

	result := sc.ScanResponseWithSuppress(context.Background(), text, opts.Target, opts.Suppress)
	dlpMatches := scanner.EnforceableInboundTextDLPMatches(dlpText, sc.ScanTextForDLPInbound(context.Background(), dlpText).Matches)
	if result.Clean && len(dlpMatches) == 0 {
		return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}
	}

	return jsonrpc.ScanVerdict{
		ID:         rpc.ID,
		Clean:      false,
		Action:     responseScanAction(sc, opts),
		Matches:    result.Matches,
		DLPMatches: dlpMatches,
	}
}

// scanBatch scans a JSON-RPC 2.0 batch response (array of responses).
// Returns a combined verdict aggregating matches from all elements. The
// suppression options apply to every element so a per-server suppress rule
// covers batched responses too.
func scanBatch(line []byte, sc *scanner.Scanner, opts ResponseScanOptions, includeDLP bool) (jsonrpc.ScanVerdict, bool) {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON batch: %v", err)}, false
	}

	if len(batch) == 0 {
		return jsonrpc.ScanVerdict{Clean: true}, false
	}

	var allMatches []scanner.ResponseMatch
	var allDLPMatches []scanner.TextDLPMatch
	var firstID json.RawMessage
	var action string
	var hasError bool
	var firstError string

	for _, elem := range batch {
		v := scanResponseOpts(elem, sc, opts, includeDLP)
		if firstID == nil && len(v.ID) > 0 {
			firstID = v.ID
		}
		if v.Error != "" {
			hasError = true
			if firstError == "" {
				firstError = v.Error
			}
		}
		if !v.Clean && v.Error == "" {
			allMatches = append(allMatches, v.Matches...)
			allDLPMatches = append(allDLPMatches, v.DLPMatches...)
			if action == "" {
				action = v.Action
			}
		}
	}

	if hasError {
		return jsonrpc.ScanVerdict{ID: firstID, Clean: false, Error: firstError}, len(allMatches) > 0 || len(allDLPMatches) > 0
	}
	if len(allMatches) == 0 && len(allDLPMatches) == 0 {
		return jsonrpc.ScanVerdict{ID: firstID, Clean: true}, false
	}
	return jsonrpc.ScanVerdict{
		ID: firstID, Clean: false, Action: action, Matches: allMatches, DLPMatches: allDLPMatches,
	}, true
}

// ScanStream reads newline-delimited JSON-RPC 2.0 responses from r, scans each
// for prompt injection and enforceable inbound DLP, and writes results to w. In
// text mode, only errors and detections are written (clean lines are silent). In
// JSON mode, every scanned line produces an output object. Returns true if any
// security finding was detected. Parse errors are reported but do not count as a
// finding.
func ScanStream(r io.Reader, w io.Writer, sc *scanner.Scanner, jsonOutput bool) (bool, error) {
	found, _, err := ScanStreamResult(r, w, sc, jsonOutput)
	return found, err
}

// ScanStreamResult scans a stream and reports security findings and malformed
// input separately.
//
// The two are different answers and must not share one. A line this command
// could not fully inspect was not verified clean, so reporting it alongside
// verified-clean input tells a caller the opposite of the truth. Callers that
// gate on process status need to distinguish "nothing was found" from
// "something could not be looked at".
func ScanStreamResult(r io.Reader, w io.Writer, sc *scanner.Scanner, jsonOutput bool) (found, malformed bool, err error) {
	reader := bufio.NewReaderSize(r, 64*1024)

	foundFinding := false
	sawMalformed := false
	lineNum := 0

	for {
		raw, overLimit, readErr := readBoundedLine(reader, transport.MaxLineSize)
		if len(raw) == 0 && !overLimit && readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return foundFinding, sawMalformed, fmt.Errorf("reading input: %w", readErr)
		}
		lineNum++

		// An over-limit record was drained rather than ending the stream. Ending
		// it would let an upstream prepend one oversized record to stop every
		// later line from being inspected, which downgrades a real finding after
		// it into a bad-input result and destroys the exit-status distinction
		// this function exists to provide.
		if overLimit {
			sawMalformed = true
			verdict := jsonrpc.ScanVerdict{
				Line:    lineNum,
				Clean:   false,
				Error:   fmt.Sprintf("line exceeds the %d byte scan limit and was not inspected", transport.MaxLineSize),
				Scanned: scanVerdictScopes(),
			}
			if writeErr := emitVerdict(w, verdict, jsonOutput); writeErr != nil {
				return foundFinding, sawMalformed, writeErr
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return foundFinding, sawMalformed, fmt.Errorf("reading input: %w", readErr)
			}
			continue
		}

		line := strings.TrimSpace(string(raw))
		if line == "" {
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return foundFinding, sawMalformed, fmt.Errorf("reading input: %w", readErr)
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		verdict, lineFound := scanStreamResponse([]byte(line), sc)
		verdict.Line = lineNum
		verdict.Scanned = scanVerdictScopes()

		if verdict.Error != "" {
			sawMalformed = true
		}
		if lineFound {
			foundFinding = true
		}

		if writeErr := emitVerdict(w, verdict, jsonOutput); writeErr != nil {
			return foundFinding, sawMalformed, writeErr
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return foundFinding, sawMalformed, fmt.Errorf("reading input: %w", readErr)
		}
	}

	return foundFinding, sawMalformed, nil
}

// readBoundedLine reads one newline-terminated record, capped at limit bytes.
//
// A record longer than the cap is DRAINED to its newline and reported as
// over-limit, so the stream continues. bufio.Scanner cannot do this: it fails
// permanently on an over-long token, which would let one oversized record
// suppress inspection of everything after it.
//
// Returns the record without its newline, whether it exceeded the cap, and any
// read error. A final record without a trailing newline is returned with io.EOF.
func readBoundedLine(r *bufio.Reader, limit int) (line []byte, overLimit bool, err error) {
	var buf []byte
	// During accumulation the terminator has not necessarily arrived yet:
	// ReadSlice can hand back "\r" at the end of one fragment and "\n" at the
	// start of the next, so a per-fragment terminator test misclassifies a legal
	// CRLF record sitting exactly on the boundary. Accumulate against a two-byte
	// grace, which is the longest terminator, and make the exact decision once the
	// whole record is in hand. The grace bounds memory; the final check bounds the
	// record.
	const maxTerminator = 2
	for {
		chunk, readErr := r.ReadSlice('\n')
		if len(buf)+len(chunk) > limit+maxTerminator {
			overLimit = true
			// Keep draining to the newline so the next read starts at a record
			// boundary rather than mid-record.
			buf = nil
		} else if !overLimit {
			buf = append(buf, chunk...)
		}
		if errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		// The record is complete. Decide against its content length, with the
		// terminator removed, so LF and CRLF senders get the same maximum.
		record := trimTrailingNewline(buf)
		if !overLimit && len(record) > limit {
			overLimit = true
			record = nil
		}
		if readErr != nil {
			return record, overLimit, readErr
		}
		return record, overLimit, nil
	}
}

func trimTrailingNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

func emitVerdict(w io.Writer, verdict jsonrpc.ScanVerdict, jsonOutput bool) error {
	if !jsonOutput {
		return writeTextVerdict(w, verdict)
	}
	data, err := json.Marshal(verdict)
	if err != nil {
		return fmt.Errorf("marshaling verdict: %w", err)
	}
	data = append(data, '\n')
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing verdict: %w", err)
	}
	return nil
}

// scanStreamResponse returns the regular stream verdict and whether any
// successfully inspected batch element contained a security finding. A batch
// parse error still owns the public verdict so callers retain the existing
// fail-closed parse semantics, while the stream result preserves a sibling
// finding for its exit-status contract.
func scanStreamResponse(line []byte, sc *scanner.Scanner) (jsonrpc.ScanVerdict, bool) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return scanBatch(trimmed, sc, ResponseScanOptions{}, true)
	}

	verdict := ScanResponse(line, sc)
	return verdict, !verdict.Clean && verdict.Error == ""
}

func scanVerdictScopes() []string {
	return []string{jsonrpc.ScanScopeResponseInjection, jsonrpc.ScanScopeResponseDLP}
}

// A2AResponseOpts groups A2A-specific dependencies for response scanning.
// All fields are nil-safe: when nil, A2A response scanning is skipped.
type A2AResponseOpts struct {
	Cfg      *config.A2AScanning
	Baseline *CardBaseline
	// CardKey identifies the Agent Card origin for drift detection.
	// Used for GetExtendedAgentCard / agent/getAuthenticatedExtendedCard
	// responses and for card-shaped results when the method is unknown.
	CardKey cardCacheKey
	// Method is the JSON-RPC method from the corresponding request.
	// When non-empty, allows precise A2A response routing without
	// relying on response shape heuristics.
	Method string
	// ScanOpts is the per-server suppression context used when A2A
	// scanning is disabled or the response is ordinary MCP traffic.
	// The zero value preserves ScanResponse (no suppression) behavior.
	ScanOpts ResponseScanOptions
}

// ScanResponseA2A scans a JSON-RPC 2.0 response with optional A2A-aware
// routing. When a2aOpts is non-nil and the response matches an A2A method
// (by tracked method name or response shape), field-aware A2A scanning runs
// instead of generic text extraction. Falls back to ScanResponseOpts for
// non-A2A traffic or when A2A scanning is disabled so per-server suppression
// stays in effect on the generic path.
func ScanResponseA2A(line []byte, sc *scanner.Scanner, a2aOpts *A2AResponseOpts) jsonrpc.ScanVerdict {
	// Nil-safe: no A2A config means standard MCP scanning.
	if a2aOpts == nil || a2aOpts.Cfg == nil || !a2aOpts.Cfg.Enabled {
		return a2aFallbackScan(line, sc, a2aOpts)
	}

	// Route by tracked method name when available (most precise). Without
	// request correlation, only a complete Agent Card shape is specific enough
	// to use A2A scanning: ordinary MCP responses can also carry task-like
	// status and history fields, and must retain their response policy.
	isA2A := a2aOpts.Method != "" && IsA2AMethod(a2aOpts.Method)
	if !isA2A {
		isA2A = isAgentCardResultShape(line)
	}
	if isA2A {
		if verdict, batch := validateA2AResponseEnvelope(line); batch {
			return a2aFallbackScan(line, sc, a2aOpts)
		} else if !verdict.Clean {
			return verdict
		}
		return scanA2AResponseDispatch(line, sc, a2aOpts)
	}

	return a2aFallbackScan(line, sc, a2aOpts)
}

// validateA2AResponseEnvelope preserves the JSON-RPC gate shared by generic
// MCP response scanning before a field-aware A2A scanner handles the result.
// It reports a batch separately because ScanResponseOpts owns element-wise
// batch validation and routing.
func validateA2AResponseEnvelope(line []byte) (jsonrpc.ScanVerdict, bool) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return jsonrpc.ScanVerdict{}, true
	}
	if err := redact.NoDuplicateJSONKeys(trimmed); err != nil && redact.IsDuplicateKeyBlock(err) {
		return jsonrpc.ScanVerdict{
			ID:    recoverTopLevelJSONRPCID(trimmed),
			Clean: false,
			Error: fmt.Sprintf("duplicate JSON object key: %v", err),
		}, false
	}
	var rpc jsonrpc.RPCResponse
	if err := json.Unmarshal(trimmed, &rpc); err != nil {
		return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}, false
	}
	if rpc.JSONRPC != jsonrpc.Version {
		return jsonrpc.ScanVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 response: jsonrpc=%q", rpc.JSONRPC),
		}, false
	}
	return jsonrpc.ScanVerdict{ID: rpc.ID, Clean: true}, false
}

func a2aFallbackScan(line []byte, sc *scanner.Scanner, a2aOpts *A2AResponseOpts) jsonrpc.ScanVerdict {
	if a2aOpts == nil {
		return ScanResponseOpts(line, sc, ResponseScanOptions{})
	}
	return ScanResponseOpts(line, sc, a2aOpts.ScanOpts)
}

// scanA2AResponseDispatch routes an A2A response through the appropriate
// scanner based on method type and result shape. Card methods and card-shaped
// results always take the Agent Card path so signature and drift checks cannot
// be skipped by omitting a tracked method or by a case-folded method name.
func scanA2AResponseDispatch(line []byte, sc *scanner.Scanner, a2aOpts *A2AResponseOpts) jsonrpc.ScanVerdict {
	rpcID := extractRPCID(line)

	if isAgentCardMethod(a2aOpts.Method) || isAgentCardResultShape(line) {
		return scanAgentCardRPCResponse(line, sc, a2aOpts, rpcID)
	}

	// All other A2A methods: field-aware body scanning.
	result := ScanA2AResponseBody(context.Background(), line, sc, a2aOpts.Cfg)
	return a2aScanToVerdict(rpcID, result)
}

func scanAgentCardRPCResponse(line []byte, sc *scanner.Scanner, a2aOpts *A2AResponseOpts, rpcID json.RawMessage) jsonrpc.ScanVerdict {
	var rpc jsonrpc.RPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return jsonrpc.ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}
	// Scan error payloads: a malicious server can inject content via
	// error.message and error.data. Don't skip scanning just because
	// the response is an error instead of a result.
	if len(rpc.Error) > 0 && string(rpc.Error) != jsonrpc.Null {
		errResult := ScanA2AResponseBody(context.Background(), line, sc, a2aOpts.Cfg)
		return a2aScanToVerdict(rpcID, errResult)
	}
	if len(rpc.Result) == 0 || string(rpc.Result) == jsonrpc.Null {
		return jsonrpc.ScanVerdict{ID: rpcID, Clean: true}
	}
	cardResult := ScanAgentCard(
		context.Background(), rpc.Result, sc,
		a2aOpts.Baseline, a2aOpts.CardKey, a2aOpts.Cfg,
	)
	return agentCardToVerdict(rpcID, cardResult, a2aOpts.Cfg)
}

// isA2AResponseShape returns true if the JSON-RPC result object has fields
// characteristic of A2A protocol responses (task with status/artifacts/history,
// or an Agent Card shape with skills/supportedInterfaces).
func isA2AResponseShape(line []byte) bool {
	fields, ok := a2aResultObjectFields(line)
	if !ok {
		return false
	}
	return isA2ATaskFields(fields) || isAgentCardFields(fields)
}

func isAgentCardResultShape(line []byte) bool {
	fields, ok := a2aResultObjectFields(line)
	return ok && isAgentCardFields(fields)
}

func a2aResultObjectFields(line []byte) (map[string]json.RawMessage, bool) {
	var probe struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(line, &probe) != nil || len(probe.Result) == 0 {
		return nil, false
	}
	var resultFields map[string]json.RawMessage
	if json.Unmarshal(probe.Result, &resultFields) != nil {
		return nil, false
	}
	return resultFields, true
}

func isA2ATaskFields(resultFields map[string]json.RawMessage) bool {
	_, hasStatus := resultFields["status"]
	_, hasArtifacts := resultFields["artifacts"]
	_, hasHistory := resultFields["history"]
	return hasStatus && (hasArtifacts || hasHistory)
}

func isAgentCardFields(resultFields map[string]json.RawMessage) bool {
	_, hasSkills := resultFields["skills"]
	_, hasInterfaces := resultFields["supportedInterfaces"]
	return hasSkills && hasInterfaces
}

// a2aScanToVerdict converts an A2AScanResult into a jsonrpc.ScanVerdict
// for use in the standard response forwarding pipeline.
func a2aScanToVerdict(rpcID json.RawMessage, result A2AScanResult) jsonrpc.ScanVerdict {
	if result.Clean {
		return jsonrpc.ScanVerdict{ID: rpcID, Clean: true}
	}

	var matches []scanner.ResponseMatch
	// Promote injection findings directly.
	matches = append(matches, result.InjectFindings...)
	// Wrap URL findings as ResponseMatch for the verdict.
	for _, u := range result.URLFindings {
		matches = append(matches, scanner.ResponseMatch{
			PatternName: u.Reason,
		})
	}
	// Wrap DLP findings as ResponseMatch for the verdict.
	for _, d := range result.DLPFindings {
		matches = append(matches, scanner.ResponseMatch{
			PatternName: d.PatternName,
		})
	}
	if result.EntropyFinding != nil {
		matches = append(matches, scanner.ResponseMatch{
			PatternName: scanner.AuditBodyEntropy,
		})
	}

	return jsonrpc.ScanVerdict{
		ID:      rpcID,
		Clean:   false,
		Action:  result.Action,
		Matches: matches,
	}
}

// agentCardToVerdict converts an AgentCardScanResult into a jsonrpc.ScanVerdict.
func agentCardToVerdict(rpcID json.RawMessage, result AgentCardScanResult, cfg *config.A2AScanning) jsonrpc.ScanVerdict {
	if result.Clean {
		return jsonrpc.ScanVerdict{ID: rpcID, Clean: true}
	}

	action := result.Action
	if action == "" && cfg != nil {
		action = cfg.Action
	}

	var matches []scanner.ResponseMatch
	if result.BaselineCapacityExceeded {
		matches = append(matches, scanner.ResponseMatch{
			PatternName: "a2a_card_baseline_capacity",
		})
	}
	if result.DriftDetected {
		matches = append(matches, scanner.ResponseMatch{
			PatternName: "a2a_card_drift",
		})
	}
	// Include field-level findings from the card scan.
	verdict := a2aScanToVerdict(rpcID, result.Findings)
	matches = append(matches, verdict.Matches...)

	return jsonrpc.ScanVerdict{
		ID:      rpcID,
		Clean:   false,
		Action:  action,
		Matches: matches,
	}
}

// writeTextVerdict writes a human-readable verdict to w.
// Clean lines produce no output; only findings are reported.
func writeTextVerdict(w io.Writer, v jsonrpc.ScanVerdict) error {
	if v.Clean {
		return nil
	}

	if v.Error != "" {
		_, err := fmt.Fprintf(w, "line %d: [ERROR] %s\n", v.Line, v.Error) //nolint:gosec // G705: CLI output, not web
		return err
	}

	names := make([]string, 0, len(v.Matches)+len(v.DLPMatches))
	for _, m := range v.Matches {
		names = append(names, m.PatternName)
	}
	for _, m := range v.DLPMatches {
		names = append(names, m.PatternName)
	}
	kind := "INJECTION"
	if len(v.DLPMatches) > 0 {
		kind = "DLP"
		if len(v.Matches) > 0 {
			kind = "SECURITY FINDING"
		}
	}
	_, err := io.WriteString(w, fmt.Sprintf("line %d: [%s] %s (action: %s)\n", v.Line, kind, strings.Join(names, ", "), v.Action))
	return err
}

// ProvenanceVerdict holds the outcome of provenance verification on a
// tools/list response, including per-tool results for logging in warn mode.
type ProvenanceVerdict struct {
	// Block is true when the response should be blocked.
	Block bool
	// Action is the configured provenance action ("block" or "warn").
	Action string
	// Results contains per-tool verification outcomes.
	Results []provenance.VerificationResult
	// Error describes why blocking was triggered (empty when clean or warn-only).
	Error string
}

// VerifyToolsListProvenance runs cryptographic provenance verification on a
// tools/list response. It maps config.MCPToolProvenance to provenance.VerifyConfig,
// calls provenance.VerifyToolsList, and returns a ProvenanceVerdict.
//
// Returns a clean verdict (Block=false, nil Results) when cfg is nil or disabled.
// Parse errors and verification failures follow fail-closed semantics.
func VerifyToolsListProvenance(response []byte, cfg *config.MCPToolProvenance) ProvenanceVerdict {
	if cfg == nil || !cfg.Enabled {
		return ProvenanceVerdict{}
	}

	vcfg, err := mapProvenanceConfig(cfg)
	if err != nil {
		return ProvenanceVerdict{
			Block:  true,
			Action: cfg.Action,
			Error:  fmt.Sprintf("provenance config error: %v", err),
		}
	}

	results, err := provenance.VerifyToolsList(response, vcfg)
	if err != nil {
		// Fail closed: unparseable tools/list response blocks.
		return ProvenanceVerdict{
			Block:  true,
			Action: cfg.Action,
			Error:  fmt.Sprintf("provenance verification error: %v", err),
		}
	}

	if len(results) == 0 {
		// No tools in response - nothing to verify.
		return ProvenanceVerdict{
			Action:  cfg.Action,
			Results: results,
		}
	}

	shouldBlock, blockErr := provenance.ShouldBlock(results, cfg.Action)
	verdict := ProvenanceVerdict{
		Block:   shouldBlock,
		Action:  cfg.Action,
		Results: results,
	}
	if blockErr != nil {
		verdict.Error = blockErr.Error()
	}
	return verdict
}

// provenancePatternName is the pattern name used in ScanVerdict matches
// for provenance verification failures.
const provenancePatternName = "mcp_tool_provenance"

// ProvenanceVerdictToScanVerdict converts a ProvenanceVerdict into a
// jsonrpc.ScanVerdict for use in the standard response forwarding pipeline.
// The rpcID is extracted from the original response for correlation.
func ProvenanceVerdictToScanVerdict(pv ProvenanceVerdict, rpcID json.RawMessage) jsonrpc.ScanVerdict {
	if !pv.Block {
		return jsonrpc.ScanVerdict{ID: rpcID, Clean: true}
	}

	var matches []scanner.ResponseMatch
	for _, r := range pv.Results {
		if r.Status == provenance.StatusFailed || r.Status == provenance.StatusError ||
			(r.Status == provenance.StatusUnsigned && pv.Action == config.ActionBlock) {
			matches = append(matches, scanner.ResponseMatch{
				PatternName: provenancePatternName,
				MatchText:   fmt.Sprintf("%s: %s (%s)", r.ToolName, r.Status, r.Detail),
			})
		}
	}

	return jsonrpc.ScanVerdict{
		ID:      rpcID,
		Clean:   false,
		Action:  pv.Action,
		Matches: matches,
	}
}

// mapProvenanceConfig converts config.MCPToolProvenance to provenance.VerifyConfig.
// TrustedKeys are hex-encoded Ed25519 public keys; each is used as both the
// key ID and the decoded key value.
func mapProvenanceConfig(cfg *config.MCPToolProvenance) (provenance.VerifyConfig, error) {
	vcfg := provenance.VerifyConfig{
		Mode:        cfg.Mode,
		OfflineOnly: cfg.OfflineOnly,
	}

	if len(cfg.TrustedKeys) > 0 {
		vcfg.TrustedKeys = make(map[string]ed25519.PublicKey, len(cfg.TrustedKeys))
		for _, hexKey := range cfg.TrustedKeys {
			raw, err := hex.DecodeString(hexKey)
			if err != nil {
				return provenance.VerifyConfig{}, fmt.Errorf("decoding trusted key %q: %w", hexKey, err)
			}
			if len(raw) != ed25519.PublicKeySize {
				return provenance.VerifyConfig{}, fmt.Errorf(
					"trusted key %q: invalid length %d, want %d",
					hexKey, len(raw), ed25519.PublicKeySize,
				)
			}
			vcfg.TrustedKeys[hexKey] = ed25519.PublicKey(raw)
		}
	}

	return vcfg, nil
}
