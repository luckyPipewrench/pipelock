// Package mcp provides scanning of MCP (Model Context Protocol) JSON-RPC 2.0
// responses for prompt injection. It extracts text content from tool result
// blocks and runs them through scanner.ScanResponse for pattern matching.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// jsonRPCVersion is the JSON-RPC protocol version used by MCP.
const jsonRPCVersion = "2.0"

// jsonNull is the JSON literal "null", used to detect nil-equivalent
// json.RawMessage values that are non-nil Go slices.
const jsonNull = "null"

// ContentBlock represents a single content block in an MCP tool result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolResult represents the result field of an MCP tool response.
type ToolResult struct {
	Content []ContentBlock `json:"content"`
}

// RPCError represents a JSON-RPC 2.0 error object.
// Data is optional per JSON-RPC 2.0 but can carry arbitrary content,
// so it must be scanned for injection like any other text field.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// RPCResponse represents a JSON-RPC 2.0 response envelope.
// Result is json.RawMessage (not *ToolResult) to handle non-standard result
// shapes without failing the entire parse — a typed *ToolResult would cause
// json.Unmarshal to error on string/array/non-object results, allowing bypass.
// Method and Params are included to scan server notifications for injection.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// ScanVerdict describes the outcome of scanning a single MCP response.
//
// Three states:
//   - Clean:     Clean=true, other fields zero/empty.
//   - Error:     Clean=false, Error set (parse/protocol failure). Not injection.
//   - Injection: Clean=false, Error empty, Matches and Action set.
type ScanVerdict struct {
	Line    int                     `json:"line"`
	ID      json.RawMessage         `json:"id"`
	Clean   bool                    `json:"clean"`
	Action  string                  `json:"action,omitempty"`
	Matches []scanner.ResponseMatch `json:"matches,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// ExtractText extracts all text content from an MCP tool result.
// First tries to parse as a standard ToolResult with content blocks (extracting
// text from ALL block types, not just "text" — prevents bypass via image blocks).
// Falls back to recursively extracting all string values from arbitrary JSON,
// preventing bypass via non-standard result shapes.
//
// Content blocks are joined with a single space to preserve word boundaries.
// Between-word splits ("previous" + "instructions") produce intact injections
// the agent will act on — scanner must detect these. Mid-word splits
// ("Igno" + "re" → "Igno re") don't match, but the injection is also broken
// for the agent, so this is not exploitable.
func ExtractText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == jsonNull {
		return ""
	}

	// Try standard ToolResult structure first.
	var tr ToolResult
	if err := json.Unmarshal(raw, &tr); err == nil && len(tr.Content) > 0 {
		var texts []string
		for _, block := range tr.Content {
			// Extract text from ALL content blocks, not just type=="text".
			// Non-text blocks (image, resource) may carry prompt injection
			// in their text field.
			if block.Text != "" {
				texts = append(texts, block.Text)
			}
		}
		if len(texts) > 0 {
			return strings.Join(texts, " ")
		}
	}

	// Fallback: recursively extract all string values from arbitrary JSON.
	// Catches non-standard result shapes (plain string, nested objects, etc).
	strs := extractStringsFromJSON(raw)
	if len(strs) > 0 {
		return strings.Join(strs, "\n")
	}

	return ""
}

// sortedKeys returns the keys of a map in sorted order. Used by JSON extraction
// functions to ensure deterministic iteration — Go map order is random, so
// split-secret concat scanning would miss secrets nondeterministically without
// stable ordering.
func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// extractStringsFromJSON recursively extracts all string values from arbitrary JSON.
// Only extracts values (not keys) to avoid false positives from field names.
func extractStringsFromJSON(raw json.RawMessage) []string {
	var result []string
	var extract func(v interface{})
	extract = func(v interface{}) {
		switch val := v.(type) {
		case string:
			result = append(result, val)
		case []interface{}:
			for _, item := range val {
				extract(item)
			}
		case map[string]interface{}:
			for _, k := range sortedKeys(val) {
				extract(val[k])
			}
		}
	}
	var parsed interface{}
	if err := json.Unmarshal(raw, &parsed); err == nil {
		extract(parsed)
	}
	return result
}

// ScanResponse parses a single JSON-RPC 2.0 response and scans its text
// content for prompt injection. Parse errors produce a verdict with Clean=false
// and the Error field set. Both result content and error messages are scanned.
// Server notifications (method+params, no id) are also scanned.
// Batch responses (JSON arrays) are detected and each element scanned individually.
func ScanResponse(line []byte, sc *scanner.Scanner) ScanVerdict {
	// Detect batch response (JSON-RPC 2.0 batch = JSON array).
	if len(line) > 0 && line[0] == '[' {
		return scanBatch(line, sc)
	}

	var rpc RPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonRPCVersion {
		return ScanVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 response: jsonrpc=%q", rpc.JSONRPC),
		}
	}

	// Extract text from result (handles standard ToolResult and arbitrary shapes).
	text := ExtractText(rpc.Result)

	// Also scan error messages for prompt injection.
	// Attackers can inject via error.message and error.data returned by malicious
	// tool servers. Falls back to recursive string extraction for non-standard
	// error shapes (e.g., plain string error), matching the Result field pattern.
	if len(rpc.Error) > 0 && string(rpc.Error) != jsonNull {
		var rpcErr RPCError
		if err := json.Unmarshal(rpc.Error, &rpcErr); err == nil && rpcErr.Message != "" {
			if text != "" {
				text += "\n"
			}
			text += rpcErr.Message
			// Also scan error.data if present.
			if errData := ExtractText(rpcErr.Data); errData != "" {
				text += "\n" + errData
			}
		} else {
			// Fallback: extract all strings from non-standard error shapes.
			if errText := ExtractText(rpc.Error); errText != "" {
				if text != "" {
					text += "\n"
				}
				text += errText
			}
		}
	}

	// Scan notification params for injection content.
	// MCP server notifications (method+params, no id) can carry payloads.
	if len(rpc.Params) > 0 && string(rpc.Params) != jsonNull {
		if paramsText := ExtractText(rpc.Params); paramsText != "" {
			if text != "" {
				text += "\n"
			}
			text += paramsText
		}
	}

	if text == "" {
		return ScanVerdict{ID: rpc.ID, Clean: true}
	}

	result := sc.ScanResponse(text)
	if result.Clean {
		return ScanVerdict{ID: rpc.ID, Clean: true}
	}

	return ScanVerdict{
		ID:      rpc.ID,
		Clean:   false,
		Action:  sc.ResponseAction(),
		Matches: result.Matches,
	}
}

// scanBatch scans a JSON-RPC 2.0 batch response (array of responses).
// Returns a combined verdict aggregating matches from all elements.
func scanBatch(line []byte, sc *scanner.Scanner) ScanVerdict {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return ScanVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON batch: %v", err)}
	}

	if len(batch) == 0 {
		return ScanVerdict{Clean: true}
	}

	var allMatches []scanner.ResponseMatch
	var firstID json.RawMessage
	var action string
	var hasError bool

	for _, elem := range batch {
		v := ScanResponse(elem, sc)
		if firstID == nil && len(v.ID) > 0 {
			firstID = v.ID
		}
		if v.Error != "" {
			hasError = true
		}
		if !v.Clean && v.Error == "" {
			allMatches = append(allMatches, v.Matches...)
			if action == "" {
				action = v.Action
			}
		}
	}

	if len(allMatches) == 0 {
		if hasError {
			return ScanVerdict{ID: firstID, Clean: false, Error: "one or more batch elements failed to parse"}
		}
		return ScanVerdict{ID: firstID, Clean: true}
	}
	return ScanVerdict{
		ID: firstID, Clean: false, Action: action, Matches: allMatches,
	}
}

// maxLineSize is the maximum line length for MCP responses (10 MB).
const maxLineSize = 10 * 1024 * 1024

// ScanStream reads newline-delimited JSON-RPC 2.0 responses from r, scans
// each for prompt injection, and writes results to w. In text mode, only
// errors and detections are written (clean lines are silent). In JSON mode,
// every scanned line produces an output object. Returns true if any injection
// was detected. Parse errors are reported but do not count as injection.
func ScanStream(r io.Reader, w io.Writer, sc *scanner.Scanner, jsonOutput bool) (bool, error) {
	lineScanner := bufio.NewScanner(r)
	lineScanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	foundInjection := false
	lineNum := 0

	for lineScanner.Scan() {
		lineNum++
		line := strings.TrimSpace(lineScanner.Text())
		if line == "" {
			continue
		}

		verdict := ScanResponse([]byte(line), sc)
		verdict.Line = lineNum

		if !verdict.Clean && verdict.Error == "" {
			foundInjection = true
		}

		if jsonOutput {
			data, err := json.Marshal(verdict)
			if err != nil {
				return foundInjection, fmt.Errorf("marshaling verdict: %w", err)
			}
			data = append(data, '\n')
			if _, err := w.Write(data); err != nil {
				return foundInjection, fmt.Errorf("writing verdict: %w", err)
			}
		} else {
			if err := writeTextVerdict(w, verdict); err != nil {
				return foundInjection, err
			}
		}
	}

	if err := lineScanner.Err(); err != nil {
		return foundInjection, fmt.Errorf("reading input: %w", err)
	}

	return foundInjection, nil
}

// writeTextVerdict writes a human-readable verdict to w.
// Clean lines produce no output; only findings are reported.
func writeTextVerdict(w io.Writer, v ScanVerdict) error {
	if v.Clean {
		return nil
	}

	if v.Error != "" {
		_, err := fmt.Fprintf(w, "line %d: [ERROR] %s\n", v.Line, v.Error) //nolint:gosec // G705: CLI output, not web
		return err
	}

	names := make([]string, 0, len(v.Matches))
	for _, m := range v.Matches {
		names = append(names, m.PatternName)
	}
	_, err := fmt.Fprintf(w, "line %d: [INJECTION] %s (action: %s)\n", v.Line, strings.Join(names, ", "), v.Action) //nolint:gosec // G705: CLI output, not web
	return err
}
