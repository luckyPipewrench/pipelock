// Package mcp provides scanning of MCP (Model Context Protocol) JSON-RPC 2.0
// responses for prompt injection. It extracts text content from tool result
// blocks and runs them through scanner.ScanResponse for pattern matching.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RPCResponse represents a JSON-RPC 2.0 response envelope.
// Result is json.RawMessage (not *ToolResult) to handle non-standard result
// shapes without failing the entire parse — a typed *ToolResult would cause
// json.Unmarshal to error on string/array/non-object results, allowing bypass.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
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
			return strings.Join(texts, "\n")
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
			for _, item := range val {
				extract(item)
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
// and the Error field set. Both result content and error messages are scanned —
// error.message is a common vector for prompt injection via tool errors.
func ScanResponse(line []byte, sc *scanner.Scanner) ScanVerdict {
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
	// Attackers can inject via error.message returned by malicious tool servers.
	if len(rpc.Error) > 0 && string(rpc.Error) != jsonNull {
		var rpcErr RPCError
		if err := json.Unmarshal(rpc.Error, &rpcErr); err == nil && rpcErr.Message != "" {
			if text != "" {
				text += "\n"
			}
			text += rpcErr.Message
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
		_, err := fmt.Fprintf(w, "line %d: [ERROR] %s\n", v.Line, v.Error)
		return err
	}

	names := make([]string, 0, len(v.Matches))
	for _, m := range v.Matches {
		names = append(names, m.PatternName)
	}
	_, err := fmt.Fprintf(w, "line %d: [INJECTION] %s (action: %s)\n", v.Line, strings.Join(names, ", "), v.Action)
	return err
}
