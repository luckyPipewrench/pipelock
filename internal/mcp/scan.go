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

// ContentBlock represents a single content block in an MCP tool result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolResult represents the result field of an MCP tool response.
type ToolResult struct {
	Content []ContentBlock `json:"content"`
}

// RPCResponse represents a JSON-RPC 2.0 response envelope.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  *ToolResult     `json:"result,omitempty"`
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

// ExtractText concatenates all text content blocks separated by newlines.
// Non-text blocks are silently skipped. Returns "" for nil or empty results.
func ExtractText(result *ToolResult) string {
	if result == nil {
		return ""
	}

	var texts []string
	for _, block := range result.Content {
		if block.Type == "text" {
			texts = append(texts, block.Text)
		}
	}
	return strings.Join(texts, "\n")
}

// ScanResponse parses a single JSON-RPC 2.0 response and scans its text
// content for prompt injection. Parse errors produce a verdict with Clean=false
// and the Error field set. Result content is always scanned when present,
// regardless of the error field (defensive against JSON-RPC spec violations).
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

	// Always scan when result has text — even if an error field is present.
	// JSON-RPC 2.0 shouldn't have both, but we scan defensively.
	text := ExtractText(rpc.Result)
	if rpc.Result == nil || text == "" {
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
