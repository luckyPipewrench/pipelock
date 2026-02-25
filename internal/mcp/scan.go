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

	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Type aliases re-export sub-package types so existing consumers of mcp.X
// continue to work without import changes. These are true aliases (not new
// types), so values are interchangeable with the originals.
type (
	// jsonrpc types.
	ContentBlock = jsonrpc.ContentBlock
	ToolResult   = jsonrpc.ToolResult
	RPCError     = jsonrpc.RPCError
	RPCResponse  = jsonrpc.RPCResponse
	ScanVerdict  = jsonrpc.ScanVerdict

	// transport types.
	MessageReader = transport.MessageReader
	MessageWriter = transport.MessageWriter

	// tools types.
	ToolScanConfig = tools.ToolScanConfig
	ToolBaseline   = tools.ToolBaseline

	// policy types.
	PolicyConfig       = policy.PolicyConfig
	PolicyVerdict      = policy.PolicyVerdict
	CompiledPolicyRule = policy.CompiledPolicyRule
)

// Package-level aliases so existing test files and remaining code in this
// package can reference the constants without qualifying with sub-packages.
const (
	maxLineSize    = transport.MaxLineSize
	jsonRPCVersion = jsonrpc.Version //nolint:goconst // alias for backward compat
	jsonNull       = jsonrpc.Null    //nolint:goconst // alias for backward compat
)

// Re-export constructor functions for backward compatibility.
var (
	ExtractText = jsonrpc.ExtractText

	NewStdioReader = transport.NewStdioReader
	NewStdioWriter = transport.NewStdioWriter
	NewHTTPClient  = transport.NewHTTPClient

	ScanTools       = tools.ScanTools
	NewToolBaseline = tools.NewToolBaseline
	LogToolFindings = tools.LogToolFindings

	NewPolicyConfig        = policy.NewPolicyConfig
	DefaultToolPolicyRules = policy.DefaultToolPolicyRules
)

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

	if rpc.JSONRPC != jsonrpc.Version {
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
	if len(rpc.Error) > 0 && string(rpc.Error) != jsonrpc.Null {
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
	if len(rpc.Params) > 0 && string(rpc.Params) != jsonrpc.Null {
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

// ScanStream reads newline-delimited JSON-RPC 2.0 responses from r, scans
// each for prompt injection, and writes results to w. In text mode, only
// errors and detections are written (clean lines are silent). In JSON mode,
// every scanned line produces an output object. Returns true if any injection
// was detected. Parse errors are reported but do not count as injection.
func ScanStream(r io.Reader, w io.Writer, sc *scanner.Scanner, jsonOutput bool) (bool, error) {
	lineScanner := bufio.NewScanner(r)
	lineScanner.Buffer(make([]byte, 0, 64*1024), transport.MaxLineSize)

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
