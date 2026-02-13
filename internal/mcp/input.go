package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// InputVerdict describes the outcome of scanning a single MCP request.
type InputVerdict struct {
	ID      json.RawMessage         `json:"id"`
	Method  string                  `json:"method,omitempty"`
	Clean   bool                    `json:"clean"`
	Action  string                  `json:"action,omitempty"`
	Matches []scanner.TextDLPMatch  `json:"dlp_matches,omitempty"`
	Inject  []scanner.ResponseMatch `json:"injection_matches,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// extractAllStringsFromJSON recursively extracts all string values AND keys
// from arbitrary JSON. Unlike extractStringsFromJSON (values only), this
// version also extracts map keys because an agent can exfiltrate secrets
// by encoding them as JSON object keys in tool arguments.
func extractAllStringsFromJSON(raw json.RawMessage) []string {
	var result []string
	var extract func(v interface{})
	extract = func(v interface{}) {
		switch val := v.(type) {
		case string:
			result = append(result, val)
		case float64:
			// Numeric values could encode secrets (e.g., ASCII code points).
			result = append(result, strconv.FormatFloat(val, 'f', -1, 64))
		case bool:
			result = append(result, strconv.FormatBool(val))
		case []interface{}:
			for _, item := range val {
				extract(item)
			}
		case map[string]interface{}:
			for k, item := range val {
				result = append(result, k) // Extract keys too.
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

// ScanRequest parses a JSON-RPC 2.0 request and scans its params for
// DLP patterns, injection patterns, and env secret leaks. Fail-closed
// on parse errors (configurable via onParseError).
func ScanRequest(line []byte, sc *scanner.Scanner, action, onParseError string) InputVerdict {
	// Detect batch request (JSON array).
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return scanRequestBatch(trimmed, sc, action, onParseError)
	}

	var rpc RPCResponse // Reuse struct — has Method and Params fields.
	if err := json.Unmarshal(trimmed, &rpc); err != nil {
		if onParseError == "forward" { //nolint:goconst // config action value
			// Still scan raw text for secrets/injection before forwarding.
			return scanRawBeforeForward(trimmed, sc, action)
		}
		return InputVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonRPCVersion {
		if onParseError == "forward" { //nolint:goconst // config action value
			// Still scan raw text for secrets/injection before forwarding.
			return scanRawBeforeForward(trimmed, sc, action)
		}
		return InputVerdict{
			ID:    rpc.ID,
			Clean: false,
			Error: fmt.Sprintf("not a JSON-RPC 2.0 message: jsonrpc=%q", rpc.JSONRPC),
		}
	}

	// No params to scan — clean.
	if len(rpc.Params) == 0 || string(rpc.Params) == jsonNull {
		return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: true}
	}

	// Extract all strings (keys + values) from params.
	strs := extractAllStringsFromJSON(rpc.Params)
	if len(strs) == 0 {
		// Fallback: serialize params to string for non-string JSON values.
		strs = []string{string(rpc.Params)}
	}

	// Include method name and ID in DLP scan — agents can exfiltrate
	// secrets by encoding them into method names or request IDs.
	if rpc.Method != "" {
		strs = append(strs, rpc.Method)
	}
	if len(rpc.ID) > 0 && string(rpc.ID) != jsonNull {
		strs = append(strs, string(rpc.ID))
	}

	joined := joinStrings(strs)

	// Run DLP patterns + env leak checks.
	dlpResult := sc.ScanTextForDLP(joined)

	// Also scan concatenated strings (no separator) to catch secrets
	// split across multiple JSON fields (e.g. "part1":"sk-ant-", "part2":"aaaa...").
	if dlpResult.Clean {
		concat := strings.Join(strs, "")
		if concat != joined {
			dlpResult = sc.ScanTextForDLP(concat)
		}
	}

	// Run injection patterns (reuses response scanning patterns).
	injResult := sc.ScanResponse(joined)

	var dlpMatches []scanner.TextDLPMatch
	var injMatches []scanner.ResponseMatch

	if !dlpResult.Clean {
		dlpMatches = dlpResult.Matches
	}
	if !injResult.Clean {
		injMatches = injResult.Matches
	}

	if len(dlpMatches) == 0 && len(injMatches) == 0 {
		return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: true}
	}

	return InputVerdict{
		ID:      rpc.ID,
		Method:  rpc.Method,
		Clean:   false,
		Action:  action,
		Matches: dlpMatches,
		Inject:  injMatches,
	}
}

// scanRawBeforeForward scans the raw bytes of an unparseable request for
// DLP patterns and injection before forwarding in on_parse_error=forward mode.
// This prevents malformed JSON from being a trivial bypass for all scanning.
func scanRawBeforeForward(raw []byte, sc *scanner.Scanner, action string) InputVerdict {
	text := string(raw)
	dlpResult := sc.ScanTextForDLP(text)
	injResult := sc.ScanResponse(text)

	var dlpMatches []scanner.TextDLPMatch
	var injMatches []scanner.ResponseMatch

	if !dlpResult.Clean {
		dlpMatches = dlpResult.Matches
	}
	if !injResult.Clean {
		injMatches = injResult.Matches
	}

	if len(dlpMatches) == 0 && len(injMatches) == 0 {
		return InputVerdict{Clean: true}
	}

	return InputVerdict{
		Clean:   false,
		Action:  action,
		Matches: dlpMatches,
		Inject:  injMatches,
	}
}

// scanRequestBatch scans a JSON-RPC 2.0 batch request (array of requests).
func scanRequestBatch(line []byte, sc *scanner.Scanner, action, onParseError string) InputVerdict {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		if onParseError == "forward" {
			return scanRawBeforeForward(line, sc, action)
		}
		return InputVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON batch: %v", err)}
	}

	if len(batch) == 0 {
		return InputVerdict{Clean: true}
	}

	var allDLP []scanner.TextDLPMatch
	var allInj []scanner.ResponseMatch
	var firstID json.RawMessage
	var hasError bool

	for _, elem := range batch {
		v := ScanRequest(elem, sc, action, onParseError)
		if firstID == nil && len(v.ID) > 0 {
			firstID = v.ID
		}
		if v.Error != "" {
			hasError = true
		}
		if !v.Clean && v.Error == "" {
			allDLP = append(allDLP, v.Matches...)
			allInj = append(allInj, v.Inject...)
		}
	}

	if len(allDLP) == 0 && len(allInj) == 0 {
		if hasError {
			return InputVerdict{ID: firstID, Clean: false, Error: "one or more batch elements failed to parse"}
		}
		return InputVerdict{ID: firstID, Clean: true}
	}
	v := InputVerdict{
		ID: firstID, Clean: false, Action: action, Matches: allDLP, Inject: allInj,
	}
	if hasError {
		v.Error = "one or more batch elements also failed to parse"
	}
	return v
}

// BlockedRequest holds the ID and notification status of a blocked MCP request,
// sent from the input scanning goroutine to the main goroutine via channel.
type BlockedRequest struct {
	ID             json.RawMessage
	IsNotification bool // Notifications have no ID — don't send error response.
	LogMessage     string
}

// blockRequestResponse generates a JSON-RPC 2.0 error response for a blocked request.
func blockRequestResponse(id json.RawMessage) []byte {
	resp := rpcError{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Error: rpcErrorDetail{
			Code:    -32001,
			Message: "pipelock: request blocked by MCP input scanning",
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// ForwardScannedInput reads newline-delimited JSON-RPC 2.0 requests from clientIn,
// scans each for DLP and injection patterns, and forwards clean requests to serverIn.
// Blocked request IDs are sent via blockedCh so the main goroutine (which owns
// clientOut writes) can send error responses without concurrent write races.
func ForwardScannedInput(
	clientIn io.Reader,
	serverIn io.Writer,
	logW io.Writer,
	sc *scanner.Scanner,
	action string,
	onParseError string,
	blockedCh chan<- BlockedRequest,
) {
	defer close(blockedCh)

	lineScanner := bufio.NewScanner(clientIn)
	lineScanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)
	lineNum := 0

	for lineScanner.Scan() {
		lineNum++
		line := bytes.TrimSpace(lineScanner.Bytes())
		if len(line) == 0 {
			continue
		}

		verdict := ScanRequest(line, sc, action, onParseError)

		if verdict.Clean {
			if err := writeMessage(serverIn, line); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
			continue
		}

		// Parse error — block by default.
		if verdict.Error != "" {
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: %s\n", lineNum, verdict.Error)
			isNotification := len(verdict.ID) == 0
			blockedCh <- BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isNotification,
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (parse error)", lineNum),
			}
			continue
		}

		// DLP or injection match.
		var reasons []string
		for _, m := range verdict.Matches {
			reasons = append(reasons, m.PatternName)
		}
		for _, m := range verdict.Inject {
			reasons = append(reasons, m.PatternName)
		}
		reasonStr := joinStrings(reasons)

		method := verdict.Method
		if method == "" {
			method = "unknown"
		}

		isNotification := len(verdict.ID) == 0

		switch action {
		case "block": //nolint:goconst // config action value
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s)\n",
				lineNum, method, reasonStr)
			blockedCh <- BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isNotification,
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked", lineNum),
			}
		case "ask":
			// HITL for input scanning is impractical — fall back to block.
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [ask not supported for input scanning]\n",
				lineNum, method, reasonStr)
			blockedCh <- BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isNotification,
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (ask fallback)", lineNum),
			}
		default: // warn
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: warning — %s request contains flagged content (%s)\n",
				lineNum, method, reasonStr)
			// Forward anyway (warn mode).
			if err := writeMessage(serverIn, line); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
		}
	}

	if err := lineScanner.Err(); err != nil {
		_, _ = fmt.Fprintf(logW, "pipelock: input scanner error: %v\n", err)
	}
}

// joinStrings joins strings with newline separator, matching ExtractText pattern.
func joinStrings(ss []string) string {
	return strings.Join(ss, "\n")
}
