package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
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
			for _, k := range sortedKeys(val) {
				result = append(result, k) // Extract keys too.
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

	// No params — but result/error/unknown fields may carry exfiltrable
	// content (e.g., a compromised agent sending response-shaped messages).
	// Extract individual string values and scan each one separately so that
	// encoded-secret detection (base64, hex) works on field values, not on
	// the whole JSON blob (which is never valid base64/hex as a unit).
	if len(rpc.Params) == 0 || string(rpc.Params) == jsonNull {
		raw := string(trimmed)

		// Extract individual strings for per-field encoded DLP checks.
		strs := extractAllStringsFromJSON(trimmed)
		joined := joinStrings(strs)

		// Run DLP on joined strings first (catches raw patterns).
		dlpResult := sc.ScanTextForDLP(joined)

		// Catch secrets split across multiple JSON fields.
		dlpResult = scanSplitSecret(trimmed, joined, sc, dlpResult)

		// Scan each extracted string individually for encoded secrets
		// (base64, hex). The joined string is not valid base64/hex as a
		// unit, so encoding checks only work on individual field values.
		if dlpResult.Clean {
			for _, s := range strs {
				if r := sc.ScanTextForDLP(s); !r.Clean {
					dlpResult = r
					break
				}
			}
		}

		// Fall back to scanning full raw JSON for DLP patterns that span
		// across JSON structure (catches patterns split by JSON syntax).
		if dlpResult.Clean {
			dlpResult = sc.ScanTextForDLP(raw)
		}

		// Run injection patterns on the full raw text (injection patterns
		// match phrases, not encoded blobs — full text is appropriate).
		injResult := sc.ScanResponse(raw)

		if dlpResult.Clean && injResult.Clean {
			return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: true}
		}
		var dlpMatches []scanner.TextDLPMatch
		var injMatches []scanner.ResponseMatch
		if !dlpResult.Clean {
			dlpMatches = dlpResult.Matches
		}
		if !injResult.Clean {
			injMatches = injResult.Matches
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

	// Catch secrets split across multiple JSON fields.
	dlpResult = scanSplitSecret(rpc.Params, joined, sc, dlpResult)

	// Scan each extracted string individually for encoded secrets (base64,
	// hex). The joined string is not valid base64/hex as a unit, so encoding
	// checks only work on individual field values.
	if dlpResult.Clean {
		for _, s := range strs {
			if r := sc.ScanTextForDLP(s); !r.Clean {
				dlpResult = r
				break
			}
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
// Extracts individual strings for per-field encoded DLP checks (base64, hex).
func scanRawBeforeForward(raw []byte, sc *scanner.Scanner, action string) InputVerdict {
	text := string(raw)

	// Extract individual strings for encoded DLP checks.
	strs := extractAllStringsFromJSON(raw)
	joined := joinStrings(strs)

	dlpResult := sc.ScanTextForDLP(joined)

	// Catch secrets split across multiple JSON fields.
	dlpResult = scanSplitSecret(raw, joined, sc, dlpResult)

	// Scan each extracted string individually for encoded secrets.
	if dlpResult.Clean {
		for _, s := range strs {
			if r := sc.ScanTextForDLP(s); !r.Clean {
				dlpResult = r
				break
			}
		}
	}

	// Fall back to full raw text for cross-structure patterns.
	if dlpResult.Clean {
		dlpResult = sc.ScanTextForDLP(text)
	}

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
	ErrorCode      int    // 0 = use default -32001; -32002 = policy block
	ErrorMessage   string // empty = use default message
}

// blockRequestResponse generates a JSON-RPC 2.0 error response for a blocked request.
// Uses ErrorCode/ErrorMessage from BlockedRequest if set, otherwise defaults.
func blockRequestResponse(br BlockedRequest) []byte {
	code := br.ErrorCode
	if code == 0 {
		code = -32001
	}
	msg := br.ErrorMessage
	if msg == "" {
		msg = "pipelock: request blocked by MCP input scanning"
	}
	resp := rpcError{
		JSONRPC: jsonRPCVersion,
		ID:      br.ID,
		Error: rpcErrorDetail{
			Code:    code,
			Message: msg,
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// ForwardScannedInput reads JSON-RPC 2.0 requests from reader, scans each for
// DLP and injection patterns, and forwards clean requests to writer.
// When policyCfg is non-nil, tool call policy rules are also checked
// independently of content scanning — the strictest action wins.
// Blocked request IDs are sent via blockedCh so the main goroutine (which owns
// clientOut writes) can send error responses without concurrent write races.
func ForwardScannedInput(
	reader MessageReader,
	writer MessageWriter,
	logW io.Writer,
	sc *scanner.Scanner,
	action string,
	onParseError string,
	blockedCh chan<- BlockedRequest,
	policyCfg *PolicyConfig,
) {
	defer close(blockedCh)

	// lineNum counts non-empty messages, not raw lines. StdioReader skips
	// empty lines internally, so this is a message index.
	lineNum := 0

	for {
		line, err := reader.ReadMessage()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				_, _ = fmt.Fprintf(logW, "pipelock: input scanner error: %v\n", err)
			}
			return
		}
		lineNum++

		verdict := ScanRequest(line, sc, action, onParseError)

		// Tool call policy check — independent of content scanning.
		policyVerdict := PolicyVerdict{}
		if policyCfg != nil {
			policyVerdict = policyCfg.CheckRequest(line)
		}

		// Parse error — block by default (policy doesn't override parse errors).
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

		// Both clean — forward.
		if verdict.Clean && !policyVerdict.Matched {
			if err := writer.WriteMessage(line); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
			continue
		}

		// Build combined reasons from content scan and policy.
		var reasons []string
		for _, m := range verdict.Matches {
			reasons = append(reasons, m.PatternName)
		}
		for _, m := range verdict.Inject {
			reasons = append(reasons, m.PatternName)
		}
		for _, r := range policyVerdict.Rules {
			reasons = append(reasons, "policy:"+r)
		}
		reasonStr := joinStrings(reasons)

		method := verdict.Method
		if method == "" {
			method = "unknown"
		}

		// Determine effective action: strictest of content scan action and policy action.
		effectiveAction := ""
		if !verdict.Clean {
			effectiveAction = action
		}
		if policyVerdict.Matched {
			effectiveAction = stricterAction(effectiveAction, policyVerdict.Action)
		}

		isNotification := len(verdict.ID) == 0

		// Determine error response fields based on what triggered the block.
		isPolicyOnly := verdict.Clean && policyVerdict.Matched
		errCode := 0 // default: -32001 (content scan)
		errMsg := "" // default message
		if isPolicyOnly {
			errCode = -32002                                         // policy-specific error code
			errMsg = "pipelock: request blocked by tool call policy" //nolint:goconst // shared error message with proxy_http.go
		}

		switch effectiveAction {
		case "block": //nolint:goconst // config action value
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s)\n",
				lineNum, method, reasonStr)
			blockedCh <- BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isNotification,
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked", lineNum),
				ErrorCode:      errCode,
				ErrorMessage:   errMsg,
			}
		case "ask": //nolint:goconst // config action value
			// HITL for input scanning is impractical — fall back to block.
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [ask not supported for input scanning]\n",
				lineNum, method, reasonStr)
			blockedCh <- BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isNotification,
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (ask fallback)", lineNum),
				ErrorCode:      errCode,
				ErrorMessage:   errMsg,
			}
		default: // warn
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: warning — %s request contains flagged content (%s)\n",
				lineNum, method, reasonStr)
			// Forward anyway (warn mode).
			if err := writer.WriteMessage(line); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
		}
	}
}

// joinStrings joins strings with newline separator, matching ExtractText pattern.
func joinStrings(ss []string) string {
	return strings.Join(ss, "\n")
}

// scanSplitSecret checks for secrets split across multiple JSON fields by
// concatenating values without separators. Keys are excluded (via
// extractStringsFromJSON, not extractAllStringsFromJSON) because interleaved
// keys break DLP regex adjacency. Returns the original result if clean or if
// concat adds no new information.
func scanSplitSecret(raw json.RawMessage, joined string, sc *scanner.Scanner, result scanner.TextDLPResult) scanner.TextDLPResult {
	if !result.Clean {
		return result
	}
	vals := extractStringsFromJSON(raw)
	if len(vals) <= 1 {
		return result
	}
	concat := strings.Join(vals, "")
	if concat == joined {
		return result
	}
	return sc.ScanTextForDLP(concat)
}
