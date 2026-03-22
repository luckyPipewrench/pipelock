// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	decide "github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/extract"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// methodToolsCall is the JSON-RPC method for MCP tool invocations.
const methodToolsCall = "tools/call"

// errPolicyBlocked is the error message returned when a tool call is denied by policy.
const errPolicyBlocked = "pipelock: request blocked by tool call policy"

// ceeStdioKey is the fixed CEE session key for stdio MCP proxies. A single
// subprocess means one session per process, so a static key is correct.
const ceeStdioKey = "_default|stdio"

// InputVerdict describes the outcome of scanning a single MCP request.
type InputVerdict struct {
	ID              json.RawMessage          `json:"id"`
	Method          string                   `json:"method,omitempty"`
	Clean           bool                     `json:"clean"`
	Action          string                   `json:"action,omitempty"`
	Matches         []scanner.TextDLPMatch   `json:"dlp_matches,omitempty"`
	Inject          []scanner.ResponseMatch  `json:"injection_matches,omitempty"`
	AddressFindings []addressprotect.Finding `json:"address_findings,omitempty"`
	Error           string                   `json:"error,omitempty"`
}

// extractToolCallName extracts the tool name from a tools/call JSON-RPC request.
// Returns "" if the message is not a tools/call or the name cannot be extracted.
func extractToolCallName(line []byte) string {
	var req struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(line, &req) != nil {
		return ""
	}
	if req.Method != methodToolsCall {
		return ""
	}
	return req.Params.Name
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

	var rpc jsonrpc.RPCResponse // Reuse struct — has Method and Params fields.
	if err := json.Unmarshal(trimmed, &rpc); err != nil {
		if onParseError == config.ActionForward {
			// Still scan raw text for secrets/injection before forwarding.
			return scanRawBeforeForward(trimmed, sc, action)
		}
		return InputVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON: %v", err)}
	}

	if rpc.JSONRPC != jsonrpc.Version {
		if onParseError == config.ActionForward {
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
	if len(rpc.Params) == 0 || string(rpc.Params) == jsonrpc.Null {
		raw := string(trimmed)

		// Extract individual strings for per-field encoded DLP checks.
		strs := extract.AllStringsFromJSON(trimmed)
		joined := joinStrings(strs)

		// Run DLP on joined strings first (catches raw patterns).
		dlpResult := sc.ScanTextForDLP(context.Background(), joined)

		// Catch secrets split across multiple JSON fields.
		dlpResult = scanSplitSecret(trimmed, joined, sc, dlpResult)

		// Scan each extracted string individually for encoded secrets
		// (base64, hex). The joined string is not valid base64/hex as a
		// unit, so encoding checks only work on individual field values.
		if dlpResult.Clean {
			for _, s := range strs {
				if r := sc.ScanTextForDLP(context.Background(), s); !r.Clean {
					dlpResult = r
					break
				}
			}
		}

		// Fall back to scanning full raw JSON for DLP patterns that span
		// across JSON structure (catches patterns split by JSON syntax).
		if dlpResult.Clean {
			dlpResult = sc.ScanTextForDLP(context.Background(), raw)
		}

		// Run injection patterns on the full raw text (injection patterns
		// match phrases, not encoded blobs -- full text is appropriate).
		injResult := sc.ScanResponse(context.Background(), raw)

		// Also scan each extracted string individually for encoded injection
		// (e.g. base64-encoded phrases) that don't decode in the full blob.
		if injResult.Clean {
			for _, s := range strs {
				if r := sc.ScanResponse(context.Background(), s); !r.Clean {
					injResult = r
					break
				}
			}
		}

		// Address poisoning detection (agentID="" for stdio).
		var addrFindings []addressprotect.Finding
		if checker := sc.AddressChecker(); checker != nil {
			addrResult := checker.CheckText(joined, "")
			if len(addrResult.Findings) > 0 {
				addrFindings = addrResult.Findings
			}
		}

		if dlpResult.Clean && injResult.Clean && len(addrFindings) == 0 {
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

		// Resolve strictest action: DLP/injection use MCP input action,
		// address findings carry their own per-verdict action.
		verdictAction := ""
		if len(dlpMatches) > 0 || len(injMatches) > 0 {
			verdictAction = action
		}
		if addrAction := addressprotect.StrictestAction(addrFindings); addrAction != "" {
			if verdictAction == "" || addrAction == config.ActionBlock {
				verdictAction = addrAction
			}
		}

		return InputVerdict{
			ID:              rpc.ID,
			Method:          rpc.Method,
			Clean:           false,
			Action:          verdictAction,
			Matches:         dlpMatches,
			Inject:          injMatches,
			AddressFindings: addrFindings,
		}
	}

	// Extract all strings (keys + values) from params.
	strs := extract.AllStringsFromJSON(rpc.Params)
	if len(strs) == 0 {
		// Fallback: serialize params to string for non-string JSON values.
		strs = []string{string(rpc.Params)}
	}

	// Include method name and ID in DLP scan — agents can exfiltrate
	// secrets by encoding them into method names or request IDs.
	if rpc.Method != "" {
		strs = append(strs, rpc.Method)
	}
	if len(rpc.ID) > 0 && string(rpc.ID) != jsonrpc.Null {
		strs = append(strs, string(rpc.ID))
	}

	joined := joinStrings(strs)

	// Run DLP patterns + env leak checks.
	dlpResult := sc.ScanTextForDLP(context.Background(), joined)

	// Catch secrets split across multiple JSON fields.
	dlpResult = scanSplitSecret(rpc.Params, joined, sc, dlpResult)

	// Scan each extracted string individually for encoded secrets (base64,
	// hex). The joined string is not valid base64/hex as a unit, so encoding
	// checks only work on individual field values.
	if dlpResult.Clean {
		for _, s := range strs {
			if r := sc.ScanTextForDLP(context.Background(), s); !r.Clean {
				dlpResult = r
				break
			}
		}
	}

	// Run injection patterns (reuses response scanning patterns).
	// First scan joined text for injection phrases that span fields.
	injResult := sc.ScanResponse(context.Background(), joined)

	// Also scan each extracted string individually for injection. Catches
	// encoded injection (e.g. base64) in a single field that doesn't decode
	// cleanly when concatenated with other fields.
	if injResult.Clean {
		for _, s := range strs {
			if r := sc.ScanResponse(context.Background(), s); !r.Clean {
				injResult = r
				break
			}
		}
	}

	var dlpMatches []scanner.TextDLPMatch
	var injMatches []scanner.ResponseMatch

	if !dlpResult.Clean {
		dlpMatches = dlpResult.Matches
	}
	if !injResult.Clean {
		injMatches = injResult.Matches
	}

	// Run address poisoning detection alongside DLP.
	// agentID="" for MCP stdio (one agent per process, global allowlist only).
	var addrFindings []addressprotect.Finding
	if checker := sc.AddressChecker(); checker != nil {
		addrResult := checker.CheckText(joined, "")
		if len(addrResult.Findings) > 0 {
			addrFindings = addrResult.Findings
		}
	}

	if len(dlpMatches) == 0 && len(injMatches) == 0 && len(addrFindings) == 0 {
		return InputVerdict{ID: rpc.ID, Method: rpc.Method, Clean: true}
	}

	// Resolve the strictest action: DLP/injection use the MCP input action,
	// address findings carry their own per-verdict action (block or warn).
	// The strictest across all finding types wins.
	verdictAction := ""
	if len(dlpMatches) > 0 || len(injMatches) > 0 {
		verdictAction = action
	}
	if addrAction := addressprotect.StrictestAction(addrFindings); addrAction != "" {
		if verdictAction == "" || addrAction == config.ActionBlock {
			verdictAction = addrAction
		}
	}

	return InputVerdict{
		ID:              rpc.ID,
		Method:          rpc.Method,
		Clean:           false,
		Action:          verdictAction,
		Matches:         dlpMatches,
		Inject:          injMatches,
		AddressFindings: addrFindings,
	}
}

// scanRawBeforeForward scans the raw bytes of an unparseable request for
// DLP patterns and injection before forwarding in on_parse_error=forward mode.
// This prevents malformed JSON from being a trivial bypass for all scanning.
// Extracts individual strings for per-field encoded DLP checks (base64, hex).
func scanRawBeforeForward(raw []byte, sc *scanner.Scanner, action string) InputVerdict {
	text := string(raw)

	// Extract individual strings for encoded DLP checks.
	strs := extract.AllStringsFromJSON(raw)
	joined := joinStrings(strs)

	dlpResult := sc.ScanTextForDLP(context.Background(), joined)

	// Catch secrets split across multiple JSON fields.
	dlpResult = scanSplitSecret(raw, joined, sc, dlpResult)

	// Scan each extracted string individually for encoded secrets.
	if dlpResult.Clean {
		for _, s := range strs {
			if r := sc.ScanTextForDLP(context.Background(), s); !r.Clean {
				dlpResult = r
				break
			}
		}
	}

	// Fall back to full raw text for cross-structure patterns.
	if dlpResult.Clean {
		dlpResult = sc.ScanTextForDLP(context.Background(), text)
	}

	injResult := sc.ScanResponse(context.Background(), text)

	// Also scan each extracted string individually for encoded injection
	// (e.g. base64-encoded phrases) that don't decode in the full blob.
	if injResult.Clean {
		for _, s := range strs {
			if r := sc.ScanResponse(context.Background(), s); !r.Clean {
				injResult = r
				break
			}
		}
	}

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
		if onParseError == config.ActionForward {
			return scanRawBeforeForward(line, sc, action)
		}
		return InputVerdict{Clean: false, Error: fmt.Sprintf("invalid JSON batch: %v", err)}
	}

	if len(batch) == 0 {
		return InputVerdict{Clean: true}
	}

	var allDLP []scanner.TextDLPMatch
	var allInj []scanner.ResponseMatch
	var allAddr []addressprotect.Finding
	var firstID json.RawMessage
	var hasError bool
	var batchAction string // track strictest action across batch elements

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
			allAddr = append(allAddr, v.AddressFindings...)
			if v.Action != "" {
				if batchAction == "" {
					batchAction = v.Action
				} else if v.Action == config.ActionBlock {
					batchAction = config.ActionBlock
				}
			}
		}
	}

	if len(allDLP) == 0 && len(allInj) == 0 && len(allAddr) == 0 {
		if hasError {
			return InputVerdict{ID: firstID, Clean: false, Error: "one or more batch elements failed to parse"}
		}
		return InputVerdict{ID: firstID, Clean: true}
	}
	if batchAction == "" {
		batchAction = action
	}
	v := InputVerdict{
		ID: firstID, Clean: false, Action: batchAction,
		Matches: allDLP, Inject: allInj, AddressFindings: allAddr,
	}
	if hasError {
		v.Error = "one or more batch elements also failed to parse"
	}
	return v
}

// BlockedRequest holds the ID and notification status of a blocked MCP request,
// sent from the input scanning goroutine to the main goroutine via channel.
// When SyntheticResponse is non-nil, the consumer sends it as-is instead of
// generating an error response (used for redirect success results).
type BlockedRequest struct {
	ID                json.RawMessage
	IsNotification    bool // Notifications have no ID — don't send error response.
	LogMessage        string
	ErrorCode         int    // 0 = use default -32001; -32002 = policy block
	ErrorMessage      string // empty = use default message
	SyntheticResponse []byte // if set, send this instead of an error response
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
		JSONRPC: jsonrpc.Version,
		ID:      br.ID,
		Error: rpcErrorDetail{
			Code:    code,
			Message: msg,
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// SessionBindingConfig controls MCP session binding (tool inventory validation).
// When non-nil with a valid Baseline, tools/call requests are checked against
// the tool inventory captured from the first tools/list response.
type SessionBindingConfig struct {
	Baseline          *tools.ToolBaseline
	UnknownToolAction string // warn, block
	NoBaselineAction  string // warn, block (action when no baseline yet)
}

// ForwardScannedInput reads JSON-RPC 2.0 requests from reader, scans each for
// DLP and injection patterns, and forwards clean requests to writer.
// When policyCfg is non-nil, tool call policy rules are also checked
// independently of content scanning — the strictest action wins.
// When bindingCfg is non-nil, tools/call requests are validated against the
// session tool baseline.
// When tracker is non-nil, each forwarded request's ID is recorded so the
// response-side (ForwardScanned) can validate that response IDs were solicited.
// When cee is non-nil, outbound payloads are recorded for cross-request
// exfiltration detection (entropy budget and fragment reassembly DLP).
// When rec is non-nil and adaptiveCfg is enabled, threat signals are recorded
// and the effective action may be upgraded based on session escalation level.
// Blocked request IDs are sent via blockedCh so the main goroutine (which owns
// clientOut writes) can send error responses without concurrent write races.
func ForwardScannedInput(
	reader transport.MessageReader,
	writer transport.MessageWriter,
	logW io.Writer,
	sc *scanner.Scanner,
	action string,
	onParseError string,
	blockedCh chan<- BlockedRequest,
	policyCfg *policy.Config,
	bindingCfg *SessionBindingConfig,
	ks *killswitch.Controller,
	chainMatcher *chains.Matcher,
	tracker *RequestTracker,
	auditLogger *audit.Logger,
	cee *CEEDeps,
	rec session.Recorder,
	adaptiveCfg *config.AdaptiveEnforcement,
	m *metrics.Metrics,
) {
	defer close(blockedCh)

	// Helper: record an adaptive signal and handle escalation side-effects.
	// Eliminates repeated nil/enabled guards at every call site.
	recordAdaptiveSignal := func(sig session.SignalType) {
		if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
			recordSignalWithEscalation(rec, sig, adaptiveCfg.EscalationThreshold, logW, auditLogger, m, "default", "", "")
		}
	}

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

		// Kill switch: deny all messages when active.
		if ks != nil {
			if d := ks.IsActiveMCP(line); d.Active {
				if d.IsNotification {
					// Notifications have no ID — silently drop.
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: kill switch dropped notification (source=%s)\n",
						lineNum, d.Source)
				} else {
					// Request with ID — send JSON-RPC error response.
					rpcID := extractRPCID(line)
					blockedCh <- BlockedRequest{
						ID:             rpcID,
						IsNotification: false,
						LogMessage:     fmt.Sprintf("pipelock: input line %d: kill switch denied (source=%s)", lineNum, d.Source),
						ErrorCode:      -32004,
						ErrorMessage:   d.Message,
					}
				}
				continue
			}
		}

		verdict := ScanRequest(line, sc, action, onParseError)

		// Tool call policy check — independent of content scanning.
		policyVerdict := policy.Verdict{}
		if policyCfg != nil {
			policyVerdict = policyCfg.CheckRequest(line)
		}

		// Session binding: validate tools/call against baseline.
		bindingAction := ""
		bindingReason := ""

		// Batch requests bypass per-method binding checks because the
		// aggregate verdict has no single Method. Fail closed: treat
		// batch requests as binding violations when session binding is
		// active, since they could contain unvalidated tools/call messages.
		trimmedLine := bytes.TrimSpace(line)
		if bindingCfg != nil && bindingCfg.Baseline != nil && len(trimmedLine) > 0 && trimmedLine[0] == '[' {
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: batch request with session binding active\n", lineNum)
			bindingAction = bindingCfg.UnknownToolAction
			bindingReason = "session_binding:batch_request"
		}

		// Extract tool name once for both binding and chain detection.
		var toolCallName string
		if verdict.Method == methodToolsCall {
			toolCallName = extractToolCallName(line)
		}

		if bindingCfg != nil && bindingCfg.Baseline != nil && verdict.Method == methodToolsCall {
			if toolCallName == "" {
				// Fail closed: tools/call without a name is a binding violation.
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: tools/call missing params.name\n", lineNum)
				bindingAction = bindingCfg.UnknownToolAction
				bindingReason = "session_binding:missing_tool_name"
			} else if !bindingCfg.Baseline.HasBaseline() {
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: tools/call %q before baseline established\n",
					lineNum, toolCallName)
				bindingAction = bindingCfg.NoBaselineAction
				bindingReason = "session_binding:no_baseline"
			} else if !bindingCfg.Baseline.IsKnownTool(toolCallName) {
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: tools/call %q not in session baseline\n",
					lineNum, toolCallName)
				bindingAction = bindingCfg.UnknownToolAction
				bindingReason = "session_binding:unknown_tool"
			}
		}

		// Chain detection: check if this tool call matches an attack pattern.
		// Runs on every tools/call regardless of content scan results.
		chainAction := ""
		chainReason := ""
		// Stdio proxy has exactly one client session per process instance.
		// "default" is the correct session key for this 1:1 architecture.
		if chainMatcher != nil && toolCallName != "" {
			cv := chainMatcher.Record("default", toolCallName, string(line))
			if cv.Matched {
				_, _ = fmt.Fprintf(logW, "pipelock: chain detected: %s (severity=%s, action=%s)\n",
					cv.PatternName, cv.Severity, cv.Action)
				if auditLogger != nil {
					auditLogger.LogChainDetection(cv.PatternName, cv.Severity, cv.Action, toolCallName, "default")
				}
				if cv.Action == config.ActionBlock {
					// Use verdict.ID from the already-parsed ScanRequest result
					// rather than re-parsing via extractRPCID. A tools/call always
					// has an ID; using the parsed value avoids a silent-drop bug
					// if re-parsing fails on unusual ID shapes.
					recordAdaptiveSignal(session.SignalBlock)
					blockedCh <- BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     fmt.Sprintf("pipelock: input line %d: chain pattern %q blocked", lineNum, cv.PatternName),
						ErrorCode:      -32004,
						ErrorMessage:   fmt.Sprintf("tool call blocked: chain pattern %q detected", cv.PatternName),
					}
					continue
				}
				// warn action: record reason for inclusion in combined verdict.
				chainAction = cv.Action
				chainReason = "chain:" + cv.PatternName
			}
		}

		// Parse error — block by default (policy doesn't override parse errors).
		if verdict.Error != "" {
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: %s\n", lineNum, verdict.Error)
			blockedCh <- BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (parse error)", lineNum),
			}
			continue
		}

		// All clean — forward (with block_all and CEE checks).
		if verdict.Clean && !policyVerdict.Matched && bindingAction == "" && chainAction == "" {
			// block_all enforcement: deny ALL traffic (including clean) when the
			// session is at an escalation level with block_all=true.
			if rec != nil && decide.UpgradeAction("", rec.EscalationLevel(), adaptiveCfg) == config.ActionBlock {
				_, _ = fmt.Fprintf(logW, "pipelock: adaptive upgrade (clean) -> block (level %s)\n", session.EscalationLabel(rec.EscalationLevel()))
				if m != nil {
					m.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(rec.EscalationLevel()))
				}
				blockedCh <- BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (session deny)", lineNum),
					ErrorCode:      -32001,
					ErrorMessage:   fmt.Sprintf("pipelock: session escalation level %s", session.EscalationLabel(rec.EscalationLevel())),
				}
				continue
			}
			// Cross-request exfiltration check on clean outbound messages.
			if reason := ceeRecordMCP(ceeStdioKey, line, cee, sc, logW, auditLogger); reason != "" {
				blockedCh <- BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: CEE blocked", lineNum),
					ErrorCode:      -32005,
					ErrorMessage:   fmt.Sprintf("pipelock: %s", reason),
				}
				continue
			}
			// Track request ID before forwarding so response-side can validate.
			// Must happen before write to prevent race: response could arrive
			// before Track completes in concurrent stdio paths.
			tracker.Track(verdict.ID)
			if err := writer.WriteMessage(line); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
			if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
				rec.RecordClean(adaptiveCfg.DecayPerCleanRequest)
			}
			continue
		}

		// Build combined reasons from content scan, policy, and binding.
		var reasons []string
		for _, m := range verdict.Matches {
			reasons = append(reasons, m.PatternName)
		}
		for _, m := range verdict.Inject {
			reasons = append(reasons, m.PatternName)
		}
		for _, f := range verdict.AddressFindings {
			reasons = append(reasons, "address:"+f.Explanation)
		}
		for _, r := range policyVerdict.Rules {
			reasons = append(reasons, "policy:"+r)
		}
		if bindingReason != "" {
			reasons = append(reasons, bindingReason)
		}
		if chainReason != "" {
			reasons = append(reasons, chainReason)
		}
		reasonStr := joinStrings(reasons)

		method := verdict.Method
		if method == "" {
			method = "unknown"
		}

		// Determine effective action: strictest of content scan, policy, and binding.
		// mergeAction handles the initial empty state correctly (empty = no action yet).
		effectiveAction := ""
		mergeAction := func(cur, next string) string {
			if cur == "" {
				return next
			}
			return policy.StricterAction(cur, next)
		}
		if !verdict.Clean {
			if len(verdict.Matches) > 0 || len(verdict.Inject) > 0 {
				effectiveAction = action
			}
			// Address findings use the address protection action, not DLP action.
			if len(verdict.AddressFindings) > 0 {
				effectiveAction = mergeAction(effectiveAction, verdict.Action)
			}
		}
		if policyVerdict.Matched {
			effectiveAction = mergeAction(effectiveAction, policyVerdict.Action)
		}
		if bindingAction != "" {
			effectiveAction = mergeAction(effectiveAction, bindingAction)
		}
		if chainAction != "" {
			effectiveAction = mergeAction(effectiveAction, chainAction)
		}

		isNotification := isRPCNotification(verdict.ID)

		// Determine error response fields based on what triggered the block.
		isPolicyOnly := verdict.Clean && policyVerdict.Matched
		errCode := 0 // default: -32001 (content scan)
		errMsg := "" // default message
		if isPolicyOnly {
			errCode = -32002 // policy-specific error code
			errMsg = errPolicyBlocked
		}

		// Escalation upgrade: may promote warn/ask to block for elevated sessions.
		originalAction := effectiveAction
		if rec != nil {
			effectiveAction = decide.UpgradeAction(effectiveAction, rec.EscalationLevel(), adaptiveCfg)
		}
		if effectiveAction != originalAction {
			_, _ = fmt.Fprintf(logW, "pipelock: adaptive upgrade %s -> %s (level %s)\n", originalAction, effectiveAction, session.EscalationLabel(rec.EscalationLevel()))
			if m != nil {
				m.RecordAdaptiveUpgrade(originalAction, effectiveAction, session.EscalationLabel(rec.EscalationLevel()))
			}
		}

		redirectSucceeded := false
		switch effectiveAction {
		case config.ActionBlock:
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s)\n",
				lineNum, method, reasonStr)
			blockedCh <- BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isNotification,
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked", lineNum),
				ErrorCode:      errCode,
				ErrorMessage:   errMsg,
			}
		case config.ActionRedirect:
			// Batch requests cannot be redirected element-by-element.
			// Fail closed: block the entire batch.
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 && trimmed[0] == '[' {
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked batch request (%s) [redirect not supported for batches]\n",
					lineNum, reasonStr)
				blockedCh <- BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (batch redirect)", lineNum),
					ErrorCode:      -32002,
					ErrorMessage:   errPolicyBlocked,
				}
				break
			}
			profile, ok := policyCfg.RedirectProfiles[policyVerdict.RedirectProfile]
			if !ok {
				// Profile not found — fail closed to block.
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [redirect profile %q not found]\n",
					lineNum, method, reasonStr, policyVerdict.RedirectProfile)
				blockedCh <- BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect profile missing)", lineNum),
					ErrorCode:      -32002,
					ErrorMessage:   errPolicyBlocked,
				}
				break
			}
			toolName, toolArgs := extractToolCallFields(line)
			policyRuleName := ""
			if len(policyVerdict.Rules) > 0 {
				policyRuleName = policyVerdict.Rules[0]
			}
			result := executeRedirect(profile, policyVerdict.RedirectProfile, verdict.ID, toolArgs, policyRuleName)
			// Determine final outcome before audit logging so the event
			// reflects the actual result delivered to the client.
			finalResult := "blocked"
			if result.Success {
				// Scan redirect handler output for prompt injection before
				// sending to client. Untrusted handler output is attack surface.
				scanVerdict := ScanResponse(result.Response, sc)
				if !scanVerdict.Clean {
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked redirect response (injection detected in handler output)\n", lineNum)
					blockedCh <- BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isNotification,
						LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect output injection)", lineNum),
						ErrorCode:      -32001,
						ErrorMessage:   "pipelock: redirect handler output blocked by response scanning",
					}
				} else {
					finalResult = "redirected"
					redirectSucceeded = true
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: redirected %s request via profile %q (%dms)\n",
						lineNum, method, policyVerdict.RedirectProfile, result.LatencyMs)
					blockedCh <- BlockedRequest{
						ID:                verdict.ID,
						IsNotification:    isNotification,
						LogMessage:        fmt.Sprintf("pipelock: input line %d: redirected", lineNum),
						SyntheticResponse: result.Response,
					}
				}
			} else {
				// Redirect handler failed — fall through to block (fail-closed).
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [redirect failed: %s]\n",
					lineNum, method, reasonStr, result.Error)
				blockedCh <- BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect failed)", lineNum),
					ErrorCode:      -32002,
					ErrorMessage:   errPolicyBlocked,
				}
			}
			if auditLogger != nil {
				auditLogger.LogToolRedirect("", toolName, argsDigest(toolArgs), policyVerdict.RedirectProfile, profile.Reason, policyRuleName, finalResult, result.LatencyMs)
			}
		case config.ActionAsk:
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
			// Cross-request exfiltration check even in warn mode.
			if reason := ceeRecordMCP(ceeStdioKey, line, cee, sc, logW, auditLogger); reason != "" {
				blockedCh <- BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: CEE blocked", lineNum),
					ErrorCode:      -32005,
					ErrorMessage:   fmt.Sprintf("pipelock: %s", reason),
				}
				continue
			}
			// Track ID before forwarding (warn mode still sends the request).
			tracker.Track(verdict.ID)
			// Forward anyway (warn mode).
			if err := writer.WriteMessage(line); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
		}

		// Signal recording: record after action is taken.
		// Successful redirects are clean (not a block). Failed redirects escalate.
		switch {
		case effectiveAction == config.ActionBlock:
			recordAdaptiveSignal(session.SignalBlock)
		case effectiveAction == config.ActionRedirect && !redirectSucceeded:
			recordAdaptiveSignal(session.SignalBlock)
		case len(reasons) > 0:
			recordAdaptiveSignal(session.SignalNearMiss)
		default:
			if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
				rec.RecordClean(adaptiveCfg.DecayPerCleanRequest)
			}
		}
	}
}

// isRPCNotification returns true if the JSON-RPC ID represents a notification.
// A notification has no "id" field (nil/empty) or "id": null. The json.RawMessage
// for null is non-nil with len=4, so len(id)==0 alone is insufficient.
func isRPCNotification(id json.RawMessage) bool {
	return len(id) == 0 || string(id) == jsonrpc.Null
}

// joinStrings joins strings with newline separator, matching jsonrpc.ExtractText pattern.
func joinStrings(ss []string) string {
	return strings.Join(ss, "\n")
}

// scanSplitSecret checks for secrets split across multiple JSON fields by
// concatenating values without separators. Keys are excluded (via
// jsonrpc.ExtractStringsFromJSON, not extract.AllStringsFromJSON) because interleaved
// keys break DLP regex adjacency. Returns the original result if clean or if
// concat adds no new information.
func scanSplitSecret(raw json.RawMessage, joined string, sc *scanner.Scanner, result scanner.TextDLPResult) scanner.TextDLPResult {
	if !result.Clean {
		return result
	}
	vals := jsonrpc.ExtractStringsFromJSON(raw)
	if len(vals) <= 1 {
		return result
	}
	concat := strings.Join(vals, "")
	if concat == joined {
		return result
	}
	return sc.ScanTextForDLP(context.Background(), concat)
}
