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
	"regexp"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	decide "github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// recoverer is an optional interface for sessions that support autonomous
// time-based de-escalation. Implemented by proxy.SessionState but not part
// of session.Recorder to avoid interface churn on mocks and tests.
type recoverer interface {
	TryAutoRecover(blockAllCheck func(int) bool) (bool, int, int)
}

// tryRecoverSession attempts autonomous de-escalation on the session recorder.
// No-op if rec does not implement recoverer or adaptive enforcement is disabled.
func tryRecoverSession(rec session.Recorder, adaptiveCfg *config.AdaptiveEnforcement, m *metrics.Metrics) {
	if adaptiveCfg == nil || !adaptiveCfg.Enabled {
		return
	}
	r, ok := rec.(recoverer)
	if !ok {
		return
	}
	blockAllCheck := func(level int) bool {
		return decide.UpgradeAction("", level, adaptiveCfg) == config.ActionBlock
	}
	if changed, from, to := r.TryAutoRecover(blockAllCheck); changed {
		fromLabel := session.EscalationLabel(from)
		toLabel := session.EscalationLabel(to)
		if m != nil {
			m.RecordSessionAutoDeescalation(fromLabel, toLabel)
			if from > 0 {
				m.SetAdaptiveSessionLevel(fromLabel, -1)
			}
			if to > 0 {
				m.SetAdaptiveSessionLevel(toLabel, 1)
			}
		}
	}
}

// methodToolsCall is the JSON-RPC method for MCP tool invocations.
const methodToolsCall = "tools/call"

// errPolicyBlocked is the error message returned when a tool call is denied by policy.
const errPolicyBlocked = "pipelock: request blocked by tool call policy"

// patternUnknown is the fallback DLP pattern name when Matches is empty but Clean is false.
const patternUnknown = "unknown"

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
	action string,
	onParseError string,
	blockedCh chan<- BlockedRequest,
	bindingCfg *SessionBindingConfig,
	tracker *RequestTracker,
	opts MCPProxyOpts,
) {
	sc := opts.Scanner
	policyCfg := opts.PolicyCfg
	ks := opts.KillSwitch
	chainMatcher := opts.ChainMatcher
	auditLogger := opts.AuditLogger
	cee := opts.CEE
	rec := opts.Rec
	adaptiveCfg := opts.AdaptiveCfg
	m := opts.Metrics
	obs := opts.captureObserver()

	defer close(blockedCh)

	// Helper: record an adaptive signal and handle escalation side-effects.
	// Eliminates repeated nil/enabled guards at every call site.
	recordAdaptiveSignal := func(sig session.SignalType) {
		if adaptiveCfg != nil && adaptiveCfg.Enabled {
			decide.RecordSignal(rec, sig, decide.EscalationParams{
				Threshold:     adaptiveCfg.EscalationThreshold,
				Logger:        auditLogger,
				Metrics:       m,
				ConsoleWriter: logW,
				Session:       "default",
			})
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

		// Strip any inbound com.pipelock/mediation from _meta before
		// scanning. Prevents spoofed mediation metadata from an agent
		// or upstream from passing through to the MCP server.
		line = stripInboundMCPMeta(line)

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

		// On-entry de-escalation: recover sessions stuck at block_all.
		// Runs before any per-message action so both clean and non-clean
		// messages benefit from recovery.
		if rec != nil {
			tryRecoverSession(rec, adaptiveCfg, m)
		}

		// Reject JSON-RPC batch requests unconditionally. MCP does not
		// use batch messages, and the response path already drops batch
		// arrays. Forwarding would produce a response blackhole and
		// bypass per-call checks (DoW, chain) due to the aggregated
		// verdict having no Method field.
		trimmedLine := bytes.TrimSpace(line)
		if len(trimmedLine) > 0 && trimmedLine[0] == '[' {
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked batch request (not supported by MCP)\n", lineNum)
			recordAdaptiveSignal(session.SignalBlock)
			blockedCh <- BlockedRequest{
				ID:           extractRPCID(line),
				ErrorCode:    -32600,
				ErrorMessage: "pipelock: batch requests are not supported by MCP",
			}
			continue
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

		// Defense-in-depth: session binding also rejects batches. The
		// unconditional batch reject above makes this unreachable, but
		// it stays as a safety net if the early check is ever removed.
		if bindingCfg != nil && bindingCfg.Baseline != nil && len(trimmedLine) > 0 && trimmedLine[0] == '[' {
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: batch request with session binding active\n", lineNum)
			bindingAction = bindingCfg.UnknownToolAction
			bindingReason = "session_binding:batch_request"
		}

		// Extract tool name once for binding, chain detection, and DoW tracking.
		var toolCallName string
		if verdict.Method == methodToolsCall {
			toolCallName = extractToolCallName(line)
		}

		// Denial-of-wallet: check tool call budget before forwarding.
		if opts.DoWCheck != nil && verdict.Method == methodToolsCall && toolCallName != "" {
			argsJSON := extractToolCallArgs(line)
			allowed, dowAction, dowReason, dowBudgetType := opts.DoWCheck(toolCallName, argsJSON)
			if !allowed {
				logMsg := fmt.Sprintf("pipelock: input line %d: tools/call %q DoW %s: %s (%s)",
					lineNum, toolCallName, dowAction, dowReason, dowBudgetType)
				_, _ = fmt.Fprintln(logW, logMsg)
				if dowAction == config.ActionBlock {
					if auditLogger != nil {
						auditLogger.LogBlocked(mustMCPAuditContext(auditLogger, "MCP", toolCallName), "denial_of_wallet", dowReason)
					}
					if m != nil {
						m.RecordBlocked("mcp", "denial_of_wallet", 0, "")
					}
					recordAdaptiveSignal(session.SignalBlock)
					blockedCh <- BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     logMsg,
						ErrorCode:      -32600,
						ErrorMessage:   "pipelock: " + dowReason,
					}
					continue
				}
				// dow_action: warn — log and record near-miss, but forward the request.
				if auditLogger != nil {
					auditLogger.LogAnomaly(mustMCPAuditContext(auditLogger, "MCP", toolCallName), "denial_of_wallet", dowReason, 0)
				}
				recordAdaptiveSignal(session.SignalNearMiss)
			}
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
		// Capture: record session binding verdict when a violation occurred.
		if bindingReason != "" {
			obs.ObserveToolPolicyVerdict(context.Background(), &capture.ToolPolicyRecord{
				Subsurface: "session_binding",
				Transport:  opts.Transport,
				Request: capture.CaptureRequest{
					ToolName:  toolCallName,
					MCPMethod: methodToolsCall,
				},
				RawFindings: []capture.Finding{{
					Kind:       capture.KindSessionBinding,
					ToolName:   toolCallName,
					PolicyRule: bindingReason,
					Action:     bindingAction,
				}},
				EffectiveAction: bindingAction,
				Outcome:         captureOutcome(bindingAction, false),
			})
		}

		// Frozen tool enforcement: when a session is in airlock hard tier,
		// only tools in the frozen snapshot are permitted. This prevents
		// tool injection after quarantine begins.
		if opts.ToolFreezer != nil && opts.FrozenToolStableKey != "" &&
			opts.ToolFreezer.IsFrozen(opts.FrozenToolStableKey) {
			// Fail-closed: block when tool name is empty (unparseable) or not in frozen set.
			if toolCallName == "" || !opts.ToolFreezer.IsToolAllowed(opts.FrozenToolStableKey, toolCallName) {
				frozenMsg := fmt.Sprintf("pipelock: input line %d: tools/call %q blocked by frozen tool inventory", lineNum, toolCallName)
				_, _ = fmt.Fprintln(logW, frozenMsg)
				if auditLogger != nil {
					auditLogger.LogBlocked(mustMCPAuditContext(auditLogger, "MCP", toolCallName), "frozen_tool", "tool not in frozen inventory")
				}
				if m != nil {
					m.RecordBlocked("mcp", "frozen_tool", 0, "")
				}
				recordAdaptiveSignal(session.SignalBlock)
				blockedCh <- BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     frozenMsg,
					ErrorCode:      -32600,
					ErrorMessage:   "pipelock: tool not in frozen inventory",
				}
				continue
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
				// Capture: record chain detection verdict.
				obs.ObserveToolPolicyVerdict(context.Background(), &capture.ToolPolicyRecord{
					Subsurface: "chain_detection",
					Transport:  opts.Transport,
					Request: capture.CaptureRequest{
						ToolName:  toolCallName,
						MCPMethod: methodToolsCall,
					},
					RawFindings: []capture.Finding{{
						Kind:     capture.KindChainDetection,
						Chain:    cv.PatternName,
						Severity: cv.Severity,
						Action:   cv.Action,
					}},
					EffectiveAction: cv.Action,
					Outcome:         captureOutcome(cv.Action, false),
				})
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

		// Pre-generate actionID for tools/call only — metadata methods
		// (tools/list, initialize, notifications) don't produce receipts.
		actionID := ""
		if verdict.Method == methodToolsCall {
			actionID = receipt.NewActionID()
		}

		taintDecision := taintDecision{
			Authority: session.AuthorityUserBroad,
			Result:    session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: taintReasonDisabled},
		}
		emitToolReceipt := func(receiptVerdict string) {
			if actionID == "" || opts.ReceiptEmitter == nil {
				return
			}
			_ = opts.ReceiptEmitter.Emit(receipt.EmitOpts{
				ActionID:            actionID,
				Verdict:             receiptVerdict,
				Transport:           opts.Transport,
				Target:              toolCallName,
				MCPMethod:           verdict.Method,
				ToolName:            toolCallName,
				SessionTaintLevel:   taintDecision.Risk.Level.String(),
				SessionContaminated: taintDecision.Risk.Contaminated,
				RecentTaintSources:  taintDecision.Risk.Sources,
				SessionTaskID:       taintDecision.Task.CurrentTaskID,
				SessionTaskLabel:    taintDecision.Task.CurrentTaskLabel,
				AuthorityKind:       taintDecision.Authority.String(),
				TaintDecision:       taintDecision.Result.Decision.String(),
				TaintDecisionReason: taintDecision.Result.Reason,
				TaskOverrideApplied: taintDecision.TaskOverrideApplied,
			})
		}
		if verdict.Method == methodToolsCall {
			taintDecision = evaluateMCPTaint(opts, toolCallName, extractToolCallArgs(line))
			if taintDecision.Result.Decision == session.PolicyAsk || taintDecision.Result.Decision == session.PolicyBlock {
				if auditLogger != nil {
					auditLogger.LogTaintDecision(
						mustMCPAuditContext(auditLogger, "MCP", toolCallName),
						taintDecision.Risk.Level.String(),
						taintDecision.ActionClass.String(),
						taintDecision.Sensitivity.String(),
						taintDecision.Authority.String(),
						taintDecision.Result.Decision.String(),
						taintDecision.Result.Reason,
						taintDecision.Risk.LastExternalURL,
						taintDecision.Risk.LastExternalKind,
					)
				}
				switch taintDecision.Result.Decision {
				case session.PolicyBlock:
					blockedCh <- BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked by taint policy", lineNum),
						ErrorCode:      -32002,
						ErrorMessage:   "pipelock: " + taintDecision.Result.Reason,
					}
					emitToolReceipt(config.ActionBlock)
					continue
				case session.PolicyAsk:
					preview := strings.TrimSpace(fmt.Sprintf("%s %s", toolCallName, taintDecision.ActionRef))
					approved, hasApprover := taintDecisionRequiresApproval(opts, toolCallName, taintApprovalReason(taintDecision), preview)
					if !hasApprover || !approved {
						blockedCh <- BlockedRequest{
							ID:             verdict.ID,
							IsNotification: isRPCNotification(verdict.ID),
							LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked by taint policy", lineNum),
							ErrorCode:      -32002,
							ErrorMessage:   "pipelock: " + taintDecision.Result.Reason,
						}
						emitToolReceipt(config.ActionBlock)
						continue
					}
					approveTaintDecision(&taintDecision)
				}
			}
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
				// Capture: record CEE verdict.
				obs.ObserveCEEVerdict(context.Background(), &capture.CEERecord{
					Subsurface: "cee_mcp_stdio",
					Transport:  opts.Transport,
					RawFindings: []capture.Finding{{
						Kind:   capture.KindCEE,
						Action: config.ActionBlock,
					}},
					EffectiveAction: config.ActionBlock,
					Outcome:         capture.OutcomeBlocked,
				})
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
			fwdLine := line
			if verdict.Method == methodToolsCall {
				fwdLine = injectMCPEnvelope(line, opts.EnvelopeEmitter, envelope.BuildOpts{
					ActionID:       actionID,
					Action:         string(receipt.ClassifyMCPTool(toolCallName, verdict.Method)),
					Verdict:        config.ActionAllow,
					SessionTaint:   taintDecision.Risk.Level.String(),
					TaskID:         taintDecision.Task.CurrentTaskID,
					AuthorityKind:  taintDecision.Authority.String(),
					RequiresReauth: taintDecision.RequiresReauth,
				})
			}
			if err := writer.WriteMessage(fwdLine); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
			emitToolReceipt(config.ActionAllow)
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
			method = patternUnknown
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
			result := executeRedirect(profile, policyVerdict.RedirectProfile, verdict.ID, toolArgs, policyRuleName, opts.RedirectRT)
			// Determine final outcome before audit logging so the event
			// reflects the actual result delivered to the client.
			finalResult := "blocked"
			if result.Success {
				// Scan redirect handler output for prompt injection AND DLP before
				// sending to client. Handler output is untrusted.
				scanVerdict := ScanResponse(result.Response, sc)
				// context.Background: no request context in stdio loop; param unused in ScanTextForDLP.
				dlpResult := sc.ScanTextForDLP(context.Background(), string(result.Response))
				// Capture: record redirect output scan verdict.
				obs.ObserveResponseVerdict(context.Background(), &capture.ResponseVerdictRecord{
					Subsurface:      "response_redirect_output",
					Transport:       opts.Transport,
					TransformKind:   capture.TransformRedirectOutput,
					WirePayload:     result.Response,
					RawFindings:     responseMatchesToFindings(scanVerdict.Matches, config.ActionBlock),
					EffectiveAction: config.ActionBlock,
					Outcome:         captureOutcome(config.ActionBlock, scanVerdict.Clean),
				})
				if !scanVerdict.Clean {
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked redirect response (injection detected in handler output)\n", lineNum)
					blockedCh <- BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isNotification,
						LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect output injection)", lineNum),
						ErrorCode:      -32001,
						ErrorMessage:   "pipelock: redirect handler output blocked by response scanning",
					}
				} else if !dlpResult.Clean {
					pattern := patternUnknown
					if len(dlpResult.Matches) > 0 {
						pattern = dlpResult.Matches[0].PatternName
					}
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked redirect response (DLP match in handler output: %s)\n", lineNum, pattern)
					blockedCh <- BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isNotification,
						LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect output DLP)", lineNum),
						ErrorCode:      -32001,
						ErrorMessage:   "pipelock: redirect handler output blocked by DLP scanning",
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
				// Capture: record CEE verdict (warn-path).
				obs.ObserveCEEVerdict(context.Background(), &capture.CEERecord{
					Subsurface: "cee_mcp_stdio",
					Transport:  opts.Transport,
					RawFindings: []capture.Finding{{
						Kind:   capture.KindCEE,
						Action: config.ActionBlock,
					}},
					EffectiveAction: config.ActionBlock,
					Outcome:         capture.OutcomeBlocked,
				})
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
			// Inject envelope for warn-mode tool calls before forwarding.
			fwdLine := line
			if verdict.Method == methodToolsCall {
				fwdLine = injectMCPEnvelope(line, opts.EnvelopeEmitter, envelope.BuildOpts{
					ActionID:       actionID,
					Action:         string(receipt.ClassifyMCPTool(toolCallName, verdict.Method)),
					Verdict:        config.ActionWarn,
					SessionTaint:   taintDecision.Risk.Level.String(),
					TaskID:         taintDecision.Task.CurrentTaskID,
					AuthorityKind:  taintDecision.Authority.String(),
					RequiresReauth: taintDecision.RequiresReauth,
				})
			}
			// Forward anyway (warn mode).
			if err := writer.WriteMessage(fwdLine); err != nil {
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

		// Action receipt: emit for tools/call decisions only.
		emitToolReceipt(effectiveAction)

		// Capture: record DLP/injection input verdict.
		if !verdict.Clean {
			var rawFindings []capture.Finding
			rawFindings = append(rawFindings, dlpMatchesToFindings(verdict.Matches)...)
			rawFindings = append(rawFindings, responseMatchesToFindings(verdict.Inject, effectiveAction)...)
			rawFindings = append(rawFindings, addressFindingsToCapture(verdict.AddressFindings)...)
			obs.ObserveDLPVerdict(context.Background(), &capture.DLPVerdictRecord{
				Subsurface:      "dlp_mcp_input",
				Transport:       opts.Transport,
				TransformKind:   capture.TransformJoinedFields,
				RawFindings:     rawFindings,
				EffectiveAction: effectiveAction,
				Outcome:         captureOutcome(effectiveAction, false),
			})
		}
		// Capture: record tool policy verdict when policy matched.
		if policyVerdict.Matched {
			var policyFindings []capture.Finding
			for _, r := range policyVerdict.Rules {
				policyFindings = append(policyFindings, capture.Finding{
					Kind:       capture.KindToolPolicy,
					PolicyRule: r,
					Action:     policyVerdict.Action,
				})
			}
			obs.ObserveToolPolicyVerdict(context.Background(), &capture.ToolPolicyRecord{
				Subsurface: "mcp_tool_policy",
				Transport:  opts.Transport,
				Request: capture.CaptureRequest{
					ToolName:  toolCallName,
					MCPMethod: verdict.Method,
				},
				RawFindings:     policyFindings,
				EffectiveAction: effectiveAction,
				Outcome:         captureOutcome(effectiveAction, false),
			})
		}
	}
}

// jsonUnicodeEscapeRe matches JSON \uXXXX escape sequences (4 hex digits).
var jsonUnicodeEscapeRe = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)

// unescapeJSONUnicode resolves JSON \uXXXX escape sequences to their UTF-8
// representation. Works on arbitrary text (including malformed JSON) by using
// regex replacement rather than JSON parsing. Handles surrogate pairs by
// replacing each \uXXXX independently (the high surrogate alone produces a
// replacement character, but the concatenated result still matches DLP patterns).
func unescapeJSONUnicode(s string) string {
	if !strings.Contains(s, `\u`) {
		return s
	}
	return jsonUnicodeEscapeRe.ReplaceAllStringFunc(s, func(match string) string {
		// match is `\uXXXX` (6 chars). Parse the 4 hex digits into uint32.
		// 4 hex digits max = 0xFFFF which fits in int32/rune without overflow.
		code, err := strconv.ParseInt(match[2:], 16, 32)
		if err != nil {
			return match
		}
		return string(rune(code))
	})
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

// injectMCPEnvelope injects a mediation envelope into a JSON-RPC message's
// params._meta field. Returns the modified message bytes, or the original
// message unmodified if parsing fails (fail-open for envelope injection --
// the message was already allowed).
func injectMCPEnvelope(msg []byte, emitter *envelope.Emitter, buildOpts envelope.BuildOpts) []byte {
	if emitter == nil {
		return msg
	}

	var rpc map[string]json.RawMessage
	if err := json.Unmarshal(msg, &rpc); err != nil {
		return msg
	}

	paramsRaw, ok := rpc["params"]
	if !ok {
		return msg
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return msg
	}
	if params == nil {
		params = make(map[string]json.RawMessage)
	}

	// Use json.RawMessage to preserve existing _meta members byte-for-byte.
	// map[string]any would round-trip through encoding/json and lose precision
	// on large integer values from other extensions.
	meta := make(map[string]json.RawMessage)
	if metaRaw, exists := params["_meta"]; exists {
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			return msg // malformed _meta -- fail-open
		}
	}
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}

	// Strip any existing mediation key, then inject.
	delete(meta, envelope.MCPMetaKey)
	envData := emitter.Build(buildOpts).ToMCPMeta()
	envBytes, err := json.Marshal(envData)
	if err != nil {
		return msg
	}
	meta[envelope.MCPMetaKey] = envBytes

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return msg
	}
	params["_meta"] = metaBytes

	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return msg
	}
	rpc["params"] = paramsBytes

	out, err := json.Marshal(rpc)
	if err != nil {
		return msg
	}
	return out
}

// stripInboundMCPMeta removes the com.pipelock/mediation key from a
// JSON-RPC message's params._meta before scanning. Prevents spoofed
// mediation metadata from passing through unmodified.
// Returns the modified message or the original if parsing fails.
func stripInboundMCPMeta(msg []byte) []byte {
	var rpc map[string]json.RawMessage
	if err := json.Unmarshal(msg, &rpc); err != nil {
		return msg
	}

	paramsRaw, ok := rpc["params"]
	if !ok {
		return msg
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return msg
	}
	if params == nil {
		return msg
	}

	metaRaw, ok := params["_meta"]
	if !ok {
		return msg
	}

	var meta map[string]json.RawMessage
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return msg
	}

	if meta == nil {
		return msg
	}
	if _, exists := meta[envelope.MCPMetaKey]; !exists {
		return msg
	}

	delete(meta, envelope.MCPMetaKey)

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return msg
	}
	params["_meta"] = metaBytes

	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return msg
	}
	rpc["params"] = paramsBytes

	out, err := json.Marshal(rpc)
	if err != nil {
		return msg
	}
	return out
}
