// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// RunHTTPProxy bridges stdio (client) to an upstream HTTP MCP server with
// bidirectional scanning. Reads JSON-RPC from clientIn, POSTs to upstreamURL,
// scans responses via ForwardScanned, writes to clientOut.
// When opts.Store is non-nil, a per-invocation session recorder is created and
// used for adaptive enforcement signal recording across both input and response
// scanning.
func RunHTTPProxy(
	ctx context.Context,
	clientIn io.Reader,
	clientOut io.Writer,
	logW io.Writer,
	upstreamURL string,
	extraHeaders http.Header,
	opts MCPProxyOpts,
) error {
	// Set transport for capture records if not already set by caller.
	if opts.Transport == "" {
		opts.Transport = "mcp_http"
	}
	opts.TaintExternalSource = true

	// Create a child context so we can stop the GET stream when stdin EOF is reached.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Per-invocation adaptive enforcement recorder.
	var rec session.Recorder
	if opts.Store != nil {
		rec = opts.Store.GetOrCreate(session.NextInvocationKey("mcp-http"))
	}

	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}

	httpClient := transport.NewHTTPClient(upstreamURL, extraHeaders)

	// Tool scanning baseline for this session. Clone the caller's ToolCfg
	// with a fresh per-session baseline so drift detection is scoped to
	// this invocation.
	var fwdToolCfg *tools.ToolScanConfig
	if opts.ToolCfg != nil && opts.ToolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:    tools.NewToolBaseline(),
			Action:      opts.ToolCfg.Action,
			DetectDrift: opts.ToolCfg.DetectDrift,
			ExtraPoison: opts.ToolCfg.ExtraPoison,
		}
	}

	// Request tracker for confused deputy protection.
	tracker := NewRequestTracker()

	// Session-scoped opts: override Rec and ToolCfg from the caller's opts.
	fwdOpts := opts
	fwdOpts.Rec = rec
	fwdOpts.ToolCfg = fwdToolCfg

	clientReader := transport.NewStdioReader(clientIn)

	var wg sync.WaitGroup
	var getStreamOnce sync.Once
	var lastScanErr error

	for {
		msg, err := clientReader.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("reading stdin: %w", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Kill switch: deny all messages when active.
		if opts.KillSwitch != nil {
			if d := opts.KillSwitch.IsActiveMCP(msg); d.Active {
				if d.IsNotification {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					continue
				}
				rpcID := extractRPCID(msg)
				resp := killswitch.ErrorResponse(rpcID, d.Message)
				if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send kill switch response: %v\n", wErr)
				}
				continue
			}
		}

		// Input scanning — call ScanRequest and CheckRequest directly.
		// The sequential (non-concurrent) architecture means no channel needed.
		decision := scanHTTPInputDecision(msg, safeLogW, "default", "default", fwdOpts)
		if decision.Blocked != nil {
			if !decision.Blocked.IsNotification {
				var resp []byte
				if decision.Blocked.SyntheticResponse != nil {
					resp = decision.Blocked.SyntheticResponse
				} else {
					resp = blockRequestResponse(*decision.Blocked)
				}
				if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send block response: %v\n", wErr)
				}
			}
			continue
		}

		// Track request ID before sending to upstream for confused deputy protection.
		// Only track requests (have "method"), not client responses to
		// server-initiated calls, to prevent tracker pollution.
		if isRequest(msg) {
			tracker.Track(extractRPCID(msg))
		}

		// POST to upstream.
		respReader, err := httpClient.SendMessage(ctx, decision.ForwardMessage)
		if err != nil {
			// Log full upstream error details to stderr for debugging.
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			// Send sanitized error to client — don't include upstream body content
			// which could contain prompt injection payloads.
			rpcID := extractRPCID(msg)
			errResp := upstreamErrorResponse(rpcID, fmt.Errorf("upstream HTTP request failed"))
			if wErr := safeClientOut.WriteMessage(errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send error response: %v\n", wErr)
			}
			continue
		}

		// Scan and forward response.
		_, scanErr := ForwardScanned(respReader, safeClientOut, safeLogW, tracker, fwdOpts)
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
			lastScanErr = scanErr
		}

		// After first successful response with a session ID, start GET stream
		// for server-initiated messages. Check session ID OUTSIDE the Once so
		// that early responses without a session ID (e.g. 202) don't consume
		// the Once and permanently prevent the GET stream.
		if httpClient.SessionID() != "" {
			getStreamOnce.Do(func() {
				startGETStream(ctx, httpClient, safeClientOut, safeLogW, fwdOpts, &wg)
			})
		}
	}

	// Terminate session if established.
	if httpClient.SessionID() != "" {
		httpClient.DeleteSession(safeLogW)
	}

	// Stop GET stream and wait for it to finish.
	cancel()
	wg.Wait()

	return lastScanErr
}

type httpInputDecision struct {
	Blocked        *BlockedRequest
	ForwardMessage []byte
}

const redirectResultRedirected = "redirected"

// scanHTTPInput checks a single input message for DLP/injection/policy/CEE.
// Returns a *BlockedRequest if the message should be blocked, nil if clean.
func scanHTTPInput(msg []byte, logW io.Writer, sessionKey, auditSessionKey string, opts MCPProxyOpts) *BlockedRequest {
	return scanHTTPInputDecision(msg, logW, sessionKey, auditSessionKey, opts).Blocked
}

// scanHTTPInputDecision is the HTTP proxy equivalent of ForwardScannedInput's
// per-message logic, but returns the block verdict plus the message to forward.
// When cee is non-nil, outbound payloads are recorded for cross-request
// exfiltration detection after content scanning passes.
func scanHTTPInputDecision(msg []byte, logW io.Writer, sessionKey, auditSessionKey string, opts MCPProxyOpts) httpInputDecision {
	sc := opts.Scanner
	inputCfg := opts.InputCfg
	policyCfg := opts.PolicyCfg
	chainMatcher := opts.ChainMatcher
	auditLogger := opts.AuditLogger
	cee := opts.CEE
	rec := opts.Rec
	adaptiveCfg := opts.AdaptiveCfg
	m := opts.Metrics
	obs := opts.captureObserver()
	result := httpInputDecision{ForwardMessage: msg}
	mcpMethod := ""
	toolName := ""
	actionID := ""
	taintEval := taintDecision{
		Authority: session.AuthorityUserBroad,
		Result:    session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: taintReasonDisabled},
	}
	receiptVerdict := ""
	defer func() {
		emitMCPToolReceipt(opts, actionID, mcpMethod, toolName, receiptVerdict, taintEval)
	}()

	// Helper: record an adaptive signal and handle escalation side-effects.
	// Eliminates repeated nil/enabled guards at every call site.
	recordAdaptiveSignal := func(sig session.SignalType) {
		if adaptiveCfg != nil && adaptiveCfg.Enabled {
			decide.RecordSignal(rec, sig, decide.EscalationParams{
				Threshold:     adaptiveCfg.EscalationThreshold,
				Logger:        auditLogger,
				Metrics:       m,
				ConsoleWriter: logW,
				Session:       auditSessionKey,
			})
		}
	}

	// On-entry de-escalation: recover sessions stuck at block_all.
	// Runs before any per-message action so both clean and non-clean
	// messages benefit from recovery.
	if rec != nil {
		tryRecoverSession(rec, adaptiveCfg, m)
	}

	// Reject JSON-RPC batch requests unconditionally. MCP does not use
	// batch messages, and the response path already drops batch arrays
	// (proxy.go, proxy_http.go upstream handler). Forwarding a batch
	// would produce a response blackhole. Rejecting here also closes the
	// verdict.Method gap where per-call checks (DoW, chain, A2A) were
	// silently skipped because the aggregated verdict had no Method.
	if trimmed := bytes.TrimSpace(msg); len(trimmed) > 0 && trimmed[0] == '[' {
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked batch request (not supported by MCP)\n")
		recordAdaptiveSignal(session.SignalBlock)
		result.Blocked = &BlockedRequest{
			ID:           extractRPCID(msg),
			ErrorCode:    -32600,
			ErrorMessage: "pipelock: batch requests are not supported by MCP",
		}
		return result
	}

	// Determine input scanning parameters.
	action := config.ActionWarn
	onParseError := config.ActionBlock
	if inputCfg != nil && inputCfg.Enabled {
		action = inputCfg.Action
		onParseError = inputCfg.OnParseError
	}

	// Content scan.
	var verdict InputVerdict
	scanEnabled := inputCfg != nil && inputCfg.Enabled
	if scanEnabled {
		verdict = ScanRequest(msg, sc, action, onParseError)
	} else {
		verdict = InputVerdict{Clean: true}
		// When input scanning is disabled, extract enough metadata from the
		// raw message so policy, taint gating, chain detection, and DoW still work.
		if policyCfg != nil || chainMatcher != nil || opts.DoWCheck != nil || opts.TaintCfg != nil || opts.ReceiptEmitter != nil || opts.EnvelopeEmitter != nil {
			verdict.ID = extractRPCID(msg)
			// Extract method for chain detection even when content scanning is off.
			var env struct {
				Method string `json:"method"`
			}
			if json.Unmarshal(msg, &env) == nil {
				verdict.Method = env.Method
			}
		}
	}

	mcpMethod = verdict.Method
	if verdict.Method == methodToolsCall {
		actionID = receipt.NewActionID()
		toolName = extractToolCallName(msg)
	}

	// A2A request body scanning: field-aware analysis for A2A protocol methods.
	// Runs after content scanning so both pipelines contribute findings.
	// When the method is unknown (input scanning disabled, no policy/chain),
	// extract it for A2A detection.
	if opts.A2ACfg != nil && opts.A2ACfg.Enabled {
		method := verdict.Method
		if method == "" {
			var env struct {
				Method string          `json:"method"`
				ID     json.RawMessage `json:"id"`
			}
			if json.Unmarshal(msg, &env) == nil {
				method = env.Method
				// Backfill verdict.ID so IsNotification works correctly
				// when input scanning is disabled and no policy/chain config
				// triggered the earlier extraction.
				if verdict.ID == nil && len(env.ID) > 0 && string(env.ID) != jsonrpc.Null {
					verdict.ID = env.ID
				}
			}
		}
		if IsA2AMethod(method) {
			a2aResult := ScanA2ARequestBody(context.Background(), msg, sc, opts.A2ACfg)
			if !a2aResult.Clean {
				a2aAction := a2aResult.Action
				if a2aAction == "" {
					a2aAction = opts.A2ACfg.Action
				}
				if a2aAction == config.ActionBlock {
					_, _ = fmt.Fprintf(logW, "pipelock: a2a input: blocked (%s)\n", a2aResult.Reason)
					if a2aResult.IsConfigMismatch() {
						recordAdaptiveSignal(session.SignalNearMiss)
					} else {
						recordAdaptiveSignal(session.SignalBlock)
					}
					result.Blocked = &BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     "blocked (a2a input scanning)",
						ErrorCode:      -32001,
						ErrorMessage:   "pipelock: request blocked by A2A input scanning",
					}
					return result
				}
				// warn mode: log and continue.
				_, _ = fmt.Fprintf(logW, "pipelock: a2a input: warning (%s)\n", a2aResult.Reason)
				recordAdaptiveSignal(session.SignalNearMiss)
			}
		}
	}

	// Denial-of-wallet: check tool call budget before forwarding.
	if opts.DoWCheck != nil && verdict.Method == methodToolsCall {
		toolName := extractToolCallName(msg)
		if toolName != "" {
			argsJSON := extractToolCallArgs(msg)
			allowed, dowAction, dowReason, dowBudgetType := opts.DoWCheck(toolName, argsJSON)
			if !allowed {
				_, _ = fmt.Fprintf(logW, "pipelock: tools/call %q DoW %s: %s (%s)\n",
					toolName, dowAction, dowReason, dowBudgetType)
				if dowAction == config.ActionBlock {
					if auditLogger != nil {
						auditLogger.LogBlocked(audit.NewMCPLogContext("MCP", toolName, ""), "denial_of_wallet", dowReason)
					}
					if m != nil {
						m.RecordBlocked("mcp", "denial_of_wallet", 0, "")
					}
					recordAdaptiveSignal(session.SignalBlock)
					result.Blocked = &BlockedRequest{ID: verdict.ID, IsNotification: isRPCNotification(verdict.ID), ErrorCode: -32600, ErrorMessage: "pipelock: " + dowReason}
					return result
				}
				// dow_action: warn — log and record near-miss, but allow the request.
				if auditLogger != nil {
					auditLogger.LogAnomaly(audit.NewMCPLogContext("MCP", toolName, ""), "denial_of_wallet", dowReason, 0)
				}
				recordAdaptiveSignal(session.SignalNearMiss)
			}
		}
	}

	// Policy check.
	policyVerdict := policy.Verdict{}
	if policyCfg != nil {
		policyVerdict = policyCfg.CheckRequest(msg)
	}

	// Chain detection: check if this tool call matches an attack pattern.
	chainAction := ""
	chainReason := ""
	if chainMatcher != nil && verdict.Method == methodToolsCall {
		toolName := extractToolCallName(msg)
		if toolName != "" {
			cv := chainMatcher.Record(sessionKey, toolName, string(msg))
			if cv.Matched {
				_, _ = fmt.Fprintf(logW, "pipelock: chain detected: %s (severity=%s, action=%s)\n",
					cv.PatternName, cv.Severity, cv.Action)
				if auditLogger != nil {
					auditLogger.LogChainDetection(cv.PatternName, cv.Severity, cv.Action, toolName, auditSessionKey)
				}
				if cv.Action == config.ActionBlock {
					recordAdaptiveSignal(session.SignalBlock)
					result.Blocked = &BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     fmt.Sprintf("chain pattern %q blocked", cv.PatternName),
						ErrorCode:      -32004,
						ErrorMessage:   fmt.Sprintf("tool call blocked: chain pattern %q detected", cv.PatternName),
					}
					return result
				}
				chainAction = cv.Action
				chainReason = "chain:" + cv.PatternName
			}
		}
	}

	// Parse error — always block.
	if verdict.Error != "" {
		_, _ = fmt.Fprintf(logW, "pipelock: input: %s\n", verdict.Error)
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isRPCNotification(verdict.ID),
			LogMessage:     "blocked (parse error)",
		}
		return result
	}

	if verdict.Method == methodToolsCall {
		taintEval = evaluateMCPTaint(opts, toolName, extractToolCallArgs(msg))
		if taintEval.Result.Decision == session.PolicyAsk || taintEval.Result.Decision == session.PolicyBlock {
			if auditLogger != nil {
				auditLogger.LogTaintDecision(
					audit.LogContext{Method: "MCP", URL: toolName},
					taintEval.Risk.Level.String(),
					taintEval.ActionClass.String(),
					taintEval.Sensitivity.String(),
					taintEval.Authority.String(),
					taintEval.Result.Decision.String(),
					taintEval.Result.Reason,
					taintEval.Risk.LastExternalURL,
					taintEval.Risk.LastExternalKind,
				)
			}
			switch taintEval.Result.Decision {
			case session.PolicyBlock:
				receiptVerdict = config.ActionBlock
				result.Blocked = &BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     "blocked by taint policy",
					ErrorCode:      -32002,
					ErrorMessage:   "pipelock: " + taintEval.Result.Reason,
				}
				return result
			case session.PolicyAsk:
				preview := strings.TrimSpace(fmt.Sprintf("%s %s", toolName, taintEval.ActionRef))
				approved, hasApprover := taintDecisionRequiresApproval(opts, toolName, taintApprovalReason(taintEval), preview)
				if !hasApprover || !approved {
					receiptVerdict = config.ActionBlock
					result.Blocked = &BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     "blocked by taint policy",
						ErrorCode:      -32002,
						ErrorMessage:   "pipelock: " + taintEval.Result.Reason,
					}
					return result
				}
				approveTaintDecision(&taintEval)
			}
		}
	}

	// All clean — proceed (with block_all and CEE checks).
	if verdict.Clean && !policyVerdict.Matched && chainAction == "" {
		// block_all enforcement: deny ALL traffic (including clean) when the
		// session is at an escalation level with block_all=true.
		if rec != nil && decide.UpgradeAction("", rec.EscalationLevel(), adaptiveCfg) == config.ActionBlock {
			_, _ = fmt.Fprintf(logW, "pipelock: adaptive upgrade (clean) -> block (level %s)\n", session.EscalationLabel(rec.EscalationLevel()))
			if m != nil {
				m.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(rec.EscalationLevel()))
			}
			receiptVerdict = config.ActionBlock
			result.Blocked = &BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     "blocked (session deny)",
				ErrorCode:      -32001,
				ErrorMessage:   "pipelock: session escalation level critical",
			}
			return result
		}
		// Cross-request exfiltration check on clean outbound messages.
		ceeKey := ceeSessionKeyMCP("", sessionKey)
		if reason := ceeRecordMCP(ceeKey, msg, cee, sc, logW, auditLogger); reason != "" {
			// Capture: record CEE verdict.
			obs.ObserveCEEVerdict(context.Background(), &capture.CEERecord{
				Subsurface: "cee_mcp_http",
				Transport:  opts.Transport,
				RawFindings: []capture.Finding{{
					Kind:   capture.KindCEE,
					Action: config.ActionBlock,
				}},
				EffectiveAction: config.ActionBlock,
				Outcome:         capture.OutcomeBlocked,
			})
			receiptVerdict = config.ActionBlock
			result.Blocked = &BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     "CEE blocked",
				ErrorCode:      -32005,
				ErrorMessage:   fmt.Sprintf("pipelock: %s", reason),
			}
			return result
		}
		if verdict.Method == methodToolsCall {
			result.ForwardMessage = decorateMCPToolMessage(msg, opts.EnvelopeEmitter, actionID, verdict.Method, toolName, config.ActionAllow, taintEval)
			receiptVerdict = config.ActionAllow
		}
		if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
			rec.RecordClean(adaptiveCfg.DecayPerCleanRequest)
		}
		return result
	}

	// Build reasons.
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
	if chainReason != "" {
		reasons = append(reasons, chainReason)
	}

	// Determine effective action (strictest wins).
	// mergeAction sets effectiveAction to the stricter of cur and next,
	// handling the initial empty state correctly (empty = no action yet).
	effectiveAction := ""
	mergeAction := func(cur, next string) string {
		if cur == "" {
			return next
		}
		return policy.StricterAction(cur, next)
	}
	if !verdict.Clean {
		effectiveAction = action
	}
	if policyVerdict.Matched {
		effectiveAction = mergeAction(effectiveAction, policyVerdict.Action)
	}
	if chainAction != "" {
		effectiveAction = mergeAction(effectiveAction, chainAction)
	}

	isNotification := isRPCNotification(verdict.ID)

	// Error code/message based on what triggered.
	errCode := 0
	errMsg := ""
	if verdict.Clean && policyVerdict.Matched {
		errCode = -32002
		errMsg = errPolicyBlocked
	}

	// Escalation upgrade: may promote warn/ask to block for elevated sessions.
	originalAction := effectiveAction
	if rec != nil {
		effectiveAction = decide.UpgradeAction(effectiveAction, rec.EscalationLevel(), adaptiveCfg)
	}
	if effectiveAction != originalAction {
		levelLabel := session.EscalationLabel(rec.EscalationLevel())
		_, _ = fmt.Fprintf(logW, "pipelock: adaptive upgrade %s -> %s (level %s)\n", originalAction, effectiveAction, levelLabel)
		if auditLogger != nil {
			auditLogger.LogAdaptiveUpgrade(auditSessionKey, levelLabel, originalAction, effectiveAction, "mcp_input", "", "")
		}
		if m != nil {
			m.RecordAdaptiveUpgrade(originalAction, effectiveAction, levelLabel)
		}
	}

	switch effectiveAction {
	case config.ActionBlock:
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s)\n", joinStrings(reasons))
		recordAdaptiveSignal(session.SignalBlock)
		receiptVerdict = effectiveAction
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isNotification,
			LogMessage:     "blocked",
			ErrorCode:      errCode,
			ErrorMessage:   errMsg,
		}
		return result
	case config.ActionRedirect:
		// Batch requests cannot be redirected element-by-element. Fail closed.
		trimmedMsg := bytes.TrimSpace(msg)
		if len(trimmedMsg) > 0 && trimmedMsg[0] == '[' {
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked batch (%s) [redirect not supported for batches]\n", joinStrings(reasons))
			recordAdaptiveSignal(session.SignalBlock)
			receiptVerdict = effectiveAction
			result.Blocked = &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (batch redirect)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
			return result
		}
		if policyCfg == nil {
			// No policy config — fail closed.
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [redirect without policy config]\n", joinStrings(reasons))
			recordAdaptiveSignal(session.SignalBlock)
			receiptVerdict = effectiveAction
			result.Blocked = &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (no policy config)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
			return result
		}
		profile, ok := policyCfg.RedirectProfiles[policyVerdict.RedirectProfile]
		if !ok {
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [redirect profile %q not found]\n", joinStrings(reasons), policyVerdict.RedirectProfile)
			recordAdaptiveSignal(session.SignalBlock)
			receiptVerdict = effectiveAction
			result.Blocked = &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (redirect profile missing)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
			return result
		}
		toolName, toolArgs := extractToolCallFields(msg)
		policyRuleName := ""
		if len(policyVerdict.Rules) > 0 {
			policyRuleName = policyVerdict.Rules[0]
		}
		redirectResult := executeRedirect(profile, policyVerdict.RedirectProfile, verdict.ID, toolArgs, policyRuleName, opts.RedirectRT)
		// Determine final outcome before audit logging so the event
		// reflects the actual result delivered to the client.
		var br *BlockedRequest
		finalResult := "blocked"
		if redirectResult.Success {
			// Scan redirect handler output for prompt injection AND DLP before
			// sending to client. Handler output is untrusted — it could contain
			// secrets or injection payloads.
			scanVerdict := ScanResponse(redirectResult.Response, sc)
			// context.Background: scanHTTPInput has no ctx param; param unused in ScanTextForDLP.
			dlpResult := sc.ScanTextForDLP(context.Background(), string(redirectResult.Response))
			if !scanVerdict.Clean {
				_, _ = fmt.Fprintf(logW, "pipelock: input: blocked redirect response (injection detected in handler output)\n")
				recordAdaptiveSignal(session.SignalBlock)
				br = &BlockedRequest{
					ID: verdict.ID, IsNotification: isNotification,
					LogMessage: "blocked (redirect output injection)", ErrorCode: -32001,
					ErrorMessage: "pipelock: redirect handler output blocked by response scanning",
				}
			} else if !dlpResult.Clean {
				pattern := patternUnknown
				if len(dlpResult.Matches) > 0 {
					pattern = dlpResult.Matches[0].PatternName
				}
				_, _ = fmt.Fprintf(logW, "pipelock: input: blocked redirect response (DLP match in handler output: %s)\n", pattern)
				recordAdaptiveSignal(session.SignalBlock)
				br = &BlockedRequest{
					ID: verdict.ID, IsNotification: isNotification,
					LogMessage: "blocked (redirect output DLP)", ErrorCode: -32001,
					ErrorMessage: "pipelock: redirect handler output blocked by DLP scanning",
				}
			} else {
				finalResult = redirectResultRedirected
				_, _ = fmt.Fprintf(logW, "pipelock: input: redirected via profile %q (%dms)\n", policyVerdict.RedirectProfile, redirectResult.LatencyMs)
				br = &BlockedRequest{
					ID: verdict.ID, IsNotification: isNotification,
					LogMessage: "redirected", SyntheticResponse: redirectResult.Response,
				}
			}
		} else {
			// Redirect handler failed — fall through to block (fail-closed).
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [redirect failed: %s]\n", joinStrings(reasons), redirectResult.Error)
			recordAdaptiveSignal(session.SignalBlock)
			br = &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (redirect failed)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
		}
		if auditLogger != nil {
			auditLogger.LogToolRedirect(auditSessionKey, toolName, argsDigest(toolArgs), policyVerdict.RedirectProfile, profile.Reason, policyRuleName, finalResult, redirectResult.LatencyMs)
		}
		if finalResult == redirectResultRedirected {
			receiptVerdict = config.ActionRedirect
		} else {
			receiptVerdict = config.ActionBlock
		}
		result.Blocked = br
		return result
	case config.ActionAsk:
		// HITL for input scanning is impractical — fall back to block (same as stdio proxy).
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [ask not supported for input scanning]\n", joinStrings(reasons))
		recordAdaptiveSignal(session.SignalBlock)
		receiptVerdict = effectiveAction
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isNotification,
			LogMessage:     "blocked (ask fallback)",
			ErrorCode:      errCode,
			ErrorMessage:   errMsg,
		}
		return result
	default: // warn
		if len(reasons) > 0 {
			_, _ = fmt.Fprintf(logW, "pipelock: input: warning (%s)\n", joinStrings(reasons))
			recordAdaptiveSignal(session.SignalNearMiss)
		}
		// Cross-request exfiltration check even in warn mode.
		ceeKey := ceeSessionKeyMCP("", sessionKey)
		if reason := ceeRecordMCP(ceeKey, msg, cee, sc, logW, auditLogger); reason != "" {
			// Capture: record CEE verdict (warn-path).
			obs.ObserveCEEVerdict(context.Background(), &capture.CEERecord{
				Subsurface: "cee_mcp_http",
				Transport:  opts.Transport,
				RawFindings: []capture.Finding{{
					Kind:   capture.KindCEE,
					Action: config.ActionBlock,
				}},
				EffectiveAction: config.ActionBlock,
				Outcome:         capture.OutcomeBlocked,
			})
			receiptVerdict = config.ActionBlock
			result.Blocked = &BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     "CEE blocked",
				ErrorCode:      -32005,
				ErrorMessage:   fmt.Sprintf("pipelock: %s", reason),
			}
			return result
		}
		// Capture: record DLP/injection input verdict when not clean.
		if !verdict.Clean {
			var rawFindings []capture.Finding
			rawFindings = append(rawFindings, dlpMatchesToFindings(verdict.Matches)...)
			rawFindings = append(rawFindings, responseMatchesToFindings(verdict.Inject, effectiveAction)...)
			obs.ObserveDLPVerdict(context.Background(), &capture.DLPVerdictRecord{
				Subsurface:      "dlp_mcp_input",
				Transport:       opts.Transport,
				TransformKind:   capture.TransformJoinedFields,
				RawFindings:     rawFindings,
				EffectiveAction: effectiveAction,
				Outcome:         captureOutcome(effectiveAction, false),
			})
		}
		if verdict.Method == methodToolsCall {
			result.ForwardMessage = decorateMCPToolMessage(msg, opts.EnvelopeEmitter, actionID, verdict.Method, toolName, config.ActionWarn, taintEval)
			receiptVerdict = config.ActionWarn
		}
		return result // forward
	}
}

// hashSessionKey produces a short, non-reversible identifier from a raw IP
// for use in audit logs, so client IPs don't leak through the session field.
func hashSessionKey(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return "ip:" + hex.EncodeToString(h[:8]) // 16 hex chars, enough to correlate
}

// extractRPCID extracts the "id" field from a JSON-RPC message.
// Returns nil for notifications (no id field) or parse failures.
func extractRPCID(msg []byte) json.RawMessage {
	var rpc struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(msg, &rpc) != nil {
		return nil
	}
	if string(rpc.ID) == jsonrpc.Null || len(rpc.ID) == 0 {
		return nil
	}
	return rpc.ID
}

// validateRPCStructure checks JSON-RPC 2.0 structural requirements that
// json.Valid() cannot catch: version field, method presence, and method type.
// Returns an error message if invalid, empty string if ok.
func validateRPCStructure(msg []byte) string {
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  json.RawMessage `json:"method"`
	}
	if json.Unmarshal(msg, &env) != nil {
		return "invalid JSON structure"
	}
	// jsonrpc field must be exactly "2.0".
	if env.JSONRPC != jsonrpc.Version {
		return "jsonrpc field must be \"2.0\""
	}
	// method field is required for client requests.
	if len(env.Method) == 0 {
		return "missing required field: method"
	}
	// Method must be a JSON string (starts with quote).
	if env.Method[0] != '"' {
		return "method must be a string"
	}
	return ""
}

// upstreamErrorResponse creates a JSON-RPC error for HTTP transport failures.
// If id is nil, the response uses a JSON null id (valid for unidentifiable requests).
func upstreamErrorResponse(id json.RawMessage, upstreamErr error) []byte {
	resp := rpcError{
		JSONRPC: jsonrpc.Version,
		ID:      id,
		Error: rpcErrorDetail{
			Code:    -32003,
			Message: fmt.Sprintf("pipelock: upstream error: %v", upstreamErr),
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// startGETStream maintains a background GET SSE connection for server-initiated
// messages. Called after the initialize handshake establishes a session ID.
// Reconnects with exponential backoff (1s base, 30s cap) on stream end or
// transient errors. Exits permanently only on transport.ErrStreamNotSupported (HTTP 405)
// or context cancellation.
// opts carries Scanner, Approver, ToolCfg, KillSwitch, Rec, AdaptiveCfg, and
// Metrics through to ForwardScanned for adaptive enforcement.
func startGETStream(
	ctx context.Context,
	httpClient *transport.HTTPClient,
	safeClientOut *syncWriter,
	safeLogW *syncWriter,
	opts MCPProxyOpts,
	wg *sync.WaitGroup,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		backoff := time.Second
		const maxBackoff = 30 * time.Second

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Kill switch: pause reconnecting while active. Without this,
			// the retry loop keeps establishing outbound connections even
			// though ForwardScanned blocks every message. Wait here instead
			// of returning so the goroutine resumes when the switch clears.
			if opts.KillSwitch != nil && opts.KillSwitch.IsActive() {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream paused: kill switch active\n")
				for opts.KillSwitch.IsActive() {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Second):
					}
				}
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream resuming: kill switch cleared\n")
			}

			reader, err := httpClient.OpenGETStream(ctx)
			if err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream: %v\n", err)
				// Permanent error — server does not support GET streams.
				if errors.Is(err, transport.ErrStreamNotSupported) {
					return
				}
				// Transient error — backoff and retry.
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}

			// Reset backoff on successful connection.
			backoff = time.Second

			// nil tracker: GET stream carries server-initiated messages,
			// not responses to client requests.
			_, scanErr := ForwardScanned(reader, safeClientOut, safeLogW, nil, opts)
			if scanErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream scan error: %v\n", scanErr)
			}

			// Stream ended — reconnect with backoff unless cancelled.
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
}

// RunHTTPListenerProxy starts an HTTP server that reverse-proxies MCP requests
// to an upstream server with bidirectional scanning. Each inbound POST is
// independently scanned and forwarded. Mcp-Session-Id and Authorization headers
// pass through transparently; the upstream owns session lifecycle.
//
// The caller is responsible for creating the net.Listener (via net.Listen or
// net.ListenConfig). This separates the bind step from serving, so callers
// detect port conflicts synchronously instead of losing them inside a goroutine.
//
// When store is non-nil, per-request session recorders are created using the
// Mcp-Session-Id header (or RemoteAddr fallback) as the session key, enabling
// adaptive enforcement signal tracking per logical MCP session.
//
// Endpoints:
//   - POST / : scan and forward JSON-RPC requests to upstream
//   - GET /health : returns 200 OK for liveness probes
func RunHTTPListenerProxy(
	ctx context.Context,
	ln net.Listener,
	upstreamURL string,
	logW io.Writer,
	opts MCPProxyOpts,
) error {
	safeLogW := &syncWriter{w: logW}

	// Shared tool baseline across all requests for drift detection.
	var fwdToolCfg *tools.ToolScanConfig
	if opts.ToolCfg != nil && opts.ToolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:    tools.NewToolBaseline(),
			Action:      opts.ToolCfg.Action,
			DetectDrift: opts.ToolCfg.DetectDrift,
			ExtraPoison: opts.ToolCfg.ExtraPoison,
		}
	}

	// Base opts shared across requests. Per-request fields (Rec) are
	// overridden on a copy inside each request handler.
	baseOpts := MCPProxyOpts{
		Scanner: opts.Scanner, Approver: opts.Approver, ToolCfg: fwdToolCfg,
		InputCfg: opts.InputCfg, PolicyCfg: opts.PolicyCfg,
		KillSwitch: opts.KillSwitch, ChainMatcher: opts.ChainMatcher,
		AuditLogger: opts.AuditLogger, CEE: opts.CEE, Metrics: opts.Metrics,
		RedirectRT: opts.RedirectRT, Transport: "mcp_http",
		CaptureObs:          opts.captureObserver(),
		ProvenanceCfg:       opts.ProvenanceCfg,
		DoWCheck:            opts.DoWCheck,
		A2ACfg:              opts.A2ACfg,
		TaintCfg:            opts.TaintCfg,
		TaintExternalSource: true,
		ReceiptEmitter:      opts.ReceiptEmitter,
		EnvelopeEmitter:     opts.EnvelopeEmitter,
	}

	// Shared HTTP client for upstream requests. Redirect-following is disabled
	// to prevent SSRF via crafted Location headers from the upstream.
	// 30s timeout prevents hanging on unresponsive upstreams.
	upstreamClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Resolve adaptive config per-request so hot-reloads take effect
		// without restarting the long-lived listener.
		var adaptiveCfg *config.AdaptiveEnforcement
		if opts.AdaptiveCfgFn != nil {
			adaptiveCfg = opts.AdaptiveCfgFn()
		} else {
			adaptiveCfg = opts.AdaptiveCfg
		}

		// Cap request body to prevent memory exhaustion.
		r.Body = http.MaxBytesReader(w, r.Body, int64(transport.MaxLineSize))
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("request body too large")))
			return
		}

		body = bytes.TrimSpace(body)
		if len(body) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("empty request body")))
			return
		}

		// Reject malformed JSON early. Without this, invalid payloads
		// reach scanHTTPInput where parse errors may be treated as
		// notifications (202 with no body), silently dropping the error.
		// Uses JSON-RPC 2.0 standard code -32700 (Parse error).
		if !json.Valid(body) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			parseErr, _ := json.Marshal(rpcError{
				JSONRPC: jsonrpc.Version,
				Error:   rpcErrorDetail{Code: -32700, Message: "pipelock: parse error: invalid JSON"},
			})
			_, _ = w.Write(parseErr)
			return
		}

		// Validate JSON-RPC 2.0 structure for single requests: version
		// must be "2.0", method must be present and a string. Batch
		// requests (JSON arrays) are validated per-element by scanHTTPInput.
		// Uses JSON-RPC 2.0 standard code -32600 (Invalid Request).
		if body[0] != '[' {
			if reason := validateRPCStructure(body); reason != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				rpcID := extractRPCID(body)
				invalidReq, _ := json.Marshal(rpcError{
					JSONRPC: jsonrpc.Version,
					ID:      rpcID,
					Error:   rpcErrorDetail{Code: -32600, Message: "pipelock: invalid request: " + reason},
				})
				_, _ = w.Write(invalidReq)
				return
			}
		}

		// Kill switch: deny all requests when active.
		if opts.KillSwitch != nil {
			if d := opts.KillSwitch.IsActiveMCP(body); d.Active {
				w.Header().Set("Content-Type", "application/json")
				if d.IsNotification {
					w.WriteHeader(http.StatusAccepted)
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					return
				}
				rpcID := extractRPCID(body)
				_, _ = w.Write(killswitch.ErrorResponse(rpcID, d.Message))
				return
			}
		}

		// Use Mcp-Session-Id header as chain detection session key so
		// concurrent clients don't share tool call history. When no
		// session ID is present, fall back to the client IP (without
		// port) so all requests from the same agent share chain history
		// even across separate TCP connections.
		chainSessionKey := r.Header.Get("Mcp-Session-Id")
		auditSessionKey := chainSessionKey
		if chainSessionKey == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			chainSessionKey = host
			// Hash the IP for audit logs to avoid persisting raw client
			// addresses in a field that bypasses report IP redaction.
			auditSessionKey = hashSessionKey(host)
		}

		// Per-request adaptive enforcement recorder. Uses RemoteAddr (without
		// port) as a stable session key: the first request has no Mcp-Session-Id
		// yet, so using the chain key would split signals across two keys (IP
		// for first request, session ID for subsequent ones).
		var reqRec session.Recorder
		if opts.Store != nil {
			adaptiveHost, _, adaptiveErr := net.SplitHostPort(r.RemoteAddr)
			if adaptiveErr != nil {
				adaptiveHost = r.RemoteAddr
			}
			reqRec = opts.Store.GetOrCreate(adaptiveHost)
		}

		// Scan Authorization header for DLP patterns. The body scanner
		// doesn't see HTTP headers, so an agent could leak credentials
		// via the Authorization header without triggering DLP.
		if auth := r.Header.Get("Authorization"); auth != "" {
			dlpResult := opts.Scanner.ScanTextForDLP(r.Context(), auth)
			if !dlpResult.Clean {
				pattern := patternUnknown
				if len(dlpResult.Matches) > 0 {
					pattern = dlpResult.Matches[0].PatternName
				}
				_, _ = fmt.Fprintf(safeLogW, "pipelock: DLP match in Authorization header: %s\n", pattern)
				if adaptiveCfg != nil && adaptiveCfg.Enabled {
					decide.RecordSignal(reqRec, session.SignalBlock, decide.EscalationParams{
						Threshold:     adaptiveCfg.EscalationThreshold,
						Logger:        opts.AuditLogger,
						Metrics:       opts.Metrics,
						ConsoleWriter: safeLogW,
						Session:       auditSessionKey,
					})
				}
				w.Header().Set("Content-Type", "application/json")
				rpcID := extractRPCID(body)
				resp, _ := json.Marshal(rpcError{
					JSONRPC: jsonrpc.Version,
					ID:      rpcID,
					Error:   rpcErrorDetail{Code: -32001, Message: "pipelock: request blocked by MCP input scanning"},
				})
				_, _ = w.Write(resp)
				return
			}
		}

		// A2A-Extensions header scanning: each comma-separated URI is
		// SSRF-scanned. A2A-Version is informational and passes through
		// without scanning.
		if baseOpts.A2ACfg != nil && baseOpts.A2ACfg.Enabled {
			headerResult := ScanA2AHeaders(r.Context(), r.Header, opts.Scanner, baseOpts.A2ACfg)
			if !headerResult.Clean {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: a2a header blocked: %s\n", headerResult.Reason)
				if adaptiveCfg != nil && adaptiveCfg.Enabled {
					ep := decide.EscalationParams{
						Threshold:     adaptiveCfg.EscalationThreshold,
						Logger:        opts.AuditLogger,
						Metrics:       opts.Metrics,
						ConsoleWriter: safeLogW,
						Session:       auditSessionKey,
					}
					if headerResult.IsConfigMismatch() {
						decide.RecordSignal(reqRec, session.SignalNearMiss, ep)
					} else {
						decide.RecordSignal(reqRec, session.SignalBlock, ep)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				rpcID := extractRPCID(body)
				resp, _ := json.Marshal(rpcError{
					JSONRPC: jsonrpc.Version,
					ID:      rpcID,
					Error:   rpcErrorDetail{Code: -32001, Message: "pipelock: request blocked by A2A header scanning"},
				})
				_, _ = w.Write(resp)
				return
			}
		}

		// Input scanning: DLP, injection, policy, chain detection.
		scanOpts := baseOpts
		scanOpts.Rec = reqRec
		scanOpts.AdaptiveCfg = adaptiveCfg
		decision := scanHTTPInputDecision(body, safeLogW, chainSessionKey, auditSessionKey, scanOpts)
		if blocked := decision.Blocked; blocked != nil {
			w.Header().Set("Content-Type", "application/json")
			if blocked.IsNotification {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			if blocked.SyntheticResponse != nil {
				_, _ = w.Write(blocked.SyntheticResponse)
			} else {
				_, _ = w.Write(blockRequestResponse(*blocked))
			}
			return
		}

		// Build upstream request with passthrough headers.
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, bytes.NewReader(decision.ForwardMessage))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(extractRPCID(body), fmt.Errorf("upstream HTTP request failed")))
			return
		}
		upReq.Header.Set("Content-Type", "application/json")
		upReq.Header.Set("Accept", "application/json, text/event-stream")

		if auth := r.Header.Get("Authorization"); auth != "" {
			upReq.Header.Set("Authorization", auth)
		}
		if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
			upReq.Header.Set("Mcp-Session-Id", sid)
		}

		// Forward A2A service parameter headers to upstream.
		// A2A-Extensions carries negotiated extension URIs (already scanned above).
		// A2A-Version carries protocol version (informational, no scanning needed).
		if ext := r.Header.Get("A2A-Extensions"); ext != "" {
			upReq.Header.Set("A2A-Extensions", ext)
		}
		if ver := r.Header.Get("A2A-Version"); ver != "" {
			upReq.Header.Set("A2A-Version", ver)
		}

		upResp, err := upstreamClient.Do(upReq)
		if err != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(extractRPCID(body), fmt.Errorf("upstream HTTP request failed")))
			return
		}
		defer upResp.Body.Close() //nolint:errcheck // best-effort cleanup

		// 202 Accepted: notification acknowledged, no body.
		if upResp.StatusCode == http.StatusAccepted {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		// Upstream error: sanitize before forwarding (don't leak body content
		// that could contain injection payloads).
		if upResp.StatusCode >= 400 {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream HTTP %d\n", upResp.StatusCode)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(extractRPCID(body), fmt.Errorf("upstream HTTP request failed")))
			return
		}

		// Read upstream response body and scan it.
		// nil tracker: HTTP reverse proxy pairs each request/response via HTTP
		// semantics, so confused deputy tracking is handled at the transport level.
		reader := &transport.SingleMessageReader{Body: upResp.Body}
		var buf bytes.Buffer
		bufWriter := &syncWriter{w: &buf}
		reqOpts := baseOpts
		reqOpts.Rec = reqRec
		reqOpts.AdaptiveCfg = adaptiveCfg
		_, scanErr := ForwardScanned(reader, bufWriter, safeLogW, nil, reqOpts)
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
		}

		// Pass Mcp-Session-Id from upstream back to client.
		if sid := upResp.Header.Get("Mcp-Session-Id"); sid != "" {
			w.Header().Set("Mcp-Session-Id", sid)
		}

		w.Header().Set("Content-Type", "application/json")
		output := bytes.TrimSpace(buf.Bytes())
		if len(output) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = w.Write(output)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on context cancellation.
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx) //nolint:errcheck // best-effort shutdown
	}()

	_, _ = fmt.Fprintf(safeLogW, "pipelock: MCP reverse proxy listening on %s\n", ln.Addr())

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP listener: %w", err)
	}
	return nil
}
