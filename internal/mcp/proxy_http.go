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
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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
		opts.Transport = "mcp_http_upstream"
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
	toolCfg := opts.toolCfg()
	var fwdToolCfg *tools.ToolScanConfig
	if toolCfg != nil && toolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:    tools.NewToolBaseline(),
			Action:      toolCfg.Action,
			DetectDrift: toolCfg.DetectDrift,
			ExtraPoison: toolCfg.ExtraPoison,
		}
	}

	// Request tracker for confused deputy protection.
	tracker := NewRequestTracker()

	// Session-scoped opts: override Rec and ToolCfg from the caller's opts.
	fwdOpts := opts
	fwdOpts.Rec = rec
	fwdOpts.ToolCfg = fwdToolCfg
	fwdOpts.ToolCfgFn = nil
	fwdOpts.WarnContext = ctx

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

		// Parse the inbound frame once per message. Kill switch, request
		// tracking, and upstream-error responses all read frame.ID
		// instead of re-parsing.
		frame := ParseMCPFrame(msg)

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
				rpcID := frame.ID
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
			tracker.Track(frame.ID)
		}

		// POST to upstream.
		respReader, err := httpClient.SendMessage(ctx, decision.ForwardMessage)
		if err != nil {
			// Log full upstream error details to stderr for debugging.
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			// Send sanitized error to client — don't include upstream body content
			// which could contain prompt injection payloads.
			rpcID := frame.ID
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
	sc := opts.scanner()
	inputCfg := opts.inputCfg()
	policyCfg := opts.policyCfg()
	auditLogger := opts.AuditLogger
	cee := opts.cee()
	rec := opts.Rec
	adaptiveCfg := opts.adaptiveCfg()
	m := opts.Metrics
	obs := opts.captureObserver()
	redactionCfg := opts.redactionConfig()
	receiptEmitter := opts.receiptEmitter()
	envelopeEmitter := opts.envelopeEmitter()
	redirectRT := opts.redirectRT()
	result := httpInputDecision{ForwardMessage: msg}
	mcpMethod := ""
	toolName := ""
	actionID := ""
	var redactionReport *redact.Report
	taintEval := taintDecision{
		Authority: session.AuthorityUserBroad,
		Result:    session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: taintReasonDisabled},
	}
	receiptVerdict := ""
	defer func() {
		emitMCPToolReceipt(receiptEmitter, opts.Transport, redactionCfg.Profile, actionID, mcpMethod, toolName, receiptVerdict, taintEval, redactionReport)
	}()

	// Parse the inbound frame once. Every gate below reads ID / Method /
	// tool fields from this frame instead of re-parsing. Redaction may
	// rewrite argument values; the frame is re-parsed after redaction so
	// downstream gates (DoW, taint) see the redacted args while
	// ID / Method / ToolCallName stay stable.
	frame := ParseMCPFrame(msg)

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
		receiptVerdict = config.ActionBlock
		result.Blocked = &BlockedRequest{
			ID:           frame.ID,
			ErrorCode:    -32600,
			ErrorMessage: "pipelock: batch requests are not supported by MCP",
		}
		return result
	}

	if pendingToolName := frame.ToolCallName; pendingToolName != "" {
		toolName = pendingToolName
		mcpMethod = methodToolsCall
		actionID = receipt.NewActionID()
	}
	rewrittenMsg, report, redactErr := applyMCPToolCallRedactionWithConfig(msg, redactionCfg)
	if redactErr != nil {
		var blockErr *redact.BlockError
		reason := redactErr.Error()
		if errors.As(redactErr, &blockErr) {
			reason = "tool arguments redaction blocked: " + string(blockErr.Reason)
		}
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s)\n", reason)
		recordAdaptiveSignal(session.SignalBlock)
		receiptVerdict = config.ActionBlock
		result.Blocked = &BlockedRequest{
			ID:             frame.ID,
			IsNotification: isRPCNotification(frame.ID),
			LogMessage:     "blocked (redaction)",
			ErrorCode:      -32001,
			ErrorMessage:   "pipelock: request blocked by MCP redaction",
		}
		return result
	}
	msg = rewrittenMsg
	result.ForwardMessage = rewrittenMsg
	redactionReport = report
	// Redaction may have rewritten argument values; re-parse so
	// downstream gates (DoW, taint) see the redacted args.
	frame = ParseMCPFrame(msg)

	// Determine input scanning parameters.
	action := config.ActionWarn
	onParseError := config.ActionBlock
	if inputCfg != nil && inputCfg.Enabled {
		action = inputCfg.Action
		onParseError = inputCfg.OnParseError
	}
	scanEnabled := inputCfg != nil && inputCfg.Enabled

	// Build the scan context once so the helper sees the same
	// DLPWarnContext the inline content scan would have seen.
	inputScanCtx := opts.warnContext()
	wc := scanner.DLPWarnContextFromCtx(inputScanCtx)
	if wc.Transport == "" {
		wc.Transport = transportMCPHTTP
		inputScanCtx = scanner.WithDLPWarnContext(inputScanCtx, wc)
	}

	// Evaluate every configured gate in one pass. The helper returns
	// a composite verdict and the first gate that short-circuited,
	// preserving per-gate block semantics and ordering.
	eval := EvaluateMCPInputGates(inputScanCtx, frame, msg, sessionKey, opts, action, onParseError, scanEnabled)
	verdict := eval.ContentVerdict
	policyVerdict := eval.PolicyVerdict

	mcpMethod = verdict.Method
	if verdict.Method == methodToolsCall {
		if actionID == "" {
			actionID = receipt.NewActionID()
		}
		toolName = frame.ToolCallName
	}
	logTaintDecision := func() {
		if auditLogger == nil {
			return
		}
		decision := eval.TaintDecision
		if eval.TaintAuditDecisionSet {
			decision = eval.TaintAuditDecision
		}
		auditLogger.LogTaintDecision(
			mustMCPAuditContext(auditLogger, "MCP", toolName),
			decision.Risk.Level.String(),
			decision.ActionClass.String(),
			decision.Sensitivity.String(),
			decision.Authority.String(),
			decision.Result.Decision.String(),
			decision.Result.Reason,
			decision.Risk.LastExternalURL,
			decision.Risk.LastExternalKind,
		)
	}

	// Dispatch block-level gate verdicts. Per-gate log / audit /
	// metrics / adaptive-signal side effects live here so the
	// transport-specific response shape (JSON-RPC error codes,
	// LogMessage strings) stays in the transport layer.
	switch eval.BlockingGate {
	case "a2a_body":
		_, _ = fmt.Fprintf(logW, "pipelock: a2a input: blocked (%s)\n", eval.A2AResult.Reason)
		if eval.A2AResult.IsConfigMismatch() {
			recordAdaptiveSignal(session.SignalNearMiss)
		} else {
			recordAdaptiveSignal(session.SignalBlock)
		}
		receiptVerdict = config.ActionBlock
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isRPCNotification(verdict.ID),
			LogMessage:     "blocked (a2a input scanning)",
			ErrorCode:      -32001,
			ErrorMessage:   "pipelock: request blocked by A2A input scanning",
		}
		return result
	case "dow":
		_, _ = fmt.Fprintf(logW, "pipelock: tools/call %q DoW %s: %s (%s)\n",
			toolName, eval.DoWAction, eval.DoWReason, eval.DoWBudgetType)
		if auditLogger != nil {
			auditLogger.LogBlocked(mustMCPAuditContext(auditLogger, "MCP", toolName), "denial_of_wallet", eval.DoWReason)
		}
		if m != nil {
			m.RecordBlocked("mcp", "denial_of_wallet", 0, "")
		}
		recordAdaptiveSignal(session.SignalBlock)
		receiptVerdict = config.ActionBlock
		result.Blocked = &BlockedRequest{ID: verdict.ID, IsNotification: isRPCNotification(verdict.ID), ErrorCode: -32600, ErrorMessage: "pipelock: " + eval.DoWReason}
		return result
	case "chain":
		_, _ = fmt.Fprintf(logW, "pipelock: chain detected: %s (severity=%s, action=%s)\n",
			eval.ChainPatternName, eval.ChainSeverity, eval.ChainAction)
		if auditLogger != nil {
			auditLogger.LogChainDetection(eval.ChainPatternName, eval.ChainSeverity, eval.ChainAction, toolName, auditSessionKey)
		}
		recordAdaptiveSignal(session.SignalBlock)
		receiptVerdict = config.ActionBlock
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isRPCNotification(verdict.ID),
			LogMessage:     fmt.Sprintf("chain pattern %q blocked", eval.ChainPatternName),
			ErrorCode:      -32004,
			ErrorMessage:   fmt.Sprintf("tool call blocked: chain pattern %q detected", eval.ChainPatternName),
		}
		return result
	case "parse_error":
		_, _ = fmt.Fprintf(logW, "pipelock: input: %s\n", verdict.Error)
		receiptVerdict = config.ActionBlock
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isRPCNotification(verdict.ID),
			LogMessage:     "blocked (parse error)",
		}
		return result
	case "taint_block", "taint_ask_denied":
		logTaintDecision()
		receiptVerdict = config.ActionBlock
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isRPCNotification(verdict.ID),
			LogMessage:     "blocked by taint policy",
			ErrorCode:      -32002,
			ErrorMessage:   "pipelock: " + eval.TaintDecision.Result.Reason,
		}
		return result
	}

	// Non-blocking warn-level side effects from gates that did not
	// short-circuit. A2A warn logs and records a near-miss; DoW warn
	// logs, records an anomaly, and records a near-miss. These
	// happen after the switch so block dispatches skip them.
	if eval.TaintApproved {
		logTaintDecision()
	}
	if !eval.A2AResult.Clean && eval.A2AEffectiveAction != "" && eval.A2AEffectiveAction != config.ActionBlock {
		_, _ = fmt.Fprintf(logW, "pipelock: a2a input: warning (%s)\n", eval.A2AResult.Reason)
		recordAdaptiveSignal(session.SignalNearMiss)
	}
	if eval.DoWAction != "" && !eval.DoWAllowed && eval.DoWAction != config.ActionBlock {
		_, _ = fmt.Fprintf(logW, "pipelock: tools/call %q DoW %s: %s (%s)\n",
			toolName, eval.DoWAction, eval.DoWReason, eval.DoWBudgetType)
		if auditLogger != nil {
			auditLogger.LogAnomaly(mustMCPAuditContext(auditLogger, "MCP", toolName), "denial_of_wallet", eval.DoWReason, 0)
		}
		recordAdaptiveSignal(session.SignalNearMiss)
	}
	// Chain warn has already been recorded as ChainAction on eval;
	// log it here so the action-merge section below can fold it in.
	if eval.ChainMatched && eval.ChainAction != config.ActionBlock {
		_, _ = fmt.Fprintf(logW, "pipelock: chain detected: %s (severity=%s, action=%s)\n",
			eval.ChainPatternName, eval.ChainSeverity, eval.ChainAction)
		if auditLogger != nil {
			auditLogger.LogChainDetection(eval.ChainPatternName, eval.ChainSeverity, eval.ChainAction, toolName, auditSessionKey)
		}
	}

	taintEval = eval.TaintDecision
	chainAction := eval.ChainAction
	chainReason := eval.ChainReason

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
			result.ForwardMessage = decorateMCPToolMessage(msg, envelopeEmitter, actionID, verdict.Method, toolName, config.ActionAllow, taintEval)
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
			receiptVerdict = config.ActionBlock
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
			receiptVerdict = config.ActionBlock
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
			receiptVerdict = config.ActionBlock
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
		redirectResult := executeRedirect(profile, policyVerdict.RedirectProfile, verdict.ID, toolArgs, policyRuleName, redirectRT)
		// Determine final outcome before audit logging so the event
		// reflects the actual result delivered to the client.
		var br *BlockedRequest
		finalResult := "blocked"
		if redirectResult.Success {
			// Scan redirect handler output for prompt injection AND DLP before
			// sending to client. Handler output is untrusted — it could contain
			// secrets or injection payloads.
			scanVerdict := ScanResponse(redirectResult.Response, sc)
			wc := scanner.DLPWarnContextFromCtx(inputScanCtx)
			if wc.Transport == "" {
				wc.Transport = transportMCPHTTP
			}
			wc.Method = mcpWarnMethod
			wc.Resource = mcpWarnResource(verdict.Method, msg)
			httpWarnCtx := scanner.WithDLPWarnContext(inputScanCtx, wc)
			dlpResult := sc.ScanTextForDLP(httpWarnCtx, string(redirectResult.Response))
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
		receiptVerdict = config.ActionBlock
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
			result.ForwardMessage = decorateMCPToolMessage(msg, envelopeEmitter, actionID, verdict.Method, toolName, config.ActionWarn, taintEval)
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

	// Shared tool baseline across all requests for drift detection and
	// session binding. It intentionally survives hot reloads for the
	// lifetime of this listener; reload updates policy knobs, not the
	// listener's observed tool inventory.
	toolBaseline := tools.NewToolBaseline()
	toolCfgFn := func() *tools.ToolScanConfig {
		cfg := opts.toolCfg()
		if cfg == nil || cfg.Action == "" {
			return nil
		}
		return &tools.ToolScanConfig{
			Baseline:                toolBaseline,
			Action:                  cfg.Action,
			DetectDrift:             cfg.DetectDrift,
			BindingUnknownAction:    cfg.BindingUnknownAction,
			BindingNoBaselineAction: cfg.BindingNoBaselineAction,
			ExtraPoison:             cfg.ExtraPoison,
		}
	}

	// Base opts shared across requests. Per-request fields (Rec) are
	// overridden on a copy inside each request handler. The static
	// Redact{Matcher,Limits,Profile} fields are fallbacks for direct
	// callers that bypass RedactionCfgFn; resolve the current snapshot
	// once here so we do not re-run opts.redactionConfig() three times.
	baseRedactionCfg := opts.redactionConfig()
	baseOpts := MCPProxyOpts{
		Scanner:             opts.scanner(),
		ScannerFn:           opts.ScannerFn,
		Approver:            opts.Approver,
		InputCfg:            opts.inputCfg(),
		InputCfgFn:          opts.InputCfgFn,
		ToolCfg:             toolCfgFn(),
		ToolCfgFn:           toolCfgFn,
		PolicyCfg:           opts.policyCfg(),
		PolicyCfgFn:         opts.PolicyCfgFn,
		KillSwitch:          opts.KillSwitch,
		ChainMatcher:        opts.chainMatcher(),
		ChainMatcherFn:      opts.ChainMatcherFn,
		AuditLogger:         opts.AuditLogger,
		CEE:                 opts.cee(),
		CEEFn:               opts.CEEFn,
		Metrics:             opts.Metrics,
		RedirectRT:          opts.redirectRT(),
		RedirectRTFn:        opts.RedirectRTFn,
		Transport:           "mcp_http_listener",
		ReceiptEmitter:      opts.receiptEmitter(),
		ReceiptEmitterFn:    opts.ReceiptEmitterFn,
		CaptureObs:          opts.captureObserver(),
		ProvenanceCfg:       opts.provenanceCfg(),
		ProvenanceCfgFn:     opts.ProvenanceCfgFn,
		RedactMatcher:       baseRedactionCfg.Matcher,
		RedactLimits:        baseRedactionCfg.Limits,
		RedactProfile:       baseRedactionCfg.Profile,
		RedactionCfgFn:      opts.RedactionCfgFn,
		DoWCheck:            opts.DoWCheck,
		A2ACfg:              opts.a2aCfg(),
		A2ACfgFn:            opts.A2ACfgFn,
		MediaPolicy:         opts.mediaPolicy(),
		MediaPolicyFn:       opts.MediaPolicyFn,
		TaintCfg:            opts.taintCfg(),
		TaintCfgFn:          opts.TaintCfgFn,
		TaintExternalSource: true,
		EnvelopeEmitter:     opts.envelopeEmitter(),
		EnvelopeEmitterFn:   opts.EnvelopeEmitterFn,
	}

	// Shared HTTP client for upstream requests. Redirect-following is disabled
	// to prevent SSRF via crafted Location headers from the upstream.
	// 30s timeout prevents hanging on unresponsive upstreams.
	//
	// Envelope-refresh implication: because redirects never follow,
	// the mediation envelope signing refresh path that lives at
	// internal/proxy/proxy.go:348 (CheckRedirect) is moot for the
	// MCP HTTP transport — there is no second hop to rebuild an
	// envelope over. If a future change enables redirect following
	// here (for example, to support upstream servers that relocate
	// endpoints) the refresh helper must be wired into the new
	// CheckRedirect closure so signed envelopes do not flow with
	// stale @target-uri / ph / hop values. The same applies to
	// internal/mcp/transport/httpclient.go:45.
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
		adaptiveCfg := opts.adaptiveCfg()
		reqScanner := baseOpts.scanner()
		reqA2ACfg := baseOpts.a2aCfg()

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

		// Parse the inbound frame once per request. Every rpcID lookup
		// and upstream-error response below reads frame.ID instead of
		// re-parsing the body bytes.
		frame := ParseMCPFrame(body)

		// Validate JSON-RPC 2.0 structure for single requests: version
		// must be "2.0", method must be present and a string. Batch
		// requests (JSON arrays) are validated per-element by scanHTTPInput.
		// Uses JSON-RPC 2.0 standard code -32600 (Invalid Request).
		if body[0] != '[' {
			if reason := validateRPCStructure(body); reason != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				rpcID := frame.ID
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
				rpcID := frame.ID
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

		warnCtx := scanner.DLPWarnContextFromCtx(r.Context())
		if warnCtx.Transport == "" {
			warnCtx.Transport = baseOpts.Transport
		}
		warnCtx.Method = mcpWarnMethod
		warnCtx.Resource = r.URL.Path
		if warnCtx.ClientIP == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			warnCtx.ClientIP = host
		}
		httpWarnCtx := scanner.WithDLPWarnContext(r.Context(), warnCtx)
		r = r.WithContext(httpWarnCtx)

		// Scan Authorization header for DLP patterns. The body scanner
		// doesn't see HTTP headers, so an agent could leak credentials
		// via the Authorization header without triggering DLP.
		if auth := r.Header.Get("Authorization"); auth != "" {
			dlpResult := reqScanner.ScanTextForDLP(r.Context(), auth)
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
				rpcID := frame.ID
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
		if reqA2ACfg != nil && reqA2ACfg.Enabled {
			headerResult := ScanA2AHeaders(r.Context(), r.Header, reqScanner, reqA2ACfg)
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
				rpcID := frame.ID
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
		scanOpts.AdaptiveCfgFn = nil
		scanOpts.WarnContext = r.Context()
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
			_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("upstream HTTP request failed")))
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
			_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("upstream HTTP request failed")))
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
			_, _ = w.Write(upstreamErrorResponse(frame.ID, fmt.Errorf("upstream HTTP request failed")))
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
		reqOpts.AdaptiveCfgFn = nil
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
