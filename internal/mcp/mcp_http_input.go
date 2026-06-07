// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

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
	// Strip any inbound com.pipelock/mediation from _meta before
	// parsing, scanning, or forwarding. Prevents an agent (or compromised
	// upstream that managed to send back through the listener) from
	// spoofing the envelope pipelock injects. Mirrors the equivalent
	// scrub on the stdio path at internal/mcp/input.go:213. The stdio
	// strip runs unconditionally on every inbound line; the HTTP listener
	// now matches.
	msg = stripInboundMCPMeta(msg)

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
	receiptLayer := ""
	receiptPattern := ""
	receiptSeverity := ""
	var receiptContractGate *mcpContractGateOutput
	defer func() {
		receiptOpts := mcpToolReceiptOpts{
			Emitter:          receiptEmitter,
			Transport:        opts.Transport,
			RedactionProfile: redactionCfg.Profile,
			ActionID:         actionID,
			MCPMethod:        mcpMethod,
			ToolName:         toolName,
			Verdict:          receiptVerdict,
			Layer:            receiptLayer,
			Pattern:          receiptPattern,
			Severity:         receiptSeverity,
			Decision:         taintEval,
			Report:           redactionReport,
			ContractGate:     receiptContractGate,
		}
		emitMCPToolReceipt(receiptOpts)
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

	// Determine input scanning parameters before redaction so block-mode
	// DLP can enforce on the original tool arguments. Warn mode still
	// redacts before forwarding below.
	action := config.ActionWarn
	onParseError := config.ActionBlock
	if inputCfg != nil && inputCfg.Enabled {
		action = inputCfg.Action
		onParseError = inputCfg.OnParseError
	}
	scanEnabled := inputCfg != nil && inputCfg.Enabled

	// Build the scan context once so pre-redaction and post-redaction
	// scans share the same DLPWarnContext.
	inputScanCtx := opts.warnContext()
	wc := scanner.DLPWarnContextFromCtx(inputScanCtx)
	if wc.Transport == "" {
		wc.Transport = transportMCPHTTP
		inputScanCtx = scanner.WithDLPWarnContext(inputScanCtx, wc)
	}

	if pendingToolName := frame.ToolCallName; pendingToolName != "" {
		toolName = pendingToolName
		mcpMethod = methodToolsCall
		actionID = receipt.NewActionID()
	}
	if scanEnabled && redactionCfg.Matcher != nil {
		originalVerdict := ScanRequest(inputScanCtx, msg, sc, action, onParseError)
		if !originalVerdict.Clean && inputVerdictEffectiveAction(originalVerdict, action) == config.ActionBlock {
			receiptLayer, receiptPattern, receiptSeverity = contentScanAttribution(originalVerdict)
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s)\n", joinInputVerdictReasons(originalVerdict))
			recordAdaptiveSignal(session.SignalBlock)
			receiptVerdict = config.ActionBlock
			result.Blocked = &BlockedRequest{
				ID:             originalVerdict.ID,
				IsNotification: isRPCNotification(originalVerdict.ID),
				LogMessage:     "blocked",
				ErrorCode:      -32001,
				ErrorMessage:   "pipelock: request blocked by MCP input scanning",
				ErrorData:      mcpBlockReasonData(mcpScannerBlockReason(originalVerdict, policy.Verdict{}, false)),
			}
			return result
		}
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
		receiptLayer, receiptPattern, receiptSeverity = redactionBlockAttribution(redactErr)
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

	// Evaluate every configured gate in one pass. The helper returns
	// a composite verdict and the first gate that short-circuited,
	// preserving per-gate block semantics and ordering.
	eval := EvaluateMCPInputGates(inputScanCtx, frame, msg, sessionKey, opts, action, onParseError, scanEnabled)
	// Cross-agent contamination escalation. Fired regardless of the gate
	// outcome: the contaminated session already emitted across the agent
	// boundary, so the adaptive signal must accumulate even when the call is
	// otherwise allowed.
	if eval.CrossAgentEscalate {
		recordAdaptiveSignal(session.SignalCrossAgentContamination)
	}
	verdict := eval.ContentVerdict
	policyVerdict := eval.PolicyVerdict
	receiptLayer, receiptPattern, receiptSeverity = pickAttribution(eval)

	mcpMethod = verdict.Method
	if verdict.Method == methodToolsCall {
		if actionID == "" {
			actionID = receipt.NewActionID()
		}
		toolName = frame.ToolCallName
	}
	captureActionClass := captureMCPFrameActionClass(toolName, verdict.Method, string(frame.Args))
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
			audit.TaintDecision{
				TaintLevel:  decision.Risk.Level.String(),
				ActionClass: decision.ActionClass.String(),
				Sensitivity: decision.Sensitivity.String(),
				Authority:   decision.Authority.String(),
				Decision:    decision.Result.Decision.String(),
				Reason:      decision.Result.Reason,
				SourceURL:   decision.Risk.LastExternalURL,
				SourceKind:  decision.Risk.LastExternalKind,
			},
		)
	}

	// Dispatch block-level gate verdicts. Per-gate log / audit /
	// metrics / adaptive-signal side effects live here so the
	// transport-specific response shape (JSON-RPC error codes,
	// LogMessage strings) stays in the transport layer.
	switch eval.BlockingGate {
	case blockingGateA2ABody:
		_, _ = fmt.Fprintf(logW, "pipelock: a2a input: blocked (%s)\n", eval.A2AResult.Reason)
		switch {
		case eval.A2AResult.IsAdaptiveNeutral():
			// Score-neutral: infrastructure errors (e.g. DNS resolver timeout
			// on an embedded A2A URL field) block the request (fail-closed)
			// but must not feed adaptive enforcement. Resolver wobble is not
			// evidence of agent misbehavior.
		case eval.A2AResult.IsConfigMismatch():
			recordAdaptiveSignal(session.SignalNearMiss)
		default:
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
	case blockingGateDoW:
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
	case blockingGateChain:
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
	case blockingGateParseError:
		_, _ = fmt.Fprintf(logW, "pipelock: input: %s\n", verdict.Error)
		receiptVerdict = config.ActionBlock
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isRPCNotification(verdict.ID),
			LogMessage:     "blocked (parse error)",
		}
		return result
	case blockingGateTaintBlock, blockingGateTaintAskDenied:
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
	// short-circuit. A2A warn logs and records a near-miss unless the
	// finding is adaptive-neutral; DoW warn logs, records an anomaly,
	// and records a near-miss. These happen after the switch so block
	// dispatches skip them.
	if eval.TaintApproved {
		logTaintDecision()
	}
	if !eval.A2AResult.Clean && eval.A2AEffectiveAction != "" && eval.A2AEffectiveAction != config.ActionBlock {
		_, _ = fmt.Fprintf(logW, "pipelock: a2a input: warning (%s)\n", eval.A2AResult.Reason)
		if !eval.A2AResult.IsAdaptiveNeutral() {
			recordAdaptiveSignal(session.SignalNearMiss)
		}
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
	bindingAction := eval.BindingAction
	bindingReason := eval.BindingReason
	chainAction := eval.ChainAction
	chainReason := eval.ChainReason
	if bindingReason != "" {
		switch bindingReason {
		case bindingReasonMissingToolName:
			_, _ = fmt.Fprintf(logW, "pipelock: tools/call missing params.name\n")
		case bindingReasonNoBaseline:
			_, _ = fmt.Fprintf(logW, "pipelock: tools/call %q before baseline established\n", toolName)
		case bindingReasonUnknownTool:
			_, _ = fmt.Fprintf(logW, "pipelock: tools/call %q not in session baseline\n", toolName)
		default:
			_, _ = fmt.Fprintf(logW, "pipelock: tools/call %q session binding violation: %s\n", toolName, bindingReason)
		}
		obs.ObserveToolPolicyVerdict(context.Background(), &capture.ToolPolicyRecord{
			Subsurface:        "session_binding",
			Transport:         opts.Transport,
			SessionID:         captureSessionID(opts.Transport),
			SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
			ConfigHash:        opts.captureConfigHash(),
			Profile:           opts.captureProfile(),
			ActionClass:       captureActionClass,
			Request: capture.CaptureRequest{
				ToolName:  toolName,
				MCPMethod: methodToolsCall,
			},
			RawFindings: []capture.Finding{{
				Kind:       capture.KindSessionBinding,
				ToolName:   toolName,
				PolicyRule: bindingReason,
				Action:     bindingAction,
			}},
			EffectiveAction: bindingAction,
			Outcome:         captureOutcome(bindingAction, false),
		})
	}

	// All clean - proceed (with block_all and CEE checks).
	if verdict.Clean && !policyVerdict.Matched && bindingAction == "" && chainAction == "" {
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
				Subsurface:        "cee_mcp_http",
				Transport:         opts.Transport,
				SessionID:         captureSessionID(opts.Transport),
				SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
				ConfigHash:        opts.captureConfigHash(),
				Profile:           opts.captureProfile(),
				ActionClass:       captureActionClass,
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
		contractGate, contractErr := evaluateMCPToolGate(frame, config.ActionAllow, false, opts)
		if contractErr != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: contract tool-call evaluation failed: %v\n", contractErr)
			receiptVerdict = config.ActionBlock
			result.Blocked = &BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     "contract tool-call evaluation failed",
				ErrorCode:      -32006,
				ErrorMessage:   "pipelock: contract tool-call evaluation failed",
			}
			return result
		}
		if contractGate.Verdict == config.ActionBlock {
			_, _ = fmt.Fprintf(logW, "pipelock: contract blocked tools/call %q (%s)\n", toolName, contractGate.Reason)
			receiptVerdict = config.ActionBlock
			receiptContractGate = &contractGate
			result.Blocked = ptrMCPBlockedRequest(mcpContractBlockRequest(verdict.ID, contractGate, "pipelock: request blocked by live-lock contract"))
			return result
		}
		if verdict.Method == methodToolsCall {
			var decorateErr error
			result.ForwardMessage, decorateErr = decorateMCPToolMessage(msg, envelopeEmitter, actionID, verdict.Method, toolName, config.ActionAllow, taintEval)
			if decorateErr != nil {
				result.Blocked = &BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     "mediation envelope injection failed",
					ErrorCode:      -32002,
					ErrorMessage:   "pipelock: mediation envelope injection failed",
				}
				return result
			}
			receiptVerdict = config.ActionAllow
			receiptContractGate = &contractGate
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
		effectiveAction = inputVerdictEffectiveAction(verdict, action)
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

	// Error code/message based on what triggered.
	errCode := 0
	errMsg := ""
	if verdict.Clean && policyVerdict.Matched {
		errCode = -32002
		errMsg = errPolicyBlocked
	}
	if bindingReason != "" && bindingAction == config.ActionBlock {
		errCode = -32000
		errMsg = "pipelock: " + bindingReason
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

	// Capture: record DLP/injection input verdict before action dispatch so
	// block/ask/redirect/warn all preserve the same replay metadata.
	if !verdict.Clean {
		var rawFindings []capture.Finding
		rawFindings = append(rawFindings, dlpMatchesToFindings(verdict.Matches)...)
		rawFindings = append(rawFindings, responseMatchesToFindings(verdict.Inject, effectiveAction)...)
		rawFindings = append(rawFindings, addressFindingsToCapture(verdict.AddressFindings)...)
		obs.ObserveDLPVerdict(context.Background(), &capture.DLPVerdictRecord{
			Subsurface:        "dlp_mcp_input",
			Transport:         opts.Transport,
			SessionID:         captureSessionID(opts.Transport),
			SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
			ConfigHash:        opts.captureConfigHash(),
			Profile:           opts.captureProfile(),
			ActionClass:       captureActionClass,
			TransformKind:     capture.TransformJoinedFields,
			RawFindings:       rawFindings,
			EffectiveAction:   effectiveAction,
			Outcome:           captureOutcome(effectiveAction, false),
		})
	}

	// Capture: record tool-policy verdict when policy matched. Mirrors the
	// stdio path (ForwardScannedInput) so a tool-policy hit produces a
	// mcp_tool_policy evidence entry on the HTTP transport too. Without this
	// the HTTP path enforced policy but never captured the verdict — a
	// transport-parity gap surfaced by the key-free capture work (#696).
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
			Subsurface:        "mcp_tool_policy",
			Transport:         opts.Transport,
			SessionID:         captureSessionID(opts.Transport),
			SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
			ConfigHash:        opts.captureConfigHash(),
			Profile:           opts.captureProfile(),
			ActionClass:       captureActionClass,
			Request: capture.CaptureRequest{
				ToolName:     toolName,
				ToolArgsJSON: string(frame.Args),
				MCPMethod:    verdict.Method,
			},
			RawFindings:     policyFindings,
			EffectiveAction: effectiveAction,
			Outcome:         captureOutcome(effectiveAction, false),
		})
	}

	switch effectiveAction {
	case config.ActionBlock:
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s)\n", joinStrings(reasons))
		recordAdaptiveSignal(session.SignalBlock)
		receiptVerdict = effectiveAction
		blockReason := mcpScannerBlockReason(verdict, policyVerdict, chainAction != "")
		if bindingReason != "" && bindingAction == config.ActionBlock {
			blockReason = blockreason.SessionBinding
		}
		result.Blocked = &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isNotification,
			LogMessage:     "blocked",
			ErrorCode:      errCode,
			ErrorMessage:   errMsg,
			ErrorData:      mcpBlockReasonData(blockReason),
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
			// No policy config - fail closed.
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
			// sending to client. Handler output is untrusted - it could contain
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
			// Redirect handler failed - fall through to block (fail-closed).
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [redirect failed: %s]\n", joinStrings(reasons), redirectResult.Error)
			recordAdaptiveSignal(session.SignalBlock)
			br = &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (redirect failed)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
		}
		if auditLogger != nil {
			auditLogger.LogToolRedirect(audit.ToolRedirectEvent{
				SessionID:       auditSessionKey,
				ToolName:        toolName,
				ArgsDigest:      argsDigest(toolArgs),
				RedirectProfile: policyVerdict.RedirectProfile,
				RedirectReason:  profile.Reason,
				PolicyRule:      policyRuleName,
				Result:          finalResult,
				LatencyMs:       redirectResult.LatencyMs,
			})
		}
		if finalResult == redirectResultRedirected {
			receiptVerdict = config.ActionRedirect
		} else {
			receiptVerdict = config.ActionBlock
		}
		result.Blocked = br
		return result
	case config.ActionAsk:
		// HITL for input scanning is impractical - fall back to block (same as stdio proxy).
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
				Subsurface:        "cee_mcp_http",
				Transport:         opts.Transport,
				SessionID:         captureSessionID(opts.Transport),
				SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
				ConfigHash:        opts.captureConfigHash(),
				Profile:           opts.captureProfile(),
				ActionClass:       captureActionClass,
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
		contractGate, contractErr := evaluateMCPToolGate(frame, effectiveAction, len(reasons) > 0, opts)
		if contractErr != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: contract tool-call evaluation failed: %v\n", contractErr)
			receiptVerdict = config.ActionBlock
			result.Blocked = &BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     "contract tool-call evaluation failed",
				ErrorCode:      -32006,
				ErrorMessage:   "pipelock: contract tool-call evaluation failed",
			}
			return result
		}
		if contractGate.Verdict == config.ActionBlock {
			_, _ = fmt.Fprintf(logW, "pipelock: contract blocked tools/call %q (%s)\n", toolName, contractGate.Reason)
			receiptVerdict = config.ActionBlock
			receiptContractGate = &contractGate
			result.Blocked = ptrMCPBlockedRequest(mcpContractBlockRequest(verdict.ID, contractGate, "pipelock: request blocked by live-lock contract"))
			return result
		}
		if verdict.Method == methodToolsCall {
			var decorateErr error
			result.ForwardMessage, decorateErr = decorateMCPToolMessage(msg, envelopeEmitter, actionID, verdict.Method, toolName, config.ActionWarn, taintEval)
			if decorateErr != nil {
				result.Blocked = &BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     "mediation envelope injection failed",
					ErrorCode:      -32002,
					ErrorMessage:   "pipelock: mediation envelope injection failed",
				}
				return result
			}
			receiptVerdict = config.ActionWarn
			receiptContractGate = &contractGate
		}
		return result // forward
	}
}
