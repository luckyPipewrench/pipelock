// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// BlockingGate values identifying which inbound gate short-circuited.
// Callers switch on these to build per-gate block dispatch responses.
const (
	blockingGateA2ABody        = "a2a_body"
	blockingGateDoW            = "dow"
	blockingGateFrozenTool     = "frozen_tool"
	blockingGateChain          = "chain"
	blockingGateParseError     = "parse_error"
	blockingGateTaintBlock     = "taint_block"
	blockingGateTaintAskDenied = "taint_ask_denied"
)

// BindingReason values populated by the stdio gate helper when a
// session binding violation fires. Callers switch on these to emit
// the right per-reason diagnostic log.
const (
	bindingReasonBatchRequest    = "session_binding:batch_request"
	bindingReasonMissingToolName = "session_binding:missing_tool_name"
	bindingReasonNoBaseline      = "session_binding:no_baseline"
	bindingReasonUnknownTool     = "session_binding:unknown_tool"
)

// MCPInputEvaluation aggregates the outputs of the configured inbound
// gates for one MCP request. EvaluateMCPInputGates populates the
// struct in a single pass; callers consume it to merge per-gate
// actions into an effective verdict, dispatch block / warn / forward,
// record adaptive signals, and emit receipts.
//
// Zero-value fields mean the gate did not run (its config was nil or
// an earlier gate short-circuited). BlockingGate names the first gate
// that issued a block-level verdict; empty means every configured
// gate ran through. An empty BlockingGate does not mean "clean" -- the
// caller may still find reasons to warn or merge non-clean content
// with matched policy.
//
// Short-circuit semantics mirror the pre-refactor callers exactly.
// On the first block verdict EvaluateMCPInputGates returns and the
// remaining gates do not run. This preserves the stateful-gate
// ordering contract: chain detection reads session state mutated by
// DoW; taint reads session state potentially mutated by chain.
type MCPInputEvaluation struct {
	// BlockingGate names the first gate that returned a block-level
	// verdict, or empty when every configured gate ran through.
	// Values: "a2a_body", "dow", "chain", "parse_error",
	// "taint_block", "taint_ask_denied". Callers use this as a
	// log-framing key; block dispatch reads the per-gate fields
	// below for the specific reason / code / message shape.
	BlockingGate string

	// ContentVerdict is the ScanRequest output. Always populated
	// because content scan is the first gate.
	ContentVerdict InputVerdict

	// A2AResult is populated when a2aCfg is non-nil and enabled and
	// the method matches IsA2AMethod. A2AResult.Clean is true when
	// no findings were produced.
	A2AResult A2AScanResult

	// A2AEffectiveAction is the action A2AResult resolved to (empty
	// when A2A did not run or the result was clean). Held separately
	// so the caller can fold an A2A warn into the effective action
	// merge alongside content and policy verdicts when no gate
	// blocked.
	A2AEffectiveAction string

	// DoW fields are populated when DoWCheck is non-nil and the
	// message is a tools/call with a non-empty ToolCallName.
	DoWAllowed    bool
	DoWAction     string
	DoWReason     string
	DoWBudgetType string

	// PolicyVerdict is populated when policyCfg is non-nil.
	PolicyVerdict policy.Verdict

	// Chain fields are populated when chainMatcher is non-nil and
	// the message is a tools/call with a non-empty ToolCallName.
	// Note that chainMatcher.Record mutates session chain state on
	// every call; the gate ordering after DoW preserves the
	// pre-refactor contract that DoW-block messages do not leave a
	// chain trace.
	ChainMatched     bool
	ChainPatternName string
	ChainSeverity    string
	ChainAction      string
	ChainReason      string

	// TaintDecision is populated when the message is a tools/call.
	// The taint evaluator reads session state potentially mutated
	// by earlier gates which is why it runs last.
	TaintDecision taintDecision

	// TaintAuditDecision preserves the raw policy result before any
	// HITL approval mutates authority / reauth fields for envelope
	// emission. TaintAuditDecisionSet is true when the decision should
	// be logged by the caller.
	TaintAuditDecision    taintDecision
	TaintAuditDecisionSet bool

	// TaintApproved is true iff the taint gate ran, produced a
	// PolicyAsk decision, and an approver allowed the call. False
	// in every other case including when the gate did not run.
	TaintApproved bool

	// BindingAction is the session-binding action ("block" or "warn")
	// when a stdio binding violation was detected. Empty when binding
	// did not fire. Stdio-only; the HTTP helper leaves this empty.
	BindingAction string

	// BindingReason names the stdio binding violation:
	// "session_binding:batch_request" (batch with binding active),
	// "session_binding:missing_tool_name" (tools/call without
	// params.name), "session_binding:no_baseline" (tools/call before
	// the first tools/list response established a baseline),
	// "session_binding:unknown_tool" (tools/call for a tool not in
	// the session baseline). Empty when binding did not fire.
	BindingReason string

	// FrozenToolName is the tool name that tripped the stdio frozen
	// tool gate. Empty when the gate did not run or did not block.
	FrozenToolName string
}

// EvaluateMCPInputGates runs the configured inbound gates for one
// MCP request and returns their aggregated verdict. Each gate is
// nil-safe: the helper skips gates whose config is nil or whose
// preconditions are not met (e.g., DoW is tools/call-only).
//
// Gate execution order (semantic, not cosmetic):
//
//  1. Content scan via ScanRequest. Always runs. Establishes
//     ContentVerdict.ID / Method used by later short-circuit paths.
//  2. A2A body scan when a2aCfg is enabled and the method matches
//     IsA2AMethod. A block verdict short-circuits the remaining
//     tools/call-scoped gates.
//  3. Denial-of-wallet check for tools/call with a non-empty tool
//     name.
//  4. Policy check against the full message bytes.
//  5. Chain detection for tools/call. Mutates chain-matcher session
//     state; running after DoW preserves the contract that DoW-block
//     messages do not leave a chain trace.
//  6. Parse-error short-circuit from ContentVerdict.Error. Runs
//     after the stateful gates above so every configured gate
//     contributes its audit signals before the block verdict is
//     emitted.
//  7. Taint evaluation for tools/call. Reads session state the
//     earlier gates may have updated. PolicyAsk triggers the inline
//     approver dialog (HITL); approved sets TaintApproved.
//
// Adaptive signal recording, audit logging, and receipt emission
// stay in the caller because those side effects happen at the
// block-dispatch site where the transport-specific response shape
// is built. Lifting them here would hide the transport intent.
//
// scanAction, onParseError, and scanEnabled come from the caller's
// inputCfg; they are parameters rather than opts-derived so the
// helper does not have to duplicate the caller's scan-enable guard.
func EvaluateMCPInputGates(
	ctx context.Context,
	frame MCPFrame,
	msg []byte,
	sessionKey string,
	opts MCPProxyOpts,
	scanAction, onParseError string,
	scanEnabled bool,
) MCPInputEvaluation {
	eval := MCPInputEvaluation{}

	sc := opts.scanner()
	policyCfg := opts.policyCfg()
	chainMatcher := opts.chainMatcher()
	a2aCfg := opts.a2aCfg()

	// Gate 1: content scan.
	if scanEnabled {
		eval.ContentVerdict = ScanRequest(ctx, msg, sc, scanAction, onParseError)
	} else {
		eval.ContentVerdict = InputVerdict{Clean: true}
		// Always backfill ID / Method from the frame so downstream
		// block paths (adaptive block_all, CEE) can return correct
		// JSON-RPC error responses even when content scanning is
		// disabled.
		eval.ContentVerdict.ID = frame.ID
		eval.ContentVerdict.Method = frame.Method
	}
	if errors.Is(frame.ParseErr, ErrInvalidMethodType) {
		eval.ContentVerdict.ID = frame.ID
		eval.ContentVerdict.Method = frame.Method
		eval.ContentVerdict.Clean = false
		eval.ContentVerdict.Error = frame.ParseErr.Error()
	}

	// Gate 2: A2A body scan. Runs before the tools/call-scoped
	// gates so an A2A body block short-circuits them.
	if a2aCfg != nil && a2aCfg.Enabled {
		method := eval.ContentVerdict.Method
		if method == "" {
			method = frame.Method
			if eval.ContentVerdict.ID == nil {
				eval.ContentVerdict.ID = frame.ID
			}
		}
		if IsA2AMethod(method) {
			eval.A2AResult = ScanA2ARequestBody(ctx, msg, sc, a2aCfg)
			if !eval.A2AResult.Clean {
				action := eval.A2AResult.Action
				if action == "" {
					action = a2aCfg.Action
				}
				eval.A2AEffectiveAction = action
				if action == config.ActionBlock {
					eval.BlockingGate = blockingGateA2ABody
					return eval
				}
			}
		}
	}

	// Gate 3: DoW. Only for tools/call with a tool name.
	if opts.DoWCheck != nil && frame.IsToolsCall() && frame.ToolCallName != "" {
		allowed, action, reason, budgetType := opts.DoWCheck(frame.ToolCallName, string(frame.Args))
		eval.DoWAllowed = allowed
		eval.DoWAction = action
		eval.DoWReason = reason
		eval.DoWBudgetType = budgetType
		if !allowed && action == config.ActionBlock {
			eval.BlockingGate = blockingGateDoW
			return eval
		}
	}

	// Gate 4: policy.
	if policyCfg != nil {
		eval.PolicyVerdict = policyCfg.CheckRequest(msg)
	}

	// Gate 5: chain. Mutates chain-matcher session state; ordering
	// after DoW preserves the pre-refactor contract that DoW-block
	// messages do not leave a chain trace.
	if chainMatcher != nil && frame.IsToolsCall() && frame.ToolCallName != "" {
		cv := chainMatcher.Record(sessionKey, frame.ToolCallName, string(msg))
		if cv.Matched {
			eval.ChainMatched = true
			eval.ChainPatternName = cv.PatternName
			eval.ChainSeverity = cv.Severity
			eval.ChainAction = cv.Action
			eval.ChainReason = "chain:" + cv.PatternName
			if cv.Action == config.ActionBlock {
				eval.BlockingGate = blockingGateChain
				return eval
			}
		}
	}

	// Gate 6: parse-error short-circuit. Runs after the stateful
	// gates so every configured gate contributes its audit signals
	// before the block verdict is emitted. Matches the pre-refactor
	// ordering in scanHTTPInputDecision and ForwardScannedInput.
	if eval.ContentVerdict.Error != "" {
		eval.BlockingGate = blockingGateParseError
		return eval
	}

	// Gate 7: taint. Only for tools/call. PolicyAsk triggers the
	// inline approver dialog so HITL runs in the request-processing
	// goroutine, matching the pre-refactor call site.
	if frame.IsToolsCall() {
		taintOpts := opts
		taintOpts.TaintCfg = opts.taintCfg()
		taintOpts.TaintCfgFn = nil
		eval.TaintDecision = evaluateMCPTaint(taintOpts, frame.ToolCallName, string(frame.Args))
		switch eval.TaintDecision.Result.Decision {
		case session.PolicyBlock:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			eval.BlockingGate = blockingGateTaintBlock
			return eval
		case session.PolicyAsk:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			preview := frame.ToolCallName + " " + eval.TaintDecision.ActionRef
			approved, hasApprover := taintDecisionRequiresApproval(opts, frame.ToolCallName, taintApprovalReason(eval.TaintDecision), preview)
			if !hasApprover || !approved {
				eval.BlockingGate = blockingGateTaintAskDenied
				return eval
			}
			approveTaintDecision(&eval.TaintDecision)
			eval.TaintApproved = true
		}
	}

	return eval
}

// EvaluateMCPInputGatesStdio is the stdio counterpart to
// EvaluateMCPInputGates. The stdio path preserves gate ordering that
// diverges from the HTTP helper in three ways, all intentional and
// captured here so a single shared helper does not have to flip
// behavior on a transport switch:
//
//  1. Policy runs before DoW. HTTP runs policy after DoW; stdio's
//     pre-refactor order placed the policy check ahead of the
//     tools/call-scoped gates, so the policy verdict is materialized
//     before any tools/call-scoped gate can short-circuit.
//  2. Session binding is two-phase, wrapping DoW. The batch
//     pre-check fires before DoW; the tool-name check fires after.
//     Batches are rejected earlier in the caller, so the pre-check
//     is defense-in-depth -- the helper still populates it so the
//     caller's capture-observe side effect runs identically.
//  3. A frozen-tool gate sits between DoW and chain detection.
//     HTTP has no frozen-tool gate; it lives only on the stdio
//     transport to enforce airlock-hard-tier tool snapshots.
//
// Unlike HTTP, stdio does not have an A2A body gate; A2A methods
// flow through a separate path. The helper omits the a2a_body
// gate entirely.
//
// Gate execution order (semantic, not cosmetic):
//
//  1. Content scan via ScanRequest. Always runs. Establishes
//     ContentVerdict.ID / Method used by later short-circuit paths.
//  2. Policy check. Populates PolicyVerdict without short-circuit;
//     the caller folds matched policy into the effective action.
//  3. Session binding batch pre-check. Populates BindingAction /
//     BindingReason when a batch request is seen with binding
//     active. No short-circuit -- batches are rejected earlier in
//     the caller path.
//  4. Tool name extraction from the frame for the tools/call gates.
//  5. Denial-of-wallet check for tools/call with a non-empty tool
//     name. Blocks short-circuit; warns populate DoWAction.
//  6. Session binding tool check for tools/call. Overrides the
//     batch pre-check when it fires (missing tool name, no
//     baseline, unknown tool). No short-circuit -- the caller
//     folds BindingAction into the effective action merge.
//  7. Frozen tool enforcement. Short-circuits on a block verdict
//     when the session has a frozen snapshot and the tool is
//     either unparseable or not in the snapshot.
//  8. Chain detection for tools/call. Mutates chain-matcher
//     session state; the 1:1 stdio architecture uses the literal
//     "default" session key. Matched patterns populate chain
//     fields; Block-action matches short-circuit.
//  9. Parse-error short-circuit from ContentVerdict.Error. Runs
//     after the stateful gates so audit signals are recorded
//     before the block verdict is emitted.
//  10. Taint evaluation for tools/call. Reads session state the
//     earlier gates may have updated. PolicyAsk triggers the
//     inline approver dialog; approved sets TaintApproved.
//
// The helper populates MCPInputEvaluation without writing to
// logW, emitting audit logs, recording metrics, or firing
// capture observes. Those side effects stay in the caller at
// the block-dispatch site so the transport-specific response
// shape (JSON-RPC error codes, LogMessage strings) stays in
// the transport layer.
//
// trimmedLine is the caller's bytes.TrimSpace(msg) result,
// threaded through so the helper does not re-trim. The caller
// already computes it for the batch reject earlier in the loop.
func EvaluateMCPInputGatesStdio(
	ctx context.Context,
	frame MCPFrame,
	msg []byte,
	trimmedLine []byte,
	bindingCfg *SessionBindingConfig,
	opts MCPProxyOpts,
	scanAction, onParseError string,
) MCPInputEvaluation {
	eval := MCPInputEvaluation{}

	sc := opts.scanner()
	policyCfg := opts.policyCfg()
	chainMatcher := opts.chainMatcher()

	// Gate 1: content scan. Always runs on stdio (inputCfg is not
	// consulted at this layer -- the caller gates enablement via
	// the scanAction / onParseError it passes in).
	eval.ContentVerdict = ScanRequest(ctx, msg, sc, scanAction, onParseError)
	if errors.Is(frame.ParseErr, ErrInvalidMethodType) {
		eval.ContentVerdict.ID = frame.ID
		eval.ContentVerdict.Method = frame.Method
		eval.ContentVerdict.Clean = false
		eval.ContentVerdict.Error = frame.ParseErr.Error()
	}

	// Gate 2: policy. No short-circuit; policy participates in the
	// effective-action merge alongside content scan and binding.
	if policyCfg != nil {
		eval.PolicyVerdict = policyCfg.CheckRequest(msg)
	}

	// Gate 3: session binding batch pre-check. Unreachable in
	// practice because the caller rejects batches before calling
	// the helper, but kept as a defense-in-depth signal so the
	// capture observe fires when the early reject is ever removed.
	if bindingCfg != nil && bindingCfg.Baseline != nil && len(trimmedLine) > 0 && trimmedLine[0] == '[' {
		eval.BindingAction = bindingCfg.UnknownToolAction
		eval.BindingReason = bindingReasonBatchRequest
	}

	// Gate 4: tool name extraction.
	toolCallName := ""
	if eval.ContentVerdict.Method == methodToolsCall {
		toolCallName = frame.ToolCallName
	}

	// Gate 5: DoW. Only for tools/call with a tool name.
	if opts.DoWCheck != nil && eval.ContentVerdict.Method == methodToolsCall && toolCallName != "" {
		allowed, action, reason, budgetType := opts.DoWCheck(toolCallName, string(frame.Args))
		eval.DoWAllowed = allowed
		eval.DoWAction = action
		eval.DoWReason = reason
		eval.DoWBudgetType = budgetType
		if !allowed && action == config.ActionBlock {
			eval.BlockingGate = blockingGateDoW
			return eval
		}
	}

	// Gate 6: session binding tool check. Overrides the batch
	// pre-check when it fires. No short-circuit.
	if bindingCfg != nil && bindingCfg.Baseline != nil && eval.ContentVerdict.Method == methodToolsCall {
		switch {
		case toolCallName == "":
			eval.BindingAction = bindingCfg.UnknownToolAction
			eval.BindingReason = bindingReasonMissingToolName
		case !bindingCfg.Baseline.HasBaseline():
			eval.BindingAction = bindingCfg.NoBaselineAction
			eval.BindingReason = bindingReasonNoBaseline
		case !bindingCfg.Baseline.IsKnownTool(toolCallName):
			eval.BindingAction = bindingCfg.UnknownToolAction
			eval.BindingReason = bindingReasonUnknownTool
		}
	}

	// Gate 7: frozen tool. Fail-closed: block when the tool name
	// is empty (unparseable) or not in the frozen set.
	if opts.ToolFreezer != nil && opts.FrozenToolStableKey != "" &&
		opts.ToolFreezer.IsFrozen(opts.FrozenToolStableKey) {
		if toolCallName == "" || !opts.ToolFreezer.IsToolAllowed(opts.FrozenToolStableKey, toolCallName) {
			eval.FrozenToolName = toolCallName
			eval.BlockingGate = blockingGateFrozenTool
			return eval
		}
	}

	// Gate 8: chain detection. Stdio is 1:1 session-per-process;
	// the literal "default" session key is correct.
	if chainMatcher != nil && toolCallName != "" {
		cv := chainMatcher.Record("default", toolCallName, string(msg))
		if cv.Matched {
			eval.ChainMatched = true
			eval.ChainPatternName = cv.PatternName
			eval.ChainSeverity = cv.Severity
			eval.ChainAction = cv.Action
			eval.ChainReason = "chain:" + cv.PatternName
			if cv.Action == config.ActionBlock {
				eval.BlockingGate = blockingGateChain
				return eval
			}
		}
	}

	// Gate 9: parse-error short-circuit.
	if eval.ContentVerdict.Error != "" {
		eval.BlockingGate = blockingGateParseError
		return eval
	}

	// Gate 10: taint. Only for tools/call. PolicyAsk triggers the
	// inline approver dialog so HITL runs in the request-processing
	// goroutine, matching the pre-refactor call site.
	if eval.ContentVerdict.Method == methodToolsCall {
		taintOpts := opts
		taintOpts.TaintCfg = opts.taintCfg()
		taintOpts.TaintCfgFn = nil
		eval.TaintDecision = evaluateMCPTaint(taintOpts, toolCallName, string(frame.Args))
		switch eval.TaintDecision.Result.Decision {
		case session.PolicyBlock:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			eval.BlockingGate = blockingGateTaintBlock
			return eval
		case session.PolicyAsk:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			preview := strings.TrimSpace(fmt.Sprintf("%s %s", toolCallName, eval.TaintDecision.ActionRef))
			approved, hasApprover := taintDecisionRequiresApproval(opts, toolCallName, taintApprovalReason(eval.TaintDecision), preview)
			if !hasApprover || !approved {
				eval.BlockingGate = blockingGateTaintAskDenied
				return eval
			}
			approveTaintDecision(&eval.TaintDecision)
			eval.TaintApproved = true
		}
	}

	return eval
}
