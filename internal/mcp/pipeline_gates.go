// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/session"
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
					eval.BlockingGate = "a2a_body"
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
			eval.BlockingGate = "dow"
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
				eval.BlockingGate = "chain"
				return eval
			}
		}
	}

	// Gate 6: parse-error short-circuit. Runs after the stateful
	// gates so every configured gate contributes its audit signals
	// before the block verdict is emitted. Matches the pre-refactor
	// ordering in scanHTTPInputDecision and ForwardScannedInput.
	if eval.ContentVerdict.Error != "" {
		eval.BlockingGate = "parse_error"
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
			eval.BlockingGate = "taint_block"
			return eval
		case session.PolicyAsk:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			preview := frame.ToolCallName + " " + eval.TaintDecision.ActionRef
			approved, hasApprover := taintDecisionRequiresApproval(opts, frame.ToolCallName, taintApprovalReason(eval.TaintDecision), preview)
			if !hasApprover || !approved {
				eval.BlockingGate = "taint_ask_denied"
				return eval
			}
			approveTaintDecision(&eval.TaintDecision)
			eval.TaintApproved = true
		}
	}

	return eval
}
