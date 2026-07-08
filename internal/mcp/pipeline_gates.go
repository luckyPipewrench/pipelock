// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// observeCrossAgentEmit records cross-agent taint propagation when a
// contaminated session emits over an MCP/A2A boundary, folding the escalation
// request into eval. The cross_agent taint source (evidence) is appended in
// place so a later gate's taint snapshot — and any receipt built from it —
// carries it. The adaptive escalation signal itself is recorded by the caller,
// which owns the EscalationParams.
func observeCrossAgentEmit(eval *MCPInputEvaluation, opts MCPProxyOpts, boundary session.CrossAgentBoundary) {
	if decide.ObserveCrossAgentContamination(opts.Rec, opts.taintCfg(), boundary).ShouldEscalate {
		eval.CrossAgentEscalate = true
	}
}

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

	// EnforcementIdentity is the per-action key used by DoW and
	// chain detection: raw tool name for ordinary tools/call, escaped
	// tool identity for reserved-prefix tools/call, or the namespaced
	// A2A method identity for A2A methods.
	EnforcementIdentity string

	// DoW fields are populated when DoWCheck is non-nil and the
	// message is a tools/call with a non-empty ToolCallName or an
	// A2A method with a baseline identity.
	DoWAllowed    bool
	DoWAction     string
	DoWReason     string
	DoWBudgetType string

	// PolicyVerdict is populated when policyCfg is non-nil.
	PolicyVerdict policy.Verdict

	// Chain fields are populated when chainMatcher is non-nil and
	// the message is a tools/call with a non-empty ToolCallName or
	// an A2A method with a baseline identity.
	// Note that chainMatcher.Record mutates session chain state on
	// every call; the gate ordering after DoW preserves the
	// pre-refactor contract that DoW-block messages do not leave a
	// chain trace.
	ChainMatched     bool
	ChainPatternName string
	ChainSeverity    string
	ChainAction      string
	ChainReason      string

	// TaintDecision is populated when the message is a tools/call or
	// A2A method. The taint evaluator reads session state potentially
	// mutated by earlier gates which is why it runs last.
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
	// when a binding violation was detected. Empty when binding did not
	// fire.
	BindingAction string

	// BindingReason names the binding violation:
	// "session_binding:batch_request" (batch with binding active),
	// "session_binding:missing_tool_name" (tools/call without
	// params.name), "session_binding:no_baseline" (tools/call or A2A
	// method before a baseline was established),
	// "session_binding:unknown_tool" (tools/call or A2A method not in
	// the session baseline). Empty when binding did not fire.
	BindingReason string

	// FrozenToolName is the tool name that tripped the stdio frozen
	// tool gate. Empty when the gate did not run or did not block.
	FrozenToolName string

	// CrossAgentEscalate is true when a contaminated session emitted across
	// an agent boundary (A2A request or MCP tools/call) at hostile taint
	// level, or when contamination state was indeterminate (fail-closed). The
	// caller records SignalCrossAgentContamination on its adaptive path; the
	// cross_agent taint source (evidence) is already appended in-gate so the
	// taint snapshot and any receipt carry it.
	CrossAgentEscalate bool
}

func mcpFrameEnforcementIdentity(frame MCPFrame, method string) string {
	// The DoW/chain/budget enforcement identity is the collision-safe callable
	// identity: a tool literally named with a reserved prefix (a2a:/tool:) is
	// namespaced away from A2A method identities, while ordinary tool names stay
	// raw so existing raw-name budget/chain configs keep matching (no fail-open).
	return mcpFrameCollisionSafeCallableIdentity(frame, method)
}

func mcpFrameCollisionSafeCallableIdentity(frame MCPFrame, method string) string {
	if frame.IsToolsCall() {
		return collisionSafeToolCallableIdentity(frame.ToolCallName)
	}
	if method == "" {
		method = frame.Method
	}
	return a2aBaselineIdentity(method)
}

func collisionSafeToolCallableIdentity(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return ""
	}
	if strings.HasPrefix(toolName, a2aBaselineIdentityPrefix) || strings.HasPrefix(toolName, toolBaselineIdentityPrefix) {
		return toolBaselineIdentity(toolName)
	}
	return toolName
}

func mcpFrameCallableArgs(frame MCPFrame) string {
	if frame.IsToolsCall() {
		return string(frame.Args)
	}
	params := mcpFrameParams(frame)
	if len(params) == 0 {
		return ""
	}
	return string(params)
}

func mcpFrameParams(frame MCPFrame) json.RawMessage {
	var decoded struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(frame.Raw, &decoded); err != nil {
		return nil
	}
	if len(decoded.Params) == 0 || string(decoded.Params) == "null" {
		return nil
	}
	return decoded.Params
}

func mcpFrameDoWArgs(frame MCPFrame, msg []byte) string {
	if frame.IsToolsCall() {
		return string(frame.Args)
	}
	return string(msg)
}

// EvaluateMCPInputGates runs the configured inbound gates for one
// MCP request and returns their aggregated verdict. Each gate is
// nil-safe: the helper skips gates whose config is nil or whose
// preconditions are not met.
//
// Gate execution order (semantic, not cosmetic). Sequence is fixed by
// the code below; see per-gate comments for placement rationale:
//
//   - content scan via ScanRequest. Always runs. Establishes
//     ContentVerdict.ID / Method used by later short-circuit paths.
//   - A2A body scan when a2aCfg is enabled and the method matches
//     IsA2AMethod. A block verdict short-circuits the remaining
//     enforcement gates.
//   - denial-of-wallet check for tools/call with a non-empty tool name
//     or A2A method with a baseline identity.
//   - policy check against the full message bytes.
//   - chain detection for tools/call and A2A method identities.
//     Mutates chain-matcher session state; running after DoW preserves
//     the contract that DoW-block messages do not leave a chain trace.
//   - parse-error short-circuit from ContentVerdict.Error. Runs after
//     the stateful gates above so every configured gate contributes
//     its audit signals before the block verdict is emitted.
//   - taint evaluation for tools/call and A2A method identities. Reads
//     session state the earlier gates may have updated. PolicyAsk
//     triggers the inline approver dialog (HITL); approved sets
//     TaintApproved.
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

	// content scan.
	if scanEnabled {
		eval.ContentVerdict = scanRequestForAgent(ctx, msg, sc, scanAction, onParseError, opts.addressProtectionAgent())
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

	method := eval.ContentVerdict.Method
	if method == "" {
		method = frame.Method
		if eval.ContentVerdict.ID == nil {
			eval.ContentVerdict.ID = frame.ID
		}
	}
	if IsA2AMethod(method) {
		// Cross-agent contamination: a contaminated session emitting an
		// A2A request to a peer agent propagates taint across the boundary.
		// Recorded before the A2A content scan and enforcement gates so the
		// evidence is captured regardless of which later gate short-circuits.
		observeCrossAgentEmit(&eval, opts, session.CrossAgentBoundaryA2ARequest)

		// A2A body scan. Runs before the enforcement gates so an
		// A2A body block short-circuits them.
		if a2aCfg != nil && a2aCfg.Enabled {
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

	// Cross-agent contamination for tools/call. A contaminated session emitting
	// a tool call to a tool/peer agent propagates taint across the MCP boundary.
	// Recorded BEFORE the short-circuiting DoW/binding/policy/chain/taint gates
	// so the cross_agent evidence (and the escalation request the caller acts on)
	// is captured even when a later gate blocks the emit. A2A-method emits are
	// recorded in their own block above for the same reason.
	if frame.IsToolsCall() {
		observeCrossAgentEmit(&eval, opts, session.CrossAgentBoundaryMCPToolCall)
	}

	enforcementIdentity := mcpFrameEnforcementIdentity(frame, eval.ContentVerdict.Method)
	eval.EnforcementIdentity = enforcementIdentity

	// DoW. Applies to tools/call by tool name and to A2A methods by the
	// namespaced method identity.
	if opts.DoWCheck != nil && enforcementIdentity != "" {
		allowed, action, reason, budgetType := opts.DoWCheck(enforcementIdentity, mcpFrameDoWArgs(frame, msg))
		eval.DoWAllowed = allowed
		eval.DoWAction = action
		eval.DoWReason = reason
		eval.DoWBudgetType = budgetType
		if !allowed && action == config.ActionBlock {
			eval.BlockingGate = blockingGateDoW
			return eval
		}
	}

	// session binding. HTTP listener traffic shares a listener-level
	// baseline; apply the same callable inventory check as stdio before
	// policy/chain/taint can treat the call as clean. Tools/call uses the raw
	// tool name for compatibility with the tools/list baseline. A2A methods
	// are not members of that MCP tool inventory; with an established baseline
	// they fail closed as unknown rather than letting a real tool named
	// "a2a:<method>" satisfy the method binding.
	if toolCfg := opts.toolCfg(); toolCfg != nil && toolCfg.Baseline != nil && toolCfg.BindingUnknownAction != "" && (enforcementIdentity != "" || frame.IsToolsCall()) {
		bindingIdentity := enforcementIdentity
		if frame.IsToolsCall() {
			bindingIdentity = frame.ToolCallName
		}
		switch {
		case frame.IsToolsCall() && frame.ToolCallName == "":
			eval.BindingAction = toolCfg.BindingUnknownAction
			eval.BindingReason = bindingReasonMissingToolName
		case !toolCfg.Baseline.HasBaseline():
			eval.BindingAction = toolCfg.BindingNoBaselineAction
			eval.BindingReason = bindingReasonNoBaseline
		case !frame.IsToolsCall() || !toolCfg.Baseline.IsKnownTool(bindingIdentity):
			eval.BindingAction = toolCfg.BindingUnknownAction
			eval.BindingReason = bindingReasonUnknownTool
		}
	}

	// policy.
	if policyCfg != nil {
		eval.PolicyVerdict = policyCfg.CheckRequest(msg)
	}

	// chain. Mutates chain-matcher session state; ordering
	// after DoW preserves the pre-refactor contract that DoW-block
	// messages do not leave a chain trace.
	if chainMatcher != nil && enforcementIdentity != "" {
		cv := chainMatcher.Record(sessionKey, enforcementIdentity, string(msg))
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

	// parse-error short-circuit. Runs after the stateful
	// gates so every configured gate contributes its audit signals
	// before the block verdict is emitted. Matches the pre-refactor
	// ordering in scanHTTPInputDecision and ForwardScannedInput.
	if eval.ContentVerdict.Error != "" {
		eval.BlockingGate = blockingGateParseError
		return eval
	}

	// taint. Applies to tools/call and A2A method identities. PolicyAsk
	// triggers the inline approver dialog so HITL runs in the
	// request-processing goroutine, matching the pre-refactor call site.
	taintIdentity := mcpFrameCollisionSafeCallableIdentity(frame, eval.ContentVerdict.Method)
	if taintIdentity != "" {
		// Cross-agent contamination was already observed before the
		// short-circuiting gates above; the cross_agent source is on the
		// session, so the taint snapshot below still carries it as evidence.
		taintOpts := opts
		taintOpts.TaintCfg = opts.taintCfg()
		taintOpts.TaintCfgFn = nil
		eval.TaintDecision = evaluateMCPTaint(taintOpts, taintIdentity, mcpFrameCallableArgs(frame))
		switch eval.TaintDecision.Result.Decision {
		case session.PolicyBlock:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			eval.BlockingGate = blockingGateTaintBlock
			return eval
		case session.PolicyAsk:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			preview := strings.TrimSpace(fmt.Sprintf("%s %s", taintIdentity, eval.TaintDecision.ActionRef))
			approved, hasApprover := taintDecisionRequiresApproval(opts, taintIdentity, taintApprovalReason(eval.TaintDecision), preview)
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
// diverges from the HTTP helper in three intentional ways, captured
// here so a single shared helper does not have to flip behavior on a
// transport switch:
//
//   - policy runs before DoW. HTTP runs policy after DoW; stdio's
//     pre-refactor order placed the policy check ahead of the
//     enforcement gates, so the policy verdict is materialized
//     before DoW or chain can short-circuit.
//   - session binding is two-phase, wrapping DoW. The batch pre-check
//     fires before DoW; the tool-name check fires after. Batches are
//     rejected earlier in the caller, so the pre-check is
//     defense-in-depth -- the helper still populates it so the
//     caller's capture-observe side effect runs identically.
//   - a frozen-tool gate sits between DoW and chain detection. HTTP
//     has no frozen-tool gate; it lives only on the stdio transport
//     to enforce airlock-hard-tier tool snapshots.
//
// Gate execution order (semantic, not cosmetic). Sequence is fixed
// by the code below; see per-gate comments for placement rationale:
//
//   - content scan via ScanRequest. Always runs. Establishes
//     ContentVerdict.ID / Method used by later short-circuit paths.
//   - A2A body scan when a2aCfg is enabled and the method matches
//     IsA2AMethod. A block verdict short-circuits the remaining gates.
//   - policy check. Populates PolicyVerdict without short-circuit;
//     the caller folds matched policy into the effective action.
//   - session binding batch pre-check. Populates BindingAction /
//     BindingReason when a batch request is seen with binding
//     active. No short-circuit -- batches are rejected earlier in
//     the caller path.
//   - tool name extraction from the frame for the tools/call gates.
//   - denial-of-wallet check for tools/call with a non-empty tool name
//     or A2A method with a baseline identity. Blocks short-circuit;
//     warns populate DoWAction.
//   - session binding callable check for tools/call and A2A method
//     identities. Overrides the batch pre-check when it fires (missing
//     tool name, no baseline, unknown callable). No short-circuit --
//     the caller folds BindingAction into the effective action merge.
//   - frozen tool enforcement. Short-circuits on a block verdict
//     when the session has a frozen snapshot and the tool is either
//     unparseable or not in the snapshot.
//   - chain detection for tools/call and A2A method identities. Mutates
//     chain-matcher session state; the 1:1 stdio architecture uses the
//     literal "default" session key. Matched patterns populate chain fields;
//     Block-action matches short-circuit.
//   - parse-error short-circuit from ContentVerdict.Error. Runs
//     after the stateful gates so audit signals are recorded before
//     the block verdict is emitted.
//   - taint evaluation for tools/call and A2A method identities. Reads
//     session state the earlier gates may have updated. PolicyAsk
//     triggers the inline approver dialog; approved sets TaintApproved.
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
	a2aCfg := opts.a2aCfg()

	// content scan. Always runs on stdio (inputCfg is not
	// consulted at this layer -- the caller gates enablement via
	// the scanAction / onParseError it passes in).
	eval.ContentVerdict = scanRequestForAgent(ctx, msg, sc, scanAction, onParseError, opts.addressProtectionAgent())
	if errors.Is(frame.ParseErr, ErrInvalidMethodType) {
		eval.ContentVerdict.ID = frame.ID
		eval.ContentVerdict.Method = frame.Method
		eval.ContentVerdict.Clean = false
		eval.ContentVerdict.Error = frame.ParseErr.Error()
	}

	method := eval.ContentVerdict.Method
	if method == "" {
		method = frame.Method
		if eval.ContentVerdict.ID == nil {
			eval.ContentVerdict.ID = frame.ID
		}
	}
	if IsA2AMethod(method) {
		observeCrossAgentEmit(&eval, opts, session.CrossAgentBoundaryA2ARequest)

		if a2aCfg != nil && a2aCfg.Enabled {
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

	// policy. No short-circuit; policy participates in the
	// effective-action merge alongside content scan and binding.
	if policyCfg != nil {
		eval.PolicyVerdict = policyCfg.CheckRequest(msg)
	}

	// session binding batch pre-check. Unreachable in
	// practice because the caller rejects batches before calling
	// the helper, but kept as a defense-in-depth signal so the
	// capture observe fires when the early reject is ever removed.
	if bindingCfg != nil && bindingCfg.Baseline != nil && len(trimmedLine) > 0 && trimmedLine[0] == '[' {
		eval.BindingAction = bindingCfg.UnknownToolAction
		eval.BindingReason = bindingReasonBatchRequest
	}

	// tool name extraction.
	toolCallName := ""
	if eval.ContentVerdict.Method == methodToolsCall {
		toolCallName = frame.ToolCallName
	}
	enforcementIdentity := mcpFrameEnforcementIdentity(frame, eval.ContentVerdict.Method)
	eval.EnforcementIdentity = enforcementIdentity

	// Cross-agent contamination for tools/call. Recorded BEFORE the
	// short-circuiting DoW/binding/frozen/chain/taint gates so the cross_agent
	// evidence and escalation request are captured even when a later gate
	// blocks the emit.
	if eval.ContentVerdict.Method == methodToolsCall {
		observeCrossAgentEmit(&eval, opts, session.CrossAgentBoundaryMCPToolCall)
	}

	// DoW. Applies to tools/call by tool name and to A2A methods by the
	// namespaced method identity.
	if opts.DoWCheck != nil && enforcementIdentity != "" {
		allowed, action, reason, budgetType := opts.DoWCheck(enforcementIdentity, mcpFrameDoWArgs(frame, msg))
		eval.DoWAllowed = allowed
		eval.DoWAction = action
		eval.DoWReason = reason
		eval.DoWBudgetType = budgetType
		if !allowed && action == config.ActionBlock {
			eval.BlockingGate = blockingGateDoW
			return eval
		}
	}

	// session binding callable check. Overrides the batch pre-check when it
	// fires. Tools/call uses the raw tool name for compatibility with the
	// tools/list baseline. A2A methods are not members of that MCP tool
	// inventory; with an established baseline they fail closed as unknown
	// rather than letting a real tool named "a2a:<method>" satisfy the method
	// binding. No short-circuit.
	if bindingCfg != nil && bindingCfg.Baseline != nil && (enforcementIdentity != "" || eval.ContentVerdict.Method == methodToolsCall) {
		switch {
		case eval.ContentVerdict.Method == methodToolsCall && toolCallName == "":
			eval.BindingAction = bindingCfg.UnknownToolAction
			eval.BindingReason = bindingReasonMissingToolName
		case !bindingCfg.Baseline.HasBaseline():
			eval.BindingAction = bindingCfg.NoBaselineAction
			eval.BindingReason = bindingReasonNoBaseline
		case eval.ContentVerdict.Method != methodToolsCall || !bindingCfg.Baseline.IsKnownTool(toolCallName):
			eval.BindingAction = bindingCfg.UnknownToolAction
			eval.BindingReason = bindingReasonUnknownTool
		}
	}

	// frozen tool. Scoped to tools/call messages because this gate enforces
	// the tool inventory snapshot captured for an MCP server. A2A frames are
	// method-based callables and are not members of that frozen tool set; they
	// are covered by the method-scoped binding, DoW, chain, taint, and
	// contract gates instead. Within tools/call the gate is fail-closed: block
	// when the tool name is empty or not in the frozen set.
	if opts.ToolFreezer != nil && opts.FrozenToolStableKey != "" &&
		eval.ContentVerdict.Method == methodToolsCall &&
		opts.ToolFreezer.IsFrozen(opts.FrozenToolStableKey) {
		if toolCallName == "" || !opts.ToolFreezer.IsToolAllowed(opts.FrozenToolStableKey, toolCallName) {
			eval.FrozenToolName = toolCallName
			eval.BlockingGate = blockingGateFrozenTool
			return eval
		}
	}

	// chain detection. Stdio is 1:1 session-per-process;
	// the literal "default" session key is correct.
	if chainMatcher != nil && enforcementIdentity != "" {
		cv := chainMatcher.Record("default", enforcementIdentity, string(msg))
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

	// parse-error short-circuit.
	if eval.ContentVerdict.Error != "" {
		eval.BlockingGate = blockingGateParseError
		return eval
	}

	// taint. Applies to tools/call and A2A method identities. PolicyAsk
	// triggers the inline approver dialog so HITL runs in the
	// request-processing goroutine, matching the pre-refactor call site.
	taintIdentity := mcpFrameCollisionSafeCallableIdentity(frame, eval.ContentVerdict.Method)
	if taintIdentity != "" {
		// Cross-agent contamination was already observed before the
		// short-circuiting gates above; the cross_agent source is on the
		// session, so the taint snapshot below still carries it as evidence.
		taintOpts := opts
		taintOpts.TaintCfg = opts.taintCfg()
		taintOpts.TaintCfgFn = nil
		eval.TaintDecision = evaluateMCPTaint(taintOpts, taintIdentity, mcpFrameCallableArgs(frame))
		switch eval.TaintDecision.Result.Decision {
		case session.PolicyBlock:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			eval.BlockingGate = blockingGateTaintBlock
			return eval
		case session.PolicyAsk:
			eval.TaintAuditDecision = eval.TaintDecision
			eval.TaintAuditDecisionSet = true
			preview := strings.TrimSpace(fmt.Sprintf("%s %s", taintIdentity, eval.TaintDecision.ActionRef))
			approved, hasApprover := taintDecisionRequiresApproval(opts, taintIdentity, taintApprovalReason(eval.TaintDecision), preview)
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
