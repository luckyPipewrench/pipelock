// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	mcpTaintSourceKind  = "mcp_response"
	taintReasonDisabled = "taint_disabled"
	taintScopeAction    = "action"
	taintScopeSource    = "source"
	taintScopeTask      = "task"
)

const (
	mcpReceiptLayerA2A           = "mcp_a2a_scanning"
	mcpReceiptLayerChain         = "mcp_chain_detection"
	mcpReceiptLayerDoW           = "mcp_denial_of_wallet"
	mcpReceiptLayerInput         = "mcp_input_scanning"
	mcpReceiptLayerPolicy        = "mcp_tool_policy"
	mcpReceiptLayerRedaction     = "mcp_input_redaction"
	mcpReceiptLayerSessionBind   = "mcp_session_binding"
	mcpReceiptLayerTaint         = "mcp_tool_taint"
	mcpReceiptLayerToolInventory = "mcp_tool_inventory"

	// mcpReceiptPatternPolicyDefault is the fallback Pattern emitted on
	// receipts when policy matched but the rule list is empty or
	// whitespace. Concrete rule names override this. Extracted as a const
	// so production and tests share the same string (goconst).
	mcpReceiptPatternPolicyDefault = "policy"
)

type taintDecision struct {
	Risk                session.SessionRisk
	Task                session.TaskContext
	ActionClass         session.ActionClass
	Sensitivity         session.ActionSensitivity
	Authority           session.AuthorityKind
	Result              session.PolicyDecisionResult
	ActionRef           string
	RequiresReauth      bool
	TaskOverrideApplied bool
}

func observeMCPResponseTaint(opts MCPProxyOpts, promptHit bool) {
	taintCfg := opts.taintCfg()
	if taintCfg == nil || !taintCfg.Enabled {
		return
	}
	rs, ok := opts.Rec.(session.RiskState)
	if !ok {
		return
	}
	observation := session.ClassifyMCPResponseObservation(mcpTaintSourceKind, opts.TaintExternalSource, promptHit)
	observation.MaxSources = taintCfg.RecentSources
	rs.ObserveRisk(observation)
}

func evaluateMCPTaint(opts MCPProxyOpts, toolName, argsJSON string) taintDecision {
	decision := taintDecision{
		ActionClass: session.ActionClassRead,
		Sensitivity: session.SensitivityNormal,
		Authority:   session.AuthorityUserBroad,
		Result:      session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: taintReasonDisabled},
	}
	taintCfg := opts.taintCfg()
	if taintCfg == nil || !taintCfg.Enabled {
		return decision
	}
	if rs, ok := opts.Rec.(session.RiskState); ok {
		decision.Risk = rs.RiskSnapshot()
	}
	decision.ActionClass, decision.Sensitivity, decision.ActionRef = session.ClassifyMCPToolCall(
		toolName,
		argsJSON,
		taintCfg.ProtectedPaths,
		taintCfg.ElevatedPaths,
	)
	decision.ActionRef = mcpActionRef(toolName, decision.ActionRef)
	if tp, ok := opts.Rec.(session.TaskContextProvider); ok {
		decision.Task = tp.TaskSnapshot()
		if taintRuntimeTrustOverrideApplies(tp.RuntimeTrustOverrides(), decision.Task, decision.Risk, decision.ActionRef) {
			decision.Result = session.PolicyDecisionResult{
				Decision: session.PolicyAllow,
				Reason:   "taint_runtime_task_override",
			}
			decision.TaskOverrideApplied = true
			return decision
		}
	}
	decision.Result = session.PolicyMatrix{Profile: taintCfg.Policy}.Evaluate(
		decision.Risk.Level,
		decision.ActionClass,
		decision.Sensitivity,
		decision.Authority,
	)
	if taintTrustOverrideApplies(taintCfg.TrustOverrides, decision.Risk, decision.ActionRef) {
		decision.Result = session.PolicyDecisionResult{
			Decision: session.PolicyAllow,
			Reason:   "taint_trust_override",
		}
	}
	return decision
}

func taintDecisionRequiresApproval(opts MCPProxyOpts, toolName, reason, preview string) (bool, bool) {
	if opts.Approver == nil {
		return false, false
	}
	decision := opts.Approver.Ask(buildHITLRequestForTaint(toolName, reason, preview))
	return decision == hitl.DecisionAllow, true
}

func approveTaintDecision(decision *taintDecision) {
	if decision == nil {
		return
	}
	decision.Authority = session.AuthorityOperatorOverride
	decision.RequiresReauth = true
}

func buildHITLRequestForTaint(toolName, reason, preview string) *hitl.Request {
	target := toolName
	if target == "" {
		target = "mcp-tools-call"
	}
	return &hitl.Request{
		URL:     target,
		Reason:  reason,
		Preview: preview,
	}
}

func mcpActionRef(toolName, target string) string {
	parts := []string{"mcp", strings.ToLower(strings.TrimSpace(toolName))}
	if strings.TrimSpace(target) != "" {
		parts = append(parts, strings.ToLower(strings.TrimSpace(target)))
	}
	return strings.Join(parts, ":")
}

func taintTrustOverrideApplies(overrides []config.TaintTrustOverride, risk session.SessionRisk, actionRef string) bool {
	for _, override := range overrides {
		if !override.ExpiresAt.IsZero() && override.ExpiresAt.Before(time.Now().UTC()) {
			continue
		}
		if !taintOverrideMatches(override, risk, actionRef) {
			continue
		}
		return true
	}
	return false
}

func taintOverrideMatches(override config.TaintTrustOverride, risk session.SessionRisk, actionRef string) bool {
	switch override.Scope {
	case taintScopeAction:
		if override.ActionMatch == "" || !taintWildcardMatch(actionRef, override.ActionMatch) {
			return false
		}
		if override.SourceMatch != "" && !taintRiskSourceMatches(risk, override.SourceMatch) {
			return false
		}
		return true
	case taintScopeSource:
		if override.SourceMatch == "" || !taintRiskSourceMatches(risk, override.SourceMatch) {
			return false
		}
		if override.ActionMatch != "" && !taintWildcardMatch(actionRef, override.ActionMatch) {
			return false
		}
		return true
	default:
		return false
	}
}

func taintRuntimeTrustOverrideApplies(overrides []session.TrustOverride, task session.TaskContext, risk session.SessionRisk, actionRef string) bool {
	now := time.Now().UTC()
	for _, override := range overrides {
		if override.Scope != taintScopeTask {
			continue
		}
		if override.TaskID == "" || override.TaskID != task.CurrentTaskID {
			continue
		}
		if !override.ExpiresAt.IsZero() && override.ExpiresAt.Before(now) {
			continue
		}
		if override.ActionMatch != "" && !taintWildcardMatch(actionRef, override.ActionMatch) {
			continue
		}
		if override.SourceMatch != "" && !taintRiskSourceMatches(risk, override.SourceMatch) {
			continue
		}
		return true
	}
	return false
}

func taintRiskSourceMatches(risk session.SessionRisk, pattern string) bool {
	return taintWildcardMatch(risk.LastExternalURL, pattern)
}

func taintWildcardMatch(value, pattern string) bool {
	if value == "" || pattern == "" {
		return false
	}
	if matched, err := path.Match(pattern, value); err == nil && matched {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return value == pattern
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	if !strings.HasSuffix(pattern, "*") && parts[len(parts)-1] != "" && !strings.HasSuffix(value, parts[len(parts)-1]) {
		return false
	}
	return true
}

func taintApprovalReason(decision taintDecision) string {
	return fmt.Sprintf("%s after %s", decision.ActionClass.String(), decision.Result.Reason)
}

type mcpToolReceiptOpts struct {
	Emitter          *receipt.Emitter
	V2Emitter        *proxydecision.Emitter
	PolicyHash       string
	Log              io.Writer
	Transport        string
	RedactionProfile string
	ActionID         string
	MCPMethod        string
	ToolName         string
	Verdict          string
	Layer            string
	Pattern          string
	Severity         string
	Decision         taintDecision
	Report           *redact.Report
	ContractGate     *mcpContractGateOutput
}

// emitMCPToolReceipt emits the post-decision tool receipt for an MCP
// tools/call message. The receipt payload bundles redaction context,
// transport, scanner attribution, and the full taint snapshot. Routed
// through EmitMCPDecision so every tool receipt in the MCP inbound
// pipeline goes through a single emission entry point.
func emitMCPToolReceipt(opts mcpToolReceiptOpts) {
	if opts.ActionID == "" || opts.Emitter == nil {
		return
	}
	emitOpts := receipt.EmitOpts{
		ActionID:            opts.ActionID,
		Verdict:             opts.Verdict,
		Layer:               opts.Layer,
		Pattern:             opts.Pattern,
		Severity:            opts.Severity,
		RedactionProfile:    opts.RedactionProfile,
		RedactionReport:     opts.Report,
		Transport:           opts.Transport,
		Target:              opts.ToolName,
		MCPMethod:           opts.MCPMethod,
		ToolName:            opts.ToolName,
		SessionTaintLevel:   opts.Decision.Risk.Level.String(),
		SessionContaminated: opts.Decision.Risk.Contaminated,
		RecentTaintSources:  opts.Decision.Risk.Sources,
		SessionTaskID:       opts.Decision.Task.CurrentTaskID,
		SessionTaskLabel:    opts.Decision.Task.CurrentTaskLabel,
		AuthorityKind:       opts.Decision.Authority.String(),
		TaintDecision:       opts.Decision.Result.Decision.String(),
		TaintDecisionReason: opts.Decision.Result.Reason,
		TaskOverrideApplied: opts.Decision.TaskOverrideApplied,
		PolicyHash:          opts.PolicyHash,
	}
	if opts.ContractGate != nil {
		emitOpts = mcpWithContractReceipt(emitOpts, *opts.ContractGate)
	}
	if _, err := EmitMCPDecision(opts.Emitter, opts.V2Emitter, nil, MCPDecision{
		Receipt: emitOpts,
	}); err != nil && opts.Log != nil {
		_, _ = fmt.Fprintf(opts.Log, "pipelock: receipt emission failed: %v\n", err)
	}
}

// pickAttribution derives the receipt Layer / Pattern / Severity for a
// block verdict, based on which gate inside MCPInputEvaluation fired.
//
// Maintenance contract: every value the gate-evaluation code assigns to
// eval.BlockingGate (see internal/mcp/pipeline_gates.go) must have a
// matching case in the switch below. The fall-through if-chain covers
// gates that produce signal on eval fields without setting BlockingGate
// (currently policy, binding, taint-allow-with-reason, dow-fallback,
// a2a-fallback, content-scan). When you add a new gate, extend the
// switch in the same change - otherwise the new gate's block receipts
// will emit empty Layer / Pattern / Severity from the final fallback.
func pickAttribution(eval MCPInputEvaluation) (layer, pattern, severity string) {
	switch eval.BlockingGate {
	case blockingGateA2ABody:
		return mcpReceiptLayerA2A, firstNonEmpty(eval.A2AResult.Reason, blockingGateA2ABody), config.SeverityHigh
	case blockingGateDoW:
		return mcpReceiptLayerDoW, firstNonEmpty(eval.DoWReason, blockingGateDoW), config.SeverityHigh
	case blockingGateFrozenTool:
		return mcpReceiptLayerToolInventory, firstNonEmpty(eval.FrozenToolName, blockingGateFrozenTool), config.SeverityHigh
	case blockingGateChain:
		return mcpReceiptLayerChain, firstNonEmpty(eval.ChainPatternName, eval.ChainReason), firstNonEmpty(eval.ChainSeverity, config.SeverityHigh)
	case blockingGateParseError:
		return mcpReceiptLayerInput, firstNonEmpty(eval.ContentVerdict.Error, blockingGateParseError), config.SeverityHigh
	case blockingGateTaintBlock, blockingGateTaintAskDenied:
		return mcpReceiptLayerTaint, firstNonEmpty(eval.TaintDecision.Result.Reason, eval.BlockingGate), taintReceiptSeverity(eval.TaintDecision)
	}

	if eval.ChainMatched || eval.ChainReason != "" {
		return mcpReceiptLayerChain, firstNonEmpty(eval.ChainPatternName, eval.ChainReason), firstNonEmpty(eval.ChainSeverity, config.SeverityHigh)
	}
	if eval.PolicyVerdict.Matched {
		return mcpReceiptLayerPolicy, firstPolicyRule(eval.PolicyVerdict.Rules), config.SeverityHigh
	}
	if eval.BindingReason != "" {
		return mcpReceiptLayerSessionBind, eval.BindingReason, config.SeverityHigh
	}
	if eval.TaintDecision.Result.Decision != session.PolicyAllow && eval.TaintDecision.Result.Reason != "" {
		return mcpReceiptLayerTaint, eval.TaintDecision.Result.Reason, taintReceiptSeverity(eval.TaintDecision)
	}
	if eval.DoWAction != "" && !eval.DoWAllowed {
		return mcpReceiptLayerDoW, firstNonEmpty(eval.DoWReason, eval.DoWAction), config.SeverityHigh
	}
	if !eval.A2AResult.Clean && eval.A2AResult.Reason != "" {
		return mcpReceiptLayerA2A, eval.A2AResult.Reason, config.SeverityHigh
	}
	if layer, pattern, severity := contentScanAttribution(eval.ContentVerdict); layer != "" {
		return layer, pattern, severity
	}
	return "", "", ""
}

func contentScanAttribution(verdict InputVerdict) (layer, pattern, severity string) {
	if len(verdict.Matches) > 0 {
		m := verdict.Matches[0]
		return mcpReceiptLayerInput, m.PatternName, firstNonEmpty(m.Severity, config.SeverityHigh)
	}
	if len(verdict.Inject) > 0 {
		return mcpReceiptLayerInput, verdict.Inject[0].PatternName, config.SeverityHigh
	}
	if len(verdict.AddressFindings) > 0 {
		return mcpReceiptLayerInput, "address:" + verdict.AddressFindings[0].Explanation, config.SeverityHigh
	}
	if verdict.Error != "" {
		return mcpReceiptLayerInput, verdict.Error, config.SeverityHigh
	}
	return "", "", ""
}

func firstPolicyRule(rules []string) string {
	if len(rules) == 0 || strings.TrimSpace(rules[0]) == "" {
		return mcpReceiptPatternPolicyDefault
	}
	return rules[0]
}

func taintReceiptSeverity(decision taintDecision) string {
	switch decision.Result.Decision {
	case session.PolicyBlock:
		return config.SeverityCritical
	case session.PolicyAsk:
		return config.SeverityHigh
	default:
		return config.SeverityMedium
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func redactionBlockAttribution(err error) (layer, pattern, severity string) {
	pattern = string(redact.ReasonInternalError)
	var blockErr *redact.BlockError
	if errors.As(err, &blockErr) && blockErr.Reason != "" {
		pattern = string(blockErr.Reason)
	}
	return mcpReceiptLayerRedaction, pattern, config.SeverityHigh
}

// decorateMCPToolMessage injects the mediation envelope for a clean or
// warn-mode tools/call that is about to be forwarded upstream. Routed
// through EmitMCPDecision so envelope injection shares the same
// emission entry point as receipt emission.
func decorateMCPToolMessage(msg []byte, emitter *envelope.Emitter, actionID, mcpMethod, toolName, receiptVerdict string, decision taintDecision) ([]byte, error) {
	if actionID == "" {
		return msg, nil
	}
	buildOpts := envelope.BuildOpts{
		ActionID:       actionID,
		Action:         string(receipt.ClassifyMCPTool(toolName, mcpMethod)),
		Verdict:        receiptVerdict,
		SessionTaint:   decision.Risk.Level.String(),
		TaskID:         decision.Task.CurrentTaskID,
		AuthorityKind:  decision.Authority.String(),
		RequiresReauth: decision.RequiresReauth,
	}
	out, err := EmitMCPDecision(nil, nil, emitter, MCPDecision{
		Envelope:   &buildOpts,
		InboundMsg: msg,
	})
	return out, err
}
