// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	mcpTaintSourceKind  = "mcp_response"
	taintReasonDisabled = "taint_disabled"
	taintScopeAction    = "action"
	taintScopeSource    = "source"
)

type taintDecision struct {
	Risk           session.SessionRisk
	ActionClass    session.ActionClass
	Sensitivity    session.ActionSensitivity
	Authority      session.AuthorityKind
	Result         session.PolicyDecisionResult
	ActionRef      string
	RequiresReauth bool
}

func observeMCPResponseTaint(opts MCPProxyOpts, promptHit bool) {
	if opts.TaintCfg == nil || !opts.TaintCfg.Enabled {
		return
	}
	rs, ok := opts.Rec.(session.RiskState)
	if !ok {
		return
	}
	observation := session.ClassifyMCPResponseObservation(mcpTaintSourceKind, opts.TaintExternalSource, promptHit)
	observation.MaxSources = opts.TaintCfg.RecentSources
	rs.ObserveRisk(observation)
}

func evaluateMCPTaint(opts MCPProxyOpts, toolName, argsJSON string) taintDecision {
	decision := taintDecision{
		ActionClass: session.ActionClassRead,
		Sensitivity: session.SensitivityNormal,
		Authority:   session.AuthorityUserBroad,
		Result:      session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: taintReasonDisabled},
	}
	if opts.TaintCfg == nil || !opts.TaintCfg.Enabled {
		return decision
	}
	if rs, ok := opts.Rec.(session.RiskState); ok {
		decision.Risk = rs.RiskSnapshot()
	}
	decision.ActionClass, decision.Sensitivity, decision.ActionRef = session.ClassifyMCPToolCall(
		toolName,
		argsJSON,
		opts.TaintCfg.ProtectedPaths,
		opts.TaintCfg.ElevatedPaths,
	)
	decision.ActionRef = mcpActionRef(toolName, decision.ActionRef)
	decision.Result = session.PolicyMatrix{Profile: opts.TaintCfg.Policy}.Evaluate(
		decision.Risk.Level,
		decision.ActionClass,
		decision.Sensitivity,
		decision.Authority,
	)
	if taintTrustOverrideApplies(opts.TaintCfg.TrustOverrides, decision.Risk, decision.ActionRef) {
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

func taintRiskSourceMatches(risk session.SessionRisk, pattern string) bool {
	if taintWildcardMatch(risk.LastExternalURL, pattern) {
		return true
	}
	for _, source := range risk.Sources {
		if taintWildcardMatch(source.URL, pattern) {
			return true
		}
	}
	return false
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

func emitMCPToolReceipt(opts MCPProxyOpts, actionID, mcpMethod, toolName, receiptVerdict string, decision taintDecision) {
	if actionID == "" || opts.ReceiptEmitter == nil {
		return
	}
	_ = opts.ReceiptEmitter.Emit(receipt.EmitOpts{
		ActionID:            actionID,
		Verdict:             receiptVerdict,
		Transport:           opts.Transport,
		Target:              toolName,
		MCPMethod:           mcpMethod,
		ToolName:            toolName,
		SessionTaintLevel:   decision.Risk.Level.String(),
		SessionContaminated: decision.Risk.Contaminated,
		RecentTaintSources:  decision.Risk.Sources,
		AuthorityKind:       decision.Authority.String(),
		TaintDecision:       decision.Result.Decision.String(),
		TaintDecisionReason: decision.Result.Reason,
	})
}

func decorateMCPToolMessage(msg []byte, emitter *envelope.Emitter, actionID, mcpMethod, toolName, receiptVerdict string, decision taintDecision) []byte {
	if actionID == "" {
		return msg
	}
	return injectMCPEnvelope(msg, emitter, envelope.BuildOpts{
		ActionID:       actionID,
		Action:         string(receipt.ClassifyMCPTool(toolName, mcpMethod)),
		Verdict:        receiptVerdict,
		SessionTaint:   decision.Risk.Level.String(),
		AuthorityKind:  decision.Authority.String(),
		RequiresReauth: decision.RequiresReauth,
	})
}
