// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

func EmitDeferredResolutionReceipt(opts MCPProxyOpts, logW io.Writer, res deferred.Resolution) error {
	final := res.FinalDecision
	if final == "" {
		final = config.ActionBlock
	}
	if final == "block" {
		final = config.ActionBlock
	}
	if final == "allow" {
		final = config.ActionAllow
	}
	if final == "step_up" {
		final = config.ActionAsk
	}
	return emitMCPToolReceipt(mcpToolReceiptOpts{
		Emitter:           opts.receiptEmitter(),
		V2Emitter:         opts.v2ReceiptEmitter(),
		PolicyHash:        opts.receiptPolicyHash(),
		Log:               logW,
		Transport:         opts.Transport,
		ActionID:          receipt.NewActionID(),
		ParentActionID:    res.ParentActionID,
		MCPMethod:         res.Method,
		ToolName:          res.Target,
		Verdict:           final,
		Layer:             mcpReceiptLayerPolicy,
		Pattern:           res.Reason,
		Severity:          config.SeverityHigh,
		Decision:          taintDecision{Authority: session.AuthorityUserBroad, Result: session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: "defer_resolution"}},
		RequireReceipt:    true,
		DecisionPhase:     receipt.DecisionPhaseResolution,
		DeferID:           res.DeferID,
		ResolutionSource:  res.ResolutionSource,
		SessionID:         res.Authority.SessionID,
		SessionIDOriginal: res.Authority.SessionIDOriginal,
	})
}

func emitDeferredResolutionReceipt(opts MCPProxyOpts, logW io.Writer, res deferred.Resolution) error {
	return EmitDeferredResolutionReceipt(opts, logW, res)
}
