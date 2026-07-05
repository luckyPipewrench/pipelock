// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
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
	if final == config.ActionStepUp {
		final = config.ActionAsk
	}
	var cascade *deferred.ReceiptCascade
	if res.CascadeDepth > 0 || res.ParentDeferID != "" || res.Linkage != "" {
		cascade = &deferred.ReceiptCascade{
			ParentDeferID: res.ParentDeferID,
			CascadeDepth:  res.CascadeDepth,
			Linkage:       res.Linkage,
		}
	}
	// Unconditional so capacity denials (no cascade context) still record the
	// policy bounds; Cascade stays nil and marshals away via omitempty.
	resolutionPolicy := deferred.ReceiptPolicyStringFor(deferred.ReceiptPolicyOptions{Bounds: res.Policy, Cascade: cascade})
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
		RequireReceipts:   opts.requireReceipts(),
		RequireReceipt:    true,
		DecisionPhase:     receipt.DecisionPhaseResolution,
		DeferID:           res.DeferID,
		ResolutionPolicy:  resolutionPolicy,
		ResolutionSource:  res.ResolutionSource,
		SessionID:         res.Authority.SessionID,
		SessionIDOriginal: res.Authority.SessionIDOriginal,
	})
}

func emitDeferredResolutionReceipt(opts MCPProxyOpts, logW io.Writer, res deferred.Resolution) error {
	return EmitDeferredResolutionReceipt(opts, logW, res)
}

// holdFailureResolution carries the surface-specific fields for a failed
// Manager.Hold so both defer transports emit identical denial receipts.
type holdFailureResolution struct {
	DeferID   string
	Authority deferred.AuthoritySnapshot
	Policy    deferred.ResolutionPolicy
	Target    string
	Method    string
	Reason    string
}

// emitHoldFailureResolution classifies a failed Hold (capacity vs cascade
// limit), emits the blocking resolution receipt, and returns the client-facing
// error message. Shared by the stdio and HTTP-forward defer paths.
func emitHoldFailureResolution(opts MCPProxyOpts, logW io.Writer, holdErr error, hf holdFailureResolution) string {
	source := deferred.HoldFailureSource(holdErr)
	cascadeDepth := 0
	parentDeferID := ""
	linkage := ""
	var limitErr *deferred.CascadeLimitError
	if errors.As(holdErr, &limitErr) {
		cascadeDepth = limitErr.Depth
		parentDeferID = limitErr.ParentDeferID
		linkage = deferred.LinkageSessionPendingAncestor
	}
	_ = emitDeferredResolutionReceipt(opts, logW, deferred.Resolution{
		DeferID:          hf.DeferID,
		ParentActionID:   hf.DeferID,
		FinalDecision:    config.ActionBlock,
		ResolutionSource: source,
		Authority:        hf.Authority,
		ParentDeferID:    parentDeferID,
		CascadeDepth:     cascadeDepth,
		Linkage:          linkage,
		Policy:           hf.Policy,
		Target:           hf.Target,
		Method:           hf.Method,
		Reason:           hf.Reason,
	})
	if source == deferred.SourceCascadeLimit {
		return "pipelock: defer cascade depth exceeded"
	}
	return "pipelock: defer capacity exceeded"
}
