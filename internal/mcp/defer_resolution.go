// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"io"
	"sync"

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
	layer := mcpReceiptLayerPolicy
	switch res.ResolutionSource {
	case deferred.SourceAuthority:
		layer = mcpReceiptLayerAuthority
	case deferred.SourceKillSwitch:
		layer = mcpReceiptLayerKillSwitch
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
		Layer:             layer,
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
// error message plus any receipt gap. Shared by the stdio and HTTP-forward
// defer paths.
func emitHoldFailureResolution(opts MCPProxyOpts, logW io.Writer, holdErr error, hf holdFailureResolution) (string, error) {
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
	emitErr := emitDeferredResolutionReceipt(opts, logW, deferred.Resolution{
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
		return "pipelock: defer cascade depth exceeded", emitErr
	}
	return "pipelock: defer capacity exceeded", emitErr
}

const (
	// mcpReceiptLayerKillSwitch matches the layer the reverse proxy records
	// for ordinary kill-switch denials.
	mcpReceiptLayerKillSwitch = "kill_switch"
	// deferredKillSwitchReason is the receipt pattern for a held call that the
	// kill switch cancelled, whichever resolver reached it first.
	deferredKillSwitchReason = "kill switch active: deferred call cancelled"
	// deferredUpstreamContractReason is the receipt pattern for a held HTTP
	// call that the live upstream gate denied at release.
	deferredUpstreamContractReason = "upstream contract denied deferred release"
	// deferredKillSwitchFallbackMessage is used only when the switch has
	// already been lifted again by the time the denial is written.
	deferredKillSwitchFallbackMessage = "pipelock: kill switch active"
)

// deferredReleasePrecheck is the Manager.BeforeAllow hook. It rejects a hold
// whose activation epoch has already passed so the manager journals the
// cancellation as a kill-switch block. It is only an early check: the claim it
// takes is released at once, because the authoritative claim is taken by
// claimDeferredRelease at the irreversible send boundary.
func deferredReleasePrecheck(opts MCPProxyOpts, generation uint64) (func(), bool) {
	if opts.beforeDeferredSendClaim != nil {
		opts.beforeDeferredSendClaim()
	}
	if opts.KillSwitch == nil {
		return func() {}, true
	}
	release, ok := opts.KillSwitch.ClaimDeferredSendAt(generation)
	if !ok {
		return nil, false
	}
	release()
	return func() {}, true
}

// claimDeferredRelease is the kill-switch check at the irreversible release
// boundary of a deferred MCP call. Callers must already hold the lock that
// serializes writes to the sink (stdio forwardMu, HTTP upstreamMu), so no
// unbounded wait sits between this claim and the write or send; the only work
// in between is the manager's journal write and the receipt that record the
// committed release, both bounded local I/O.
//
// Ordering: every activation source (config reload, API, signal, Conductor
// sources) sets its flag and bumps the deferred generation while holding the
// controller's deferredMu write lock, and ClaimDeferredSendAt takes the same
// write lock to compare the generation captured when the call was read and to
// evaluate every source, including a stat of the sentinel file. The two
// critical sections are therefore totally ordered. If an activation completes
// first, the claim observes the bumped generation or the active source and the
// call is cancelled. If the claim completes first, the release is committed at
// that instant and the activation is ordered after it, exactly like an
// ordinary call that was already forwarded. This is why it no longer matters
// that Manager.Resolve removes a hold from its map before invoking the
// callback: a ResolveAll that finds nothing left to cancel still wins here,
// because the activation that triggered it is ordered before this claim.
func claimDeferredRelease(opts MCPProxyOpts, generation uint64) (func(), bool) {
	if opts.beforeDeferredSinkClaim != nil {
		opts.beforeDeferredSinkClaim()
	}
	if opts.KillSwitch == nil {
		return func() {}, true
	}
	return opts.KillSwitch.ClaimDeferredSendAt(generation)
}

// lockAndClaimDeferredRelease takes the sink lock, then the kill-switch claim.
// On success it returns res unchanged with a finish func that releases the
// claim and the lock; the manager runs it with defer. On a failed claim it
// unlocks at once and returns the kill-switch cancellation.
func lockAndClaimDeferredRelease(mu sync.Locker, opts MCPProxyOpts, generation uint64, res deferred.Resolution) (deferred.Resolution, func()) {
	mu.Lock()
	handedOff := false
	defer func() {
		if !handedOff {
			mu.Unlock()
		}
	}()
	release, ok := claimDeferredRelease(opts, generation)
	if !ok {
		markDeferredKillSwitch(&res)
		return res, nil
	}
	handedOff = true
	return res, func() {
		release()
		mu.Unlock()
	}
}

// markDeferredKillSwitch rewrites a resolution into the kill-switch
// cancellation recorded in the resolution receipt.
func markDeferredKillSwitch(res *deferred.Resolution) {
	res.FinalDecision = config.ActionBlock
	res.ResolutionSource = deferred.SourceKillSwitch
	res.Reason = deferredKillSwitchReason
}

// deferredKillSwitchMessage returns the operator-configured kill-switch
// message the ordinary killed path sends to the client.
func deferredKillSwitchMessage(opts MCPProxyOpts) string {
	if opts.KillSwitch != nil {
		if d := opts.KillSwitch.IsActiveMCP(nil); d.Active && d.Message != "" {
			return d.Message
		}
	}
	return deferredKillSwitchFallbackMessage
}
