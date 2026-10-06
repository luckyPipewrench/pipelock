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
		Emitter:         opts.receiptEmitter(),
		V2Emitter:       opts.v2ReceiptEmitter(),
		PolicyHash:      opts.receiptPolicyHash(),
		Log:             logW,
		Transport:       opts.Transport,
		ActionID:        receipt.NewActionID(),
		ParentActionID:  res.ParentActionID,
		MCPMethod:       res.Method,
		ToolName:        res.Target,
		Verdict:         final,
		Layer:           layer,
		Pattern:         res.Reason,
		Severity:        config.SeverityHigh,
		Decision:        taintDecision{Authority: session.AuthorityUserBroad, Result: session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: "defer_resolution"}},
		RequireReceipts: opts.requireReceipts(),
		RequireReceipt:  true,
		// A resolution receipt must be on disk before the journal entry that
		// closes the hold: restart recovery, which writes the journal entry
		// right after, would otherwise leave a hold closed with no receipt.
		Durable:           true,
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

// deferredReceiptSettlement orders a released call's evidence. The allow
// resolution receipt is the proof that a held call was released, so it is
// written after the journal records a pending release (Manager.AfterJournal).
// Whenever the release then closes to block, the same hook writes the
// corrective block receipt before the corrective terminal journal entry, and
// Resolve reuses that receipt instead of emitting another one.
// Prepare runs before the journal and so only probes that a required receipt
// could be written at all.
//
// When the receipt is required and its write fails after the journal accepted
// the allow, the manager closes the decision to a block everywhere it is
// recorded: a corrective journal entry, the value ResolveApprovalResult hands
// the operator API, and the client error.
//
// Prepare, AfterJournal and Resolve run in sequence on the resolving
// goroutine, so the struct needs no lock.
type deferredReceiptSettlement struct {
	done     bool
	err      error
	decision string
	source   string
}

// probeAllow closes an allow whose required receipt cannot possibly be written:
// no receipt emitter is configured, or one is already marked unhealthy. It
// writes nothing. A write that fails later is caught by commitAllow.
func (s *deferredReceiptSettlement) probeAllow(opts MCPProxyOpts, res deferred.Resolution) deferred.Resolution {
	if res.FinalDecision == config.ActionAllow && !receiptWritable(opts) {
		res.FinalDecision = config.ActionBlock
		res.ResolutionSource = deferred.SourceCancel
		res.Reason = deferred.ReasonReceiptNotWritten
	}
	return res
}

// receiptWritable reports whether a required receipt has a usable emitter.
// Receipts that are not required never close a release.
func receiptWritable(opts MCPProxyOpts) bool {
	if !opts.requireReceipts() {
		return true
	}
	v1, v2 := opts.receiptEmitter(), opts.v2ReceiptEmitter()
	v1OK := v1 != nil && v1.InitError() == nil && v1.HealthError() == nil
	v2OK := v2 != nil && v2.HealthError() == nil
	if v2 != nil && !v2OK {
		return false
	}
	return v1OK || v2OK
}

// commitAllow writes the release resolution receipt from Manager.AfterJournal:
// the initial allow, or the corrective block when the release closes.
func (s *deferredReceiptSettlement) commitAllow(opts MCPProxyOpts, logW io.Writer, res deferred.Resolution) error {
	return s.emit(opts, logW, res)
}

// ensure returns the outcome of emitting the receipt for the final resolution.
// A receipt already written for exactly this decision and source is reused; any
// other final resolution (a block, or an allow the journal or the receipt write then closed) gets its
// own receipt so the chain describes what actually happened.
func (s *deferredReceiptSettlement) ensure(opts MCPProxyOpts, logW io.Writer, res deferred.Resolution) error {
	if s.done && s.decision == res.FinalDecision && s.source == res.ResolutionSource {
		return s.err
	}
	return s.emit(opts, logW, res)
}

func (s *deferredReceiptSettlement) emit(opts MCPProxyOpts, logW io.Writer, res deferred.Resolution) error {
	s.err = emitDeferredResolutionReceipt(opts, logW, res)
	s.done, s.decision, s.source = true, res.FinalDecision, res.ResolutionSource
	return s.err
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
