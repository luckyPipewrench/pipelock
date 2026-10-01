// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// deferKillSwitchPollInterval is how often held calls are checked against the
// kill switch while nothing else is happening on the session.
//
// Activation is otherwise noticed only when the next message arrives or when a
// held call reaches its release claim. The sentinel file has no event source at
// all, so without a poll a call held for a long resolver or approval window
// would sit through a documented kill. A second is short against the minutes a
// hold can last and costs one stat of the sentinel path per tick, and only
// while something is held.
var deferKillSwitchPollInterval = time.Second

// watchDeferredKillSwitch cancels every held call as soon as the kill switch is
// active, whichever source activated it. It returns when ctx is done. It is a
// no-op for a session with no kill switch or no defer manager.
//
// Cancellation goes through Manager.ResolveAll, so each hold resolves block
// with resolution_source kill_switch and gets the same resolution receipt and
// journal row the on-message path produces. Resolving a hold is idempotent, so
// racing the on-message check or the release claim is safe: whichever runs
// first wins and the others find nothing left to cancel.
func watchDeferredKillSwitch(ctx context.Context, ks *killswitch.Controller, manager *deferred.Manager) {
	if ks == nil || manager == nil {
		return
	}
	ticker := time.NewTicker(deferKillSwitchPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if manager.HeldCount() == 0 {
				continue
			}
			if ks.IsActive() {
				manager.ResolveAll(config.ActionBlock, deferred.SourceKillSwitch)
			}
		}
	}
}

// emitKillSwitchDenialReceipt signs the refusal of a tool call (or A2A
// request) by the kill switch. Held calls the kill switch cancels already
// produce a kill_switch resolution receipt; a plain call refused before it
// reaches any other gate produced nothing, so the receipt chain showed an
// allowed call followed by silence while the client had in fact been refused.
//
// Only frames with a receipt target (a tool call or an A2A method) are
// receipted, the same rule every other MCP block uses. A failure to emit is
// logged and, under require_receipts, reported; the denial itself stands
// either way because it is already fail-closed.
func emitKillSwitchDenialReceipt(opts MCPProxyOpts, logW io.Writer, frame MCPFrame, d killswitch.Decision) {
	method := methodToolsCall
	target := frame.ToolCallName
	if target == "" && IsA2AMethod(frame.Method) {
		method = frame.Method
		target = frame.Method
	}
	if target == "" {
		return
	}
	emitter := opts.receiptEmitter()
	if emitter == nil {
		return
	}
	pattern := "kill switch active: request denied"
	if d.Source != "" {
		pattern = fmt.Sprintf("kill switch active (%s): request denied", d.Source)
	}
	if _, err := EmitMCPDecision(emitter, opts.v2ReceiptEmitter(), nil, MCPDecision{
		Receipt: opts.withReceiptPolicyHash(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     mcpReceiptLayerKillSwitch,
			Pattern:   pattern,
			Severity:  config.SeverityHigh,
			Transport: opts.Transport,
			Target:    target,
			MCPMethod: method,
			ToolName:  frame.ToolCallName,
		}),
	}); err != nil {
		logReceiptEmitFailure(logW, err, opts.requireReceipts(), config.ActionBlock)
	}
}
