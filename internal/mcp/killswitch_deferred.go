// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
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

// maxKillSwitchBatchReceipts caps how many members of one refused JSON-RPC
// batch get an individual receipt. A batch is refused as a whole and every
// member costs a signature on the reader goroutine, so an uncapped batch lets
// one message become one receipt per member for as long as the kill switch is
// active. The client's response is not capped: every member with an id still
// gets its error.
const maxKillSwitchBatchReceipts = 64

// refuseKillSwitchRequest signs the refusal of a message the kill switch
// denied and returns the batch response to send, or nil when the frame is not a
// batch or no member has an id, so the caller keeps its single-message and
// notification handling. A batch is parsed once for both the receipts and the
// response.
func refuseKillSwitchRequest(opts MCPProxyOpts, logW io.Writer, frame MCPFrame, d killswitch.Decision) []byte {
	if !frame.IsBatch {
		emitKillSwitchDenialReceipt(opts, logW, frame, d)
		return nil
	}
	members := killSwitchBatchMembers(frame)
	emitKillSwitchBatchReceipts(opts, logW, members, d)
	return killSwitchBatchResponse(members, d.Message)
}

// emitKillSwitchBatchReceipts receipts the members of a refused batch that are
// tool calls or A2A requests, up to maxKillSwitchBatchReceipts. The batch
// wrapper has no target of its own, and a refused batch must not leave less
// evidence than the same calls sent one at a time, but the evidence is bounded:
// past the cap nothing more is signed and one warning says how many were not.
func emitKillSwitchBatchReceipts(opts MCPProxyOpts, logW io.Writer, members []MCPFrame, d killswitch.Decision) {
	if opts.receiptEmitter() == nil {
		return
	}
	receipted, skipped := 0, 0
	for _, member := range members {
		if _, _, ok := killSwitchReceiptTarget(member); !ok {
			continue
		}
		if receipted >= maxKillSwitchBatchReceipts {
			skipped++
			continue
		}
		receipted++
		emitKillSwitchDenialReceipt(opts, logW, member, d)
	}
	if skipped > 0 {
		_, _ = fmt.Fprintf(logW, "pipelock: kill switch refused a batch: %d refused members were not individually receipted (cap %d)\n",
			skipped, maxKillSwitchBatchReceipts)
	}
}

// killSwitchReceiptTarget returns the receipt method and target of a frame, or
// false when it has none: only a tool call or an A2A method is receipted, the
// same rule every other MCP block uses.
func killSwitchReceiptTarget(frame MCPFrame) (method, target string, ok bool) {
	if frame.ToolCallName != "" {
		return methodToolsCall, frame.ToolCallName, true
	}
	if IsA2AMethod(frame.Method) {
		return frame.Method, frame.Method, true
	}
	return "", "", false
}

// emitKillSwitchDenialReceipt signs the refusal of a single tool call (or A2A
// request) by the kill switch. Held calls the kill switch cancels already
// produce a kill_switch resolution receipt; a plain call refused before it
// reaches any other gate produced nothing, so the receipt chain showed an
// allowed call followed by silence while the client had in fact been refused.
// A batch goes through refuseKillSwitchRequest, which bounds its receipts.
//
// A failure to emit is logged and, under require_receipts, reported; the
// denial itself stands either way because it is already fail-closed.
func emitKillSwitchDenialReceipt(opts MCPProxyOpts, logW io.Writer, frame MCPFrame, d killswitch.Decision) {
	method, target, ok := killSwitchReceiptTarget(frame)
	if !ok {
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

// killSwitchBatchMembers parses the members of a batch frame. A body that is
// not a JSON array of objects yields nothing, and a nested array is skipped:
// JSON-RPC defines no nested batch, so it has no target to receipt and no
// request to answer.
func killSwitchBatchMembers(frame MCPFrame) []MCPFrame {
	var raws []json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(frame.Raw), &raws); err != nil {
		return nil
	}
	members := make([]MCPFrame, 0, len(raws))
	for _, raw := range raws {
		member := ParseMCPFrame(raw)
		if member.IsBatch {
			continue
		}
		members = append(members, member)
	}
	return members
}

// killSwitchBatchResponse answers a refused batch the way the single-object
// path answers a refused request: one -32004 error per member that carries an
// id, as a JSON-RPC batch response. It returns nil when no member has an id
// (every member is a notification, or there are none), so the caller keeps its
// notification handling for that case.
func killSwitchBatchResponse(members []MCPFrame, message string) []byte {
	var out bytes.Buffer
	out.WriteByte('[')
	count := 0
	for _, member := range members {
		if member.ID == nil {
			continue
		}
		if count > 0 {
			out.WriteByte(',')
		}
		out.Write(killswitch.ErrorResponse(member.ID, message))
		count++
	}
	if count == 0 {
		return nil
	}
	out.WriteByte(']')
	return out.Bytes()
}
