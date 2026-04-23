// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// MCPDecision bundles the per-decision state a gate in the inbound
// MCP pipeline needs to emit. Today each gate calls
// receiptEmitter.Emit(...) and (for allow/warn tool calls) the
// envelope-injection helper separately, which means the emission
// field set drifts between gates and between transports.
//
// EmitMCPDecision fans a single Decision out to both emitters in a
// deterministic order so every gate sees the same two-stage emission
// semantics: receipt first, then envelope injection on the inbound
// message bytes.
//
// The struct deliberately wraps the existing receipt.EmitOpts and
// envelope.BuildOpts instead of duplicating their fields. Duplicating
// would force this file to evolve every time the receipt schema gains
// a field; wrapping keeps MCPDecision as pure routing.
type MCPDecision struct {
	// Receipt is handed straight to receipt.Emitter.Emit when the
	// decision should produce a receipt. A zero-value Receipt (in
	// particular, empty ActionID) is the skip signal. The emission
	// path already no-ops on empty ActionID but surfacing the skip
	// explicitly here keeps the decision contract legible at callers.
	Receipt receipt.EmitOpts

	// Envelope, if non-nil, is injected into InboundMsg via the
	// existing injectMCPEnvelope helper. Used today for clean and
	// warn-mode tools/call forwarding. A nil Envelope means no
	// injection runs and InboundMsg flows through unchanged.
	Envelope *envelope.BuildOpts

	// InboundMsg is the already-rewritten JSON-RPC bytes that would
	// be forwarded upstream. When Envelope is non-nil,
	// EmitMCPDecision returns the envelope-injected rewrite of these
	// bytes; otherwise the caller gets InboundMsg back verbatim.
	//
	// Callers that do not need envelope injection (block, strip,
	// redirect) can set this to nil and ignore the returned bytes.
	InboundMsg []byte
}

// EmitMCPDecision emits the receipt and (optionally) injects the
// mediation envelope for d. Returns the outbound message bytes —
// envelope-injected when d.Envelope is non-nil, d.InboundMsg verbatim
// otherwise. The returned error is the receipt-emit error if one
// occurred; envelope injection does not return an error (the existing
// helper is fail-open).
//
// Both emitters are nil-safe:
//
//   - nil receiptEmitter: receipt stage is skipped silently.
//   - nil envelopeEmitter or nil d.Envelope: envelope stage is
//     skipped and the input message flows through unchanged.
//   - empty d.Receipt.ActionID: receipt stage is skipped (the
//     downstream emitter interprets this as "no receipt for this
//     decision"; surfacing the check here avoids an unnecessary
//     call and keeps the contract legible at gate sites).
//
// Receipt and envelope emission are independent: a failed receipt
// emit does not block envelope injection and a nil envelope does
// not block receipt emission. This matches today's scatter-gather
// callsites where the two are inlined in sequence with no
// cross-dependency.
//
// Callers that want fine-grained control (e.g., conditional
// injection based on session taint state) assemble their Envelope
// build opts before handing the decision to EmitMCPDecision and
// leave Envelope nil when injection should skip.
func EmitMCPDecision(
	receiptEmitter *receipt.Emitter,
	envelopeEmitter *envelope.Emitter,
	d MCPDecision,
) (outbound []byte, err error) {
	outbound = d.InboundMsg

	if receiptEmitter != nil && d.Receipt.ActionID != "" {
		err = receiptEmitter.Emit(d.Receipt)
		// Intentional: continue to envelope injection even on receipt
		// error. The two stages are independent at today's callsites
		// and coupling them here would break parity.
	}

	if envelopeEmitter != nil && d.Envelope != nil && d.InboundMsg != nil {
		outbound = injectMCPEnvelope(d.InboundMsg, envelopeEmitter, *d.Envelope)
	}

	return outbound, err
}
