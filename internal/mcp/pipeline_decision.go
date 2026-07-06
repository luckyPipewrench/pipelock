// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

var ErrReceiptRequired = errors.New("receipt required but not emitted")

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
	// Receipt is handed straight to receipt.Emitter.Emit when the decision should
	// produce a receipt. A zero-value Receipt (in particular, empty ActionID) is
	// the skip signal unless RequireReceipt is set, in which case the decision
	// fails closed.
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

	// RequireReceipt escalates a missing or failed receipt into an error.
	// Callers use this only for otherwise-forwardable decisions so an
	// operator can opt into "no receipt, no traffic" without changing the
	// default warn-and-forward behavior.
	RequireReceipt bool
}

// EmitMCPDecision emits the receipt and (optionally) injects the
// mediation envelope for d. Returns the outbound message bytes -
// envelope-injected when d.Envelope is non-nil, d.InboundMsg verbatim
// otherwise. The returned error is the receipt-emit error if one
// occurred, or the envelope-injection error. Envelope injection is
// fail-closed on malformed params: callers must treat a non-nil error
// as a block and must not forward the returned bytes.
//
// Both emitters are nil-safe:
//
//   - nil receiptEmitter: receipt stage is skipped silently unless
//     RequireReceipt is set, in which case the decision fails closed.
//   - nil envelopeEmitter or nil d.Envelope: envelope stage is
//     skipped and the input message flows through unchanged.
//   - empty d.Receipt.ActionID: receipt stage is skipped unless
//     RequireReceipt is set, in which case the decision fails closed.
//
// Receipt and envelope emission are independent unless RequireReceipt turns a
// missing or failed receipt into a blocking error: best-effort receipt failures
// do not block envelope injection, and a nil envelope does not block receipt
// emission. Required receipt failures return before envelope injection so the
// caller never receives rewritten bytes for a fail-closed decision.
//
// Callers that want fine-grained control (e.g., conditional
// injection based on session taint state) assemble their Envelope
// build opts before handing the decision to EmitMCPDecision and
// leave Envelope nil when injection should skip.
func EmitMCPDecision(
	receiptEmitter *receipt.Emitter,
	v2Emitter *proxydecision.Emitter,
	envelopeEmitter *envelope.Emitter,
	d MCPDecision,
) (outbound []byte, err error) {
	outbound = d.InboundMsg

	v1Emitted := false
	receiptRequired := d.RequireReceipt
	durableIntent := receiptRequired && receipt.NormalizeVerdict(d.Receipt.Verdict) == config.ActionAllow
	if receiptRequired && d.Receipt.ActionID == "" {
		err = fmt.Errorf("empty action id: %w", ErrReceiptRequired)
	} else if receiptRequired && receiptEmitter == nil {
		err = fmt.Errorf("%w: emitter unavailable", ErrReceiptRequired)
	} else if receiptEmitter != nil && d.Receipt.ActionID != "" {
		if durableIntent {
			d.Receipt.DecisionPhase = receipt.DecisionPhaseIntent
			err = receiptEmitter.EmitDurable(d.Receipt)
		} else {
			err = receiptEmitter.Emit(d.Receipt)
		}
		v1Emitted = err == nil
		// Optional receipt errors continue to envelope injection; the
		// RequireReceipt gate below upgrades errors to fail-closed before
		// envelope mutation.
	}
	if receiptRequired && err != nil && !errors.Is(err, ErrReceiptRequired) {
		err = fmt.Errorf("%w: %w", ErrReceiptRequired, err)
	}
	if receiptRequired && err != nil {
		return outbound, err
	}
	if v1Emitted && v2Emitter != nil {
		if v2Decision, ok := mcpV2DecisionFromReceipt(d.Receipt); ok {
			if v2Err := v2Emitter.Emit(v2Decision); v2Err != nil && err == nil {
				err = v2Err
			}
		}
	}

	if envelopeEmitter != nil && d.Envelope != nil && d.InboundMsg != nil {
		var envelopeErr error
		outbound, envelopeErr = injectMCPEnvelope(d.InboundMsg, envelopeEmitter, *d.Envelope)
		if envelopeErr != nil {
			return outbound, envelopeErr
		}
	}

	return outbound, err
}

func emitMCPOutcomeReceipt(
	receiptEmitter *receipt.Emitter,
	v2Emitter *proxydecision.Emitter,
	logW io.Writer,
	opts receipt.EmitOpts,
	status string,
	bytesTransferred int64,
	reason string,
) {
	if receiptEmitter == nil || opts.ActionID == "" {
		return
	}
	if status == "" {
		status = "unknown"
	}
	if reason == "" {
		reason = "complete"
	}
	bytesValue := "unknown"
	if bytesTransferred >= 0 {
		bytesValue = fmt.Sprintf("%d", bytesTransferred)
	}
	opts.DecisionPhase = receipt.DecisionPhaseOutcome
	opts.Verdict = config.ActionAllow
	opts.Layer = "outcome"
	opts.Pattern = fmt.Sprintf("status=%s bytes=%s reason=%s", status, bytesValue, reason)
	if _, err := EmitMCPDecision(receiptEmitter, v2Emitter, nil, MCPDecision{Receipt: opts}); err != nil {
		logReceiptEmitFailure(logW, err, false, config.ActionAllow)
	}
}

// mcpV2DecisionFromReceipt derives the v2 proxy_decision input from the v1
// EmitOpts. The returned bool is false when the decision cannot form a valid v2
// payload (empty target), so the caller skips emission rather than letting the
// emitter's validator reject a malformed receipt. This mirrors the forward
// proxy's v2DecisionFromOpts and keeps the v2 stream free of validation churn
// for tool calls that arrive without a tool name.
func mcpV2DecisionFromReceipt(opts receipt.EmitOpts) (proxydecision.Decision, bool) {
	if opts.Target == "" {
		return proxydecision.Decision{}, false
	}
	d := proxydecision.Decision{
		ActionType: "mcp_tool_call",
		Transport:  opts.Transport,
		Target:     opts.Target,
		Verdict:    receipt.NormalizeVerdict(opts.Verdict),
		PolicyHash: opts.PolicyHash,
		RuleID:     opts.Pattern,
		PolicySources: []string{
			proxydecision.SourceScanner,
		},
		WinningSource: proxydecision.SourceScanner,
	}
	if opts.Layer == "kill_switch" {
		d.PolicySources = []string{proxydecision.SourceKillSwitch}
		d.WinningSource = proxydecision.SourceKillSwitch
	}
	if opts.ContractWinningSource != "" ||
		len(opts.ContractPolicySources) > 0 ||
		opts.ActiveManifestHash != "" ||
		opts.ContractHash != "" ||
		opts.ContractSelectorID != "" {
		d.WinningSource = opts.ContractWinningSource
		if d.WinningSource == "" {
			d.WinningSource = proxydecision.SourceContract
		}
		d.PolicySources = append([]string{}, opts.ContractPolicySources...)
		if !stringSliceContains(d.PolicySources, proxydecision.SourceContract) {
			d.PolicySources = append(d.PolicySources, proxydecision.SourceContract)
		}
		d.RuleID = opts.ContractRuleID
		d.LiveVerdict = receipt.NormalizeVerdict(opts.ContractLiveVerdict)
		d.ActiveManifestHash = opts.ActiveManifestHash
		d.ContractHash = opts.ContractHash
		d.SelectorID = opts.ContractSelectorID
		d.ContractGeneration = opts.ContractGeneration
	}
	return d, true
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
