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

var errMCPV2ReceiptEmit = errors.New("mcp v2 proxydecision receipt emit failed")

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

	// RequiredMode is the configured require_receipts policy. A per-call
	// RequireReceipt may still refuse a deferred call in best-effort mode,
	// but only RequiredMode may quarantine every shard and stop the process.
	RequiredMode bool

	// Durable writes the receipt fsync-confirmed whatever its verdict. Required
	// receipts for forwardable verdicts are always durable; this extends that to
	// a receipt whose loss after a later durable write would leave a gap, such
	// as a deferred resolution written before its journal entry. It changes how
	// the receipt is written. When RequireReceipt is set, every configured
	// family must confirm this write before the caller can commit its state.
	Durable bool
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
	return emitMCPDecision(receiptEmitter, v2Emitter, envelopeEmitter, d, false)
}

// MCPReceiptGroup keeps each v2 writer paired with the corresponding signed
// v1 shard. Admission selects the index once; every later emission must carry
// the same index in Receipt. A missing pair is an error, never a fallback to
// another shard.
type MCPReceiptGroup struct {
	Shards            *receipt.ReceiptShardSet
	V2                []*proxydecision.Emitter
	OnRequiredFailure func(error)
}

// EmitMCPGroupDecision requires both signed writes for a grouped decision.
// The legacy EmitMCPDecision contract intentionally remains unchanged.
func EmitMCPGroupDecision(group MCPReceiptGroup, envelopeEmitter *envelope.Emitter, d MCPDecision) ([]byte, error) {
	if d.RequiredMode {
		d.RequireReceipt = true
	}
	if group.Shards == nil || !d.Receipt.ShardSelected || d.Receipt.ShardIndex < 0 || d.Receipt.ShardIndex >= len(group.V2) {
		return d.InboundMsg, fmt.Errorf("%w: receipt group shard was not selected at admission", ErrReceiptRequired)
	}
	if len(group.V2) != group.Shards.ShardCount() || group.V2[d.Receipt.ShardIndex] == nil {
		return d.InboundMsg, fmt.Errorf("%w: receipt group shard pair unavailable", ErrReceiptRequired)
	}
	v1, selectErr := group.Shards.SelectedEmitter(d.Receipt)
	if selectErr != nil {
		return d.InboundMsg, fmt.Errorf("%w: %w", ErrReceiptRequired, selectErr)
	}
	out, err := emitMCPDecision(v1, group.V2[d.Receipt.ShardIndex], envelopeEmitter, d, true)
	if d.RequiredMode && err != nil && (errors.Is(err, receipt.ErrReceiptPostAdvance) || v1.HealthError() != nil || group.V2[d.Receipt.ShardIndex].HealthError() != nil) {
		group.Shards.MarkUnhealthy(err)
		if group.OnRequiredFailure != nil {
			group.OnRequiredFailure(err)
		}
	}
	return out, err
}

func emitMCPDecision(
	receiptEmitter *receipt.Emitter,
	v2Emitter *proxydecision.Emitter,
	envelopeEmitter *envelope.Emitter,
	d MCPDecision,
	strictPair bool,
) (outbound []byte, err error) {
	outbound = d.InboundMsg

	v1Emitted := false
	v2Emitted := false
	receiptRequired := d.RequireReceipt
	escalateReceiptError := func() (bool, error) {
		if !receiptRequired || err == nil {
			return false, nil
		}
		if !errors.Is(err, ErrReceiptRequired) {
			err = fmt.Errorf("%w: %w", ErrReceiptRequired, err)
		}
		return true, err
	}
	// A forwardable verdict is one whose request or response actually egresses to
	// its peer: allow, warn, and forward carry a request upstream, and strip
	// writes the redacted response back to the client. redirect invokes a
	// handler that can perform work and return bytes; block/ask/defer deny or
	// hold the original action. Every egressing required
	// receipt is recorded DURABLY (fsync-confirmed) before those bytes leave, so a
	// crash between the write and the next flush cannot lose the decision record
	// for traffic that already went out. This closes the crash-durability window
	// that previously applied to warn/forward/strip (only allow was durable
	// before).
	verdict := receipt.NormalizeVerdict(d.Receipt.Verdict)
	durableReceipt := receiptRequired &&
		(verdict == config.ActionAllow ||
			verdict == config.ActionWarn ||
			verdict == config.ActionForward ||
			verdict == config.ActionStrip ||
			verdict == config.ActionRedirect)
	// Only allow carries the DecisionPhaseIntent label (it is paired with a
	// downstream DecisionPhaseOutcome); warn/forward/strip/redirect stay single-phase
	// durable decision receipts, which the completeness verifier counts as
	// neither an intent nor an outcome, so broadening durability cannot create an
	// unmatched-intent. The DecisionPhase=="" guard means a caller that already
	// set a phase (e.g. a deferred-resolution receipt carrying
	// DecisionPhaseResolution with a final allow verdict) keeps its phase instead
	// of being overwritten to intent.
	markIntent := receiptRequired && verdict == config.ActionAllow && d.Receipt.DecisionPhase == ""
	// The intent phase is a property of the decision itself, so mark it before
	// either emitter is attempted rather than only on the v1 path. This keeps the
	// v1 and v2 emitters (which both consume d.Receipt) consistent even when v1 is
	// absent.
	if markIntent && d.Receipt.ActionID != "" {
		d.Receipt.DecisionPhase = receipt.DecisionPhaseIntent
	}
	syncReceipt := durableReceipt || d.Durable
	if receiptRequired && d.Receipt.ActionID == "" {
		err = fmt.Errorf("empty action id: %w", ErrReceiptRequired)
	} else if receiptEmitter != nil && d.Receipt.ActionID != "" {
		if syncReceipt {
			err = receiptEmitter.EmitDurable(d.Receipt)
		} else {
			err = receiptEmitter.Emit(d.Receipt)
		}
		v1Emitted = err == nil
		// Optional receipt errors continue to envelope injection; the
		// RequireReceipt gate below upgrades errors to fail-closed before
		// envelope mutation.
	}
	if d.Receipt.ActionID != "" && v2Emitter != nil {
		if v2Err := emitMCPV2Decision(v2Emitter, d.Receipt, receiptRequired, syncReceipt); v2Err != nil {
			if err == nil || syncReceipt {
				err = v2Err
			}
		} else {
			v2Emitted = true
		}
	}
	// An outcome closes its intent only through the v1 receipt, which carries
	// the action ID and phase; a v2 proxy_decision record carries neither. So a
	// v2 success never stands in for a required outcome's v1 receipt, or the
	// caller would report an outcome the chain can't pair.
	v2Covers := v2Emitted && d.Receipt.DecisionPhase != receipt.DecisionPhaseOutcome
	// Before bytes egress, every configured receipt family must record the
	// decision; one family never stands in for another's failure. A v2 record
	// carries no action ID or phase and has no native AEL activity, so it
	// cannot represent a missing v1 intent, and a v1 record cannot represent a
	// missing v2 one. Explicitly durable required decisions also need every
	// family, since a caller may persist state based on that confirmation.
	// An unconfigured (nil) family is not required. Other decisions that do not
	// egress keep best-effort receipts: the action is already denied.
	v1Satisfied := receiptEmitter == nil || v1Emitted
	v2Satisfied := v2Emitter == nil || v2Emitted
	if receiptRequired && !strictPair && (v1Emitted || v2Covers) && (!syncReceipt || (v1Satisfied && v2Satisfied)) {
		err = nil
	}
	if strictPair && receiptRequired && (!v1Emitted || !v2Emitted) && err == nil {
		err = fmt.Errorf("%w: receipt group shard pair incomplete", ErrReceiptRequired)
	}
	if receiptRequired && !v1Emitted && !v2Covers && err == nil {
		err = fmt.Errorf("%w: emitter unavailable", ErrReceiptRequired)
	}
	if done, escalateErr := escalateReceiptError(); done {
		return outbound, escalateErr
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

// emitMCPV2Decision writes the v2 proxy_decision receipt for opts. durable
// selects the fsync-confirmed write; required turns an underivable v2 payload
// into an error instead of a skip.
func emitMCPV2Decision(v2Emitter *proxydecision.Emitter, opts receipt.EmitOpts, required, durable bool) error {
	if v2Emitter == nil {
		return nil
	}
	v2Decision, ok := mcpV2DecisionFromReceipt(opts)
	if !ok {
		if required {
			return fmt.Errorf("%w: could not derive v2 decision action_id=%s transport=%s target=%q",
				errMCPV2ReceiptEmit, opts.ActionID, opts.Transport, opts.Target)
		}
		return nil
	}
	var emitErr error
	if durable {
		emitErr = v2Emitter.EmitDurable(v2Decision)
	} else {
		emitErr = v2Emitter.Emit(v2Decision)
	}
	if err := emitErr; err != nil {
		return fmt.Errorf("%w: %w", errMCPV2ReceiptEmit, err)
	}
	return nil
}

// emitMCPOutcomeReceipt records what happened to a call whose intent was
// allowed and which Pipelock went on to send: the verdict stays allow and the
// status says how the exchange ended. A call refused after its intent was
// written uses emitMCPBlockedOutcomeReceipt instead.
func emitMCPOutcomeReceipt(
	receiptEmitter *receipt.Emitter,
	v2Emitter *proxydecision.Emitter,
	group *MCPReceiptGroup,
	logW io.Writer,
	opts receipt.EmitOpts,
	status string,
	bytesTransferred int64,
	reason string,
	required bool,
) {
	opts.Verdict = config.ActionAllow
	opts.Layer = mcpOutcomeLayer
	emitMCPOutcome(receiptEmitter, v2Emitter, group, logW, opts, status, bytesTransferred, reason, required)
}

// emitMCPBlockedOutcomeReceipt closes an allowed intent for a call Pipelock
// refused before sending it, such as one a live upstream contract denied after
// the input scan passed. The outcome carries a block verdict under the intent's
// action ID, so the chain shows the call was stopped rather than a bare allow.
// The caller sets the refusing layer and any contract fields on opts.
func emitMCPBlockedOutcomeReceipt(
	receiptEmitter *receipt.Emitter,
	v2Emitter *proxydecision.Emitter,
	group *MCPReceiptGroup,
	logW io.Writer,
	opts receipt.EmitOpts,
	bytesTransferred int64,
	reason string,
	requireReceipts bool,
) {
	opts.Verdict = config.ActionBlock
	emitMCPOutcome(receiptEmitter, v2Emitter, group, logW, opts, mcpOutcomeStatusBlocked, bytesTransferred, reason, requireReceipts)
}

const (
	mcpOutcomeLayer         = "outcome"
	mcpOutcomeStatusBlocked = "blocked"
)

// emitMCPOutcome writes an outcome receipt and logs a failure; outcomes never
// block, so the error is not returned.
func emitMCPOutcome(
	receiptEmitter *receipt.Emitter,
	v2Emitter *proxydecision.Emitter,
	group *MCPReceiptGroup,
	logW io.Writer,
	opts receipt.EmitOpts,
	status string,
	bytesTransferred int64,
	reason string,
	requireReceipts bool,
) {
	// The v1 receipt carries the action ID and phase that pair an outcome with
	// its intent; a v2 proxy_decision record carries neither, so it is only
	// written alongside v1, never as the outcome on its own.
	if (receiptEmitter == nil && group == nil) || opts.ActionID == "" {
		return
	}
	opts = mcpOutcomeReceiptOpts(opts, status, bytesTransferred, reason)
	// A blocked outcome closes an intent that required recording wrote
	// durably, so it is synced too: losing it would leave that allow intent
	// unmatched for a call that was refused.
	durable := requireReceipts && opts.Verdict == config.ActionBlock
	d := MCPDecision{Receipt: opts, Durable: durable, RequireReceipt: requireReceipts && group != nil, RequiredMode: requireReceipts}
	var err error
	if group != nil {
		_, err = EmitMCPGroupDecision(*group, nil, d)
	} else {
		_, err = EmitMCPDecision(receiptEmitter, v2Emitter, nil, d)
	}
	if err != nil {
		logReceiptEmitFailure(logW, err, requireReceipts, opts.Verdict)
	}
}

// mcpOutcomeReceiptOpts turns an intent's receipt options into its outcome:
// same action ID, outcome phase, and a status/bytes/reason pattern. The caller
// sets the verdict and layer.
func mcpOutcomeReceiptOpts(opts receipt.EmitOpts, status string, bytesTransferred int64, reason string) receipt.EmitOpts {
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
	opts.Pattern = fmt.Sprintf("status=%s bytes=%s reason=%s", status, bytesValue, reason)
	return opts
}

// A stream can fail before an admitted JSON-RPC request exists. In a group,
// record that event as a single-phase diagnostic so it cannot appear to close
// an intent. Preserve the legacy single-chain outcome bytes.
func emitMCPStandaloneStreamReceipt(proxyOpts MCPProxyOpts, logW io.Writer, opts receipt.EmitOpts, status, reason string) {
	if proxyOpts.ReceiptGroup == nil {
		emitMCPOutcomeReceipt(proxyOpts.receiptEmitter(), proxyOpts.v2ReceiptEmitter(), nil, logW, opts, status, -1, reason, proxyOpts.requireReceipts())
		return
	}
	if opts.ActionID == "" {
		return
	}
	opts = mcpOutcomeReceiptOpts(opts, status, -1, reason)
	opts.DecisionPhase = ""
	opts.Verdict = config.ActionWarn
	opts.Layer = mcpOutcomeLayer
	_, err := EmitMCPGroupDecision(*proxyOpts.ReceiptGroup, nil, MCPDecision{Receipt: opts, RequireReceipt: proxyOpts.requireReceipts(), RequiredMode: proxyOpts.requireReceipts()})
	if err != nil {
		logReceiptEmitFailure(logW, err, proxyOpts.requireReceipts(), opts.Verdict)
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
