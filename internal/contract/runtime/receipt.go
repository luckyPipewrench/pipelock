// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

// ErrInvalidProxyDecisionInput is returned when BuildProxyDecisionReceipt is
// called with input that would fail PayloadProxyDecisionStruct validation.
// Callers MUST treat it as a programming bug — the input fields come from
// pipelock's own evaluator and proxy chain, not from agent-controlled data,
// so a missing field means the call site forgot to populate the input.
var ErrInvalidProxyDecisionInput = errors.New("contract runtime: invalid proxy_decision receipt input")

// ProxyDecisionInput aggregates the fields needed to assemble a v2
// proxy_decision EvidenceReceipt body. The builder is pure: it does not
// consult runtime state and does not sign. Transport call sites populate
// this struct, hand the result to the receipt signer, and write the signed
// envelope to the flight recorder.
type ProxyDecisionInput struct {
	// Decision is the runtime verdict for this request. Decision.Verdict,
	// Decision.PolicySources, Decision.WinningSource, Decision.RuleID,
	// and Decision.LiveVerdict shape the typed payload.
	Decision Decision

	// ResolvedContract is the per-session contract pin. Optional: leave nil
	// when the request had no contract pin (no active manifest, observation
	// path, no resolved selector). When set, the builder stamps the
	// receipt's active_manifest_hash, contract_hash, selector_id, and
	// contract_generation fields from ReceiptContext.
	ResolvedContract *ResolvedContract

	// ActionType labels the action class. Examples: "http_request",
	// "mcp_tool_call", "websocket_frame". Must be non-empty.
	ActionType string

	// Target identifies what was acted upon. URL for HTTP, fully qualified
	// tool name for MCP, peer URL for WebSocket. Must be non-empty.
	Target string

	// Transport identifies the surface that produced this decision.
	// Examples: "forward", "intercept", "mcp_http", "mcp_stdio",
	// "websocket". Must be non-empty.
	Transport string

	// Identity fields are optional at build time; the receipt signer or
	// flight recorder fills them before signing. Leaving them zero is
	// allowed because the signer's outer Validate() catches a missing
	// EventID / Timestamp anyway, and forcing the builder to require them
	// here would couple the builder to clock and ID generation.
	EventID         string
	Timestamp       time.Time
	Principal       string
	Actor           string
	DelegationChain []string

	// Chain fields are filled by the flight recorder when sequencing the
	// receipt into the per-session log. The builder accepts whatever the
	// caller passes; leaving them zero is the common case for fresh
	// receipts that have not yet been chained.
	ChainSeq      uint64
	ChainPrevHash string
}

// BuildProxyDecisionReceipt turns a runtime Decision plus transport metadata
// into an unsigned EvidenceReceipt v2 envelope ready for the receipt signer.
//
// The builder validates that the typed payload fields the v2 registry will
// require are present (action_type, target, verdict, transport,
// policy_sources, winning_source) before constructing the envelope, so an
// invalid input fails fast at build time instead of later at Validate()
// time on a partly-constructed receipt.
//
// Verdict / LiveVerdict semantics: ProxyDecisionPayload omits LiveVerdict
// from the wire payload when it equals Verdict (the ModeLive case). When
// the runtime ran in ModeShadow or ModeCapture and the contract path
// produced a different live verdict than the scanner-floor verdict the
// proxy actually applied, LiveVerdict surfaces the divergence so audit
// consumers can reason about what live mode would have done.
//
// Signing is the caller's responsibility — the builder leaves
// receipt.Signature zero. The caller hands the unsigned envelope to the
// receipt signer (which knows the active key, key purpose, and chain
// position) and writes the signed result to the flight recorder.
func BuildProxyDecisionReceipt(in ProxyDecisionInput) (contractreceipt.EvidenceReceipt, error) {
	payload := ProxyDecisionPayload(in.Decision, in.ActionType, in.Target, in.Transport)
	if err := validateProxyDecisionFields(payload); err != nil {
		return contractreceipt.EvidenceReceipt{}, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		// PayloadProxyDecisionStruct is a closed shape of strings and
		// []string; json.Marshal cannot fail on a valid value. Wrap the
		// error anyway so a future refactor that adds a non-marshalable
		// field surfaces here instead of producing a silently empty
		// payload.
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: marshal payload: %w", ErrInvalidProxyDecisionInput, err)
	}

	receipt := contractreceipt.EvidenceReceipt{
		RecordType:      contractreceipt.RecordTypeEvidenceV2,
		ReceiptVersion:  2,
		PayloadKind:     contractreceipt.PayloadProxyDecision,
		EventID:         in.EventID,
		Timestamp:       in.Timestamp,
		Principal:       in.Principal,
		Actor:           in.Actor,
		DelegationChain: append([]string(nil), in.DelegationChain...),
		ChainSeq:        in.ChainSeq,
		ChainPrevHash:   in.ChainPrevHash,
		Payload:         json.RawMessage(body),
	}
	if in.ResolvedContract != nil {
		receipt = in.ResolvedContract.ReceiptContext().StampReceipt(receipt)
	}
	return receipt, nil
}

// validateProxyDecisionFields mirrors validateProxyDecision in the receipt
// registry: the v2 dispatcher rejects a payload missing any of these fields
// with ErrPayloadMissingField. Validating up front turns the failure into
// an early build-time error instead of a delayed Validate() failure on a
// partially-constructed envelope.
func validateProxyDecisionFields(p contractreceipt.PayloadProxyDecisionStruct) error {
	if p.ActionType == "" {
		return fmt.Errorf("%w: action_type", ErrInvalidProxyDecisionInput)
	}
	if p.Target == "" {
		return fmt.Errorf("%w: target", ErrInvalidProxyDecisionInput)
	}
	if p.Verdict == "" {
		return fmt.Errorf("%w: verdict", ErrInvalidProxyDecisionInput)
	}
	if p.Transport == "" {
		return fmt.Errorf("%w: transport", ErrInvalidProxyDecisionInput)
	}
	if len(p.PolicySources) == 0 {
		return fmt.Errorf("%w: policy_sources", ErrInvalidProxyDecisionInput)
	}
	if p.WinningSource == "" {
		return fmt.Errorf("%w: winning_source", ErrInvalidProxyDecisionInput)
	}
	return nil
}
