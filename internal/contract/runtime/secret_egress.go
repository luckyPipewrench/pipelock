// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract/egress"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/egressevidence"
)

// ErrInvalidSecretEgressInput rejects malformed fixture builder input.
var ErrInvalidSecretEgressInput = errors.New("contract runtime: invalid secret-egress decision receipt input")

// SecretEgressDecisionInput supplies explicit facts and context for a fixture-
// only unsigned receipt. Registry is immutable and mandatory. PolicyHash names
// the resolved policy inputs but this builder does not resolve authority or
// rewrite-fallback references against that policy. A production signing adapter
// must do that before signing; this constructor is not registered as an emitter.
type SecretEgressDecisionInput struct {
	Decision         egressevidence.Decision
	Registry         *egressevidence.Registry
	ResolvedContract *ResolvedContract
	PolicyHash       string
	EventID          string
	Timestamp        time.Time
	Principal        string
	Actor            string
	DelegationChain  []string
	ChainSeq         uint64
	ChainPrevHash    string
}

// BuildSecretEgressDecisionReceipt validates a decision against its supplied
// immutable registry and constructs an unsigned EvidenceReceipt v2. EventID
// and Timestamp are caller-supplied and mandatory; ChainPrevHash must be
// nonempty (receipt.GenesisHash for the first event); the receipt event ID must be
// distinct from action and decision IDs. No signing, persistence, forwarding,
// coverage declaration or admission change occurs here.
func BuildSecretEgressDecisionReceipt(in SecretEgressDecisionInput) (contractreceipt.EvidenceReceipt, error) {
	if err := in.Decision.ValidateAt(in.Registry); err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: decision: %w", ErrInvalidSecretEgressInput, err)
	}
	if in.EventID == "" || in.EventID == in.Decision.ActionID || in.EventID == in.Decision.DecisionID {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: event_id missing or aliases action or decision ID", ErrInvalidSecretEgressInput)
	}
	if in.ChainPrevHash == "" {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: chain_prev_hash", ErrInvalidSecretEgressInput)
	}
	if in.Timestamp.IsZero() {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: timestamp", ErrInvalidSecretEgressInput)
	}
	policyHash := contractreceipt.NormalizePolicyHash(in.PolicyHash)
	if err := contractreceipt.ValidatePolicyHash(policyHash); err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: %w", ErrInvalidSecretEgressInput, err)
	}
	registryHash, err := egress.RegistryHash(in.Registry)
	if err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: %w", ErrInvalidSecretEgressInput, err)
	}
	payload := contractreceipt.PayloadSecretEgressDecisionV1Struct{RegistryHash: registryHash, Decision: in.Decision}
	body, err := json.Marshal(payload)
	if err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: marshal payload: %w", ErrInvalidSecretEgressInput, err)
	}
	r := buildEvidenceReceiptEnvelope(ProxyDecisionInput{
		ResolvedContract: in.ResolvedContract,
		PolicyHash:       in.PolicyHash,
		EventID:          in.EventID,
		Timestamp:        in.Timestamp.UTC(),
		Principal:        in.Principal,
		Actor:            in.Actor,
		DelegationChain:  in.DelegationChain,
		ChainSeq:         in.ChainSeq,
		ChainPrevHash:    in.ChainPrevHash,
	}, contractreceipt.PayloadSecretEgressDecisionV1, policyHash, body)
	if err := r.ValidateSecretEgressContext(); err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("%w: %w", ErrInvalidSecretEgressInput, err)
	}
	return r, nil
}
