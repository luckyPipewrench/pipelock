// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package activation contains contract promotion and rollback policy helpers.
package activation

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	defaultProductionAuthorities = 3
	defaultProductionSignatures  = 2

	signatureAlgorithm = "ed25519"
	signaturePrefix    = "ed25519:"
)

var (
	ErrRosterRequired          = errors.New("activation roster is required")
	ErrProductionAuthorityPool = errors.New("production activation requires at least three active operator authorities")
	ErrDualControl             = errors.New("activation dual control requirement not met")
	ErrRollbackAuthorization   = errors.New("rollback authorization is required")
)

// Signer signs lifecycle receipt preimages.
type Signer interface {
	KeyID() string
	Sign([]byte) ([]byte, error)
}

// Policy controls promotion and rollback dual-control checks.
type Policy struct {
	Production               bool
	MinProductionAuthorities int
	RequiredSignatures       int
}

// ReceiptContext supplies the chain and scope fields stamped into lifecycle receipts.
type ReceiptContext struct {
	EventID              string
	Timestamp            time.Time
	Principal            string
	Actor                string
	ChainSeq             uint64
	ChainPrevHash        string
	ActiveManifestHash   string
	ContractHash         string
	SelectorID           string
	ContractGeneration   uint64
	DeterministicEventID string
}

// RequiredSignatures returns the effective distinct-principal signature count.
func RequiredSignatures(policy Policy) int {
	if policy.RequiredSignatures > 0 {
		return policy.RequiredSignatures
	}
	if policy.Production {
		return defaultProductionSignatures
	}
	return 1
}

// ValidateProductionAuthorityPool requires a production roster to contain at
// least three active, in-window activation authorities with distinct principals.
func ValidateProductionAuthorityPool(roster *signing.LoadedRoster, now time.Time, policy Policy) error {
	if !policy.Production {
		return nil
	}
	if roster == nil {
		return ErrRosterRequired
	}
	required := policy.MinProductionAuthorities
	if required <= 0 {
		required = defaultProductionAuthorities
	}
	principals := map[string]struct{}{}
	for _, key := range roster.Body.Keys {
		if key.KeyPurpose != signing.PurposeContractActivationSigning.String() {
			continue
		}
		resolved, err := roster.ResolveKey(key.KeyID, now)
		if err != nil || resolved.Principal == "" {
			continue
		}
		principals[resolved.Principal] = struct{}{}
	}
	if len(principals) < required {
		return fmt.Errorf("%w: got %d active principals, want %d", ErrProductionAuthorityPool, len(principals), required)
	}
	return nil
}

// ValidateManifestDualControl verifies that the manifest carries enough
// distinct active activation authorities for the requested lifecycle policy.
// Cryptographic verification remains in the store package; this helper checks
// the production operator-count invariant before a swap is attempted.
func ValidateManifestDualControl(signatures []contract.ManifestSignature, roster *signing.LoadedRoster, now time.Time, policy Policy) error {
	if roster == nil {
		return ErrRosterRequired
	}
	if err := ValidateProductionAuthorityPool(roster, now, policy); err != nil {
		return err
	}
	required := RequiredSignatures(policy)
	seenKeys := map[string]struct{}{}
	seenPrincipals := map[string]struct{}{}
	for _, sig := range signatures {
		if sig.KeyPurpose != signing.PurposeContractActivationSigning.String() {
			continue
		}
		key, err := roster.ResolveKey(sig.KeyID, now)
		if err != nil || key.KeyPurpose != signing.PurposeContractActivationSigning.String() || key.Principal == "" {
			continue
		}
		if sig.Principal != "" && sig.Principal != key.Principal {
			continue
		}
		if _, dup := seenKeys[sig.KeyID]; dup {
			continue
		}
		if _, dup := seenPrincipals[key.Principal]; dup {
			continue
		}
		seenKeys[sig.KeyID] = struct{}{}
		seenPrincipals[key.Principal] = struct{}{}
	}
	if len(seenPrincipals) < required {
		return fmt.Errorf("%w: got %d distinct activation principals, want %d", ErrDualControl, len(seenPrincipals), required)
	}
	return nil
}

// PromoteIntentPayload builds the signed intent payload for a pending promotion.
func PromoteIntentPayload(targetHash string, targetGeneration uint64, priorHash, intentID string) contractreceipt.PayloadContractPromoteIntentStruct {
	return contractreceipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: targetHash,
		TargetGeneration:   targetGeneration,
		PriorManifestHash:  priorHash,
		IntentID:           intentID,
	}
}

// PromoteCommittedPayload builds the signed commit payload for a promotion result.
func PromoteCommittedPayload(targetHash, priorHash, intentID, outcome, rejectReason string) contractreceipt.PayloadContractPromoteCommittedStruct {
	return contractreceipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: targetHash,
		PriorManifestHash:  priorHash,
		IntentID:           intentID,
		ValidationOutcome:  outcome,
		RejectReason:       rejectReason,
	}
}

// RollbackAuthorizedPayload builds the signed authorization payload for rollback.
func RollbackAuthorizedPayload(targetHash string, currentGeneration uint64, signatures []string, authorizationID string) (contractreceipt.PayloadContractRollbackAuthorizedStruct, error) {
	if authorizationID == "" || len(signatures) == 0 {
		return contractreceipt.PayloadContractRollbackAuthorizedStruct{}, ErrRollbackAuthorization
	}
	return contractreceipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   targetHash,
		CurrentGeneration:    currentGeneration,
		AuthorizerSignatures: append([]string(nil), signatures...),
		AuthorizationID:      authorizationID,
	}, nil
}

// RollbackCommittedPayload builds the signed commit payload for a rollback result.
func RollbackCommittedPayload(targetHash, priorHash, authorizationID, outcome, rejectReason string) (contractreceipt.PayloadContractRollbackCommittedStruct, error) {
	if authorizationID == "" {
		return contractreceipt.PayloadContractRollbackCommittedStruct{}, ErrRollbackAuthorization
	}
	return contractreceipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: targetHash,
		PriorManifestHash:  priorHash,
		AuthorizationID:    authorizationID,
		ValidationOutcome:  outcome,
		RejectReason:       rejectReason,
	}, nil
}

// SignReceipt builds and signs an EvidenceReceipt v2 for a lifecycle payload.
func SignReceipt(kind contractreceipt.PayloadKind, payload any, ctx ReceiptContext, signer Signer, keyPurpose signing.KeyPurpose) (contractreceipt.EvidenceReceipt, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("marshal lifecycle payload: %w", err)
	}
	eventID := ctx.EventID
	if eventID == "" {
		if ctx.DeterministicEventID != "" {
			eventID = ctx.DeterministicEventID
		} else {
			id, uuidErr := uuid.NewV7()
			if uuidErr != nil {
				return contractreceipt.EvidenceReceipt{}, fmt.Errorf("generate lifecycle event id: %w", uuidErr)
			}
			eventID = id.String()
		}
	}
	timestamp := ctx.Timestamp.UTC()
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}
	rcpt := contractreceipt.EvidenceReceipt{
		RecordType:         contractreceipt.RecordTypeEvidenceV2,
		ReceiptVersion:     2,
		PayloadKind:        kind,
		Canonicalization:   contractreceipt.DefaultCanonicalizationProfile(),
		Crit:               contractreceipt.CritForPayloadKind(kind),
		EventID:            eventID,
		Timestamp:          timestamp,
		Principal:          ctx.Principal,
		Actor:              ctx.Actor,
		ChainSeq:           ctx.ChainSeq,
		ChainPrevHash:      ctx.ChainPrevHash,
		ActiveManifestHash: ctx.ActiveManifestHash,
		ContractHash:       ctx.ContractHash,
		SelectorID:         ctx.SelectorID,
		ContractGeneration: ctx.ContractGeneration,
		Payload:            payloadJSON,
	}
	preimage, err := rcpt.SignablePreimage()
	if err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("build lifecycle receipt preimage: %w", err)
	}
	sig, err := signer.Sign(preimage)
	if err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("sign lifecycle receipt: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("sign lifecycle receipt: signature size=%d", len(sig))
	}
	rcpt.Signature = contractreceipt.SignatureProof{
		SignerKeyID: signer.KeyID(),
		KeyPurpose:  keyPurpose.String(),
		Algorithm:   signatureAlgorithm,
		Signature:   signaturePrefix + hex.EncodeToString(sig),
	}
	if err := rcpt.Validate(); err != nil {
		return contractreceipt.EvidenceReceipt{}, fmt.Errorf("validate lifecycle receipt: %w", err)
	}
	return rcpt, nil
}
