// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Sentinel errors for payload dispatch and envelope validation.
var (
	// ErrUnknownPayloadKind is returned when payload_kind is not in the v2 registry.
	ErrUnknownPayloadKind = errors.New("unknown payload_kind for v2 receipt")
	// ErrPayloadMissingField is returned when a required field is empty or zero.
	ErrPayloadMissingField = errors.New("payload missing required field")
	// ErrPayloadInvalidEnum is returned when an enum-like field holds a disallowed value.
	ErrPayloadInvalidEnum = errors.New("payload field has invalid enum value")
	// ErrUnsupportedRecordType is returned when record_type is not evidence_receipt_v2.
	ErrUnsupportedRecordType = errors.New("unsupported record_type for v2 verifier")
	// ErrWrongReceiptVersion is returned when receipt_version is not 2.
	ErrWrongReceiptVersion = errors.New("EvidenceReceipt requires receipt_version=2")
)

// payloadValidators maps every known PayloadKind to its structural validator.
var payloadValidators = map[PayloadKind]func(json.RawMessage) error{
	PayloadProxyDecision:              validateProxyDecision,
	PayloadContractRatified:           validateContractRatified,
	PayloadContractPromoteIntent:      validateContractPromoteIntent,
	PayloadContractPromoteCommitted:   validateContractPromoteCommitted,
	PayloadContractRollbackAuthorized: validateContractRollbackAuthorized,
	PayloadContractRollbackCommitted:  validateContractRollbackCommitted,
	PayloadContractDemoted:            validateContractDemoted,
	PayloadContractExpired:            validateContractExpired,
	PayloadContractDrift:              validateContractDrift,
	PayloadShadowDelta:                validateShadowDelta,
	PayloadOpportunityMissing:         validateOpportunityMissing,
	PayloadKeyRotation:                validateKeyRotation,
	PayloadContractRedactionRequest:   validateContractRedactionRequest,
}

// requireNonEmpty returns ErrPayloadMissingField if val is empty.
func requireNonEmpty(fieldName, val string) error {
	if val == "" {
		return fmt.Errorf("%w: %s", ErrPayloadMissingField, fieldName)
	}
	return nil
}

// requireNonEmptySlice returns ErrPayloadMissingField if s is empty or nil.
func requireNonEmptySlice[T any](fieldName string, s []T) error {
	if len(s) == 0 {
		return fmt.Errorf("%w: %s", ErrPayloadMissingField, fieldName)
	}
	return nil
}

// validationOutcomeValues are the allowed values for validation_outcome fields.
const (
	outcomeAccepted = "accepted"
	outcomeRejected = "rejected"
)

// allowedRequestKinds are the allowed values for request_kind in redaction requests.
const (
	requestKindWithdrawPublicProof   = "withdraw_public_proof"
	requestKindLocalErasureTombstone = "local_erasure_tombstone"
)

func validateProxyDecision(raw json.RawMessage) error {
	var p PayloadProxyDecisionStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: action_type (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("action_type", p.ActionType); err != nil {
		return err
	}
	if err := requireNonEmpty("target", p.Target); err != nil {
		return err
	}
	if err := requireNonEmpty("verdict", p.Verdict); err != nil {
		return err
	}
	if err := requireNonEmpty("transport", p.Transport); err != nil {
		return err
	}
	if err := requireNonEmptySlice("policy_sources", p.PolicySources); err != nil {
		return err
	}
	return requireNonEmpty("winning_source", p.WinningSource)
}

func validateContractRatified(raw json.RawMessage) error {
	var p PayloadContractRatifiedStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("ratifier_key_id", p.RatifierKeyID); err != nil {
		return err
	}
	if err := requireNonEmptySlice("ratified_rule_ids", p.RatifiedRuleIDs); err != nil {
		return err
	}
	if len(p.RatificationDecisionPerRule) == 0 {
		return fmt.Errorf("%w: ratification_decision_per_rule", ErrPayloadMissingField)
	}
	return nil
}

func validateContractPromoteIntent(raw json.RawMessage) error {
	var p PayloadContractPromoteIntentStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: target_manifest_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("target_manifest_hash", p.TargetManifestHash); err != nil {
		return err
	}
	if err := requireNonEmpty("prior_manifest_hash", p.PriorManifestHash); err != nil {
		return err
	}
	return requireNonEmpty("intent_id", p.IntentID)
}

func validateContractPromoteCommitted(raw json.RawMessage) error {
	var p PayloadContractPromoteCommittedStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: target_manifest_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("target_manifest_hash", p.TargetManifestHash); err != nil {
		return err
	}
	if err := requireNonEmpty("prior_manifest_hash", p.PriorManifestHash); err != nil {
		return err
	}
	if err := requireNonEmpty("intent_id", p.IntentID); err != nil {
		return err
	}
	if err := requireNonEmpty("validation_outcome", p.ValidationOutcome); err != nil {
		return err
	}
	if p.ValidationOutcome != outcomeAccepted && p.ValidationOutcome != outcomeRejected {
		return fmt.Errorf("%w: validation_outcome=%q (must be %q or %q)",
			ErrPayloadInvalidEnum, p.ValidationOutcome, outcomeAccepted, outcomeRejected)
	}
	return nil
}

func validateContractRollbackAuthorized(raw json.RawMessage) error {
	var p PayloadContractRollbackAuthorizedStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: rollback_target_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("rollback_target_hash", p.RollbackTargetHash); err != nil {
		return err
	}
	if err := requireNonEmptySlice("authorizer_signatures", p.AuthorizerSignatures); err != nil {
		return err
	}
	return requireNonEmpty("authorization_id", p.AuthorizationID)
}

func validateContractRollbackCommitted(raw json.RawMessage) error {
	var p PayloadContractRollbackCommittedStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: rollback_target_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("rollback_target_hash", p.RollbackTargetHash); err != nil {
		return err
	}
	if err := requireNonEmpty("prior_manifest_hash", p.PriorManifestHash); err != nil {
		return err
	}
	if err := requireNonEmpty("authorization_id", p.AuthorizationID); err != nil {
		return err
	}
	if err := requireNonEmpty("validation_outcome", p.ValidationOutcome); err != nil {
		return err
	}
	if p.ValidationOutcome != outcomeAccepted && p.ValidationOutcome != outcomeRejected {
		return fmt.Errorf("%w: validation_outcome=%q (must be %q or %q)",
			ErrPayloadInvalidEnum, p.ValidationOutcome, outcomeAccepted, outcomeRejected)
	}
	return nil
}

func validateContractDemoted(raw json.RawMessage) error {
	var p PayloadContractDemotedStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	if err := requireNonEmpty("demotion_reason", p.DemotionReason); err != nil {
		return err
	}
	if err := requireNonEmpty("prior_state", p.PriorState); err != nil {
		return err
	}
	if err := requireNonEmpty("new_state", p.NewState); err != nil {
		return err
	}
	return requireNonEmpty("aggregation_window", p.AggregationWindow)
}

func validateContractExpired(raw json.RawMessage) error {
	var p PayloadContractExpiredStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	return requireNonEmpty("expiration_reason", p.ExpirationReason)
}

func validateContractDrift(raw json.RawMessage) error {
	var p PayloadContractDriftStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	return requireNonEmpty("drift_kind", p.DriftKind)
}

func validateShadowDelta(raw json.RawMessage) error {
	var p PayloadShadowDeltaStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	if err := requireNonEmpty("original_verdict", p.OriginalVerdict); err != nil {
		return err
	}
	if err := requireNonEmpty("candidate_verdict", p.CandidateVerdict); err != nil {
		return err
	}
	if len(p.Aggregation) == 0 {
		return fmt.Errorf("%w: aggregation", ErrPayloadMissingField)
	}
	return nil
}

func validateOpportunityMissing(raw json.RawMessage) error {
	var p PayloadOpportunityMissingStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("contract_hash", p.ContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("rule_id", p.RuleID); err != nil {
		return err
	}
	if err := requireNonEmpty("parent_context", p.ParentContext); err != nil {
		return err
	}
	if err := requireNonEmpty("historical_opportunity_rate", p.HistoricalOpportunityRate); err != nil {
		return err
	}
	if err := requireNonEmpty("current_opportunity_rate", p.CurrentOpportunityRate); err != nil {
		return err
	}
	return requireNonEmpty("window", p.Window)
}

func validateKeyRotation(raw json.RawMessage) error {
	var p PayloadKeyRotationStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: key_id (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("key_id", p.KeyID); err != nil {
		return err
	}
	if err := requireNonEmpty("key_purpose", p.KeyPurpose); err != nil {
		return err
	}
	if err := requireNonEmpty("old_status", p.OldStatus); err != nil {
		return err
	}
	if err := requireNonEmpty("new_status", p.NewStatus); err != nil {
		return err
	}
	if err := requireNonEmpty("roster_hash", p.RosterHash); err != nil {
		return err
	}
	return requireNonEmpty("authorization_id", p.AuthorizationID)
}

func validateContractRedactionRequest(raw json.RawMessage) error {
	var p PayloadContractRedactionRequestStruct
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%w: target_contract_hash (unmarshal: %w)", ErrPayloadMissingField, err)
	}
	if err := requireNonEmpty("target_contract_hash", p.TargetContractHash); err != nil {
		return err
	}
	if err := requireNonEmpty("request_kind", p.RequestKind); err != nil {
		return err
	}
	if p.RequestKind != requestKindWithdrawPublicProof && p.RequestKind != requestKindLocalErasureTombstone {
		return fmt.Errorf("%w: request_kind=%q (must be %q or %q)",
			ErrPayloadInvalidEnum, p.RequestKind,
			requestKindWithdrawPublicProof, requestKindLocalErasureTombstone)
	}
	if err := requireNonEmpty("reason_class", p.ReasonClass); err != nil {
		return err
	}
	if err := requireNonEmpty("authorization_id", p.AuthorizationID); err != nil {
		return err
	}
	return requireNonEmpty("tombstone_hash", p.TombstoneHash)
}
