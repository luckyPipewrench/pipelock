// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

const testReceiptSignature = "ed25519:" + "" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"

// marshalPayload marshals v to json.RawMessage for test use.
func marshalPayload(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return json.RawMessage(b)
}

// --- proxy_decision ---

func TestValidateProxyDecision_AcceptsValid(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	if err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingTarget(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingPolicySources(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: nil,
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_ratified ---

func TestValidateContractRatified_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "sha256:abc",
		RatifierKeyID:               "key-1",
		RatifiedRuleIDs:             []string{"rule-1"},
		RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
	}
	if err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRatified_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "",
		RatifierKeyID:               "key-1",
		RatifiedRuleIDs:             []string{"rule-1"},
		RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
	}
	err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_promote_intent ---

func TestValidateContractPromoteIntent_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: "sha256:target",
		TargetGeneration:   2,
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
	}
	if err := callValidator(t, receipt.PayloadContractPromoteIntent, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractPromoteIntent_RejectsMissingIntentID(t *testing.T) {
	p := receipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: "sha256:target",
		TargetGeneration:   2,
		PriorManifestHash:  "sha256:prior",
		IntentID:           "",
	}
	err := callValidator(t, receipt.PayloadContractPromoteIntent, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_promote_committed ---

func TestValidateContractPromoteCommitted_AcceptsAccepted(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "accepted",
	}
	if err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractPromoteCommitted_AcceptsRejected(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "rejected",
		RejectReason:       "hash mismatch",
	}
	if err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsBadValidationOutcome(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "maybe",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

// --- contract_rollback_authorized ---

func TestValidateContractRollbackAuthorized_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   "sha256:target",
		CurrentGeneration:    5,
		AuthorizerSignatures: []string{"ed25519:aabb"},
		AuthorizationID:      "auth-1",
	}
	if err := callValidator(t, receipt.PayloadContractRollbackAuthorized, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRollbackAuthorized_RejectsMissingSignatures(t *testing.T) {
	p := receipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   "sha256:target",
		CurrentGeneration:    5,
		AuthorizerSignatures: nil,
		AuthorizationID:      "auth-1",
	}
	err := callValidator(t, receipt.PayloadContractRollbackAuthorized, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_rollback_committed ---

func TestValidateContractRollbackCommitted_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "accepted",
	}
	if err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsBadOutcome(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "pending",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

// --- contract_demoted ---

func TestValidateContractDemoted_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	if err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingNewState(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_expired ---

func TestValidateContractExpired_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractExpiredStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		ExpirationReason: "ttl exceeded",
	}
	if err := callValidator(t, receipt.PayloadContractExpired, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractExpired_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadContractExpiredStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "",
		ExpirationReason: "ttl exceeded",
	}
	err := callValidator(t, receipt.PayloadContractExpired, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_drift ---

func TestValidateContractDrift_AcceptsValid(t *testing.T) {
	p := receipt.PayloadContractDriftStruct{
		ContractHash: "sha256:abc",
		RuleID:       "rule-1",
		DriftKind:    "positive",
	}
	if err := callValidator(t, receipt.PayloadContractDrift, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractDrift_RejectsMissingDriftKind(t *testing.T) {
	p := receipt.PayloadContractDriftStruct{
		ContractHash: "sha256:abc",
		RuleID:       "rule-1",
		DriftKind:    "",
	}
	err := callValidator(t, receipt.PayloadContractDrift, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- shadow_delta ---

func TestValidateShadowDelta_AcceptsValid(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "allowed",
		Aggregation:      map[string]string{"window": "7d"},
	}
	if err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingOriginalVerdict(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		OriginalVerdict:  "",
		CandidateVerdict: "allowed",
		Aggregation:      map[string]string{"window": "7d"},
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- opportunity_missing ---

func TestValidateOpportunityMissing_AcceptsValid(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	if err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingWindow(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- key_rotation ---

func TestValidateKeyRotation_AcceptsValid(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	if err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingRosterHash(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

// --- contract_redaction_request ---

func TestValidateContractRedactionRequest_AcceptsWithdrawPublicProof(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	if err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRedactionRequest_AcceptsLocalErasure(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "local_erasure_tombstone",
		ReasonClass:        "gdpr",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	if err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsBadRequestKind(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "delete_everything",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

// --- additional missing-field coverage ---

func TestValidateProxyDecision_RejectsMissingActionType(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingVerdict(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingTransport(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "",
		PolicySources: []string{"dlp"},
		WinningSource: "dlp",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_RejectsMissingWinningSource(t *testing.T) {
	p := receipt.PayloadProxyDecisionStruct{
		ActionType:    "block",
		Target:        "https://example.com/",
		Verdict:       "blocked",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "",
	}
	err := callValidator(t, receipt.PayloadProxyDecision, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateProxyDecision_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadProxyDecision, json.RawMessage(`not-json`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractRatified_RejectsMissingRatifierKeyID(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "sha256:abc",
		RatifierKeyID:               "",
		RatifiedRuleIDs:             []string{"rule-1"},
		RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
	}
	err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRatified_RejectsMissingRatifiedRuleIDs(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "sha256:abc",
		RatifierKeyID:               "key-1",
		RatifiedRuleIDs:             nil,
		RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
	}
	err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRatified_RejectsMissingDecisionPerRule(t *testing.T) {
	p := receipt.PayloadContractRatifiedStruct{
		ContractHash:                "sha256:abc",
		RatifierKeyID:               "key-1",
		RatifiedRuleIDs:             []string{"rule-1"},
		RatificationDecisionPerRule: nil,
	}
	err := callValidator(t, receipt.PayloadContractRatified, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRatified_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractRatified, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractPromoteIntent_RejectsMissingTargetManifestHash(t *testing.T) {
	p := receipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: "",
		TargetGeneration:   2,
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
	}
	err := callValidator(t, receipt.PayloadContractPromoteIntent, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteIntent_RejectsMissingPriorManifestHash(t *testing.T) {
	p := receipt.PayloadContractPromoteIntentStruct{
		TargetManifestHash: "sha256:target",
		TargetGeneration:   2,
		PriorManifestHash:  "",
		IntentID:           "intent-1",
	}
	err := callValidator(t, receipt.PayloadContractPromoteIntent, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteIntent_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractPromoteIntent, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsMissingTargetManifestHash(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsMissingPriorManifest(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "",
		IntentID:           "intent-1",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsMissingIntentID(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_RejectsMissingValidationOutcome(t *testing.T) {
	p := receipt.PayloadContractPromoteCommittedStruct{
		TargetManifestHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		IntentID:           "intent-1",
		ValidationOutcome:  "",
	}
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractPromoteCommitted_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractPromoteCommitted, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractRollbackAuthorized_RejectsMissingRollbackTargetHash(t *testing.T) {
	p := receipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   "",
		CurrentGeneration:    5,
		AuthorizerSignatures: []string{"ed25519:aabb"},
		AuthorizationID:      "auth-1",
	}
	err := callValidator(t, receipt.PayloadContractRollbackAuthorized, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackAuthorized_RejectsMissingAuthorizationID(t *testing.T) {
	p := receipt.PayloadContractRollbackAuthorizedStruct{
		RollbackTargetHash:   "sha256:target",
		CurrentGeneration:    5,
		AuthorizerSignatures: []string{"ed25519:aabb"},
		AuthorizationID:      "",
	}
	err := callValidator(t, receipt.PayloadContractRollbackAuthorized, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackAuthorized_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractRollbackAuthorized, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsMissingRollbackTargetHash(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsMissingPriorManifest(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsMissingAuthorizationID(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "",
		ValidationOutcome:  "accepted",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_RejectsMissingValidationOutcome(t *testing.T) {
	p := receipt.PayloadContractRollbackCommittedStruct{
		RollbackTargetHash: "sha256:target",
		PriorManifestHash:  "sha256:prior",
		AuthorizationID:    "auth-1",
		ValidationOutcome:  "",
	}
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRollbackCommitted_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractRollbackCommitted, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingDemotionReason(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingPriorState(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "",
		NewState:          "shadow",
		AggregationWindow: "7d",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_RejectsMissingAggregationWindow(t *testing.T) {
	p := receipt.PayloadContractDemotedStruct{
		ContractHash:      "sha256:abc",
		RuleID:            "rule-1",
		DemotionReason:    "missed windows",
		PriorState:        "active",
		NewState:          "shadow",
		AggregationWindow: "",
	}
	err := callValidator(t, receipt.PayloadContractDemoted, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDemoted_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractDemoted, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractExpired_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadContractExpiredStruct{
		ContractHash:     "",
		RuleID:           "rule-1",
		ExpirationReason: "ttl exceeded",
	}
	err := callValidator(t, receipt.PayloadContractExpired, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractExpired_RejectsMissingExpirationReason(t *testing.T) {
	p := receipt.PayloadContractExpiredStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		ExpirationReason: "",
	}
	err := callValidator(t, receipt.PayloadContractExpired, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractExpired_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractExpired, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractDrift_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadContractDriftStruct{
		ContractHash: "",
		RuleID:       "rule-1",
		DriftKind:    "positive",
	}
	err := callValidator(t, receipt.PayloadContractDrift, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDrift_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadContractDriftStruct{
		ContractHash: "sha256:abc",
		RuleID:       "",
		DriftKind:    "positive",
	}
	err := callValidator(t, receipt.PayloadContractDrift, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractDrift_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractDrift, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "",
		RuleID:           "rule-1",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "allowed",
		Aggregation:      map[string]string{"window": "7d"},
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "allowed",
		Aggregation:      map[string]string{"window": "7d"},
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingCandidateVerdict(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "",
		Aggregation:      map[string]string{"window": "7d"},
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateShadowDelta_RejectsMissingAggregation(t *testing.T) {
	p := receipt.PayloadShadowDeltaStruct{
		ContractHash:     "sha256:abc",
		RuleID:           "rule-1",
		OriginalVerdict:  "blocked",
		CandidateVerdict: "allowed",
		Aggregation:      nil,
	}
	err := callValidator(t, receipt.PayloadShadowDelta, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateShadowDelta_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadShadowDelta, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingContractHash(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingRuleID(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingParentContext(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingHistoricalRate(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "",
		CurrentOpportunityRate:    "0.10",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_RejectsMissingCurrentRate(t *testing.T) {
	p := receipt.PayloadOpportunityMissingStruct{
		ContractHash:              "sha256:abc",
		RuleID:                    "rule-1",
		ParentContext:             "agent-xyz",
		HistoricalOpportunityRate: "0.85",
		CurrentOpportunityRate:    "",
		Window:                    "7d",
	}
	err := callValidator(t, receipt.PayloadOpportunityMissing, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateOpportunityMissing_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadOpportunityMissing, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingKeyID(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingKeyPurpose(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingOldStatus(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingNewStatus(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "",
		RosterHash:      "sha256:roster",
		AuthorizationID: "auth-1",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_RejectsMissingAuthorizationID(t *testing.T) {
	p := receipt.PayloadKeyRotationStruct{
		KeyID:           "key-1",
		KeyPurpose:      "receipt-signing",
		OldStatus:       "active",
		NewStatus:       "revoked",
		RosterHash:      "sha256:roster",
		AuthorizationID: "",
	}
	err := callValidator(t, receipt.PayloadKeyRotation, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateKeyRotation_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadKeyRotation, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingTargetContractHash(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingReasonClass(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingAuthorizationID(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "privacy",
		AuthorizationID:    "",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingTombstoneHash(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "withdraw_public_proof",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_RejectsMissingRequestKind(t *testing.T) {
	p := receipt.PayloadContractRedactionRequestStruct{
		TargetContractHash: "sha256:abc",
		RequestKind:        "",
		ReasonClass:        "privacy",
		AuthorizationID:    "auth-1",
		TombstoneHash:      "sha256:tomb",
	}
	err := callValidator(t, receipt.PayloadContractRedactionRequest, marshalPayload(t, p))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestValidateContractRedactionRequest_InvalidJSON(t *testing.T) {
	err := callValidator(t, receipt.PayloadContractRedactionRequest, json.RawMessage(`{bad}`))
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField on invalid JSON, got: %v", err)
	}
}

// --- strict decode: unknown-field and trailing-token rejection ---

func TestValidateProxyDecision_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{
		"action_type":"connect","target":"x.com","verdict":"allow",
		"transport":"forward","policy_sources":["a"],"winning_source":"a",
		"future_field":"sneaky"
	}`)
	err := callValidator(t, receipt.PayloadProxyDecision, raw)
	if err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestValidateContractRedactionRequest_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{
		"target_contract_hash":"sha256:abc",
		"request_kind":"withdraw_public_proof",
		"reason_class":"legal",
		"authorization_id":"sha256:auth",
		"tombstone_hash":"sha256:tomb",
		"advisory_extension":"hidden"
	}`)
	err := callValidator(t, receipt.PayloadContractRedactionRequest, raw)
	if err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestValidateProxyDecision_RejectsTrailingTokens(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"action_type":"connect","target":"x","verdict":"allow","transport":"forward","policy_sources":["a"],"winning_source":"a"} extra`)
	err := callValidator(t, receipt.PayloadProxyDecision, raw)
	if err == nil {
		t.Fatal("trailing tokens accepted")
	}
}

func TestValidateProxyDecision_RejectsTrailingDelimiter(t *testing.T) {
	t.Parallel()
	cases := []json.RawMessage{
		json.RawMessage(`{"action_type":"connect","target":"x","verdict":"allow","transport":"forward","policy_sources":["a"],"winning_source":"a"}]`),
		json.RawMessage(`{"action_type":"connect","target":"x","verdict":"allow","transport":"forward","policy_sources":["a"],"winning_source":"a"}}`),
	}
	for _, raw := range cases {
		err := callValidator(t, receipt.PayloadProxyDecision, raw)
		if err == nil {
			t.Fatalf("trailing delimiter accepted for %s", raw)
		}
	}
}

// callValidator dispatches to the validator for kind with raw payload.
// It is intentionally wired through the exported EvidenceReceipt.Validate()
// to exercise the full dispatch path.
func callValidator(t *testing.T, kind receipt.PayloadKind, raw json.RawMessage) error {
	t.Helper()
	r := receipt.EvidenceReceipt{
		RecordType:     receipt.RecordTypeEvidenceV2,
		ReceiptVersion: 2,
		PayloadKind:    kind,
		EventID:        "01900000-0000-7000-8000-000000000001",
		Payload:        raw,
		Signature: receipt.SignatureProof{
			SignerKeyID: "test-key",
			KeyPurpose:  testKeyPurposeForPayload(kind),
			Algorithm:   "ed25519",
			Signature:   testReceiptSignature,
		},
	}
	return r.Validate()
}

func testKeyPurposeForPayload(kind receipt.PayloadKind) string {
	switch kind {
	case receipt.PayloadContractPromoteIntent,
		receipt.PayloadContractRollbackAuthorized,
		receipt.PayloadKeyRotation,
		receipt.PayloadContractRedactionRequest:
		return "contract-activation-signing"
	default:
		return "receipt-signing"
	}
}

func TestTestReceiptSignatureShape(t *testing.T) {
	t.Parallel()
	if got := strings.TrimPrefix(testReceiptSignature, "ed25519:"); len(got) != 128 {
		t.Fatalf("test signature hex length=%d, want 128", len(got))
	}
}
