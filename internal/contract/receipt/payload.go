// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

// PayloadProxyDecisionStruct holds the typed fields for a proxy_decision payload.
type PayloadProxyDecisionStruct struct {
	ActionType    string   `json:"action_type"`
	Target        string   `json:"target"`
	Verdict       string   `json:"verdict"`
	Transport     string   `json:"transport"`
	PolicySources []string `json:"policy_sources"`
	WinningSource string   `json:"winning_source"`
	// RuleID is optional.
	RuleID string `json:"rule_id,omitempty"`
}

// PayloadContractRatifiedStruct holds the typed fields for a contract_ratified payload.
type PayloadContractRatifiedStruct struct {
	ContractHash                string            `json:"contract_hash"`
	RatifierKeyID               string            `json:"ratifier_key_id"`
	RatifiedRuleIDs             []string          `json:"ratified_rule_ids"`
	RatificationDecisionPerRule map[string]string `json:"ratification_decision_per_rule"`
}

// PayloadContractPromoteIntentStruct holds the typed fields for a contract_promote_intent payload.
type PayloadContractPromoteIntentStruct struct {
	TargetManifestHash string `json:"target_manifest_hash"`
	TargetGeneration   uint64 `json:"target_generation"`
	PriorManifestHash  string `json:"prior_manifest_hash"`
	IntentID           string `json:"intent_id"`
}

// PayloadContractPromoteCommittedStruct holds the typed fields for a contract_promote_committed payload.
type PayloadContractPromoteCommittedStruct struct {
	TargetManifestHash string `json:"target_manifest_hash"`
	PriorManifestHash  string `json:"prior_manifest_hash"`
	IntentID           string `json:"intent_id"`
	// ValidationOutcome must be "accepted" or "rejected".
	ValidationOutcome string `json:"validation_outcome"`
	// RejectReason is required when ValidationOutcome is "rejected".
	RejectReason string `json:"reject_reason,omitempty"`
}

// PayloadContractRollbackAuthorizedStruct holds the typed fields for a contract_rollback_authorized payload.
type PayloadContractRollbackAuthorizedStruct struct {
	RollbackTargetHash   string   `json:"rollback_target_hash"`
	CurrentGeneration    uint64   `json:"current_generation"`
	AuthorizerSignatures []string `json:"authorizer_signatures"`
	AuthorizationID      string   `json:"authorization_id"`
}

// PayloadContractRollbackCommittedStruct holds the typed fields for a contract_rollback_committed payload.
type PayloadContractRollbackCommittedStruct struct {
	RollbackTargetHash string `json:"rollback_target_hash"`
	PriorManifestHash  string `json:"prior_manifest_hash"`
	AuthorizationID    string `json:"authorization_id"`
	// ValidationOutcome must be "accepted" or "rejected".
	ValidationOutcome string `json:"validation_outcome"`
	// RejectReason is required when ValidationOutcome is "rejected".
	RejectReason string `json:"reject_reason,omitempty"`
}

// PayloadContractDemotedStruct holds the typed fields for a contract_demoted payload.
type PayloadContractDemotedStruct struct {
	ContractHash      string `json:"contract_hash"`
	RuleID            string `json:"rule_id"`
	DemotionReason    string `json:"demotion_reason"`
	PriorState        string `json:"prior_state"`
	NewState          string `json:"new_state"`
	AggregationWindow string `json:"aggregation_window"`
}

// PayloadContractExpiredStruct holds the typed fields for a contract_expired payload.
type PayloadContractExpiredStruct struct {
	ContractHash     string `json:"contract_hash"`
	RuleID           string `json:"rule_id"`
	ExpirationReason string `json:"expiration_reason"`
}

// PayloadContractDriftStruct holds the typed fields for a contract_drift payload.
// For PR 1.1 minimal validation, only the three required fields are checked.
// Positive drift includes observation_summary; negative drift includes
// missed_windows and opportunity_status. Those optional fields are deferred to PR 1.3.
type PayloadContractDriftStruct struct {
	ContractHash string `json:"contract_hash"`
	RuleID       string `json:"rule_id"`
	DriftKind    string `json:"drift_kind"`
	// Optional fields deferred to PR 1.3.
	ObservationSummary string `json:"observation_summary,omitempty"`
	MissedWindows      uint64 `json:"missed_windows,omitempty"`
	OpportunityStatus  string `json:"opportunity_status,omitempty"`
}

// PayloadShadowDeltaStruct holds the typed fields for a shadow_delta payload.
type PayloadShadowDeltaStruct struct {
	ContractHash     string            `json:"contract_hash"`
	RuleID           string            `json:"rule_id"`
	OriginalVerdict  string            `json:"original_verdict"`
	CandidateVerdict string            `json:"candidate_verdict"`
	Aggregation      map[string]string `json:"aggregation"`
}

// PayloadOpportunityMissingStruct holds the typed fields for an opportunity_missing payload.
// Rate fields use decimal strings per JCS rule (floats forbidden in signable preimages).
type PayloadOpportunityMissingStruct struct {
	ContractHash              string `json:"contract_hash"`
	RuleID                    string `json:"rule_id"`
	ParentContext             string `json:"parent_context"`
	HistoricalOpportunityRate string `json:"historical_opportunity_rate"`
	CurrentOpportunityRate    string `json:"current_opportunity_rate"`
	Window                    string `json:"window"`
}

// PayloadKeyRotationStruct holds the typed fields for a key_rotation payload.
type PayloadKeyRotationStruct struct {
	KeyID           string `json:"key_id"`
	KeyPurpose      string `json:"key_purpose"`
	OldStatus       string `json:"old_status"`
	NewStatus       string `json:"new_status"`
	RosterHash      string `json:"roster_hash"`
	AuthorizationID string `json:"authorization_id"`
}

// PayloadContractRedactionRequestStruct holds the typed fields for a contract_redaction_request payload.
type PayloadContractRedactionRequestStruct struct {
	TargetContractHash string `json:"target_contract_hash"`
	// RequestKind must be "withdraw_public_proof" or "local_erasure_tombstone".
	RequestKind     string `json:"request_kind"`
	ReasonClass     string `json:"reason_class"`
	AuthorizationID string `json:"authorization_id"`
	TombstoneHash   string `json:"tombstone_hash"`
}
