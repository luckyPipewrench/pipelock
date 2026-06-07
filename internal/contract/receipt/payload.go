// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

// PayloadProxyDecisionStruct holds the typed fields for a proxy_decision payload.
//
// Verdict is what the proxy enforced for this request. LiveVerdict is what
// the contract evaluator would have enforced under ModeLive given the same
// inputs: in ModeLive the two are equal, but ModeShadow / ModeCapture surface
// the scanner-floor verdict as Verdict and the contract's would-have-been
// outcome as LiveVerdict so audit consumers can distinguish "scanner allowed
// and contract agreed" from "scanner allowed but contract would have blocked
// in live mode." LiveVerdict is omitempty for legacy emissions and for paths
// where the runtime did not surface a separate live result.
type PayloadProxyDecisionStruct struct {
	ActionType    string   `json:"action_type"`
	Target        string   `json:"target"`
	Verdict       string   `json:"verdict"`
	LiveVerdict   string   `json:"live_verdict,omitempty"`
	Transport     string   `json:"transport"`
	PolicySources []string `json:"policy_sources"`
	WinningSource string   `json:"winning_source"`
	// RuleID is optional.
	RuleID string `json:"rule_id,omitempty"`
}

// PayloadProxyDecisionWithSpansStruct is the v2 compatibility boundary for
// proxy decisions that carry source-span provenance. The base proxy-decision
// fields are intentionally repeated in a new payload_kind instead of making
// source_spans an optional field on proxy_decision: v2 receipts reject unknown
// payload fields, so this shape gives old and new validators an unambiguous
// branch.
type PayloadProxyDecisionWithSpansStruct struct {
	ActionType    string       `json:"action_type"`
	Target        string       `json:"target"`
	Verdict       string       `json:"verdict"`
	LiveVerdict   string       `json:"live_verdict,omitempty"`
	Transport     string       `json:"transport"`
	PolicySources []string     `json:"policy_sources"`
	WinningSource string       `json:"winning_source"`
	RuleID        string       `json:"rule_id,omitempty"`
	SourceSpans   []SourceSpan `json:"source_spans"`
}

// SourceSpan carries signed, re-checkable provenance for one scanner match. It
// indexes only the normalized/redacted scanner view named by NormalizedView.
// Emitters must populate RedactedSample and MatchHash from sanitized or
// class-only values; the schema rejects malformed fields but cannot prove a
// caller avoided raw matched bytes.
type SourceSpan struct {
	SourceID       string `json:"source_id"`
	SourceKind     string `json:"source_kind"`
	NormalizedView string `json:"normalized_view"`

	PipelockBinaryDigest string `json:"pipelock_binary_digest"`
	RulesBundleDigest    string `json:"rules_bundle_digest"`
	TransformProfile     string `json:"transform_profile"`
	PolicyHash           string `json:"policy_hash"`

	RuleID        string `json:"rule_id"`
	Bundle        string `json:"bundle,omitempty"`
	BundleVersion string `json:"bundle_version,omitempty"`

	CharOffset *int `json:"char_offset,omitempty"`
	CharLength *int `json:"char_length,omitempty"`

	MatchHash    string `json:"match_hash"`
	MatchHashAlg string `json:"match_hash_alg"`
	MatchClass   string `json:"match_class"`

	RedactedSample string `json:"redacted_sample,omitempty"`
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
	ContractHash     string                 `json:"contract_hash"`
	RuleID           string                 `json:"rule_id"`
	OriginalVerdict  string                 `json:"original_verdict"`
	CandidateVerdict string                 `json:"candidate_verdict"`
	Aggregation      ShadowDeltaAggregation `json:"aggregation"`
}

// ShadowDeltaAggregation summarizes one rule/window delta bucket.
type ShadowDeltaAggregation struct {
	WindowStart      string   `json:"window_start"`
	WindowEnd        string   `json:"window_end"`
	LosslessCount    uint64   `json:"lossless_count"`
	DeltaSampleCount uint64   `json:"delta_sample_count"`
	ExemplarIDs      []string `json:"exemplar_ids"`
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
