// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersionContract is the current Contract schema version.
const SchemaVersionContract = 1

// ContractKind is the only valid contract_kind value for v2.4.
const ContractKind = "behavioral_contract"

// Contract is the typed signable body of a learn-and-lock policy contract.
//
// The struct's json tags ARE the projection that feeds JCS canonicalization.
// Fields not present in this struct are dropped before signing. There is no
// signed_body wrapper; advisory data lives outside this struct in the
// distribution wrapper (ContractEnvelope).
type Contract struct {
	SchemaVersion     int               `json:"schema_version"`
	ContractKind      string            `json:"contract_kind"`
	ContractHash      string            `json:"contract_hash"`
	PriorContractHash string            `json:"prior_contract_hash,omitempty"`
	SignerKeyID       string            `json:"signer_key_id"`
	KeyPurpose        string            `json:"key_purpose"`
	DataClassRoot     string            `json:"data_class_root"`
	FieldDataClasses  map[string]string `json:"field_data_classes"`
	Selector          Selector          `json:"selector"`
	ObservationWindow ObservationWindow `json:"observation_window"`
	Compile           ContractCompile   `json:"compile"`
	Defaults          ContractDefaults  `json:"defaults"`
	Rules             []Rule            `json:"rules"`
}

// Selector identifies which sessions a contract applies to.
type Selector struct {
	Agent      string `json:"agent,omitempty"`
	AgentGlob  string `json:"agent_glob,omitempty"`
	Default    bool   `json:"default,omitempty"`
	SelectorID string `json:"selector_id"`
}

// ObservationWindow describes the recorder-evidence window the contract was compiled from.
type ObservationWindow struct {
	Start                 time.Time `json:"start"`
	End                   time.Time `json:"end"`
	EventCount            uint64    `json:"event_count"`
	SessionCount          uint64    `json:"session_count"`
	ObservationWindowRoot string    `json:"observation_window_root"`
}

// ContractCompile carries build provenance under the signature.
type ContractCompile struct {
	PipelockVersion        string `json:"pipelock_version"`
	PipelockBuildSHA       string `json:"pipelock_build_sha"`
	GoVersion              string `json:"go_version"`
	ModuleDigestRoot       string `json:"module_digest_root"`
	CompileConfigHash      string `json:"compile_config_hash"`
	InferenceAlgorithm     string `json:"inference_algorithm"`
	NormalizationAlgorithm string `json:"normalization_algorithm"`
}

// ContractDefaults are the per-contract config defaults.
type ContractDefaults struct {
	Fidelity   string                  `json:"fidelity"`
	Confidence map[string]any          `json:"confidence"`
	Privacy    ContractDefaultsPrivacy `json:"privacy"`
}

// ContractDefaultsPrivacy holds privacy-budget defaults.
type ContractDefaultsPrivacy struct {
	DefaultDataClass DataClass   `json:"default_data_class"`
	SaltEpoch        uint64      `json:"salt_epoch"`
	ForbidClasses    []DataClass `json:"forbid_classes"`
}

// Rule is a single learned rule.
type Rule struct {
	RuleID            string         `json:"rule_id"`
	DisplayName       string         `json:"display_name"`
	RuleKind          string         `json:"rule_kind"`
	LifecycleState    string         `json:"lifecycle_state"`
	Confidence        string         `json:"confidence"`
	WilsonLower       string         `json:"wilson_lower"` // decimal string per JCS rule
	Observation       map[string]any `json:"observation"`
	Selector          map[string]any `json:"selector"`
	Budgets           map[string]any `json:"budgets,omitempty"`
	Rationale         map[string]any `json:"rationale"`
	RecurringSupport  map[string]any `json:"recurring_support"`
	OpportunityHealth map[string]any `json:"opportunity_health"`
}

// ContractEnvelope is the unsigned outer wrapper carrying body + detached signature.
type ContractEnvelope struct {
	Body      Contract `json:"body"`
	Signature string   `json:"signature"`
}

// SignablePreimage returns the JCS-canonicalized bytes for this Contract.
// The signature is not part of its own preimage; ContractEnvelope.Signature is detached.
func (c Contract) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal contract: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse contract for canonicalization: %w", err)
	}
	return Canonicalize(tree)
}
