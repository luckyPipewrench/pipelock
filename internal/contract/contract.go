// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SchemaVersionContract is the current Contract schema version.
const SchemaVersionContract = 1

// ContractKind is the only valid contract_kind value for v2.4.
const ContractKind = "behavioral_contract"

// Rule lifecycle states. The runtime evaluator only honors LifecycleEnforce
// for live decisions; other states observe or are inert.
const (
	LifecycleProposed    = "proposed"
	LifecycleCaptureOnly = "capture_only"
	LifecycleEnforce     = "enforce"
	LifecycleExpired     = "expired"
	LifecycleDemoted     = "demoted"
)

// Rule kinds enforceable by the v1 contract runtime. New kinds must land
// in the runtime evaluator AND in EnforceableRuleKinds() in the same change;
// otherwise they fail validation in LifecycleEnforce state.
const (
	RuleKindHTTPDestination = "http_destination"
	RuleKindHTTPAction      = "http_action"
	RuleKindMCPToolCall     = "mcp_tool_call"
)

// ErrContractSchemaVersion rejects contracts with non-current schema_version.
var ErrContractSchemaVersion = errors.New("contract: unsupported schema_version")

// ErrContractKind rejects contracts with non-enumerated contract_kind.
var ErrContractKind = errors.New("contract: invalid contract_kind")

// ErrCaptureGrade rejects rules that claim enforcement without sufficient
// capture-surface evidence.
var ErrCaptureGrade = errors.New("contract: invalid capture grade")

// ErrUnenforceableRuleKind rejects rules in LifecycleEnforce state whose
// rule_kind is not in EnforceableRuleKinds(). Rules in non-enforce states
// (proposed, capture_only, expired, demoted) may carry forward-compatible
// kinds; only enforced rules are gated.
var ErrUnenforceableRuleKind = errors.New("contract: rule_kind not enforceable in this schema version")

// ErrUnsupportedLifecycle rejects rules whose lifecycle_state is not in the
// enumerated set. Without this gate a typo (e.g. "enforce ", "enabled")
// silently falls through every state-keyed branch — the rule-kind validator
// only runs on the literal LifecycleEnforce string, so a poisoned lifecycle
// can carry a rule that was meant to be enforced and turn it into runtime
// dead code.
var ErrUnsupportedLifecycle = errors.New("contract: unsupported lifecycle_state")

// EnforceableRuleKinds returns the rule kinds the v1 runtime can evaluate
// for live enforcement. The validator uses this to gate
// LifecycleEnforce rules so a contract cannot ship enforced rules the
// runtime would silently ignore. Add a new kind here only when the
// matching runtime evaluator branch lands in the same change.
func EnforceableRuleKinds() []string {
	return []string{RuleKindHTTPDestination, RuleKindHTTPAction, RuleKindMCPToolCall}
}

func ruleKindEnforceable(kind string) bool {
	for _, k := range EnforceableRuleKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

// validLifecycle reports whether state is one of the enumerated values.
func validLifecycle(state string) bool {
	switch state {
	case LifecycleProposed, LifecycleCaptureOnly, LifecycleEnforce, LifecycleExpired, LifecycleDemoted:
		return true
	default:
		return false
	}
}

// Capture-grade values describe how much scanner evidence backed a rule.
const (
	CaptureGradeNone    = "none"
	CaptureGradeSummary = "summary"
	CaptureGradePartial = "partial"
	CaptureGradeFull    = "full"
)

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
	RuleID               string         `json:"rule_id"`
	DisplayName          string         `json:"display_name"`
	RuleKind             string         `json:"rule_kind"`
	LifecycleState       string         `json:"lifecycle_state"`
	RequiredCaptureGrade string         `json:"required_capture_grade,omitempty"`
	ObservedCaptureGrade string         `json:"observed_capture_grade,omitempty"`
	Confidence           string         `json:"confidence"`
	WilsonLower          string         `json:"wilson_lower"` // decimal string per JCS rule
	Observation          map[string]any `json:"observation"`
	Selector             map[string]any `json:"selector"`
	Budgets              map[string]any `json:"budgets,omitempty"`
	Rationale            map[string]any `json:"rationale"`
	RecurringSupport     map[string]any `json:"recurring_support"`
	OpportunityHealth    map[string]any `json:"opportunity_health"`
}

// ContractEnvelope is the unsigned outer wrapper carrying body + detached signature.
type ContractEnvelope struct {
	Body      Contract `json:"body"`
	Signature string   `json:"signature"`
}

// Validate runs structural and data-class checks on the contract body.
// Cryptographic verification (signature, contract_hash) happens externally in verify.go.
//
// Validate is the SECOND-LINE check on the typed struct. Unknown-field
// rejection is the FIRST-LINE check and MUST happen at the transport
// boundary via LoadContract / DecodeStrictJSON; once we are inside this
// method the input has already been re-marshaled from the typed struct,
// which means any unknown fields the caller might have parsed without
// strict-decode have already been silently dropped. Callers that bypass
// LoadContract and feed Contract directly into Validate forfeit
// unknown-field detection. Use LoadContract.
func (c Contract) Validate() error {
	if c.SchemaVersion != SchemaVersionContract {
		return fmt.Errorf("%w: got %d, want %d", ErrContractSchemaVersion, c.SchemaVersion, SchemaVersionContract)
	}
	if c.ContractKind != ContractKind {
		return fmt.Errorf("%w: got %q, want %q", ErrContractKind, c.ContractKind, ContractKind)
	}
	// Data-class coverage: walk the contract body and reject regulated fields.
	// Marshal back to generic tree so the existing walker can be reused.
	raw, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal contract for validate: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return fmt.Errorf("parse contract for validate: %w", err)
	}
	bodyMap, ok := tree.(map[string]any)
	if !ok {
		return fmt.Errorf("contract body is not a map after marshal+parse")
	}
	if err := validateRuleLifecycles(c.Rules); err != nil {
		return err
	}
	if err := validateRuleKinds(c.Rules); err != nil {
		return err
	}
	if err := validateRuleCaptureGrades(c.Rules); err != nil {
		return err
	}
	fcls := make(map[string]any, len(c.FieldDataClasses))
	for k, v := range c.FieldDataClasses {
		fcls[k] = v
	}
	return ValidateDataClassCoverage(bodyMap, fcls)
}

func validateRuleLifecycles(rules []Rule) error {
	for i, rule := range rules {
		if !validLifecycle(rule.LifecycleState) {
			return fmt.Errorf(
				"%w: rules[%d] lifecycle_state %q",
				ErrUnsupportedLifecycle,
				i,
				rule.LifecycleState,
			)
		}
	}
	return nil
}

func validateRuleKinds(rules []Rule) error {
	for i, rule := range rules {
		if rule.LifecycleState != LifecycleEnforce {
			continue
		}
		if !ruleKindEnforceable(rule.RuleKind) {
			return fmt.Errorf(
				"%w: rules[%d] kind %q (enforceable: %v)",
				ErrUnenforceableRuleKind,
				i,
				rule.RuleKind,
				EnforceableRuleKinds(),
			)
		}
	}
	return nil
}

func validateRuleCaptureGrades(rules []Rule) error {
	for i, rule := range rules {
		if rule.RuleKind == "" {
			return fmt.Errorf("%w: rules[%d] missing rule_kind", ErrCaptureGrade, i)
		}
		required, observed := effectiveCaptureGrades(rule)
		if required == "" {
			return fmt.Errorf("%w: rules[%d] missing required_capture_grade", ErrCaptureGrade, i)
		}
		if observed == "" {
			return fmt.Errorf("%w: rules[%d] missing observed_capture_grade", ErrCaptureGrade, i)
		}
		if !validCaptureGrade(required) {
			return fmt.Errorf("%w: rules[%d] invalid required_capture_grade %q", ErrCaptureGrade, i, required)
		}
		if !validCaptureGrade(observed) {
			return fmt.Errorf("%w: rules[%d] invalid observed_capture_grade %q", ErrCaptureGrade, i, observed)
		}
		if rule.LifecycleState == LifecycleEnforce && compareCaptureGrade(observed, required) < 0 {
			return fmt.Errorf(
				"%w: rules[%d] enforce requires %s evidence, observed %s",
				ErrCaptureGrade,
				i,
				required,
				observed,
			)
		}
	}
	return nil
}

func effectiveCaptureGrades(rule Rule) (string, string) {
	if rule.LifecycleState == LifecycleCaptureOnly && rule.RequiredCaptureGrade == "" && rule.ObservedCaptureGrade == "" {
		return CaptureGradeFull, CaptureGradeFull
	}
	return rule.RequiredCaptureGrade, rule.ObservedCaptureGrade
}

func validCaptureGrade(grade string) bool {
	return captureGradeRank(grade) >= 0
}

func compareCaptureGrade(observed, required string) int {
	return captureGradeRank(observed) - captureGradeRank(required)
}

func captureGradeRank(grade string) int {
	switch grade {
	case CaptureGradeNone:
		return 0
	case CaptureGradeSummary:
		return 1
	case CaptureGradePartial:
		return 2
	case CaptureGradeFull:
		return 3
	default:
		return -1
	}
}

// SignablePreimage returns the JCS-canonicalized bytes for this Rule.
// Used by MerkleRoot to produce deterministic leaf hashes per rule.
func (r Rule) SignablePreimage() ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("marshal rule: %w", err)
	}
	tree, err := ParseJSONStrict(raw)
	if err != nil {
		return nil, fmt.Errorf("parse rule for canonicalization: %w", err)
	}
	return Canonicalize(tree)
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
