// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import (
	"errors"
	"testing"
)

func TestPackageBootstraps(t *testing.T) {
	t.Parallel()
	// Smoke test: package compiles. More tests added as types land.
}

func TestContract_SignablePreimage_Stable(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:     1,
		ContractKind:      "behavioral_contract",
		ContractHash:      "sha256:abc",
		PriorContractHash: "",
		SignerKeyID:       "contract-compile-key-v3",
		KeyPurpose:        "contract-compile-signing",
		DataClassRoot:     "internal",
		FieldDataClasses:  map[string]string{"selector.agent": "internal"},
		Selector:          Selector{Agent: "buster", SelectorID: "sha256:sel"},
	}
	got, err := c.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	got2, err := c.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage second call: %v", err)
	}
	if string(got) != string(got2) {
		t.Errorf("preimage is non-deterministic: got1=%q got2=%q", got, got2)
	}
}

func TestContract_SignablePreimage_MarshalError(t *testing.T) {
	t.Parallel()
	// A Contract whose Defaults.Confidence contains an unmarshalable value (channel)
	// causes json.Marshal to fail in SignablePreimage, exercising that error branch.
	c := Contract{
		Defaults: ContractDefaults{
			Confidence: map[string]any{"ch": make(chan int)},
		},
	}
	_, err := c.SignablePreimage()
	if err == nil {
		t.Error("expected error from SignablePreimage with unmarshalable Confidence, got nil")
	}
}

func TestContract_Validate_AcceptsValidContract(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    "internal",
		FieldDataClasses: map[string]string{},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestContract_Validate_RejectsBadSchemaVersion(t *testing.T) {
	t.Parallel()
	c := Contract{SchemaVersion: 99, ContractKind: ContractKind, DataClassRoot: "internal"}
	if err := c.Validate(); !errors.Is(err, ErrContractSchemaVersion) {
		t.Errorf("got %v, want ErrContractSchemaVersion", err)
	}
}

func TestContract_Validate_RejectsBadContractKind(t *testing.T) {
	t.Parallel()
	c := Contract{SchemaVersion: SchemaVersionContract, ContractKind: "wrong_kind", DataClassRoot: "internal"}
	if err := c.Validate(); !errors.Is(err, ErrContractKind) {
		t.Errorf("got %v, want ErrContractKind", err)
	}
}

func TestContract_Validate_RejectsRegulatedField(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion: SchemaVersionContract,
		ContractKind:  ContractKind,
		DataClassRoot: "internal",
		FieldDataClasses: map[string]string{
			"selector.agent": string(DataClassRegulated),
		},
		Selector: Selector{Agent: "x"},
	}
	if err := c.Validate(); !errors.Is(err, ErrRegulatedField) {
		t.Errorf("got %v, want ErrRegulatedField", err)
	}
}

func TestContract_Validate_RejectsInvalidDataClassRoot(t *testing.T) {
	t.Parallel()
	c := Contract{SchemaVersion: SchemaVersionContract, ContractKind: ContractKind, DataClassRoot: invalidDataClassName}
	if err := c.Validate(); !errors.Is(err, ErrInvalidDataClass) {
		t.Errorf("got %v, want ErrInvalidDataClass", err)
	}
}

func TestContract_Validate_RejectsRegulatedDataClassRoot(t *testing.T) {
	t.Parallel()
	c := Contract{SchemaVersion: SchemaVersionContract, ContractKind: ContractKind, DataClassRoot: string(DataClassRegulated)}
	if err := c.Validate(); !errors.Is(err, ErrRegulatedField) {
		t.Errorf("got %v, want ErrRegulatedField", err)
	}
}

func TestContract_Validate_RejectsEnforceWithInsufficientCaptureGrade(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:               "r-http-action",
			RuleKind:             RuleKindHTTPAction,
			LifecycleState:       LifecycleEnforce,
			RequiredCaptureGrade: CaptureGradeFull,
			ObservedCaptureGrade: CaptureGradePartial,
			Confidence:           "stable",
			WilsonLower:          "0.99",
			Observation:          map[string]any{},
			Selector:             map[string]any{},
			Rationale:            map[string]any{},
			RecurringSupport:     map[string]any{},
			OpportunityHealth:    map[string]any{},
		}},
	}
	if err := c.Validate(); !errors.Is(err, ErrCaptureGrade) {
		t.Errorf("got %v, want ErrCaptureGrade", err)
	}
}

func TestContract_Validate_AcceptsEnforceWithFullCaptureGrade(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:               "r-url",
			RuleKind:             "http_destination",
			LifecycleState:       "enforce",
			RequiredCaptureGrade: CaptureGradeFull,
			ObservedCaptureGrade: CaptureGradeFull,
			Confidence:           "stable",
			WilsonLower:          "0.99",
			Observation:          map[string]any{},
			Selector:             map[string]any{},
			Rationale:            map[string]any{},
			RecurringSupport:     map[string]any{},
			OpportunityHealth:    map[string]any{},
		}},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestContract_Validate_BackfillsV1CaptureOnlyCaptureGrade(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:         "r-missing",
			RuleKind:       "http_destination",
			LifecycleState: "capture_only",
		}},
	}
	if err := c.Validate(); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestContract_Validate_RejectsEnforceMissingCaptureGrade(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:         "r-missing",
			RuleKind:       "http_destination",
			LifecycleState: "enforce",
		}},
	}
	if err := c.Validate(); !errors.Is(err, ErrCaptureGrade) {
		t.Errorf("got %v, want ErrCaptureGrade", err)
	}
}

func TestContract_Validate_RejectsInvalidCaptureGrade(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:               "r-invalid",
			RuleKind:             "http_destination",
			LifecycleState:       "capture_only",
			RequiredCaptureGrade: "complete",
			ObservedCaptureGrade: CaptureGradeFull,
		}},
	}
	if err := c.Validate(); !errors.Is(err, ErrCaptureGrade) {
		t.Errorf("got %v, want ErrCaptureGrade", err)
	}
}

func TestContract_Validate_RejectsMissingRuleKind(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:               "r-missing-kind",
			LifecycleState:       "capture_only",
			RequiredCaptureGrade: CaptureGradeFull,
			ObservedCaptureGrade: CaptureGradeFull,
		}},
	}
	if err := c.Validate(); !errors.Is(err, ErrCaptureGrade) {
		t.Errorf("got %v, want ErrCaptureGrade", err)
	}
}

func TestContract_Validate_RejectsUnknownLifecycleState(t *testing.T) {
	t.Parallel()
	// A lifecycle string that isn't in the enumerated set must be rejected at
	// validation time. Without this, a poisoned or typo'd lifecycle ("enforce ",
	// "enabled") slips past the rule-kind gate (which only fires when the value
	// is exactly LifecycleEnforce) and gets silently treated as inert.
	cases := []string{"enforce ", "Enforce", "enabled", "active", " "}
	for _, state := range cases {
		state := state
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			c := Contract{
				SchemaVersion:    SchemaVersionContract,
				ContractKind:     ContractKind,
				DataClassRoot:    string(DataClassInternal),
				FieldDataClasses: map[string]string{},
				Rules: []Rule{{
					RuleID:               "r-1",
					RuleKind:             RuleKindHTTPDestination,
					LifecycleState:       state,
					RequiredCaptureGrade: CaptureGradeFull,
					ObservedCaptureGrade: CaptureGradeFull,
					Confidence:           "stable",
					WilsonLower:          "0.99",
					Observation:          map[string]any{},
					Selector:             map[string]any{},
					Rationale:            map[string]any{},
					RecurringSupport:     map[string]any{},
					OpportunityHealth:    map[string]any{},
				}},
			}
			err := c.Validate()
			if !errors.Is(err, ErrUnsupportedLifecycle) {
				t.Fatalf("lifecycle %q: got %v, want ErrUnsupportedLifecycle", state, err)
			}
		})
	}
}

func TestContract_Validate_AcceptsAllEnumeratedLifecycles(t *testing.T) {
	t.Parallel()
	for _, state := range []string{LifecycleProposed, LifecycleCaptureOnly, LifecycleEnforce, LifecycleExpired, LifecycleDemoted} {
		state := state
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			c := Contract{
				SchemaVersion:    SchemaVersionContract,
				ContractKind:     ContractKind,
				DataClassRoot:    string(DataClassInternal),
				FieldDataClasses: map[string]string{},
				Rules: []Rule{{
					RuleID:               "r-1",
					RuleKind:             RuleKindHTTPDestination,
					LifecycleState:       state,
					RequiredCaptureGrade: CaptureGradeFull,
					ObservedCaptureGrade: CaptureGradeFull,
					Confidence:           "stable",
					WilsonLower:          "0.99",
					Observation:          map[string]any{},
					Selector:             map[string]any{},
					Rationale:            map[string]any{},
					RecurringSupport:     map[string]any{},
					OpportunityHealth:    map[string]any{},
				}},
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("lifecycle %q: got %v, want nil", state, err)
			}
		})
	}
}

func TestContract_Validate_RejectsEnforceWithUnenforceableRuleKind(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:               "r-future",
			RuleKind:             "mcp_resource_access",
			LifecycleState:       LifecycleEnforce,
			RequiredCaptureGrade: CaptureGradeFull,
			ObservedCaptureGrade: CaptureGradeFull,
			Confidence:           "stable",
			WilsonLower:          "0.99",
			Observation:          map[string]any{},
			Selector:             map[string]any{},
			Rationale:            map[string]any{},
			RecurringSupport:     map[string]any{},
			OpportunityHealth:    map[string]any{},
		}},
	}
	err := c.Validate()
	if !errors.Is(err, ErrUnenforceableRuleKind) {
		t.Fatalf("got %v, want ErrUnenforceableRuleKind", err)
	}
}

func TestContract_Validate_AcceptsCaptureOnlyWithUnenforceableRuleKind(t *testing.T) {
	t.Parallel()
	// Forward compat: non-enforce rules can carry kinds the runtime
	// does not yet evaluate. They are observation-only and never gate
	// live decisions, so they cannot bypass the floor.
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:         "r-future",
			RuleKind:       "mcp_resource_access",
			LifecycleState: LifecycleCaptureOnly,
		}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("got %v, want nil", err)
	}
}

func TestContract_Validate_AcceptsMCPToolCallEnforce(t *testing.T) {
	t.Parallel()
	c := Contract{
		SchemaVersion:    SchemaVersionContract,
		ContractKind:     ContractKind,
		DataClassRoot:    string(DataClassInternal),
		FieldDataClasses: map[string]string{},
		Rules: []Rule{{
			RuleID:               "r-mcp",
			RuleKind:             RuleKindMCPToolCall,
			LifecycleState:       LifecycleEnforce,
			RequiredCaptureGrade: CaptureGradeFull,
			ObservedCaptureGrade: CaptureGradeFull,
			Confidence:           "stable",
			WilsonLower:          "0.99",
			Observation:          map[string]any{},
			Selector: map[string]any{
				"server": map[string]any{"value": "stripe"},
				"tool":   map[string]any{"value": "create_payment_intent"},
			},
			Rationale:         map[string]any{},
			RecurringSupport:  map[string]any{},
			OpportunityHealth: map[string]any{},
		}},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("got %v, want nil — registry must accept mcp_tool_call enforce", err)
	}
}

func TestContract_Validate_AcceptsEnforceForEveryEnforceableRuleKind(t *testing.T) {
	t.Parallel()
	for _, kind := range EnforceableRuleKinds() {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			c := Contract{
				SchemaVersion:    SchemaVersionContract,
				ContractKind:     ContractKind,
				DataClassRoot:    string(DataClassInternal),
				FieldDataClasses: map[string]string{},
				Rules: []Rule{{
					RuleID:               "r-" + kind,
					RuleKind:             kind,
					LifecycleState:       LifecycleEnforce,
					RequiredCaptureGrade: CaptureGradeFull,
					ObservedCaptureGrade: CaptureGradeFull,
					Confidence:           "stable",
					WilsonLower:          "0.99",
					Observation:          map[string]any{},
					Selector:             map[string]any{},
					Rationale:            map[string]any{},
					RecurringSupport:     map[string]any{},
					OpportunityHealth:    map[string]any{},
				}},
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("kind %q: got %v, want nil", kind, err)
			}
		})
	}
}

func TestContract_SignablePreimage_KeyOrderIndependent(t *testing.T) {
	t.Parallel()
	a := Contract{SchemaVersion: 1, ContractKind: "behavioral_contract", DataClassRoot: "internal", FieldDataClasses: map[string]string{"a": "public", "b": "internal"}}
	b := Contract{SchemaVersion: 1, ContractKind: "behavioral_contract", DataClassRoot: "internal", FieldDataClasses: map[string]string{"b": "internal", "a": "public"}}
	pa, err := a.SignablePreimage()
	if err != nil {
		t.Fatalf("a preimage: %v", err)
	}
	pb, err := b.SignablePreimage()
	if err != nil {
		t.Fatalf("b preimage: %v", err)
	}
	if string(pa) != string(pb) {
		t.Errorf("map key order leaked into preimage: %q vs %q", pa, pb)
	}
}
