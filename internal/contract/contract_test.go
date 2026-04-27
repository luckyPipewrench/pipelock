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
