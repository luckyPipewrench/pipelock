// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contract

import "testing"

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
