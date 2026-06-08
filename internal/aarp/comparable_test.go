// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"encoding/json"
	"testing"
)

// decodeComparable parses comparable bytes into a generic map for assertions.
func decodeComparable(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("comparable is not valid JSON: %v\n%s", err, b)
	}
	return m
}

func TestComparableAppraisal_SignedMediated(t *testing.T) {
	t.Parallel()
	env, opts := signedEnvelope(t)
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	b, err := ComparableAppraisal(ap)
	if err != nil {
		t.Fatalf("ComparableAppraisal: %v", err)
	}
	m := decodeComparable(t, b)

	if m["assertion_signed"] != true {
		t.Errorf("assertion_signed = %v, want true", m["assertion_signed"])
	}
	if m["profile"] != Profile {
		t.Errorf("profile = %v, want %q", m["profile"], Profile)
	}
	vc := toStrings(m["verified_claims"])
	if !contains(vc, ClaimReceiptSignatureValid) || !contains(vc, ClaimMediatorKeyPinned) {
		t.Errorf("verified_claims = %v, want both signature_valid and mediator_key_pinned", vc)
	}
	// does_not_assert is the fixed general list, sorted.
	dna := toStrings(m["does_not_assert"])
	if len(dna) != len(docsNotAsserted) {
		t.Errorf("does_not_assert len = %d, want %d", len(dna), len(docsNotAsserted))
	}
	for i := 1; i < len(dna); i++ {
		if dna[i-1] > dna[i] {
			t.Errorf("does_not_assert not sorted: %v", dna)
		}
	}
	// axes must carry mediator_key_pinned under identity, signature under integrity.
	axes, ok := m["axes"].(map[string]any)
	if !ok {
		t.Fatalf("axes is not an object: %T", m["axes"])
	}
	if !contains(toStrings(axes[AxisIdentity]), ClaimMediatorKeyPinned) {
		t.Errorf("identity axis missing mediator_key_pinned: %v", axes[AxisIdentity])
	}
}

func TestComparableAppraisal_ForgedNoInflation(t *testing.T) {
	t.Parallel()
	env, opts := signedEnvelope(t)
	// Tamper one signature byte: the signature must fail and nothing inflates.
	env.Signatures[0].Sig = flipFirstSigChar(env.Signatures[0].Sig)
	ap, err := Verify(env, opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	b, err := ComparableAppraisal(ap)
	if err != nil {
		t.Fatalf("ComparableAppraisal: %v", err)
	}
	m := decodeComparable(t, b)
	if m["assertion_signed"] != false {
		t.Errorf("assertion_signed = %v, want false on forged signature", m["assertion_signed"])
	}
	if vc := toStrings(m["verified_claims"]); len(vc) != 0 {
		t.Errorf("verified_claims = %v, want empty on forged signature", vc)
	}
	if cu := toStrings(m["claimed_unverified"]); !contains(cu, "mediated") {
		t.Errorf("claimed_unverified = %v, want to include mediated", cu)
	}
}

func TestComparableAppraisal_DeduplicatesAndSorts(t *testing.T) {
	t.Parallel()
	// An appraisal with duplicate and unsorted claims must canonicalize to a
	// sorted, de-duplicated list (sortedUnique).
	ap := newAppraisal()
	ap.VerifiedClaims = []string{"b", "a", "b", "a"}
	ap.ClaimedUnverified = []string{"z", "z"}
	b, err := ComparableAppraisal(ap)
	if err != nil {
		t.Fatalf("ComparableAppraisal: %v", err)
	}
	m := decodeComparable(t, b)
	if got := toStrings(m["verified_claims"]); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("verified_claims = %v, want [a b]", got)
	}
	if got := toStrings(m["claimed_unverified"]); len(got) != 1 || got[0] != "z" {
		t.Errorf("claimed_unverified = %v, want [z]", got)
	}
}

func TestComparableChain_LinkedAndBroken(t *testing.T) {
	t.Parallel()
	envs, _ := buildChain(t, 3)

	linked, err := ComparableChain(envs)
	if err != nil {
		t.Fatalf("ComparableChain: %v", err)
	}
	m := decodeComparable(t, linked)
	if m["chain_linked"] != true {
		t.Errorf("chain_linked = %v, want true", m["chain_linked"])
	}
	if n, _ := m["length"].(float64); int(n) != 3 {
		t.Errorf("length = %v, want 3", m["length"])
	}

	// Reorder the middle and last envelopes: the prior_hash linkage breaks.
	envs[1], envs[2] = envs[2], envs[1]
	broken, err := ComparableChain(envs)
	if err != nil {
		t.Fatalf("ComparableChain: %v", err)
	}
	if decodeComparable(t, broken)["chain_linked"] != false {
		t.Errorf("reordered chain reported linked")
	}
}

// flipFirstSigChar flips the first base64 char after the alg prefix so the wire
// stays well-formed but the signature no longer verifies.
func flipFirstSigChar(wire string) string {
	for i := 0; i < len(wire); i++ {
		if wire[i] == ':' && i+1 < len(wire) {
			b := []byte(wire)
			if b[i+1] == 'A' {
				b[i+1] = 'B'
			} else {
				b[i+1] = 'A'
			}
			return string(b)
		}
	}
	return wire
}

func toStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
