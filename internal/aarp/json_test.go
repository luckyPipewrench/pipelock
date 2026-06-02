// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// validEnvelopeJSON returns the JSON of a signed, structurally valid envelope as
// a generic map so tests can splice hostile fields into specific positions.
func validEnvelopeJSON(t *testing.T) map[string]any {
	t.Helper()
	env, _ := signedEnvelope(t)
	raw, err := Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	return m
}

func TestUnmarshal_RejectsRawUnsafeNumber(t *testing.T) {
	// done-state item 2: an unsafe integer as a RAW JSON number is rejected. The
	// same value as a typed string is fine (the chain seq field below).
	m := validEnvelopeJSON(t)
	m["chain"] = map[string]any{
		"issuer_id":  "issuer-1",
		"seq":        json.Number("9007199254740992"), // 2^53 as a raw number
		"prior_hash": GenesisPriorHash,
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Unmarshal(raw); !errors.Is(err, ErrUnsafeNumber) {
		t.Fatalf("Unmarshal(raw unsafe number) = %v, want ErrUnsafeNumber", err)
	}
}

func TestUnmarshal_AcceptsTypedStringForSameValue(t *testing.T) {
	// The same large value as a typed string passes number-safety and decodes.
	m := validEnvelopeJSON(t)
	m["chain"] = map[string]any{
		"issuer_id":  "issuer-1",
		"seq":        "9007199254740992", // typed string: allowed
		"prior_hash": strings.Repeat("a", 64),
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal(typed string) = %v, want nil", err)
	}
	if got.Chain == nil || got.Chain.Seq != "9007199254740992" {
		t.Fatalf("chain seq not decoded: %+v", got.Chain)
	}
}

func TestUnmarshal_RejectsDuplicateKeys(t *testing.T) {
	// A duplicate key is a parser-differential smuggling vector; reject at the
	// raw layer before any struct decode.
	raw := []byte(`{"profile":"aarp/v0.1","profile":"aarp/v9.9","subject":{},"assertion":{},"signatures":[]}`)
	if _, err := Unmarshal(raw); !errors.Is(err, ErrSchema) {
		t.Fatalf("Unmarshal(duplicate key) = %v, want ErrSchema", err)
	}
}

func TestUnmarshal_RejectsUnknownField(t *testing.T) {
	m := validEnvelopeJSON(t)
	m["x_attacker_field"] = "smuggled"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Unmarshal(raw); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Unmarshal(unknown field) = %v, want ErrUnknownField", err)
	}
}

func TestUnmarshal_RejectsUnknownFieldInNestedObject(t *testing.T) {
	m := validEnvelopeJSON(t)
	subj := m["subject"].(map[string]any)
	subj["x_extra"] = "smuggled"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := Unmarshal(raw); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("Unmarshal(unknown nested field) = %v, want ErrUnknownField", err)
	}
}

func TestUnmarshal_RejectsTrailingTokens(t *testing.T) {
	env, _ := signedEnvelope(t)
	raw, err := Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	withTrailer := append(append([]byte(nil), raw...), []byte(` {"x":1}`)...)
	if _, err := Unmarshal(withTrailer); !errors.Is(err, ErrSchema) {
		t.Fatalf("Unmarshal(trailing tokens) = %v, want ErrSchema", err)
	}
}

// TestCanonicalPayload_Deterministic proves the canonical payload bytes are
// stable across re-marshaling (the property all parallel signatures rely on).
func TestCanonicalPayload_Deterministic(t *testing.T) {
	env, _ := signedEnvelope(t)
	d1, err := env.PayloadDigest()
	if err != nil {
		t.Fatalf("PayloadDigest: %v", err)
	}
	// Round-trip through JSON and recompute.
	raw, _ := Marshal(env)
	got, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	d2, err := got.PayloadDigest()
	if err != nil {
		t.Fatalf("PayloadDigest after round-trip: %v", err)
	}
	if d1 != d2 {
		t.Fatalf("payload digest changed across round-trip: %s != %s", d1, d2)
	}
}

func TestUnknownClaim_ReportedClaimOnly(t *testing.T) {
	pub, priv := genKey(t)
	signer, _ := NewEd25519Signer(testKeyID, "mediator", priv)
	e := baseEnvelope()
	e.Assertion.Claimed = []string{"some_future_claim"}
	env, _ := Sign(e, signer)
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !contains(ap.ClaimedUnverified, "some_future_claim") {
		t.Errorf("unknown claim not reported claim-only: %v", ap.ClaimedUnverified)
	}
}
