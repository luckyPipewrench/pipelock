// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

const (
	enfTestSalt    = "test-salt"
	enfTestValue   = "secret-value"
	enfEmptyValue  = ""
	enfBogusClass  = contract.DataClass("bogus-class")
	enfReasonSalt  = reasonInternalNeedsSalt
	enfReasonOptIn = reasonSensitiveOptIn
	enfReasonReg   = reasonRegulatedBlocked
	enfReasonInv   = reasonInvalidClass
)

// expectedHMAC computes the canonical hex HMAC-SHA256 the production code
// must emit. Tests use this helper to lock the construction byte-for-byte;
// any future refactor that switches to bare sha256(salt||value) or any
// other keyed-hash variant fails these tests.
func expectedHMAC(salt, value string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestApply_PublicEmits(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	out := e.Apply(enfTestValue, contract.DataClassPublic, false)
	if out.Decision != DecisionEmit {
		t.Fatalf("decision: got %d, want DecisionEmit", out.Decision)
	}
	if out.Rewritten != enfTestValue {
		t.Fatalf("rewritten: got %q, want %q", out.Rewritten, enfTestValue)
	}
	if out.Reason != "" {
		t.Fatalf("reason: got %q, want empty", out.Reason)
	}
	if out.DataClass != contract.DataClassPublic {
		t.Fatalf("data class echo: got %q", out.DataClass)
	}
}

func TestApply_InternalRedactsWithSalt(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	out := e.Apply(enfTestValue, contract.DataClassInternal, false)
	if out.Decision != DecisionRedact {
		t.Fatalf("decision: got %d, want DecisionRedact", out.Decision)
	}
	want := expectedHMAC(enfTestSalt, enfTestValue)
	if out.Rewritten != want {
		t.Fatalf("rewritten: got %q, want %q", out.Rewritten, want)
	}
	if !hmac.Equal([]byte(out.Rewritten), []byte(want)) {
		t.Fatalf("rewritten failed hmac.Equal byte check")
	}
}

func TestApply_InternalBlocksWithoutSalt(t *testing.T) {
	e := NewEnforcer(nil)
	out := e.Apply(enfTestValue, contract.DataClassInternal, false)
	if out.Decision != DecisionBlock {
		t.Fatalf("decision: got %d, want DecisionBlock", out.Decision)
	}
	if out.Rewritten != "" {
		t.Fatalf("rewritten: got %q, want empty", out.Rewritten)
	}
	if out.Reason != enfReasonSalt {
		t.Fatalf("reason: got %q, want %q", out.Reason, enfReasonSalt)
	}
}

func TestApply_SensitiveAllowedRedacts(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	out := e.Apply(enfTestValue, contract.DataClassSensitive, true)
	if out.Decision != DecisionRedact {
		t.Fatalf("decision: got %d, want DecisionRedact", out.Decision)
	}
	want := expectedHMAC(enfTestSalt, enfTestValue)
	if out.Rewritten != want {
		t.Fatalf("rewritten: got %q, want %q", out.Rewritten, want)
	}
}

func TestApply_SensitiveWithoutOptIn(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	out := e.Apply(enfTestValue, contract.DataClassSensitive, false)
	if out.Decision != DecisionRequireOptIn {
		t.Fatalf("decision: got %d, want DecisionRequireOptIn", out.Decision)
	}
	if out.Rewritten != "" {
		t.Fatalf("rewritten: got %q, want empty", out.Rewritten)
	}
	if out.Reason != enfReasonOptIn {
		t.Fatalf("reason: got %q, want %q", out.Reason, enfReasonOptIn)
	}
}

func TestApply_SensitiveAllowedNoSaltBlocks(t *testing.T) {
	// Operator opted into sensitive, but the salt resolver failed; we MUST
	// fail closed even though allow_sensitive=true. Otherwise sensitive
	// values would emit in plaintext when the salt is missing.
	e := NewEnforcer(nil)
	out := e.Apply(enfTestValue, contract.DataClassSensitive, true)
	if out.Decision != DecisionBlock {
		t.Fatalf("decision: got %d, want DecisionBlock", out.Decision)
	}
	if out.Reason != enfReasonSalt {
		t.Fatalf("reason: got %q, want %q", out.Reason, enfReasonSalt)
	}
}

func TestApply_RegulatedBlocks(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	out := e.Apply(enfTestValue, contract.DataClassRegulated, true)
	if out.Decision != DecisionBlock {
		t.Fatalf("decision: got %d, want DecisionBlock", out.Decision)
	}
	if out.Rewritten != "" {
		t.Fatalf("rewritten: got %q, want empty", out.Rewritten)
	}
	if out.Reason != enfReasonReg {
		t.Fatalf("reason: got %q, want %q", out.Reason, enfReasonReg)
	}
}

func TestApply_InvalidClassBlocks(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	out := e.Apply(enfTestValue, enfBogusClass, true)
	if out.Decision != DecisionBlock {
		t.Fatalf("decision: got %d, want DecisionBlock", out.Decision)
	}
	if out.Reason != enfReasonInv {
		t.Fatalf("reason: got %q, want %q", out.Reason, enfReasonInv)
	}
	if out.Rewritten != "" {
		t.Fatalf("rewritten: got %q, want empty", out.Rewritten)
	}
}

func TestApply_EmptyValuePublicEmits(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	out := e.Apply(enfEmptyValue, contract.DataClassPublic, false)
	if out.Decision != DecisionEmit {
		t.Fatalf("decision: got %d, want DecisionEmit", out.Decision)
	}
	if out.Rewritten != "" {
		t.Fatalf("rewritten: got %q, want empty", out.Rewritten)
	}
}

func TestApply_EmptyValueInternalDeterministic(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	out := e.Apply(enfEmptyValue, contract.DataClassInternal, false)
	if out.Decision != DecisionRedact {
		t.Fatalf("decision: got %d, want DecisionRedact", out.Decision)
	}
	want := expectedHMAC(enfTestSalt, enfEmptyValue)
	if out.Rewritten != want {
		t.Fatalf("rewritten (empty value): got %q, want %q", out.Rewritten, want)
	}
}

func TestApply_DeterministicAcrossCalls(t *testing.T) {
	e := NewEnforcer([]byte(enfTestSalt))
	first := e.Apply(enfTestValue, contract.DataClassInternal, false)
	second := e.Apply(enfTestValue, contract.DataClassInternal, false)
	if first.Rewritten != second.Rewritten {
		t.Fatalf("non-deterministic redaction: %q vs %q", first.Rewritten, second.Rewritten)
	}
	if first.Decision != second.Decision {
		t.Fatalf("non-deterministic decision: %d vs %d", first.Decision, second.Decision)
	}
}
