//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func testAppliedState() FollowerAppliedState {
	return FollowerAppliedState{
		ActiveBundleID:                 "bundle-active-1",
		ActiveBundleVersion:            7,
		ActiveBundleHash:               testHash("ab"),
		ActiveBundleMinPipelockVersion: "3.0.0",
		PipelockVersion:                "3.1.0",
		GitCommit:                      "abcdef1",
		BuildDate:                      "2026-05-20T00:00:00Z",
		LastPolicyPollAt:               testNow,
		LastSuccessfulApplyAt:          testNow,
		ObservedAt:                     testNow,
	}
}

func TestFollowerAppliedState_Validate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*FollowerAppliedState)
		wantErr error
	}{
		{"happy", func(*FollowerAppliedState) {}, nil},
		{"empty_optionals_ok", func(s *FollowerAppliedState) {
			*s = FollowerAppliedState{ObservedAt: testNow}
		}, nil},
		{"missing_observed_at", func(s *FollowerAppliedState) { s.ObservedAt = time.Time{} }, ErrMissingField},
		{"string_over_cap", func(s *FollowerAppliedState) {
			s.ActiveBundleID = strings.Repeat("a", MaxRuntimeStringBytes+1)
		}, ErrPayloadTooLarge},
		{"string_control_char", func(s *FollowerAppliedState) { s.PipelockVersion = "3.1\x00" }, ErrInvalidAppliedState},
		{"string_invalid_utf8", func(s *FollowerAppliedState) { s.GitCommit = "\xff\xfe" }, ErrInvalidAppliedState},
		{"error_code_control_char", func(s *FollowerAppliedState) { s.LastApplyErrorCode = "bad\tcode" }, ErrInvalidAppliedState},
		{"message_over_rune_cap", func(s *FollowerAppliedState) {
			s.LastApplyErrorMessage = strings.Repeat("é", MaxApplyErrorMessageRunes+1)
		}, ErrPayloadTooLarge},
		{"message_control_char", func(s *FollowerAppliedState) { s.LastApplyErrorMessage = "line1\nline2" }, ErrInvalidAppliedState},
		{"message_invalid_utf8", func(s *FollowerAppliedState) { s.LastApplyErrorMessage = "bad\xff" }, ErrInvalidAppliedState},
		{"hash_uppercase", func(s *FollowerAppliedState) { s.ActiveBundleHash = strings.Repeat("AB", 32) }, ErrInvalidHash},
		{"hash_wrong_length", func(s *FollowerAppliedState) { s.ActiveBundleHash = "abcd" }, ErrInvalidHash},
		{"hash_non_hex", func(s *FollowerAppliedState) { s.ActiveBundleHash = strings.Repeat("zz", 32) }, ErrInvalidHash},
		{"empty_hash_ok", func(s *FollowerAppliedState) { s.ActiveBundleHash = "" }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := testAppliedState()
			tc.mutate(&state)
			err := state.Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestAuditBatchEnvelope_ValidateWithAppliedState(t *testing.T) {
	t.Run("valid_applied_state_passes", func(t *testing.T) {
		batch := testAuditBatch()
		applied := testAppliedState()
		batch.AppliedState = &applied
		if err := batch.Validate(); err != nil {
			t.Fatalf("Validate() with valid applied-state = %v", err)
		}
	})
	t.Run("malformed_applied_state_fails_whole_batch", func(t *testing.T) {
		batch := testAuditBatch()
		applied := testAppliedState()
		applied.ObservedAt = time.Time{} // present but missing required field
		batch.AppliedState = &applied
		err := batch.Validate()
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField (fail-closed)", err)
		}
	})
}

// TestAuditBatchEnvelope_V1NilAppliedStatePreimageStable pins invariant #1: a v1
// envelope (nil AppliedState) serializes with no applied_state key and its
// canonical preimage is byte-identical to itself after a set-then-clear cycle,
// so existing v1 batches produce unchanged signed bytes.
func TestAuditBatchEnvelope_V1NilAppliedStatePreimageStable(t *testing.T) {
	base := testAuditBatch()
	base.Signatures = nil

	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "applied_state") {
		t.Fatalf("nil AppliedState must not appear on the wire: %s", raw)
	}

	pre1, err := base.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(base): %v", err)
	}

	withState := base
	applied := testAppliedState()
	withState.AppliedState = &applied
	withState.AppliedState = nil // clear again -> must equal the original v1 preimage
	pre2, err := withState.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(cleared): %v", err)
	}
	if string(pre1) != string(pre2) {
		t.Fatalf("v1 nil-applied-state preimage not stable:\n%s\n%s", pre1, pre2)
	}
}

func TestAuditBatchEnvelope_PreimageIncludesAppliedState(t *testing.T) {
	base := testAuditBatch()
	base.Signatures = nil
	basePre, err := base.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(base): %v", err)
	}

	withState := base
	applied := testAppliedState()
	withState.AppliedState = &applied
	statePre, err := withState.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(withState): %v", err)
	}
	if string(basePre) == string(statePre) {
		t.Fatal("adding applied-state must change the signed preimage")
	}
	if !strings.Contains(string(statePre), "applied_state") {
		t.Fatalf("applied-state must be inside the canonical preimage: %s", statePre)
	}

	// Mutating any applied-state field must change the preimage (proves each
	// field is covered by the signature, not dropped in canonicalization).
	for _, tc := range []struct {
		name   string
		mutate func(*FollowerAppliedState)
	}{
		{"active_bundle_id", func(s *FollowerAppliedState) { s.ActiveBundleID = "other" }},
		{"active_bundle_version", func(s *FollowerAppliedState) { s.ActiveBundleVersion = 999 }},
		{"active_bundle_hash", func(s *FollowerAppliedState) { s.ActiveBundleHash = testHash("cd") }},
		{"active_bundle_min_pipelock_version", func(s *FollowerAppliedState) { s.ActiveBundleMinPipelockVersion = "9.9.9" }},
		{"pipelock_version", func(s *FollowerAppliedState) { s.PipelockVersion = "9.9.9" }},
		{"git_commit", func(s *FollowerAppliedState) { s.GitCommit = "deadbeef" }},
		{"build_date", func(s *FollowerAppliedState) { s.BuildDate = "2099-01-01" }},
		{"last_policy_poll_at", func(s *FollowerAppliedState) { s.LastPolicyPollAt = testNow.Add(time.Hour) }},
		{"last_successful_apply_at", func(s *FollowerAppliedState) { s.LastSuccessfulApplyAt = testNow.Add(time.Hour) }},
		{"last_apply_error_code", func(s *FollowerAppliedState) { s.LastApplyErrorCode = "apply_failed" }},
		{"last_apply_error_message", func(s *FollowerAppliedState) { s.LastApplyErrorMessage = "boom" }},
		{"observed_at", func(s *FollowerAppliedState) { s.ObservedAt = testNow.Add(time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutState := testAppliedState()
			tc.mutate(&mutState)
			mut := base
			mut.AppliedState = &mutState
			pre, err := mut.SignablePreimage()
			if err != nil {
				t.Fatalf("SignablePreimage: %v", err)
			}
			if string(pre) == string(statePre) {
				t.Fatalf("preimage unchanged after mutating applied_state.%s", tc.name)
			}
		})
	}
}

// TestAuditBatchEnvelope_ValidateForConductor_AppliedStateObservedAt covers the
// fail-closed clock-skew gate on applied-state ObservedAt directly: a value
// within skew passes, and a future value beyond skew is rejected with
// ErrSkewExceeded even when EmittedAt itself is within skew.
func TestAuditBatchEnvelope_ValidateForConductor_AppliedStateObservedAt(t *testing.T) {
	t.Run("within_skew_passes", func(t *testing.T) {
		batch := testAuditBatch()
		batch.EmittedAt = testNow
		applied := testAppliedState()
		applied.ObservedAt = testNow
		batch.AppliedState = &applied
		if err := batch.ValidateForConductor(testNow, DefaultAuditMaxSkew); err != nil {
			t.Fatalf("ValidateForConductor() = %v, want nil", err)
		}
	})
	t.Run("future_observed_at_rejected", func(t *testing.T) {
		batch := testAuditBatch()
		batch.EmittedAt = testNow // keep EmittedAt in-skew so ObservedAt is the isolated cause
		applied := testAppliedState()
		applied.ObservedAt = testNow.Add(2 * DefaultAuditMaxSkew)
		batch.AppliedState = &applied
		if err := batch.ValidateForConductor(testNow, DefaultAuditMaxSkew); !errors.Is(err, ErrSkewExceeded) {
			t.Fatalf("ValidateForConductor() = %v, want ErrSkewExceeded for future observed_at", err)
		}
	})
}

// TestAuditBatchEnvelope_AppliedStateTamperBreaksSignature pins invariant #4:
// applied-state rides inside the signed preimage, so mutating it after signing
// makes VerifySignatures fail.
func TestAuditBatchEnvelope_AppliedStateTamperBreaksSignature(t *testing.T) {
	batch := testAuditBatch()
	applied := testAppliedState()
	batch.AppliedState = &applied
	pub, proof := signedProof(t, batch.SignablePreimage, "audit-signer-1", signing.PurposeAuditBatchSigning)
	batch.Signatures = []SignatureProof{proof}
	resolve := mapResolver(map[string]SignatureKey{
		"audit-signer-1": {PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning},
	})
	if err := batch.VerifySignaturesAt(testNow, resolve); err != nil {
		t.Fatalf("VerifySignatures on untampered applied-state = %v", err)
	}
	// Tamper: rewrite a field of the signed envelope's applied-state.
	batch.AppliedState.ActiveBundleHash = testHash("cd")
	if err := batch.VerifySignaturesAt(testNow, resolve); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("tampered applied-state VerifySignatures = %v, want ErrSignatureVerification", err)
	}
}

// TestAuditBatchEnvelope_AppliedStatePreimageUTC ensures applied-state
// timestamps canonicalize to UTC, so two producers in different timezones
// describing the same instant sign identical bytes.
func TestAuditBatchEnvelope_AppliedStatePreimageUTC(t *testing.T) {
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("timezone data unavailable: %v", err)
	}
	utcBatch := testAuditBatch()
	utcApplied := testAppliedState()
	utcBatch.AppliedState = &utcApplied

	jstBatch := testAuditBatch()
	jstApplied := testAppliedState()
	jstApplied.LastPolicyPollAt = jstApplied.LastPolicyPollAt.In(tokyo)
	jstApplied.LastSuccessfulApplyAt = jstApplied.LastSuccessfulApplyAt.In(tokyo)
	jstApplied.ObservedAt = jstApplied.ObservedAt.In(tokyo)
	jstBatch.AppliedState = &jstApplied

	preUTC, err := utcBatch.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(utc): %v", err)
	}
	preJST, err := jstBatch.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(jst): %v", err)
	}
	if string(preUTC) != string(preJST) {
		t.Fatalf("applied-state preimage diverged across timezones:\n%s\n%s", preUTC, preJST)
	}
	// SignablePreimage must not mutate the caller's applied-state pointer.
	if !jstApplied.ObservedAt.Equal(testNow) || jstApplied.ObservedAt.Location() == time.UTC {
		t.Fatalf("SignablePreimage mutated caller applied-state timestamp: %v", jstApplied.ObservedAt)
	}
}

// TestAuditBatchEnvelope_IdentityIsEnvelopeBound pins invariant #5: applied-state
// carries no identity of its own; the same applied-state under two different
// envelope identities yields different signed preimages, so identity cannot be
// spoofed from inside applied-state.
func TestAuditBatchEnvelope_IdentityIsEnvelopeBound(t *testing.T) {
	applied := testAppliedState()
	a := testAuditBatch()
	a.Signatures = nil
	a.AppliedState = &applied
	b := a
	b.InstanceID = "instance-2"
	preA, err := a.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(a): %v", err)
	}
	preB, err := b.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(b): %v", err)
	}
	if string(preA) == string(preB) {
		t.Fatal("envelope identity must bind the signed preimage")
	}
}
