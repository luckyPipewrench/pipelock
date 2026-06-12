//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var testNow = time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)

func TestPolicyBundle_SignablePreimageExcludesSignatures(t *testing.T) {
	a := testPolicyBundle()
	b := testPolicyBundle()
	b.Signatures[0].Signature = testSignature("ab")
	b.Signatures[0].SignerKeyID = "different-signer"

	preA, err := a.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(a): %v", err)
	}
	preB, err := b.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(b): %v", err)
	}
	if string(preA) != string(preB) {
		t.Fatalf("preimage changed when detached signatures changed:\na=%s\nb=%s", preA, preB)
	}
}

func TestPolicyBundle_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		if err := testPolicyBundle().Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("forbidden_license_field", func(t *testing.T) {
		b := testPolicyBundle()
		b.Payload.ConfigYAML = "mode: strict\nlicense_key: token\n"
		err := b.Validate()
		if !errors.Is(err, ErrForbiddenLicenseField) {
			t.Fatalf("Validate() = %v, want ErrForbiddenLicenseField", err)
		}
	})

	t.Run("wrong_signature_purpose", func(t *testing.T) {
		b := testPolicyBundle()
		b.Signatures[0].KeyPurpose = signing.PurposeRemoteKillSigning
		err := b.Validate()
		if !errors.Is(err, ErrWrongKeyPurpose) {
			t.Fatalf("Validate() = %v, want ErrWrongKeyPurpose", err)
		}
	})

	t.Run("audience_mismatch", func(t *testing.T) {
		b := testPolicyBundle()
		err := b.ValidateForFollower("org-test", "fleet-prod", "instance-other", map[string]string{"tier": "prod"})
		if !errors.Is(err, ErrAudienceMismatch) {
			t.Fatalf("ValidateForFollower() = %v, want ErrAudienceMismatch", err)
		}
	})

	t.Run("label_audience_match", func(t *testing.T) {
		b := testPolicyBundle()
		b.Audience = Audience{Labels: map[string]string{"tier": "prod"}}
		err := b.ValidateForFollower("org-test", "fleet-prod", "instance-other", map[string]string{"tier": "prod"})
		if err != nil {
			t.Fatalf("ValidateForFollower() = %v, want nil", err)
		}
	})

	t.Run("payload_hash_mismatch", func(t *testing.T) {
		b := testPolicyBundle()
		b.PayloadSHA256 = testHash("03")
		err := b.Validate()
		if !errors.Is(err, ErrHashMismatch) {
			t.Fatalf("Validate() = %v, want ErrHashMismatch", err)
		}
	})

	t.Run("policy_hash_mismatch", func(t *testing.T) {
		b := testPolicyBundle()
		b.PolicyHash = testHash("02")
		err := b.Validate()
		if !errors.Is(err, ErrHashMismatch) {
			t.Fatalf("Validate() = %v, want ErrHashMismatch", err)
		}
	})
}

func TestRemoteKillMessage_RequiresTwoDistinctSigners(t *testing.T) {
	msg := testRemoteKillMessage()
	if err := msg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	msg.Signatures = msg.Signatures[:1]
	err := msg.Validate()
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("Validate() = %v, want ErrThresholdRequired", err)
	}

	msg = testRemoteKillMessage()
	msg.Signatures[1].SignerKeyID = msg.Signatures[0].SignerKeyID
	err = msg.Validate()
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("Validate() duplicate signer = %v, want ErrThresholdRequired", err)
	}
}

func TestRollbackAuthorization_RequiresLowerTargetVersion(t *testing.T) {
	auth := testRollbackAuthorization()
	if err := auth.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	auth.TargetVersion = auth.CurrentVersion
	err := auth.Validate()
	if !errors.Is(err, ErrInvalidRollback) {
		t.Fatalf("Validate() = %v, want ErrInvalidRollback", err)
	}
}

func TestAuditBatchEnvelope_ValidateV2ChainAndForkDetection(t *testing.T) {
	batch := testAuditBatch()
	if err := batch.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	v1 := batch
	v1.Chain.EntryVersion = 1
	err := v1.Validate()
	if !errors.Is(err, ErrInvalidSequenceRange) {
		t.Fatalf("Validate() with v1 chain = %v, want ErrInvalidSequenceRange", err)
	}

	other := batch
	other.PayloadSHA256 = testHash("20")
	if !batch.ForksWith(other) {
		t.Fatal("ForksWith() = false for overlapping seq range with different payload hash")
	}

	nonOverlap := other
	nonOverlap.SeqStart = batch.SeqEnd + 1
	nonOverlap.SeqEnd = batch.SeqEnd + 10
	if batch.ForksWith(nonOverlap) {
		t.Fatal("ForksWith() = true for non-overlapping seq range")
	}
}

func TestAuditBatchEnvelope_DroppedAccounting(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		batch := testAuditBatch()
		batch.Dropped = DroppedAccounting{
			Count: 3,
			Reasons: []DroppedReason{
				{Reason: "queue_full", Count: 2},
				{Reason: "payload_too_large", Count: 1},
			},
		}
		if err := batch.Validate(); err != nil {
			t.Fatalf("Validate() = %v, want nil", err)
		}
	})

	t.Run("count_mismatch", func(t *testing.T) {
		batch := testAuditBatch()
		batch.Dropped = DroppedAccounting{
			Count:   3,
			Reasons: []DroppedReason{{Reason: "queue_full", Count: 2}},
		}
		err := batch.Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})

	t.Run("duplicate_reason", func(t *testing.T) {
		batch := testAuditBatch()
		batch.Dropped = DroppedAccounting{
			Count: 2,
			Reasons: []DroppedReason{
				{Reason: "queue_full", Count: 1},
				{Reason: "queue_full", Count: 1},
			},
		}
		err := batch.Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})
}

func TestCapabilitiesResponse_RequiresMTLSAndThresholds(t *testing.T) {
	caps := CapabilitiesResponse{
		SchemaVersion:          SchemaVersion,
		ConductorID:            "conductor-us-1",
		RequiredMTLS:           true,
		ConductorBundle:        SchemaRange{Min: 1, Max: 1},
		RemoteKill:             SchemaRange{Min: 1, Max: 1},
		RollbackAuthorization:  SchemaRange{Min: 1, Max: 1},
		AuditBatch:             SchemaRange{Min: 1, Max: 3},
		ReceiptEntryVersions:   []int{2},
		MaxCreatedSkewSeconds:  int(DefaultAuditMaxSkew / time.Second),
		EmergencyStream:        true,
		RemoteKillThreshold:    RequiredCatastrophicSigners,
		RollbackThreshold:      RequiredCatastrophicSigners,
		TrustRotationThreshold: RequiredCatastrophicSigners,
	}
	if err := caps.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	caps.RequiredMTLS = false
	err := caps.Validate()
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Validate() = %v, want ErrInvalidState", err)
	}

	caps = validCapabilitiesResponse()
	caps.ReceiptEntryVersions = []int{1}
	err = caps.Validate()
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Validate() without v2 receipt entries = %v, want ErrInvalidState", err)
	}

	caps = validCapabilitiesResponse()
	caps.MaxCreatedSkewSeconds = int(MaxAllowedAuditSkew/time.Second) + 1
	err = caps.Validate()
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("Validate() over skew cap = %v, want ErrSkewExceeded", err)
	}

	caps = validCapabilitiesResponse()
	caps.RemoteKill = SchemaRange{Min: 2, Max: 3}
	err = caps.Validate()
	if !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Validate() range excluding current schema = %v, want ErrInvalidState", err)
	}

	caps = validCapabilitiesResponse()
	caps.RemoteKillThreshold = MaxCapabilityThreshold + 1
	err = caps.Validate()
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("Validate() over local threshold cap = %v, want ErrThresholdRequired", err)
	}

	caps = validCapabilitiesResponse()
	caps.RemoteKillThreshold = MaxCapabilityThreshold + 1
	if err := caps.ValidateWithLocalThresholdCap(MaxCapabilityThreshold + 2); err != nil {
		t.Fatalf("ValidateWithLocalThresholdCap(custom cap) = %v, want nil", err)
	}
}

func TestPolicyBundle_VerifySignatures(t *testing.T) {
	bundle := testPolicyBundle()
	pub, proof := signedProof(t, bundle.SignablePreimage, "policy-signer-1", signing.PurposePolicyBundleSigning)
	bundle.Signatures = []SignatureProof{proof}
	resolver := mapResolver(map[string]SignatureKey{
		"policy-signer-1": {PublicKey: pub, KeyPurpose: signing.PurposePolicyBundleSigning},
	})

	if err := bundle.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}

	tampered := bundle
	tampered.PolicyHash = testHash("09")
	err := tampered.VerifySignatures(resolver)
	if !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("VerifySignatures(tampered) = %v, want ErrSignatureVerification", err)
	}

	err = bundle.VerifySignatures(mapResolver(map[string]SignatureKey{
		"policy-signer-1": {PublicKey: pub, KeyPurpose: signing.PurposeRemoteKillSigning},
	}))
	if !errors.Is(err, ErrWrongKeyPurpose) {
		t.Fatalf("VerifySignatures(wrong roster purpose) = %v, want ErrWrongKeyPurpose", err)
	}
}

func TestRemoteKillMessage_VerifySignaturesThreshold(t *testing.T) {
	msg := testRemoteKillMessage()
	pub1, proof1 := signedProof(t, msg.SignablePreimage, "kill-signer-1", signing.PurposeRemoteKillSigning)
	pub2, proof2 := signedProof(t, msg.SignablePreimage, "kill-signer-2", signing.PurposeRemoteKillSigning)
	msg.Signatures = []SignatureProof{proof1, proof2}
	resolver := mapResolver(map[string]SignatureKey{
		"kill-signer-1": {PublicKey: pub1, KeyPurpose: signing.PurposeRemoteKillSigning},
		"kill-signer-2": {PublicKey: pub2, KeyPurpose: signing.PurposeRemoteKillSigning},
	})

	if err := msg.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}

	msg.Signatures = []SignatureProof{proof1}
	err := msg.VerifySignatures(resolver)
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("VerifySignatures(one signer) = %v, want ErrThresholdRequired", err)
	}
}

func testPolicyBundle() PolicyBundle {
	payload := PolicyBundlePayload{
		ConfigYAML: "mode: strict\nmcp_tool_policy:\n  enabled: true\n",
		RuleBundles: []RuleBundleRef{{
			Name:    "official",
			Version: "2026.05.23",
			SHA256:  testHash("04"),
		}},
	}
	return PolicyBundle{
		SchemaVersion:      SchemaVersion,
		BundleID:           "bundle-0001",
		OrgID:              "org-test",
		FleetID:            "fleet-prod",
		Environment:        "prod",
		Audience:           Audience{InstanceIDs: []string{"instance-1"}},
		Version:            1,
		PreviousBundleHash: testHash("01"),
		CreatedAt:          testNow,
		NotBefore:          testNow.Add(-time.Minute),
		ExpiresAt:          testNow.Add(time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         mustPolicyHash(payload),
		PayloadSHA256:      mustPayloadHash(payload),
		Payload:            payload,
		Signatures: []SignatureProof{
			testProof("policy-signer-1", signing.PurposePolicyBundleSigning),
		},
	}
}

func validCapabilitiesResponse() CapabilitiesResponse {
	return CapabilitiesResponse{
		SchemaVersion:          SchemaVersion,
		ConductorID:            "conductor-us-1",
		RequiredMTLS:           true,
		ConductorBundle:        SchemaRange{Min: 1, Max: 1},
		RemoteKill:             SchemaRange{Min: 1, Max: 1},
		RollbackAuthorization:  SchemaRange{Min: 1, Max: 1},
		AuditBatch:             SchemaRange{Min: 1, Max: 3},
		ReceiptEntryVersions:   []int{2},
		MaxCreatedSkewSeconds:  int(DefaultAuditMaxSkew / time.Second),
		EmergencyStream:        true,
		RemoteKillThreshold:    RequiredCatastrophicSigners,
		RollbackThreshold:      RequiredCatastrophicSigners,
		TrustRotationThreshold: RequiredCatastrophicSigners,
	}
}

func testRemoteKillMessage() RemoteKillMessage {
	return RemoteKillMessage{
		SchemaVersion: SchemaVersion,
		MessageID:     "kill-0001",
		OrgID:         "org-test",
		FleetID:       "fleet-prod",
		Audience:      Audience{InstanceIDs: []string{"*"}},
		State:         KillSwitchActive,
		Counter:       42,
		Reason:        "incident",
		CreatedAt:     testNow,
		NotBefore:     testNow.Add(-time.Minute),
		ExpiresAt:     testNow.Add(5 * time.Minute),
		Signatures: []SignatureProof{
			testProof("kill-signer-1", signing.PurposeRemoteKillSigning),
			testProof("kill-signer-2", signing.PurposeRemoteKillSigning),
		},
	}
}

func testRollbackAuthorization() RollbackAuthorization {
	return RollbackAuthorization{
		SchemaVersion:   SchemaVersion,
		AuthorizationID: "rollback-0001",
		OrgID:           "org-test",
		FleetID:         "fleet-prod",
		CurrentBundleID: "bundle-0002",
		CurrentVersion:  2,
		TargetBundleID:  "bundle-0001",
		TargetVersion:   1,
		Counter:         5,
		Reason:          "bad bundle",
		CreatedAt:       testNow,
		ExpiresAt:       testNow.Add(10 * time.Minute),
		Signatures: []SignatureProof{
			testProof("rollback-signer-1", signing.PurposePolicyBundleRollback),
			testProof("rollback-signer-2", signing.PurposePolicyBundleRollback),
		},
	}
}

func testAuditBatch() AuditBatchEnvelope {
	payload := testAuditPayload()
	return AuditBatchEnvelope{
		SchemaVersion:      SchemaVersion,
		BatchID:            "audit-batch-0001",
		OrgID:              "org-test",
		FleetID:            "fleet-prod",
		InstanceID:         "instance-1",
		AuditSchemaVersion: 2,
		EmittedAt:          testNow,
		SeqStart:           10,
		SeqEnd:             20,
		EventCount:         11,
		PayloadSHA256:      testBytesHash(payload),
		PayloadBytes:       uint64(len(payload)),
		Chain: EvidenceChain{
			EntryVersion:           2,
			SegmentID:              "segment-1",
			SeqStart:               10,
			SeqEnd:                 20,
			PreviousSegmentTail:    testHash("11"),
			SegmentHeadHash:        testHash("12"),
			SegmentTailHash:        testHash("13"),
			CheckpointSeq:          20,
			CheckpointHash:         testHash("14"),
			CheckpointSignature:    testSignature("15"),
			CheckpointSignerKeyID:  "recorder-signer-1",
			FollowerRecorderKeyID:  "recorder-key-1",
			FollowerRecorderPubHex: strings.Repeat("16", 32),
		},
		Signatures: []SignatureProof{
			testProof("instance-audit-signer-1", signing.PurposeAuditBatchSigning),
		},
	}
}

func TestPolicyBundle_PreimageStableAcrossTimezones(t *testing.T) {
	// Two bundles that describe the same logical instant but in different
	// timezones must produce identical canonical preimages. Without the
	// UTC normalization in SignablePreimage, Go's default time.Time JSON
	// marshal embeds the source zone offset and the signed bytes diverge.
	utc := testPolicyBundle()
	utc.CreatedAt = utc.CreatedAt.UTC()
	utc.NotBefore = utc.NotBefore.UTC()
	utc.ExpiresAt = utc.ExpiresAt.UTC()

	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("timezone data unavailable: %v", err)
	}
	jst := testPolicyBundle()
	jst.CreatedAt = jst.CreatedAt.In(tokyo)
	jst.NotBefore = jst.NotBefore.In(tokyo)
	jst.ExpiresAt = jst.ExpiresAt.In(tokyo)

	preUTC, err := utc.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(utc): %v", err)
	}
	preJST, err := jst.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(jst): %v", err)
	}
	if string(preUTC) != string(preJST) {
		t.Fatalf("preimage diverged across timezones:\nutc=%s\njst=%s", preUTC, preJST)
	}
}

func TestPolicyBundle_PreimageChangesWithPolicyFields(t *testing.T) {
	// Detached-signature stability is one half of the contract; the other
	// half is that changing actual policy content MUST change the preimage.
	// A regression that drops a field from the canonicalization (refactor,
	// json tag change, etc.) silently breaks the entire signing chain.
	base := testPolicyBundle()
	basePre, err := base.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage(base): %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PolicyBundle)
	}{
		{"min_pipelock_version", func(b *PolicyBundle) { b.MinPipelockVersion = "9.9.9" }},
		{"previous_bundle_hash", func(b *PolicyBundle) { b.PreviousBundleHash = testHash("ff") }},
		{"environment", func(b *PolicyBundle) { b.Environment = "staging" }},
		{"audience_instance", func(b *PolicyBundle) { b.Audience = Audience{InstanceIDs: []string{"instance-other"}} }},
		{"version", func(b *PolicyBundle) { b.Version = 999 }},
		{"config_yaml", func(b *PolicyBundle) { b.Payload.ConfigYAML = "mode: balanced\n" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mut := testPolicyBundle()
			tc.mutate(&mut)
			pre, err := mut.SignablePreimage()
			if err != nil {
				t.Fatalf("SignablePreimage: %v", err)
			}
			if string(pre) == string(basePre) {
				t.Fatalf("preimage unchanged after mutating %s — field is missing from canonicalization", tc.name)
			}
		})
	}
}

func TestPolicyBundle_RejectsNestedLicenseField(t *testing.T) {
	// Shallow rejection misses license keys smuggled under agents.<name>
	// or any other submap. The recursive walker must surface the full path.
	b := testPolicyBundle()
	b.Payload.ConfigYAML = "mode: strict\nagents:\n  claude-code:\n    license_key: smuggled\n"
	err := b.Validate()
	if !errors.Is(err, ErrForbiddenLicenseField) {
		t.Fatalf("Validate() = %v, want ErrForbiddenLicenseField", err)
	}
	if !strings.Contains(err.Error(), "agents.claude-code.license_key") {
		t.Fatalf("error should name nested path; got %v", err)
	}
}

func TestPolicyBundle_RequiresMinPipelockVersion(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		b := testPolicyBundle()
		b.MinPipelockVersion = ""
		err := b.Validate()
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		b := testPolicyBundle()
		b.MinPipelockVersion = "1.2"
		err := b.Validate()
		if !errors.Is(err, ErrInvalidMinVersion) {
			t.Fatalf("Validate() = %v, want ErrInvalidMinVersion", err)
		}
	})
	t.Run("non_numeric_component", func(t *testing.T) {
		b := testPolicyBundle()
		b.MinPipelockVersion = "1.2.beta"
		err := b.Validate()
		if !errors.Is(err, ErrInvalidMinVersion) {
			t.Fatalf("Validate() = %v, want ErrInvalidMinVersion", err)
		}
	})
	t.Run("leading_zero_component", func(t *testing.T) {
		b := testPolicyBundle()
		b.MinPipelockVersion = "1.02.3"
		err := b.Validate()
		if !errors.Is(err, ErrInvalidMinVersion) {
			t.Fatalf("Validate() = %v, want ErrInvalidMinVersion", err)
		}
	})
}

func TestPolicyBundle_ConfigYAMLSizeCap(t *testing.T) {
	b := testPolicyBundle()
	b.Payload.ConfigYAML = "mode: strict\n" + strings.Repeat("# noise\n", MaxConfigYAMLBytes)
	err := b.Validate()
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Validate() = %v, want ErrPayloadTooLarge", err)
	}
}

func TestPolicyBundle_ValidateAtTime(t *testing.T) {
	b := testPolicyBundle()
	// Inside window passes.
	if err := b.ValidateAtTime(testNow); err != nil {
		t.Fatalf("ValidateAtTime(inside) = %v, want nil", err)
	}
	// Before NotBefore → ErrNotYetValid.
	err := b.ValidateAtTime(b.NotBefore.Add(-time.Hour))
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("ValidateAtTime(before) = %v, want ErrNotYetValid", err)
	}
	// After ExpiresAt → ErrExpired.
	err = b.ValidateAtTime(b.ExpiresAt.Add(time.Hour))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("ValidateAtTime(after) = %v, want ErrExpired", err)
	}
}

func TestRemoteKillMessage_ValidateAtTimeAndReasonCap(t *testing.T) {
	m := testRemoteKillMessage()
	if err := m.ValidateAtTime(testNow); err != nil {
		t.Fatalf("ValidateAtTime(inside) = %v, want nil", err)
	}
	err := m.ValidateAtTime(m.ExpiresAt.Add(time.Minute))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("ValidateAtTime(after) = %v, want ErrExpired", err)
	}

	oversized := testRemoteKillMessage()
	oversized.Reason = strings.Repeat("x", MaxReasonBytes+1)
	if err := oversized.Validate(); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("Validate(oversized reason) = %v, want ErrPayloadTooLarge", err)
	}

	control := testRemoteKillMessage()
	control.Reason = "incident\nsecond-line"
	if err := control.Validate(); !errors.Is(err, ErrInvalidReason) {
		t.Fatalf("Validate(control reason) = %v, want ErrInvalidReason", err)
	}
}

func TestRollbackAuthorization_ValidateAtTime(t *testing.T) {
	r := testRollbackAuthorization()
	if err := r.ValidateAtTime(testNow); err != nil {
		t.Fatalf("ValidateAtTime(inside) = %v, want nil", err)
	}
	err := r.ValidateAtTime(r.ExpiresAt.Add(time.Second))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("ValidateAtTime(after) = %v, want ErrExpired", err)
	}
}

func TestAuditBatchEnvelope_ValidateForConductorSkew(t *testing.T) {
	batch := testAuditBatch()
	// Inside default skew.
	if err := batch.ValidateForConductor(testNow.Add(30*time.Second), DefaultAuditMaxSkew); err != nil {
		t.Fatalf("ValidateForConductor(inside) = %v, want nil", err)
	}
	// Past default skew → ErrSkewExceeded.
	err := batch.ValidateForConductor(testNow.Add(2*time.Minute), DefaultAuditMaxSkew)
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateForConductor(past) = %v, want ErrSkewExceeded", err)
	}
	// Future emission > skew (clock drift) → ErrSkewExceeded.
	err = batch.ValidateForConductor(testNow.Add(-2*time.Minute), DefaultAuditMaxSkew)
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateForConductor(future) = %v, want ErrSkewExceeded", err)
	}
	// Operator misconfig > MaxAllowedAuditSkew → ErrSkewExceeded.
	err = batch.ValidateForConductor(testNow, MaxAllowedAuditSkew+time.Second)
	if !errors.Is(err, ErrSkewExceeded) {
		t.Fatalf("ValidateForConductor(over-cap config) = %v, want ErrSkewExceeded", err)
	}
}

func TestAuditBatchEnvelope_ValidateForConductorWithPayload(t *testing.T) {
	batch := testAuditBatch()
	payload := testAuditPayload()
	if err := batch.ValidateForConductorWithPayload(testNow, DefaultAuditMaxSkew, payload); err != nil {
		t.Fatalf("ValidateForConductorWithPayload(valid) = %v, want nil", err)
	}

	err := batch.ValidateForConductorWithPayload(testNow, DefaultAuditMaxSkew, append(payload, 'x'))
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("ValidateForConductorWithPayload(size mismatch) = %v, want ErrHashMismatch", err)
	}

	sameSizeDifferentHash := append([]byte(nil), payload...)
	sameSizeDifferentHash[0] ^= 0x01
	err = batch.ValidateForConductorWithPayload(testNow, DefaultAuditMaxSkew, sameSizeDifferentHash)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("ValidateForConductorWithPayload(hash mismatch) = %v, want ErrHashMismatch", err)
	}
}

func TestAuditBatchEnvelope_PayloadBytesClassification(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		batch := testAuditBatch()
		batch.PayloadBytes = 0
		err := batch.Validate()
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField", err)
		}
	})

	t.Run("too_large", func(t *testing.T) {
		batch := testAuditBatch()
		batch.PayloadBytes = MaxAuditPayloadBytes + 1
		err := batch.Validate()
		if !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("Validate() = %v, want ErrPayloadTooLarge", err)
		}
	})
}

func TestAudience_RejectsMixedWildcard(t *testing.T) {
	a := Audience{InstanceIDs: []string{"*", "instance-1"}}
	err := a.Validate()
	if !errors.Is(err, ErrInvalidAudienceWildcard) {
		t.Fatalf("Validate() = %v, want ErrInvalidAudienceWildcard", err)
	}
	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("Validate() = %v, want ErrInvalidAudience classification", err)
	}
	// Pure wildcard still passes.
	if err := (Audience{InstanceIDs: []string{"*"}}).Validate(); err != nil {
		t.Fatalf("Validate(pure wildcard) = %v, want nil", err)
	}
}

func TestAudience_RejectsMixedSelectorTypes(t *testing.T) {
	a := Audience{
		InstanceIDs: []string{"instance-1"},
		Labels:      map[string]string{"ring": "canary"},
	}
	err := a.Validate()
	if !errors.Is(err, ErrInvalidAudienceSelectors) {
		t.Fatalf("Validate() = %v, want ErrInvalidAudienceSelectors", err)
	}
	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("Validate() = %v, want ErrInvalidAudience classification", err)
	}
}

func TestIsIdentifierRejectsEmpty(t *testing.T) {
	if isIdentifier("") {
		t.Fatal("isIdentifier(empty) = true, want false")
	}
}

func TestValidateIdentifierExport(t *testing.T) {
	if err := ValidateIdentifier("org_id", "org-main"); err != nil {
		t.Fatalf("ValidateIdentifier(valid) error = %v", err)
	}
	if err := ValidateIdentifier("org_id", "-org"); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("ValidateIdentifier(invalid) error = %v, want ErrInvalidIdentifier", err)
	}
}

func TestRemoteKillMessage_RejectsSamePublicKeyAcrossSignerIDs(t *testing.T) {
	// A roster that maps two distinct IDs to the same public key would
	// otherwise satisfy threshold with one underlying signer. This is the
	// exact failure mode the catastrophic-threshold rule exists to prevent.
	msg := testRemoteKillMessage()
	pub, proof1 := signedProof(t, msg.SignablePreimage, "kill-signer-A", signing.PurposeRemoteKillSigning)
	_, proof2 := signedProof(t, msg.SignablePreimage, "kill-signer-B", signing.PurposeRemoteKillSigning)
	// Force proof2's signature to a valid sig produced by pub by re-signing
	// is not possible without the priv key; instead simulate the roster
	// trick: both IDs map to the SAME pub. Use proof1's signature for both
	// IDs so verification passes per-signature.
	proof2.Signature = proof1.Signature
	msg.Signatures = []SignatureProof{proof1, proof2}

	resolver := mapResolver(map[string]SignatureKey{
		"kill-signer-A": {PublicKey: pub, KeyPurpose: signing.PurposeRemoteKillSigning},
		"kill-signer-B": {PublicKey: pub, KeyPurpose: signing.PurposeRemoteKillSigning},
	})
	err := msg.VerifySignaturesAt(testNow, resolver)
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("VerifySignaturesAt(same pubkey under different IDs) = %v, want ErrThresholdRequired", err)
	}
}

func TestPolicyBundle_VerifySignaturesRejectsRevokedAndExpiredRoster(t *testing.T) {
	bundle := testPolicyBundle()
	pub, proof := signedProof(t, bundle.SignablePreimage, "policy-signer-1", signing.PurposePolicyBundleSigning)
	bundle.Signatures = []SignatureProof{proof}

	t.Run("revoked", func(t *testing.T) {
		revoked := testNow.Add(-time.Hour)
		resolver := mapResolver(map[string]SignatureKey{
			"policy-signer-1": {
				PublicKey:  pub,
				KeyPurpose: signing.PurposePolicyBundleSigning,
				RevokedAt:  &revoked,
			},
		})
		err := bundle.VerifySignaturesAt(testNow, resolver)
		if !errors.Is(err, ErrSignatureVerification) {
			t.Fatalf("VerifySignaturesAt(revoked) = %v, want ErrSignatureVerification", err)
		}
	})

	t.Run("not_yet_valid", func(t *testing.T) {
		resolver := mapResolver(map[string]SignatureKey{
			"policy-signer-1": {
				PublicKey:  pub,
				KeyPurpose: signing.PurposePolicyBundleSigning,
				NotBefore:  testNow.Add(time.Hour),
			},
		})
		err := bundle.VerifySignaturesAt(testNow, resolver)
		if !errors.Is(err, ErrNotYetValid) {
			t.Fatalf("VerifySignaturesAt(not yet valid) = %v, want ErrNotYetValid", err)
		}
	})

	t.Run("expired_key", func(t *testing.T) {
		resolver := mapResolver(map[string]SignatureKey{
			"policy-signer-1": {
				PublicKey:  pub,
				KeyPurpose: signing.PurposePolicyBundleSigning,
				NotAfter:   testNow.Add(-time.Hour),
			},
		})
		err := bundle.VerifySignaturesAt(testNow, resolver)
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("VerifySignaturesAt(expired) = %v, want ErrExpired", err)
		}
	})

	t.Run("nil_resolver", func(t *testing.T) {
		err := bundle.VerifySignaturesAt(testNow, nil)
		if !errors.Is(err, ErrSignatureVerification) {
			t.Fatalf("VerifySignaturesAt(nil resolver) = %v, want ErrSignatureVerification", err)
		}
	})
}

func TestDroppedAccounting_OverflowGuard(t *testing.T) {
	// Crafted Reason.Count values whose sum wraps uint64 back to d.Count
	// would otherwise pass the count==total equality check.
	d := DroppedAccounting{
		Count: 5,
		Reasons: []DroppedReason{
			{Reason: "queue_full", Count: math.MaxUint64 - 4},
			{Reason: "payload_too_large", Count: 10}, // sum wraps to 5
		},
	}
	err := d.Validate()
	if !errors.Is(err, ErrInvalidDroppedAccounting) {
		t.Fatalf("Validate(overflow) = %v, want ErrInvalidDroppedAccounting", err)
	}
}

func TestMessageIdentifiersAreBounded(t *testing.T) {
	b := testPolicyBundle()
	b.BundleID = "bad id with spaces"
	err := b.Validate()
	if !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("Validate() = %v, want ErrInvalidIdentifier", err)
	}

	b = testPolicyBundle()
	b.BundleID = strings.Repeat("a", MaxIDBytes+1)
	err = b.Validate()
	if !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("Validate(long id) = %v, want ErrInvalidIdentifier", err)
	}
}

func TestPolicyBundlePayload_PolicyHashYAMLDocumentHandling(t *testing.T) {
	payload := PolicyBundlePayload{ConfigYAML: "mode: strict\n---\n"}
	if _, err := payload.PolicyHash(); err != nil {
		t.Fatalf("PolicyHash(empty trailing doc) = %v, want nil", err)
	}

	payload.ConfigYAML = "mode: strict\n---\nmode: balanced\n"
	_, err := payload.PolicyHash()
	if !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("PolicyHash(non-empty trailing doc) = %v, want ErrInvalidHash", err)
	}

	payload.ConfigYAML = "mode: [\n"
	if _, err := payload.PolicyHash(); err == nil {
		t.Fatal("PolicyHash(malformed yaml) = nil, want error")
	}
}

func TestCanonicalHashMethods(t *testing.T) {
	if got, err := testPolicyBundle().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("PolicyBundle.CanonicalHash() = %q, %v; want hash", got, err)
	}
	if got, err := testRemoteKillMessage().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("RemoteKillMessage.CanonicalHash() = %q, %v; want hash", got, err)
	}
	if got, err := testRollbackAuthorization().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("RollbackAuthorization.CanonicalHash() = %q, %v; want hash", got, err)
	}
	if got, err := testAuditBatch().CanonicalHash(); err != nil || got == "" {
		t.Fatalf("AuditBatchEnvelope.CanonicalHash() = %q, %v; want hash", got, err)
	}
}

func TestRemoteKillMessage_ValidateForFollower(t *testing.T) {
	msg := testRemoteKillMessage()
	if err := msg.ValidateForFollower("org-test", "fleet-prod", "instance-1", nil); err != nil {
		t.Fatalf("ValidateForFollower(wildcard) = %v, want nil", err)
	}
	if err := msg.ValidateForFollower("org-other", "fleet-prod", "instance-1", nil); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("ValidateForFollower(org mismatch) = %v, want ErrAudienceMismatch", err)
	}

	msg.Audience = Audience{Labels: map[string]string{"ring": "canary"}}
	if err := msg.ValidateForFollower("org-test", "fleet-prod", "instance-2", map[string]string{"ring": "canary"}); err != nil {
		t.Fatalf("ValidateForFollower(label match) = %v, want nil", err)
	}
	if err := msg.ValidateForFollower("org-test", "fleet-prod", "instance-2", map[string]string{"ring": "prod"}); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("ValidateForFollower(label mismatch) = %v, want ErrAudienceMismatch", err)
	}
}

func TestRollbackAuthorization_VerifySignatures(t *testing.T) {
	auth := testRollbackAuthorization()
	pub1, proof1 := signedProof(t, auth.SignablePreimage, "rollback-signer-1", signing.PurposePolicyBundleRollback)
	pub2, proof2 := signedProof(t, auth.SignablePreimage, "rollback-signer-2", signing.PurposePolicyBundleRollback)
	auth.Signatures = []SignatureProof{proof1, proof2}
	resolver := mapResolver(map[string]SignatureKey{
		"rollback-signer-1": {PublicKey: pub1, KeyPurpose: signing.PurposePolicyBundleRollback},
		"rollback-signer-2": {PublicKey: pub2, KeyPurpose: signing.PurposePolicyBundleRollback},
	})
	if err := auth.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}

	auth.TargetBundleID = "bundle-other"
	if err := auth.VerifySignaturesAt(testNow, resolver); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("VerifySignaturesAt(tampered) = %v, want ErrSignatureVerification", err)
	}
}

func TestAuditBatchEnvelope_VerifySignatures(t *testing.T) {
	batch := testAuditBatch()
	pub, proof := signedProof(t, batch.SignablePreimage, "audit-signer-1", signing.PurposeAuditBatchSigning)
	batch.Signatures = []SignatureProof{proof}
	resolver := mapResolver(map[string]SignatureKey{
		"audit-signer-1": {PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning},
	})
	if err := batch.VerifySignatures(resolver); err != nil {
		t.Fatalf("VerifySignatures() = %v, want nil", err)
	}

	batch.PayloadBytes++
	if err := batch.VerifySignaturesAt(testNow, resolver); !errors.Is(err, ErrSignatureVerification) {
		t.Fatalf("VerifySignaturesAt(tampered) = %v, want ErrSignatureVerification", err)
	}
}

func TestValidationEdgeCases(t *testing.T) {
	t.Run("signature_proof_missing_signer", func(t *testing.T) {
		err := (SignatureProof{KeyPurpose: signing.PurposePolicyBundleSigning, Algorithm: SignatureAlgorithmEd25519, Signature: testSignature("aa")}).
			Validate(signing.PurposePolicyBundleSigning)
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField", err)
		}
	})

	t.Run("signature_proof_bad_algorithm", func(t *testing.T) {
		proof := testProof("signer-1", signing.PurposePolicyBundleSigning)
		proof.Algorithm = "ecdsa"
		err := proof.Validate(signing.PurposePolicyBundleSigning)
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("Validate() = %v, want ErrInvalidSignature", err)
		}
	})

	t.Run("dropped_reasons_with_zero_count", func(t *testing.T) {
		err := (DroppedAccounting{Reasons: []DroppedReason{{Reason: "queue_full", Count: 1}}}).Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})

	t.Run("dropped_count_without_reasons", func(t *testing.T) {
		err := (DroppedAccounting{Count: 1}).Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})

	t.Run("dropped_reason_invalid_identifier", func(t *testing.T) {
		err := (DroppedReason{Reason: "bad reason", Count: 1}).Validate()
		if !errors.Is(err, ErrInvalidDroppedAccounting) {
			t.Fatalf("Validate() = %v, want ErrInvalidDroppedAccounting", err)
		}
	})

	t.Run("rule_bundle_missing_version", func(t *testing.T) {
		err := (RuleBundleRef{Name: "official", SHA256: testHash("04")}).Validate()
		if !errors.Is(err, ErrMissingField) {
			t.Fatalf("Validate() = %v, want ErrMissingField", err)
		}
	})

	t.Run("evidence_chain_checkpoint_out_of_range", func(t *testing.T) {
		chain := testAuditBatch().Chain
		chain.CheckpointSeq = chain.SeqEnd + 1
		err := chain.Validate(chain.SeqStart, chain.SeqEnd)
		if !errors.Is(err, ErrInvalidSequenceRange) {
			t.Fatalf("Validate() = %v, want ErrInvalidSequenceRange", err)
		}
	})

	t.Run("invalid_signature_string_prefix", func(t *testing.T) {
		err := validateEd25519SignatureString("bad:" + strings.Repeat("aa", 64))
		if !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("validateEd25519SignatureString() = %v, want ErrInvalidSignature", err)
		}
	})

	t.Run("invalid_public_key_hex", func(t *testing.T) {
		err := validatePublicKeyHex("pub", "ff")
		if !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("validatePublicKeyHex() = %v, want ErrInvalidHash", err)
		}
	})
}

func TestRemoteKillMessage_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RemoteKillMessage)
		want error
	}{
		{"unsupported_schema", func(m *RemoteKillMessage) { m.SchemaVersion = 99 }, ErrUnsupportedSchemaVersion},
		{"missing_message_id", func(m *RemoteKillMessage) { m.MessageID = "" }, ErrMissingField},
		{"missing_org", func(m *RemoteKillMessage) { m.OrgID = "" }, ErrMissingField},
		{"empty_audience", func(m *RemoteKillMessage) { m.Audience = Audience{} }, ErrInvalidAudience},
		{"invalid_state", func(m *RemoteKillMessage) { m.State = "paused" }, ErrInvalidState},
		{"missing_counter", func(m *RemoteKillMessage) { m.Counter = 0 }, ErrMissingField},
		{"invalid_window", func(m *RemoteKillMessage) { m.ExpiresAt = m.NotBefore }, ErrInvalidValidityWindow},
		{"missing_created_at", func(m *RemoteKillMessage) { m.CreatedAt = time.Time{} }, ErrMissingField},
		{"invalid_utf8_reason", func(m *RemoteKillMessage) { m.Reason = string([]byte{0xff}) }, ErrInvalidReason},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := testRemoteKillMessage()
			tt.edit(&msg)
			if err := msg.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRollbackAuthorization_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*RollbackAuthorization)
		want error
	}{
		{"unsupported_schema", func(r *RollbackAuthorization) { r.SchemaVersion = 99 }, ErrUnsupportedSchemaVersion},
		{"missing_authorization_id", func(r *RollbackAuthorization) { r.AuthorizationID = "" }, ErrMissingField},
		{"missing_fleet", func(r *RollbackAuthorization) { r.FleetID = "" }, ErrMissingField},
		{"missing_current_bundle", func(r *RollbackAuthorization) { r.CurrentBundleID = "" }, ErrMissingField},
		{"missing_target_bundle", func(r *RollbackAuthorization) { r.TargetBundleID = "" }, ErrMissingField},
		{"missing_counter", func(r *RollbackAuthorization) { r.Counter = 0 }, ErrMissingField},
		{"invalid_validity", func(r *RollbackAuthorization) { r.ExpiresAt = r.CreatedAt }, ErrInvalidValidityWindow},
		{"control_reason", func(r *RollbackAuthorization) { r.Reason = "bad\tbundle" }, ErrInvalidReason},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := testRollbackAuthorization()
			tt.edit(&auth)
			if err := auth.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRollbackAuthorization_ValidateToleratesLegacyAudience(t *testing.T) {
	for _, audience := range []Audience{
		{InstanceIDs: []string{"instance-1"}},
		{Labels: map[string]string{"tier": "prod"}},
	} {
		auth := testRollbackAuthorization()
		auth.Audience = audience
		if err := auth.Validate(); err != nil {
			t.Fatalf("Validate() with audience %+v error = %v, want nil", audience, err)
		}
	}
}

func TestAuditBatchEnvelope_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*AuditBatchEnvelope)
		want error
	}{
		{"unsupported_schema", func(a *AuditBatchEnvelope) { a.SchemaVersion = 99 }, ErrUnsupportedSchemaVersion},
		{"missing_batch_id", func(a *AuditBatchEnvelope) { a.BatchID = "" }, ErrMissingField},
		{"missing_instance_id", func(a *AuditBatchEnvelope) { a.InstanceID = "" }, ErrMissingField},
		{"missing_audit_schema", func(a *AuditBatchEnvelope) { a.AuditSchemaVersion = 0 }, ErrMissingField},
		{"missing_emitted_at", func(a *AuditBatchEnvelope) { a.EmittedAt = time.Time{} }, ErrMissingField},
		{"invalid_seq", func(a *AuditBatchEnvelope) { a.SeqEnd = a.SeqStart - 1 }, ErrInvalidSequenceRange},
		{"missing_event_count", func(a *AuditBatchEnvelope) { a.EventCount = 0 }, ErrMissingField},
		{"invalid_payload_hash", func(a *AuditBatchEnvelope) { a.PayloadSHA256 = "not-hex" }, ErrInvalidHash},
		{"invalid_dropped", func(a *AuditBatchEnvelope) { a.Dropped = DroppedAccounting{Count: 1} }, ErrInvalidDroppedAccounting},
		{"invalid_chain", func(a *AuditBatchEnvelope) { a.Chain.SeqEnd++ }, ErrInvalidSequenceRange},
		{"missing_signatures", func(a *AuditBatchEnvelope) { a.Signatures = nil }, ErrThresholdRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch := testAuditBatch()
			tt.edit(&batch)
			if err := batch.Validate(); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestEvidenceChain_ValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		edit func(*EvidenceChain)
		want error
	}{
		{"wrong_entry_version", func(c *EvidenceChain) { c.EntryVersion = 3 }, ErrInvalidSequenceRange},
		{"missing_segment", func(c *EvidenceChain) { c.SegmentID = "" }, ErrMissingField},
		{"seq_mismatch", func(c *EvidenceChain) { c.SeqStart++ }, ErrInvalidSequenceRange},
		{"bad_hash", func(c *EvidenceChain) { c.CheckpointHash = "bad" }, ErrInvalidHash},
		{"bad_previous_tail", func(c *EvidenceChain) { c.PreviousSegmentTail = "bad" }, ErrInvalidHash},
		{"bad_checkpoint_signature", func(c *EvidenceChain) { c.CheckpointSignature = "bad" }, ErrInvalidSignature},
		{"missing_checkpoint_key", func(c *EvidenceChain) { c.CheckpointSignerKeyID = "" }, ErrMissingField},
		{"missing_recorder_key", func(c *EvidenceChain) { c.FollowerRecorderKeyID = "" }, ErrMissingField},
		{"bad_recorder_pub", func(c *EvidenceChain) { c.FollowerRecorderPubHex = "bad" }, ErrInvalidHash},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := testAuditBatch().Chain
			tt.edit(&chain)
			if err := chain.Validate(10, 20); !errors.Is(err, tt.want) {
				t.Fatalf("Validate() = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAudienceAndLabelValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		aud  Audience
	}{
		{"empty_instance", Audience{InstanceIDs: []string{""}}},
		{"bad_instance", Audience{InstanceIDs: []string{"-bad"}}},
		{"empty_label_value", Audience{Labels: map[string]string{"ring": ""}}},
		{"long_label_key", Audience{Labels: map[string]string{strings.Repeat("a", MaxLabelKeyBytes+1): "v"}}},
		{"long_label_value", Audience{Labels: map[string]string{"ring": strings.Repeat("a", MaxLabelValueBytes+1)}}},
		{"bad_label_identifier", Audience{Labels: map[string]string{"-ring": "canary"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.aud.Validate(); !errors.Is(err, ErrInvalidAudience) {
				t.Fatalf("Validate() = %v, want ErrInvalidAudience", err)
			}
		})
	}
}

func TestRejectLicenseFieldsYAMLDocumentHandling(t *testing.T) {
	if err := rejectLicenseFields(""); !errors.Is(err, ErrForbiddenLicenseField) {
		t.Fatalf("rejectLicenseFields(empty) = %v, want ErrForbiddenLicenseField", err)
	}
	if err := rejectLicenseFields("mode: strict\n---\n"); err != nil {
		t.Fatalf("rejectLicenseFields(empty trailing doc) = %v, want nil", err)
	}
	if err := rejectLicenseFields("mode: strict\n---\nmode: balanced\n"); !errors.Is(err, ErrForbiddenLicenseField) {
		t.Fatalf("rejectLicenseFields(non-empty trailing doc) = %v, want ErrForbiddenLicenseField", err)
	}
	if err := rejectLicenseFields("mode: [\n"); !errors.Is(err, ErrForbiddenLicenseField) {
		t.Fatalf("rejectLicenseFields(malformed) = %v, want ErrForbiddenLicenseField", err)
	}
}

func testProof(keyID string, purpose signing.KeyPurpose) SignatureProof {
	return SignatureProof{
		SignerKeyID: keyID,
		KeyPurpose:  purpose,
		Algorithm:   SignatureAlgorithmEd25519,
		Signature:   testSignature("aa"),
	}
}

func signedProof(
	t *testing.T,
	preimage func() ([]byte, error),
	keyID string,
	purpose signing.KeyPurpose,
) (ed25519.PublicKey, SignatureProof) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg, err := preimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	sig := ed25519.Sign(priv, msg)
	return pub, SignatureProof{
		SignerKeyID: keyID,
		KeyPurpose:  purpose,
		Algorithm:   SignatureAlgorithmEd25519,
		Signature:   SignaturePrefixEd25519 + hex.EncodeToString(sig),
	}
}

func mapResolver(keys map[string]SignatureKey) SignatureKeyResolver {
	return func(signerKeyID string) (SignatureKey, error) {
		key, ok := keys[signerKeyID]
		if !ok {
			return SignatureKey{}, ErrSignatureVerification
		}
		return key, nil
	}
}

func mustPayloadHash(payload PolicyBundlePayload) string {
	hash, err := payload.PayloadHash()
	if err != nil {
		panic(err)
	}
	return hash
}

func mustPolicyHash(payload PolicyBundlePayload) string {
	hash, err := payload.PolicyHash()
	if err != nil {
		panic(err)
	}
	return hash
}

func testAuditPayload() []byte {
	return []byte(`{"events":[{"seq":10,"kind":"scan","verdict":"allow"},{"seq":11,"kind":"scan","verdict":"block"}]}`)
}

func testBytesHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func testHash(seed string) string {
	return strings.Repeat(seed, 32)
}

func testSignature(seed string) string {
	return SignaturePrefixEd25519 + strings.Repeat(seed, 64)
}
