// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	proxydecision "github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type v2ByteVerifyRecorder struct {
	entries []recorder.Entry
}

func (r *v2ByteVerifyRecorder) Record(entry recorder.Entry) error {
	r.entries = append(r.entries, entry)
	return nil
}

func TestVerifyV2BytesWithKey_AcceptsRealProxyDecisionEmitterBytes(t *testing.T) {
	t.Parallel()

	seed := sha256.Sum256([]byte("v2 byte verifier real emitter signer"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	signer := proxydecision.NewKeyedSigner(priv)
	rec := &v2ByteVerifyRecorder{}
	emitter := proxydecision.NewEmitter(proxydecision.EmitterConfig{
		Recorder:  rec,
		Signer:    signer,
		Principal: "local",
		Actor:     "pipelock",
		Clock:     func() time.Time { return time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC) },
		EventID:   func() (string, error) { return "01900000-0000-7000-8000-000000000042", nil },
	})
	if emitter == nil {
		t.Fatal("NewEmitter returned nil")
	}

	if err := emitter.Emit(proxydecision.Decision{
		ActionType:    "http_request",
		Transport:     "forward",
		Target:        "https://api.vendor.example/v1/things",
		Verdict:       "block",
		WinningSource: proxydecision.SourceScanner,
		PolicySources: []string{proxydecision.SourceScanner},
		RuleID:        "prompt_injection",
		PolicyHash:    validPolicyHash,
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(rec.entries) != 1 {
		t.Fatalf("recorded entries = %d, want 1", len(rec.entries))
	}
	raw, ok := rec.entries[0].Detail.(json.RawMessage)
	if !ok {
		t.Fatalf("entry detail is %T, want json.RawMessage", rec.entries[0].Detail)
	}

	var stored receipt.EvidenceReceipt
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("unmarshal stored receipt: %v", err)
	}
	emitted, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("marshal stored receipt: %v", err)
	}
	if string(raw) != string(emitted) {
		t.Fatalf("stored bytes are not the emitter's compact receipt bytes\nstored=%s\nemitted=%s", raw, emitted)
	}
	if err := receipt.VerifyV2BytesWithKey(raw, pub, signer.KeyID()); err != nil {
		t.Fatalf("VerifyV2BytesWithKey real emitter bytes: %v", err)
	}
}

func TestVerifyV2BytesWithKey_LateExactByteAndSignatureRejects(t *testing.T) {
	t.Parallel()

	r, pub := signedReceiptWithCompactPayload(t)
	valid, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal valid receipt: %v", err)
	}
	otherSeed := sha256.Sum256([]byte("v2 byte verifier wrong public key"))
	otherPub := ed25519.NewKeyFromSeed(otherSeed[:]).Public().(ed25519.PublicKey)

	tests := []struct {
		name       string
		raw        []byte
		pubKey     ed25519.PublicKey
		signerID   string
		wantErrSub string
	}{
		{
			name:       "payload raw bytes differ from typed payload",
			raw:        reorderProxyDecisionPayloadBytes(t, valid),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "receipt payload bytes do not match v2 emitted JSON",
		},
		{
			name:       "envelope raw bytes differ from emitted envelope",
			raw:        reorderReceiptEnvelopeBytes(t, valid),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "receipt bytes do not match v2 emitted JSON",
		},
		{
			name:       "wrong receipt version",
			raw:        []byte(strings.Replace(string(valid), `"receipt_version":2`, `"receipt_version":3`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "receipt_version=2",
		},
		{
			name:       "signer id mismatch after exact byte checks",
			raw:        valid,
			pubKey:     pub,
			signerID:   "other-receipt-key",
			wantErrSub: "signer_key_id",
		},
		{
			name:       "public key mismatch after exact byte checks",
			raw:        valid,
			pubKey:     otherPub,
			signerID:   "receipt-key",
			wantErrSub: "signature verification failed",
		},
		{
			name:       "signature mismatch after exact byte checks",
			raw:        flipReceiptSignatureHex(t, r),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "signature verification failed",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := receipt.VerifyV2BytesWithKey(tc.raw, tc.pubKey, tc.signerID)
			if err == nil {
				t.Fatal("VerifyV2BytesWithKey error = nil, want rejection")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("VerifyV2BytesWithKey error = %q, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}

func TestVerifyV2BytesWithKey_AcceptsAllImplementedPayloadKindBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind    receipt.PayloadKind
		payload json.RawMessage
	}{
		{
			kind: receipt.PayloadProxyDecision,
			payload: marshalPayload(t, receipt.PayloadProxyDecisionStruct{
				ActionType:    "block",
				Target:        "https://example.com/",
				Verdict:       "blocked",
				Transport:     "forward",
				PolicySources: []string{"dlp"},
				WinningSource: "dlp",
			}),
		},
		{
			kind:    receipt.PayloadProxyDecisionWithSpans,
			payload: marshalPayload(t, validProxyDecisionWithSpansPayload(t)),
		},
		{
			kind: receipt.PayloadContractRatified,
			payload: marshalPayload(t, receipt.PayloadContractRatifiedStruct{
				ContractHash:                "sha256:abc",
				RatifierKeyID:               "key-1",
				RatifiedRuleIDs:             []string{"rule-1"},
				RatificationDecisionPerRule: map[string]string{"rule-1": "approved"},
			}),
		},
		{
			kind: receipt.PayloadContractPromoteIntent,
			payload: marshalPayload(t, receipt.PayloadContractPromoteIntentStruct{
				TargetManifestHash: "sha256:target",
				TargetGeneration:   2,
				PriorManifestHash:  "sha256:prior",
				IntentID:           "intent-1",
			}),
		},
		{
			kind: receipt.PayloadContractPromoteCommitted,
			payload: marshalPayload(t, receipt.PayloadContractPromoteCommittedStruct{
				TargetManifestHash: "sha256:target",
				PriorManifestHash:  "sha256:prior",
				IntentID:           "intent-1",
				ValidationOutcome:  "accepted",
			}),
		},
		{
			kind: receipt.PayloadContractRollbackAuthorized,
			payload: marshalPayload(t, receipt.PayloadContractRollbackAuthorizedStruct{
				RollbackTargetHash:   "sha256:target",
				CurrentGeneration:    5,
				AuthorizerSignatures: []string{"ed25519:aabb"},
				AuthorizationID:      "auth-1",
			}),
		},
		{
			kind: receipt.PayloadContractRollbackCommitted,
			payload: marshalPayload(t, receipt.PayloadContractRollbackCommittedStruct{
				RollbackTargetHash: "sha256:target",
				PriorManifestHash:  "sha256:prior",
				AuthorizationID:    "auth-1",
				ValidationOutcome:  "accepted",
			}),
		},
		{
			kind: receipt.PayloadContractDemoted,
			payload: marshalPayload(t, receipt.PayloadContractDemotedStruct{
				ContractHash:      "sha256:abc",
				RuleID:            "rule-1",
				DemotionReason:    "missed windows",
				PriorState:        "active",
				NewState:          "shadow",
				AggregationWindow: "7d",
			}),
		},
		{
			kind: receipt.PayloadContractExpired,
			payload: marshalPayload(t, receipt.PayloadContractExpiredStruct{
				ContractHash:     "sha256:abc",
				RuleID:           "rule-1",
				ExpirationReason: "ttl exceeded",
			}),
		},
		{
			kind: receipt.PayloadContractDrift,
			payload: marshalPayload(t, receipt.PayloadContractDriftStruct{
				ContractHash: "sha256:abc",
				RuleID:       "rule-1",
				DriftKind:    "positive",
			}),
		},
		{
			kind: receipt.PayloadShadowDelta,
			payload: marshalPayload(t, receipt.PayloadShadowDeltaStruct{
				ContractHash:     "sha256:abc",
				RuleID:           "rule-1",
				OriginalVerdict:  "blocked",
				CandidateVerdict: "allowed",
				Aggregation:      validShadowDeltaAggregation(),
			}),
		},
		{
			kind: receipt.PayloadOpportunityMissing,
			payload: marshalPayload(t, receipt.PayloadOpportunityMissingStruct{
				ContractHash:              "sha256:abc",
				RuleID:                    "rule-1",
				ParentContext:             "agent-xyz",
				HistoricalOpportunityRate: "0.85",
				CurrentOpportunityRate:    "0.10",
				Window:                    "7d",
			}),
		},
		{
			kind: receipt.PayloadKeyRotation,
			payload: marshalPayload(t, receipt.PayloadKeyRotationStruct{
				KeyID:           "key-1",
				KeyPurpose:      "receipt-signing",
				OldStatus:       "active",
				NewStatus:       "revoked",
				RosterHash:      "sha256:roster",
				AuthorizationID: "auth-1",
			}),
		},
		{
			kind: receipt.PayloadContractRedactionRequest,
			payload: marshalPayload(t, receipt.PayloadContractRedactionRequestStruct{
				TargetContractHash: "sha256:abc",
				RequestKind:        "withdraw_public_proof",
				ReasonClass:        "privacy",
				AuthorizationID:    "auth-1",
				TombstoneHash:      "sha256:tomb",
			}),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(string(tc.kind), func(t *testing.T) {
			t.Parallel()
			raw, pub := signedReceiptBytesForPayloadKind(t, tc.kind, tc.payload)
			if err := receipt.VerifyV2BytesWithKey(raw, pub, "receipt-key"); err != nil {
				t.Fatalf("VerifyV2BytesWithKey valid %s bytes: %v", tc.kind, err)
			}
		})
	}
}

func reorderProxyDecisionPayloadBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	from := `"payload":{"action_type":"block","target":"https://example.com/","verdict":"blocked","transport":"forward","policy_sources":["dlp"],"winning_source":"dlp"}`
	to := `"payload":{"target":"https://example.com/","action_type":"block","verdict":"blocked","transport":"forward","policy_sources":["dlp"],"winning_source":"dlp"}`
	out := strings.Replace(string(raw), from, to, 1)
	if out == string(raw) {
		t.Fatal("payload replacement did not match valid receipt bytes")
	}
	return []byte(out)
}

func reorderReceiptEnvelopeBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var env struct {
		RecordType       json.RawMessage `json:"record_type"`
		ReceiptVersion   json.RawMessage `json:"receipt_version"`
		PayloadKind      json.RawMessage `json:"payload_kind"`
		Canonicalization json.RawMessage `json:"canonicalization"`
		Crit             json.RawMessage `json:"crit"`
		EventID          json.RawMessage `json:"event_id"`
		Timestamp        json.RawMessage `json:"timestamp"`
		Signature        json.RawMessage `json:"signature"`
		ChainSeq         json.RawMessage `json:"chain_seq"`
		ChainPrevHash    json.RawMessage `json:"chain_prev_hash"`
		PolicyHash       json.RawMessage `json:"policy_hash"`
		Payload          json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal valid receipt envelope: %v", err)
	}
	return []byte(fmt.Sprintf(
		`{"receipt_version":%s,"record_type":%s,"payload_kind":%s,"canonicalization":%s,"crit":%s,"event_id":%s,"timestamp":%s,"signature":%s,"chain_seq":%s,"chain_prev_hash":%s,"policy_hash":%s,"payload":%s}`,
		env.ReceiptVersion, env.RecordType, env.PayloadKind, env.Canonicalization, env.Crit, env.EventID, env.Timestamp,
		env.Signature, env.ChainSeq, env.ChainPrevHash, env.PolicyHash, env.Payload,
	))
}

func flipReceiptSignatureHex(t *testing.T, r receipt.EvidenceReceipt) []byte {
	t.Helper()
	const prefix = "ed25519:"
	if !strings.HasPrefix(r.Signature.Signature, prefix) {
		t.Fatalf("signature %q missing %q prefix", r.Signature.Signature, prefix)
	}
	sig := []byte(r.Signature.Signature)
	last := len(sig) - 1
	if sig[last] == '0' {
		sig[last] = '1'
	} else {
		sig[last] = '0'
	}
	r.Signature.Signature = string(sig)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal signature-mutated receipt: %v", err)
	}
	return raw
}

func signedReceiptBytesForPayloadKind(
	t *testing.T,
	kind receipt.PayloadKind,
	payload json.RawMessage,
) ([]byte, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("v2 byte verifier all payload kinds"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	r := receipt.EvidenceReceipt{
		RecordType:       receipt.RecordTypeEvidenceV2,
		ReceiptVersion:   2,
		PayloadKind:      kind,
		Canonicalization: receipt.DefaultCanonicalizationProfile(),
		Crit:             receipt.CritForPayloadKind(kind),
		EventID:          "01900000-0000-7000-8000-000000000043",
		Timestamp:        time.Date(2026, 7, 5, 12, 1, 0, 0, time.UTC),
		ChainPrevHash:    "sha256:0",
		Payload:          payload,
	}
	switch kind {
	case receipt.PayloadProxyDecision, receipt.PayloadProxyDecisionWithSpans:
		r.PolicyHash = validPolicyHash
	}
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage for %s: %v", kind, err)
	}
	r.Signature = receipt.SignatureProof{
		SignerKeyID: "receipt-key",
		KeyPurpose:  testKeyPurposeForPayload(kind),
		Algorithm:   "ed25519",
		Signature:   "ed25519:" + fmt.Sprintf("%x", ed25519.Sign(priv, preimage)),
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal %s receipt: %v", kind, err)
	}
	return raw, priv.Public().(ed25519.PublicKey)
}
