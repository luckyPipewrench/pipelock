// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

const validReceiptSignature = "ed25519:" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"
const validPolicyHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// minimalProxyDecisionPayload returns a valid proxy_decision payload as raw JSON.
func minimalProxyDecisionPayload() json.RawMessage {
	return json.RawMessage(`{
		"action_type": "block",
		"target": "https://example.com/",
		"verdict": "blocked",
		"transport": "forward",
		"policy_sources": ["dlp"],
		"winning_source": "dlp"
	}`)
}

func validReceipt() receipt.EvidenceReceipt {
	return receipt.EvidenceReceipt{
		RecordType:       receipt.RecordTypeEvidenceV2,
		ReceiptVersion:   2,
		PayloadKind:      receipt.PayloadProxyDecision,
		Canonicalization: receipt.DefaultCanonicalizationProfile(),
		Crit:             receipt.CritForPayloadKind(receipt.PayloadProxyDecision),
		EventID:          "01900000-0000-7000-8000-000000000001",
		Timestamp:        time.Now(),
		PolicyHash:       validPolicyHash,
		Payload:          minimalProxyDecisionPayload(),
		Signature: receipt.SignatureProof{
			SignerKeyID: "receipt-key",
			KeyPurpose:  "receipt-signing",
			Algorithm:   "ed25519",
			Signature:   validReceiptSignature,
		},
	}
}

func TestEvidenceReceipt_Validate_RejectsV1RecordType(t *testing.T) {
	r := validReceipt()
	r.RecordType = receipt.RecordTypeActionV1
	err := r.Validate()
	if !errors.Is(err, receipt.ErrUnsupportedRecordType) {
		t.Fatalf("expected ErrUnsupportedRecordType, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsWrongVersion(t *testing.T) {
	r := validReceipt()
	r.ReceiptVersion = 3
	err := r.Validate()
	if !errors.Is(err, receipt.ErrWrongReceiptVersion) {
		t.Fatalf("expected ErrWrongReceiptVersion, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsMissingCanonicalization(t *testing.T) {
	r := validReceipt()
	r.Canonicalization = receipt.CanonicalizationProfile{}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsUnknownCrit(t *testing.T) {
	r := validReceipt()
	r.Crit = []string{receipt.CritCanonicalization, "future_extension"}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsMissingSourceSpanCrit(t *testing.T) {
	r, _ := signedSpannedReceipt(t)
	r.Crit = []string{receipt.CritCanonicalization}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsSourceSpanCritOnPlainPayload(t *testing.T) {
	r := validReceipt()
	r.Crit = []string{receipt.CritCanonicalization, receipt.CritSourceSpans}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsMissingEventID(t *testing.T) {
	r := validReceipt()
	r.EventID = ""
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsUnknownPayloadKind(t *testing.T) {
	r := validReceipt()
	r.PayloadKind = "not_a_real_kind"
	err := r.Validate()
	if !errors.Is(err, receipt.ErrUnknownPayloadKind) {
		t.Fatalf("expected ErrUnknownPayloadKind, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_AcceptsValidProxyDecision(t *testing.T) {
	r := validReceipt()
	if err := r.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsDecisionMissingPolicyHash(t *testing.T) {
	r := validReceipt()
	r.PolicyHash = ""
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsDecisionMalformedPolicyHash(t *testing.T) {
	r := validReceipt()
	r.PolicyHash = "sha256:ABCDEF"
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_AllowsLifecycleWithoutPolicyHash(t *testing.T) {
	r := validReceipt()
	r.PayloadKind = receipt.PayloadContractPromoteCommitted
	r.Crit = receipt.CritForPayloadKind(receipt.PayloadContractPromoteCommitted)
	r.PolicyHash = ""
	r.Payload = json.RawMessage(`{"target_manifest_hash":"sha256:target","prior_manifest_hash":"sha256:prior","intent_id":"intent-1","validation_outcome":"accepted"}`)
	if err := r.Validate(); err != nil {
		t.Fatalf("unexpected lifecycle validation error: %v", err)
	}
}

func TestEvidenceReceipt_Validate_ReservedDeferKindFailsClosed(t *testing.T) {
	r := validReceipt()
	r.PayloadKind = receipt.PayloadDeferOpened
	r.Crit = receipt.CritForPayloadKind(receipt.PayloadDeferOpened)
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadKindNotImplemented) {
		t.Fatalf("expected ErrPayloadKindNotImplemented, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsMissingSignature(t *testing.T) {
	r := validReceipt()
	r.Signature = receipt.SignatureProof{}
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("expected ErrPayloadMissingField, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsWrongKeyPurpose(t *testing.T) {
	r := validReceipt()
	r.Signature.KeyPurpose = "contract-activation-signing"
	err := r.Validate()
	if !errors.Is(err, contract.ErrWrongKeyPurpose) {
		t.Fatalf("expected ErrWrongKeyPurpose, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsWrongSignatureAlgorithm(t *testing.T) {
	r := validReceipt()
	r.Signature.Algorithm = "ed25519ph"
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestEvidenceReceipt_Validate_RejectsBadSignatureEncoding(t *testing.T) {
	r := validReceipt()
	r.Signature.Signature = "ed25519:not-hex"
	err := r.Validate()
	if !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("expected ErrPayloadInvalidEnum, got: %v", err)
	}
}

func TestEvidenceReceipt_SignablePreimage_Stable(t *testing.T) {
	r := validReceipt()
	a, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	b, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("preimage not stable: first=%q second=%q", a, b)
	}
}

func TestEvidenceReceipt_SignablePreimage_RejectsDuplicateJSONKey(t *testing.T) {
	// ParseJSONStrict rejects duplicate keys; the payload field is included in
	// the preimage, so duplicate keys in the envelope JSON must surface as an
	// error from SignablePreimage.
	r := validReceipt()
	// Inject a duplicate key at the envelope level by building raw JSON manually.
	// We can't marshal a Go struct with duplicate keys, so we build a preimage
	// that contains a duplicate by re-marshalling with modified JSON.
	// Instead, we test that a receipt whose Payload is invalid does NOT silently
	// produce a preimage: use a json.RawMessage that is invalid JSON.
	r.Payload = json.RawMessage(`{invalid`)
	// json.Marshal succeeds (Payload is just bytes), but ParseJSONStrict will fail.
	_, err := r.SignablePreimage()
	if err == nil {
		t.Fatal("expected error from SignablePreimage with invalid payload JSON, got nil")
	}
}

func TestEvidenceReceipt_SignablePreimage_RejectsPayloadDuplicateKey(t *testing.T) {
	// A payload with duplicate JSON keys passes json.RawMessage.MarshalJSON
	// (the bytes are valid JSON), but ParseJSONStrict (which rejects duplicate
	// keys) returns ErrDuplicateKey. This exercises the ParseJSONStrict error
	// branch in EvidenceReceipt.SignablePreimage.
	r := validReceipt()
	r.Payload = json.RawMessage(`{"action_type":"block","action_type":"warn"}`)
	_, err := r.SignablePreimage()
	if err == nil {
		t.Fatal("expected error from ParseJSONStrict duplicate key, got nil")
	}
}

func TestEvidenceReceipt_SignablePreimage_ExcludesSignature(t *testing.T) {
	// Base receipt is shared; only Signature differs between the two variants.
	base := validReceipt()

	r1 := base
	r1.Signature = receipt.SignatureProof{
		SignerKeyID: "key-alpha",
		KeyPurpose:  "receipt-signing",
		Algorithm:   "ed25519",
		Signature:   "ed25519:aabbcc",
	}
	preimageWithSig, err := r1.SignablePreimage()
	if err != nil {
		t.Fatalf("error with sig: %v", err)
	}

	r2 := base
	r2.Signature = receipt.SignatureProof{
		SignerKeyID: "key-beta",
		KeyPurpose:  "receipt-signing",
		Algorithm:   "ed25519",
		Signature:   "ed25519:ddeeff",
	}
	preimageWithDiffSig, err := r2.SignablePreimage()
	if err != nil {
		t.Fatalf("error with diff sig: %v", err)
	}

	if string(preimageWithSig) != string(preimageWithDiffSig) {
		t.Fatalf("signature field affects preimage: got different bytes")
	}
}

func TestReceiptHash_StableAndPayloadSensitive(t *testing.T) {
	r := validReceipt()
	first, err := receipt.ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash first: %v", err)
	}
	second, err := receipt.ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash second: %v", err)
	}
	if first != second {
		t.Fatalf("ReceiptHash unstable: first=%q second=%q", first, second)
	}

	r.Payload = json.RawMessage(`{"action_type":"block","target":"https://example.com/other","verdict":"blocked","transport":"forward","policy_sources":["dlp"],"winning_source":"dlp"}`)
	changed, err := receipt.ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash changed payload: %v", err)
	}
	if changed == first {
		t.Fatalf("ReceiptHash did not change after payload mutation: %q", changed)
	}
}

func TestReceiptHash_RejectsInvalidPayloadJSON(t *testing.T) {
	r := validReceipt()
	r.Payload = json.RawMessage(`{invalid`)
	if _, err := receipt.ReceiptHash(r); err == nil {
		t.Fatal("ReceiptHash invalid payload error = nil, want error")
	}
}

func TestVerifyWithKey(t *testing.T) {
	r, pub := signedReceipt(t)
	if err := receipt.VerifyWithKey(r, pub, "receipt-key"); err != nil {
		t.Fatalf("VerifyWithKey valid receipt: %v", err)
	}

	if err := receipt.VerifyWithKey(r, pub, ""); !errors.Is(err, receipt.ErrPayloadMissingField) {
		t.Fatalf("VerifyWithKey empty signer key id error = %v, want ErrPayloadMissingField", err)
	}

	if err := receipt.VerifyWithKey(r, pub, "other-key"); !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("VerifyWithKey signer key mismatch error = %v, want ErrPayloadInvalidEnum", err)
	}

	if err := receipt.VerifyWithKey(r, ed25519.PublicKey("short"), "receipt-key"); !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("VerifyWithKey short key error = %v, want ErrPayloadInvalidEnum", err)
	}

	badHex := r
	badHex.Signature.Signature = "ed25519:not-hex"
	if err := receipt.VerifyWithKey(badHex, pub, "receipt-key"); !errors.Is(err, receipt.ErrPayloadInvalidEnum) {
		t.Fatalf("VerifyWithKey bad hex error = %v, want ErrPayloadInvalidEnum", err)
	}

	tampered := r
	tampered.Payload = json.RawMessage(`{"action_type":"block","target":"https://example.com/tampered","verdict":"blocked","transport":"forward","policy_sources":["dlp"],"winning_source":"dlp"}`)
	if err := receipt.VerifyWithKey(tampered, pub, "receipt-key"); !errors.Is(err, receipt.ErrSignatureVerification) {
		t.Fatalf("VerifyWithKey tampered error = %v, want ErrSignatureVerification", err)
	}
}

func TestVerifyV2BytesWithKey_ExactBytesMutationCorpus(t *testing.T) {
	t.Parallel()

	r, pub := signedReceiptWithCompactPayload(t)
	valid, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal valid receipt: %v", err)
	}
	if err := receipt.VerifyV2BytesWithKey(valid, pub, "receipt-key"); err != nil {
		t.Fatalf("VerifyV2BytesWithKey valid bytes: %v", err)
	}

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
	if err := json.Unmarshal(valid, &env); err != nil {
		t.Fatalf("Unmarshal raw envelope: %v", err)
	}
	reordered := []byte(fmt.Sprintf(
		`{"receipt_version":%s,"record_type":%s,"payload_kind":%s,"canonicalization":%s,"crit":%s,"event_id":%s,"timestamp":%s,"signature":%s,"chain_seq":%s,"chain_prev_hash":%s,"policy_hash":%s,"payload":%s}`,
		env.ReceiptVersion, env.RecordType, env.PayloadKind, env.Canonicalization, env.Crit, env.EventID, env.Timestamp,
		env.Signature, env.ChainSeq, env.ChainPrevHash, env.PolicyHash, env.Payload,
	))
	otherSeed := sha256.Sum256([]byte("receipt verify other key"))
	otherPub := ed25519.NewKeyFromSeed(otherSeed[:]).Public().(ed25519.PublicKey)
	malformedSignature := strings.Replace(string(valid), "ed25519:", "ed25519:not-hex", 1)
	wrongVersion := strings.Replace(string(valid), `"receipt_version":2`, `"receipt_version":3`, 1)

	cases := []struct {
		name       string
		raw        []byte
		pubKey     ed25519.PublicKey
		signerID   string
		wantErrSub string
	}{
		{
			name:       "flipped signed byte",
			raw:        []byte(strings.Replace(string(valid), "https://example.com/", "https://example.net/", 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "signature verification failed",
		},
		{
			name:       "reordered top-level keys",
			raw:        reordered,
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "emitted JSON",
		},
		{
			name:       "added unknown top-level field",
			raw:        []byte(strings.Replace(string(valid), `{"record_type":`, `{"unknown":true,"record_type":`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "unknown field",
		},
		{
			name:       "added unknown nested signed field",
			raw:        []byte(strings.Replace(string(valid), `"payload":{`, `"payload":{"unknown":true,`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "unknown field",
		},
		{
			name:       "reordered payload keys",
			raw:        []byte(strings.Replace(string(valid), `"payload":{"action_type":"block","target":"https://example.com/"`, `"payload":{"target":"https://example.com/","action_type":"block"`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "payload bytes",
		},
		{
			name:       "duplicate key",
			raw:        []byte(strings.Replace(string(valid), `{"record_type":`, `{"record_type":"evidence_receipt_v2","record_type":`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "duplicate object key",
		},
		{
			name:       "nested duplicate key",
			raw:        []byte(strings.Replace(string(valid), `"payload":{"action_type":`, `"payload":{"action_type":"block","action_type":`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "duplicate object key",
		},
		{
			name:       "trailing token",
			raw:        append(append([]byte(nil), valid...), []byte(` {}`)...),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "trailing tokens",
		},
		{
			name:       "trailing whitespace",
			raw:        append(append([]byte(nil), valid...), '\n'),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "emitted JSON",
		},
		{
			name:       "truncated",
			raw:        valid[:len(valid)-1],
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "EOF",
		},
		{
			name:       "null detail",
			raw:        []byte("null"),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "empty or null payload",
		},
		{
			name:       "empty bytes",
			raw:        nil,
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "empty or null payload",
		},
		{
			name:       "empty payload",
			raw:        []byte(strings.Replace(string(valid), string(env.Payload), `{}`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "action_type",
		},
		{
			name:       "null required payload field",
			raw:        []byte(strings.Replace(string(valid), `"target":"https://example.com/"`, `"target":null`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "payload missing required field: target",
		},
		{
			name:       "bad number",
			raw:        []byte(strings.Replace(string(valid), `"chain_seq":0`, `"chain_seq":1.5`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "cannot unmarshal number 1.5",
		},
		{
			name:       "exponent number",
			raw:        []byte(strings.Replace(string(valid), `"chain_seq":0`, `"chain_seq":1e3`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "cannot unmarshal number 1e3",
		},
		{
			name:       "big integer",
			raw:        []byte(strings.Replace(string(valid), `"chain_seq":0`, `"chain_seq":18446744073709551616`, 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "cannot unmarshal number 18446744073709551616",
		},
		{
			name:       "unicode nfd mutation",
			raw:        []byte(strings.Replace(string(valid), "https://example.com/", "https://example.com/cafe\u0301", 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "signature verification failed",
		},
		{
			name:       "malformed signature",
			raw:        []byte(malformedSignature),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "signature.signature hex",
		},
		{
			name:       "empty signature",
			raw:        []byte(strings.Replace(string(valid), r.Signature.Signature, "", 1)),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "signature.signature prefix",
		},
		{
			name:       "wrong key",
			raw:        valid,
			pubKey:     otherPub,
			signerID:   "receipt-key",
			wantErrSub: "signature verification failed",
		},
		{
			name:       "wrong signer id",
			raw:        valid,
			pubKey:     pub,
			signerID:   "other-key",
			wantErrSub: "signer_key_id",
		},
		{
			name:       "wrong version",
			raw:        []byte(wrongVersion),
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "receipt_version=2",
		},
		{
			name:       "hostile non-json bytes",
			raw:        []byte{0xff, '{', '"'},
			pubKey:     pub,
			signerID:   "receipt-key",
			wantErrSub: "strict decode",
		},
	}
	for _, tc := range cases {
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

func TestVerifyV2BytesWithKey_SpannedPayloadAdversarialEdgesReject(t *testing.T) {
	t.Parallel()

	r, pub := signedSpannedReceipt(t)
	valid, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal valid spanned receipt: %v", err)
	}
	if err := receipt.VerifyV2BytesWithKey(valid, pub, "receipt-key"); err != nil {
		t.Fatalf("VerifyV2BytesWithKey valid spanned bytes: %v", err)
	}

	cases := []struct {
		name       string
		raw        []byte
		wantErrSub string
	}{
		{
			name: "unknown field inside source_spans array object",
			raw: []byte(strings.Replace(
				string(valid),
				`"source_spans":[{"source_id":"request-url"`,
				`"source_spans":[{"unknown":true,"source_id":"request-url"`,
				1,
			)),
			wantErrSub: "unknown field",
		},
		{
			name: "duplicate key inside source_spans array object",
			raw: []byte(strings.Replace(
				string(valid),
				`"source_spans":[{"source_id":"request-url"`,
				`"source_spans":[{"source_id":"request-url","source_id":"other"`,
				1,
			)),
			wantErrSub: "duplicate object key",
		},
		{
			name: "payload kind spoofed away from actual source_spans shape",
			raw: []byte(strings.Replace(
				string(valid),
				`"payload_kind":"proxy_decision_with_spans"`,
				`"payload_kind":"proxy_decision"`,
				1,
			)),
			wantErrSub: "source_spans",
		},
		{
			name: "crit spoofed away from actual payload kind",
			raw: []byte(strings.Replace(
				string(valid),
				`"crit":["canonicalization","source_spans"]`,
				`"crit":["canonicalization"]`,
				1,
			)),
			wantErrSub: "source_spans",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := receipt.VerifyV2BytesWithKey(tc.raw, pub, "receipt-key")
			if err == nil {
				t.Fatal("VerifyV2BytesWithKey error = nil, want rejection")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("VerifyV2BytesWithKey error = %q, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}

func signedReceiptWithCompactPayload(t *testing.T) (receipt.EvidenceReceipt, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("receipt verify test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	r := validReceipt()
	var compact bytes.Buffer
	if err := json.Compact(&compact, r.Payload); err != nil {
		t.Fatalf("compact payload: %v", err)
	}
	r.Payload = compact.Bytes()
	r.Signature = receipt.SignatureProof{}
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	r.Signature = receipt.SignatureProof{
		SignerKeyID: "receipt-key",
		KeyPurpose:  "receipt-signing",
		Algorithm:   "ed25519",
		Signature:   "ed25519:" + fmt.Sprintf("%x", ed25519.Sign(priv, preimage)),
	}
	return r, priv.Public().(ed25519.PublicKey)
}

func TestVerifyWithKey_SpannedReceiptTamperBreaksSignature(t *testing.T) {
	t.Parallel()
	r, pub := signedSpannedReceipt(t)
	if err := receipt.VerifyWithKey(r, pub, "receipt-key"); err != nil {
		t.Fatalf("VerifyWithKey valid spanned receipt: %v", err)
	}

	var payload receipt.PayloadProxyDecisionWithSpansStruct
	if err := json.Unmarshal(r.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	payload.SourceSpans[0].NormalizedView = receipt.NormalizedViewDLPNormalized
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	r.Payload = body
	if err := receipt.VerifyWithKey(r, pub, "receipt-key"); !errors.Is(err, receipt.ErrSignatureVerification) {
		t.Fatalf("VerifyWithKey tampered spanned receipt error = %v, want ErrSignatureVerification", err)
	}
}

func signedReceipt(t *testing.T) (receipt.EvidenceReceipt, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("receipt verify test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	r := validReceipt()
	r.Signature = receipt.SignatureProof{}
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	r.Signature = receipt.SignatureProof{
		SignerKeyID: "receipt-key",
		KeyPurpose:  "receipt-signing",
		Algorithm:   "ed25519",
		Signature:   "ed25519:" + fmt.Sprintf("%x", ed25519.Sign(priv, preimage)),
	}
	return r, priv.Public().(ed25519.PublicKey)
}

func signedSpannedReceipt(t *testing.T) (receipt.EvidenceReceipt, ed25519.PublicKey) {
	t.Helper()
	const eventID = "01900000-0000-7000-8000-000000000010"
	seed := sha256.Sum256([]byte("receipt verify spanned test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	payload := receipt.PayloadProxyDecisionWithSpansStruct{
		ActionType:    "block",
		Target:        "https://example.com/" + testRedactedValue,
		Verdict:       "block",
		Transport:     "forward",
		PolicySources: []string{"dlp"},
		WinningSource: "scanner",
		RuleID:        testAWSAccessKeyRule,
		SourceSpans:   []receipt.SourceSpan{receiptTestSourceSpan(t, eventID)},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	r := receipt.EvidenceReceipt{
		RecordType:       receipt.RecordTypeEvidenceV2,
		ReceiptVersion:   2,
		PayloadKind:      receipt.PayloadProxyDecisionWithSpans,
		Canonicalization: receipt.DefaultCanonicalizationProfile(),
		Crit:             receipt.CritForPayloadKind(receipt.PayloadProxyDecisionWithSpans),
		EventID:          eventID,
		Timestamp:        time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC),
		ChainPrevHash:    "sha256:0",
		PolicyHash:       validPolicyHash,
		Payload:          body,
	}
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	r.Signature = receipt.SignatureProof{
		SignerKeyID: "receipt-key",
		KeyPurpose:  "receipt-signing",
		Algorithm:   "ed25519",
		Signature:   "ed25519:" + fmt.Sprintf("%x", ed25519.Sign(priv, preimage)),
	}
	return r, priv.Public().(ed25519.PublicKey)
}

func receiptTestSourceSpan(t *testing.T, eventID string) receipt.SourceSpan {
	t.Helper()
	offset := 20
	length := len(testRedactedValue)
	span := receipt.SourceSpan{
		SourceID:             "request-url",
		SourceKind:           receipt.SourceKindHTTPRequestURL,
		NormalizedView:       receipt.NormalizedViewSanitizedTarget,
		PipelockBinaryDigest: testSHA256Digest,
		RulesBundleDigest:    testSHA256Digest,
		TransformProfile:     "pipelock-transform-v1",
		PolicyHash:           testSHA256Digest,
		RuleID:               testAWSAccessKeyRule,
		CharOffset:           &offset,
		CharLength:           &length,
		MatchHashAlg:         testHMACSHA256,
		MatchClass:           "secret:aws_access_key",
		RedactedSample:       testRedactedValue,
	}
	hash, err := receipt.SourceSpanMatchHash([]byte(testSpanMACKey), eventID, 0, span, span.RedactedSample)
	if err != nil {
		t.Fatalf("SourceSpanMatchHash: %v", err)
	}
	span.MatchHash = hash
	return span
}
