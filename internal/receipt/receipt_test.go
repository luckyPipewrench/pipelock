// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	testSigPrefix = "ed25519:"
)

func generateTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func signValidReceipt(t *testing.T, priv ed25519.PrivateKey) Receipt {
	t.Helper()
	ar := validActionRecord()
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return r
}

func TestSign_HappyPath(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	ar := validActionRecord()

	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	if r.Version != ReceiptVersion {
		t.Errorf("receipt version = %d, want %d", r.Version, ReceiptVersion)
	}
	if !strings.HasPrefix(r.Signature, testSigPrefix) {
		t.Errorf("signature missing %q prefix: %s", testSigPrefix, r.Signature)
	}
	if r.SignerKey != hex.EncodeToString(pub) {
		t.Errorf("signer_key = %s, want %s", r.SignerKey, hex.EncodeToString(pub))
	}
}

func TestSign_InvalidPrivateKeySize(t *testing.T) {
	t.Parallel()

	ar := validActionRecord()
	shortKey := make([]byte, 16)
	_, err := Sign(ar, shortKey)
	if err == nil {
		t.Fatal("Sign() expected error for short private key, got nil")
	}
	if !strings.Contains(err.Error(), "invalid private key size") {
		t.Errorf("Sign() error = %q, want substring \"invalid private key size\"", err)
	}
}

func TestSign_InvalidActionRecord(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	ar := validActionRecord()
	ar.ActionID = "" // missing required field

	_, err := Sign(ar, priv)
	if err == nil {
		t.Fatal("Sign() expected error for invalid action record, got nil")
	}
	if !strings.Contains(err.Error(), "invalid action record") {
		t.Errorf("Sign() error = %q, want substring \"invalid action record\"", err)
	}
}

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	if err := VerifyInternalConsistencyOnly(r); err != nil {
		t.Fatalf("VerifyInternalConsistencyOnly() error: %v", err)
	}
}

func TestVerify_TamperedRecord(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	// Tamper with the action record after signing.
	r.ActionRecord.Target = "https://evil.example.com"

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for tampered record, got nil")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"signature verification failed\"", err)
	}
}

func TestVerify_TamperedRunNonceFails(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	ar := validActionRecord()
	ar.RunNonce = "0123456789abcdef0123456789abcdef"
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	r.ActionRecord.RunNonce = "1123456789abcdef0123456789abcdef"
	err = VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for tampered run_nonce, got nil")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"signature verification failed\"", err)
	}
}

func TestVerify_LegacyReceiptWithoutRunNonceStillVerifies(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	ar := validActionRecord()
	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if r.ActionRecord.RunNonce != "" {
		t.Fatalf("legacy fixture run_nonce = %q, want empty", r.ActionRecord.RunNonce)
	}
	if err := VerifyInternalConsistencyOnly(r); err != nil {
		t.Fatalf("VerifyInternalConsistencyOnly() legacy receipt without run_nonce: %v", err)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	// Flip a byte in the signature hex.
	sigHex := r.Signature[len(testSigPrefix):]
	flipped := flipHexByte(sigHex)
	r.Signature = testSigPrefix + flipped

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for tampered signature, got nil")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"signature verification failed\"", err)
	}
}

func TestVerifyWithKey_MatchingKey(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	err := VerifyWithKey(r, hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("VerifyWithKey() error: %v", err)
	}
}

func TestVerifyWithKey_WrongKey(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	// Generate a different key pair.
	otherPub, _ := generateTestKey(t)

	err := VerifyWithKey(r, hex.EncodeToString(otherPub))
	if err == nil {
		t.Fatal("VerifyWithKey() expected error for wrong key, got nil")
	}
	if !strings.Contains(err.Error(), "does not match expected key") {
		t.Errorf("VerifyWithKey() error = %q, want substring \"does not match expected key\"", err)
	}
}

func TestVerifyV1BytesWithKey_ExactBytesMutationCorpus(t *testing.T) {
	t.Parallel()

	pub, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	valid, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal valid receipt: %v", err)
	}
	expectedKey := hex.EncodeToString(pub)
	if err := VerifyV1BytesWithKey(valid, expectedKey); err != nil {
		t.Fatalf("VerifyV1BytesWithKey valid bytes: %v", err)
	}

	var env receiptBytesEnvelopeV1
	if err := json.Unmarshal(valid, &env); err != nil {
		t.Fatalf("Unmarshal raw envelope: %v", err)
	}
	reordered := []byte(fmt.Sprintf(
		`{"action_record":%s,"version":%d,"signature":%q,"signer_key":%q}`,
		env.ActionRecord, env.Version, env.Signature, env.SignerKey,
	))
	otherPub, _ := generateTestKey(t)
	malformedSignature := strings.Replace(string(valid), "ed25519:", "ed25519:not-hex", 1)
	missingSignaturePrefix := strings.Replace(string(valid), env.Signature, strings.TrimPrefix(env.Signature, testSigPrefix), 1)
	shortSignature := strings.Replace(string(valid), env.Signature, testSigPrefix+hex.EncodeToString(make([]byte, 16)), 1)
	wrongVersion := strings.Replace(string(valid), `"version":1`, `"version":99`, 1)
	badSignerKey := strings.Replace(string(valid), env.SignerKey, "not-valid-hex", 1)
	shortSignerKey := strings.Replace(string(valid), env.SignerKey, hex.EncodeToString(make([]byte, 16)), 1)

	cases := []struct {
		name       string
		raw        []byte
		keyHex     string
		wantErrSub string
	}{
		{
			name:       "flipped signed byte",
			raw:        []byte(strings.Replace(string(valid), testTarget, "https://example.net/api", 1)),
			keyHex:     expectedKey,
			wantErrSub: "signature verification failed",
		},
		{
			name:       "reordered top-level keys",
			raw:        reordered,
			keyHex:     expectedKey,
			wantErrSub: "emitted JSON",
		},
		{
			name:       "added unknown top-level field",
			raw:        []byte(strings.Replace(string(valid), `{"version":1`, `{"version":1,"unknown":true`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "unknown field",
		},
		{
			name:       "added unknown nested signed field",
			raw:        []byte(strings.Replace(string(valid), `"action_record":{"version":1`, `"action_record":{"version":1,"unknown":true`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "unknown field",
		},
		{
			name:       "duplicate key",
			raw:        []byte(strings.Replace(string(valid), `{"version":1`, `{"version":1,"version":1`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "duplicate object key",
		},
		{
			name:       "nested duplicate key",
			raw:        []byte(strings.Replace(string(valid), `"action_record":{"version":1`, `"action_record":{"version":1,"version":1`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "duplicate object key",
		},
		{
			name:       "trailing token",
			raw:        append(append([]byte(nil), valid...), []byte(` {}`)...),
			keyHex:     expectedKey,
			wantErrSub: "trailing tokens",
		},
		{
			name:       "trailing whitespace",
			raw:        append(append([]byte(nil), valid...), '\n'),
			keyHex:     expectedKey,
			wantErrSub: "emitted JSON",
		},
		{
			name:       "truncated",
			raw:        valid[:len(valid)-1],
			keyHex:     expectedKey,
			wantErrSub: "EOF",
		},
		{
			name:       "null detail",
			raw:        []byte("null"),
			keyHex:     expectedKey,
			wantErrSub: "empty or null payload",
		},
		{
			name:       "null action record",
			raw:        []byte(strings.Replace(string(valid), string(env.ActionRecord), `null`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "empty or null payload",
		},
		{
			name:       "empty bytes",
			raw:        nil,
			keyHex:     expectedKey,
			wantErrSub: "empty or null payload",
		},
		{
			name:       "empty action record",
			raw:        []byte(strings.Replace(string(valid), string(env.ActionRecord), `{}`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "emitted JSON",
		},
		{
			name:       "null required field",
			raw:        []byte(strings.Replace(string(valid), `"target":"`+testTarget+`"`, `"target":null`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "emitted JSON",
		},
		{
			name:       "bad number",
			raw:        []byte(strings.Replace(string(valid), `"chain_seq":0`, `"chain_seq":1.5`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "cannot unmarshal number 1.5",
		},
		{
			name:       "exponent number",
			raw:        []byte(strings.Replace(string(valid), `"chain_seq":0`, `"chain_seq":1e3`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "cannot unmarshal number 1e3",
		},
		{
			name:       "big integer",
			raw:        []byte(strings.Replace(string(valid), `"chain_seq":0`, `"chain_seq":18446744073709551616`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "cannot unmarshal number 18446744073709551616",
		},
		{
			name:       "unicode nfd mutation",
			raw:        []byte(strings.Replace(string(valid), testTarget, "https://example.com/cafe\u0301", 1)),
			keyHex:     expectedKey,
			wantErrSub: "signature verification failed",
		},
		{
			name:       "empty expected key",
			raw:        valid,
			keyHex:     "",
			wantErrSub: "requires a trusted public key",
		},
		{
			name:       "invalid action record",
			raw:        []byte(strings.Replace(string(valid), `"target":"`+testTarget+`"`, `"target":""`, 1)),
			keyHex:     expectedKey,
			wantErrSub: "invalid action record",
		},
		{
			name:       "malformed signature",
			raw:        []byte(malformedSignature),
			keyHex:     expectedKey,
			wantErrSub: "decoding signature",
		},
		{
			name:       "missing signature prefix",
			raw:        []byte(missingSignaturePrefix),
			keyHex:     expectedKey,
			wantErrSub: "missing ed25519:",
		},
		{
			name:       "short signature",
			raw:        []byte(shortSignature),
			keyHex:     expectedKey,
			wantErrSub: "invalid signature length",
		},
		{
			name:       "empty signature",
			raw:        []byte(strings.Replace(string(valid), env.Signature, "", 1)),
			keyHex:     expectedKey,
			wantErrSub: "receipt has no signature",
		},
		{
			name:       "empty signer key",
			raw:        []byte(strings.Replace(string(valid), env.SignerKey, "", 1)),
			keyHex:     expectedKey,
			wantErrSub: "receipt has no signer_key",
		},
		{
			name:       "bad signer key hex",
			raw:        []byte(badSignerKey),
			keyHex:     "not-valid-hex",
			wantErrSub: "decoding signer_key",
		},
		{
			name:       "short signer key",
			raw:        []byte(shortSignerKey),
			keyHex:     hex.EncodeToString(make([]byte, 16)),
			wantErrSub: "invalid signer_key length",
		},
		{
			name:       "wrong key",
			raw:        valid,
			keyHex:     hex.EncodeToString(otherPub),
			wantErrSub: "does not match expected key",
		},
		{
			name:       "wrong version",
			raw:        []byte(wrongVersion),
			keyHex:     expectedKey,
			wantErrSub: "unsupported receipt version",
		},
		{
			name:       "hostile non-json bytes",
			raw:        []byte{0xff, '{', '"'},
			keyHex:     expectedKey,
			wantErrSub: "not valid UTF-8",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := VerifyV1BytesWithKey(tc.raw, tc.keyHex)
			if err == nil {
				t.Fatal("VerifyV1BytesWithKey error = nil, want rejection")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("VerifyV1BytesWithKey error = %q, want substring %q", err, tc.wantErrSub)
			}
		})
	}
}

func TestVerifyV1BytesWithKey_AcceptsRawDetailFromRealEmitter(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateTestKey(t)
	rec := newTestRecorder(t, dir, priv)
	e := NewEmitter(EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testConfigHash,
		Principal:  testPrincipal,
		Actor:      testActor,
	})
	if e == nil {
		t.Fatal("NewEmitter returned nil")
	}

	if err := e.Emit(EmitOpts{
		ActionID:            NewActionID(),
		Target:              `https://example.com/api?q=<tag>&n=1`,
		Verdict:             config.ActionBlock,
		Transport:           testTransport,
		Method:              http.MethodPost,
		SessionTaintLevel:   session.TaintExternalUntrusted.String(),
		SessionContaminated: true,
		RecentTaintSources: []session.TaintSourceRef{{
			URL:       "https://vendor.example/prompt",
			Kind:      "http_response",
			Level:     session.TaintExternalUntrusted,
			Timestamp: time.Date(2026, 7, 5, 12, 30, 0, 0, time.UTC),
		}},
		Shield: &ShieldSummary{
			Pipeline:        "html",
			TotalRewrites:   2,
			TrackingBeacons: 1,
		},
	}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}

	entries, err := recorder.ReadEntries(filepath.Join(dir, "evidence-proxy-0.jsonl"))
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	expectedKey := hex.EncodeToString(pub)
	for _, entry := range entries {
		if entry.Type != recorderEntryType {
			continue
		}
		if len(entry.RawDetail) == 0 {
			t.Fatal("receipt entry RawDetail is empty")
		}
		if err := VerifyV1BytesWithKey(entry.RawDetail, expectedKey); err != nil {
			t.Fatalf("VerifyV1BytesWithKey(real RawDetail): %v\nraw=%s", err, entry.RawDetail)
		}
		return
	}
	t.Fatal("no action_receipt entry found")
}

func TestVerify_MissingSignature(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.Signature = ""

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for missing signature, got nil")
	}
	if !strings.Contains(err.Error(), "no signature") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"no signature\"", err)
	}
}

func TestVerify_MissingSignerKey(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.SignerKey = ""

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for missing signer_key, got nil")
	}
	if !strings.Contains(err.Error(), "no signer_key") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"no signer_key\"", err)
	}
}

func TestVerify_WrongVersion(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.Version = 99

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for wrong version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported receipt version") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"unsupported receipt version\"", err)
	}
}

func TestVerify_BadHexSignerKey(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.SignerKey = "not-valid-hex!"

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for bad hex signer_key, got nil")
	}
	if !strings.Contains(err.Error(), "decoding signer_key") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"decoding signer_key\"", err)
	}
}

func TestVerify_BadHexSignature(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	r.Signature = testSigPrefix + "not-valid-hex!"

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for bad hex signature, got nil")
	}
	if !strings.Contains(err.Error(), "decoding signature") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"decoding signature\"", err)
	}
}

func TestVerify_WrongSignatureLength(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	// Set signature to valid hex but wrong length (16 bytes instead of 64).
	r.Signature = testSigPrefix + hex.EncodeToString(make([]byte, 16))

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for wrong signature length, got nil")
	}
	if !strings.Contains(err.Error(), "invalid signature length") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"invalid signature length\"", err)
	}
}

func TestVerify_WrongKeyLength(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	// Set signer_key to valid hex but wrong length (16 bytes instead of 32).
	r.SignerKey = hex.EncodeToString(make([]byte, 16))

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for wrong key length, got nil")
	}
	if !strings.Contains(err.Error(), "invalid signer_key length") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"invalid signer_key length\"", err)
	}
}

func TestVerify_MissingSignaturePrefix(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)
	// Remove the ed25519: prefix.
	r.Signature = strings.TrimPrefix(r.Signature, testSigPrefix)

	err := VerifyInternalConsistencyOnly(r)
	if err == nil {
		t.Fatal("VerifyInternalConsistencyOnly() expected error for missing signature prefix, got nil")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("VerifyInternalConsistencyOnly() error = %q, want substring \"missing\"", err)
	}
}

func TestMarshal_Unmarshal_RoundTrip(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	r := signValidReceipt(t, priv)

	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	r2, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	// Verify the unmarshaled receipt still verifies.
	if err := VerifyInternalConsistencyOnly(r2); err != nil {
		t.Fatalf("VerifyInternalConsistencyOnly(unmarshaled) error: %v", err)
	}

	// Check key fields survived the round trip.
	if r2.Version != r.Version {
		t.Errorf("version: got %d, want %d", r2.Version, r.Version)
	}
	if r2.Signature != r.Signature {
		t.Errorf("signature mismatch after round trip")
	}
	if r2.SignerKey != r.SignerKey {
		t.Errorf("signer_key mismatch after round trip")
	}
	if r2.ActionRecord.ActionID != r.ActionRecord.ActionID {
		t.Errorf("action_id mismatch after round trip")
	}
	if r2.ActionRecord.Target != r.ActionRecord.Target {
		t.Errorf("target mismatch after round trip")
	}
}

func TestUnmarshal_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := Unmarshal([]byte("not json"))
	if err == nil {
		t.Fatal("Unmarshal() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal receipt") {
		t.Errorf("Unmarshal() error = %q, want substring \"unmarshal receipt\"", err)
	}
}

func TestUnmarshal_EmptyJSON(t *testing.T) {
	t.Parallel()

	r, err := Unmarshal([]byte("{}"))
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	// Empty JSON produces zero-value receipt. Verify should fail on it.
	if err := VerifyInternalConsistencyOnly(r); err == nil {
		t.Error("VerifyInternalConsistencyOnly() on empty receipt expected error, got nil")
	}
}

func TestSign_PreservesTimestamp(t *testing.T) {
	t.Parallel()

	_, priv := generateTestKey(t)
	ar := validActionRecord()
	fixedTime := time.Date(2026, 4, 4, 15, 30, 0, 0, time.UTC)
	ar.Timestamp = fixedTime

	r, err := Sign(ar, priv)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}
	if !r.ActionRecord.Timestamp.Equal(fixedTime) {
		t.Errorf("timestamp = %v, want %v", r.ActionRecord.Timestamp, fixedTime)
	}
}

func TestUnmarshalRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	// A duplicate key nested inside the action_record must be rejected on the
	// verify path with the shared sentinel. Exhaustive scanner cases (nesting,
	// arrays, depth bound, unicode escapes, string-delimiter handling) live in
	// internal/jsonscan.
	dupReceipt := `{"version":1,"action_record":{"version":1,"verdict":"allow","verdict":"block"},"signature":"ed25519:00","signer_key":"00"}`
	if _, err := Unmarshal([]byte(dupReceipt)); !errors.Is(err, ErrDuplicateKey) {
		t.Errorf("Unmarshal(dup verdict) = %v, want errors.Is ErrDuplicateKey", err)
	}
	// A clean receipt must not trip the duplicate-key check (it fails later on
	// signature, not on ErrDuplicateKey).
	clean := `{"version":1,"action_record":{"version":1},"signature":"ed25519:00","signer_key":"00"}`
	if _, err := Unmarshal([]byte(clean)); errors.Is(err, ErrDuplicateKey) {
		t.Errorf("Unmarshal(clean) wrongly reported ErrDuplicateKey: %v", err)
	}
}

// flipHexByte flips the first hex character in a hex string to produce
// a different but still valid hex string.
func flipHexByte(h string) string {
	if len(h) == 0 {
		return h
	}
	b := []byte(h)
	if b[0] == 'f' {
		b[0] = '0'
	} else {
		b[0] = 'f'
	}
	return string(b)
}
