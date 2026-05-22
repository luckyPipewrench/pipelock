// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testMessageKeyID = "test-server-2026-05"
	testMessageAlg   = MessageSigAlgEd25519
)

func newTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return pub, priv
}

func newTestNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func mustEmbed(t *testing.T, envelope []byte, sig SignedMessage) []byte {
	t.Helper()
	out, err := EmbedMessageSignature(envelope, sig)
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	return out
}

func envelopeWithoutMeta(t *testing.T, params, id json.RawMessage) []byte {
	t.Helper()
	type env struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id,omitempty"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
	}
	data, err := json.Marshal(env{JSONRPC: "2.0", ID: id, Method: "tools/call", Params: params})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

// --- SignMessage error paths ---

func TestSignMessage_RejectsBadPrivateKey(t *testing.T) {
	bad := make(ed25519.PrivateKey, 8) // wrong size
	_, err := SignMessage("tools/call", nil, nil, bad, testMessageKeyID, newTestNonce(t), time.Now())
	if err == nil {
		t.Fatal("expected error for wrong private-key size")
	}
}

func TestSignMessage_RequiresKeyID(t *testing.T) {
	_, priv := newTestKeypair(t)
	_, err := SignMessage("tools/call", nil, nil, priv, "", newTestNonce(t), time.Now())
	if err == nil {
		t.Fatal("expected error for empty keyID")
	}
}

func TestSignMessage_RejectsShortNonce(t *testing.T) {
	_, priv := newTestKeypair(t)
	// 8 raw bytes < MinNonceLen
	short := base64.StdEncoding.EncodeToString([]byte("12345678"))
	_, err := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, short, time.Now())
	if err == nil {
		t.Fatal("expected error for short nonce")
	}
}

func TestSignMessage_RejectsBadBase64Nonce(t *testing.T) {
	_, priv := newTestKeypair(t)
	_, err := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, "not!!base64", time.Now())
	if err == nil {
		t.Fatal("expected error for non-base64 nonce")
	}
}

// --- VerifyMessage happy path ---

func TestVerifyMessage_RoundTrip(t *testing.T) {
	pub, priv := newTestKeypair(t)
	method := "tools/call"
	params := json.RawMessage(`{"name":"echo","arguments":{"x":1}}`)
	id := json.RawMessage(`42`)
	ts := time.Now()
	nonce := newTestNonce(t)

	sig, err := SignMessage(method, params, id, priv, testMessageKeyID, nonce, ts)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed := mustEmbed(t, envelopeWithoutMeta(t, params, id), sig)

	cfg := MessageVerifyConfig{
		PublicKey:  pub,
		KeyID:      testMessageKeyID,
		MaxAge:     5 * time.Minute,
		NonceCache: NewMemoryReplayCache(),
		Clock:      func() time.Time { return ts.Add(1 * time.Second) },
	}
	result := VerifyMessage(signed, cfg)
	if result.Status != MessageSigVerified {
		t.Errorf("expected Verified, got %v / %s", result.Status, result.Reason)
	}
	if result.SignedBy != testMessageKeyID {
		t.Errorf("SignedBy=%q want %q", result.SignedBy, testMessageKeyID)
	}
}

// --- VerifyMessage failure paths ---

func TestVerifyMessage_Unsigned(t *testing.T) {
	pub, _ := newTestKeypair(t)
	env := envelopeWithoutMeta(t, nil, nil)
	cfg := MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     testMessageKeyID,
		MaxAge:    5 * time.Minute,
	}
	result := VerifyMessage(env, cfg)
	if result.Status != MessageSigUnsigned {
		t.Errorf("expected Unsigned, got %v / %s", result.Status, result.Reason)
	}
}

func TestVerifyMessage_BadKeyID(t *testing.T) {
	pub, priv := newTestKeypair(t)
	ts := time.Now()
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)
	cfg := MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     "some-other-key",
		MaxAge:    5 * time.Minute,
		Clock:     func() time.Time { return ts },
	}
	result := VerifyMessage(signed, cfg)
	if result.Status != MessageSigBadKeyID {
		t.Errorf("expected BadKeyID, got %v / %s", result.Status, result.Reason)
	}
}

func TestVerifyMessage_Expired(t *testing.T) {
	pub, priv := newTestKeypair(t)
	ts := time.Now()
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	cfg := MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     testMessageKeyID,
		MaxAge:    1 * time.Minute,
		Clock:     func() time.Time { return ts.Add(10 * time.Minute) },
	}
	result := VerifyMessage(signed, cfg)
	if result.Status != MessageSigExpired {
		t.Errorf("expected Expired, got %v / %s", result.Status, result.Reason)
	}
}

func TestVerifyMessage_FutureTimestamp(t *testing.T) {
	pub, priv := newTestKeypair(t)
	ts := time.Now()
	// Sign with a timestamp far in the future.
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), ts.Add(1*time.Hour))
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	cfg := MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     testMessageKeyID,
		MaxAge:    1 * time.Minute,
		Clock:     func() time.Time { return ts },
	}
	result := VerifyMessage(signed, cfg)
	if result.Status != MessageSigExpired {
		t.Errorf("expected Expired (future), got %v / %s", result.Status, result.Reason)
	}
}

func TestVerifyMessage_Replay(t *testing.T) {
	pub, priv := newTestKeypair(t)
	ts := time.Now()
	nonce := newTestNonce(t)
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, nonce, ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	cache := NewMemoryReplayCache()
	cfg := MessageVerifyConfig{
		PublicKey:  pub,
		KeyID:      testMessageKeyID,
		MaxAge:     5 * time.Minute,
		NonceCache: cache,
		Clock:      func() time.Time { return ts.Add(1 * time.Second) },
	}
	// First time: ok.
	first := VerifyMessage(signed, cfg)
	if first.Status != MessageSigVerified {
		t.Fatalf("first should verify, got %v", first.Status)
	}
	// Second time with same nonce: replay.
	second := VerifyMessage(signed, cfg)
	if second.Status != MessageSigReplay {
		t.Errorf("expected Replay on second call, got %v / %s", second.Status, second.Reason)
	}
}

func TestVerifyMessage_TamperedParams(t *testing.T) {
	pub, priv := newTestKeypair(t)
	ts := time.Now()
	method := "tools/call"
	params := json.RawMessage(`{"name":"echo","arguments":{"x":1}}`)
	sig, _ := SignMessage(method, params, nil, priv, testMessageKeyID, newTestNonce(t), ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, params, nil), sig)

	// Tamper with params after signing — replace x:1 with x:2.
	tampered := strings.Replace(string(signed), `"x":1`, `"x":2`, 1)

	cfg := MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     testMessageKeyID,
		MaxAge:    5 * time.Minute,
		Clock:     func() time.Time { return ts.Add(1 * time.Second) },
	}
	result := VerifyMessage([]byte(tampered), cfg)
	if result.Status != MessageSigInvalid {
		t.Errorf("expected Invalid after tampering, got %v / %s", result.Status, result.Reason)
	}
}

func TestVerifyMessage_TamperedMethod(t *testing.T) {
	pub, priv := newTestKeypair(t)
	ts := time.Now()
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	// Replace method name.
	tampered := strings.Replace(string(signed), `"method":"tools/call"`, `"method":"resources/read"`, 1)

	cfg := MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     testMessageKeyID,
		MaxAge:    5 * time.Minute,
		Clock:     func() time.Time { return ts.Add(1 * time.Second) },
	}
	result := VerifyMessage([]byte(tampered), cfg)
	if result.Status != MessageSigInvalid {
		t.Errorf("expected Invalid after method tamper, got %v / %s", result.Status, result.Reason)
	}
}

func TestVerifyMessage_MalformedEnvelope(t *testing.T) {
	pub, _ := newTestKeypair(t)
	cfg := MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     testMessageKeyID,
		MaxAge:    5 * time.Minute,
	}
	result := VerifyMessage([]byte(`{not valid json`), cfg)
	if result.Status != MessageSigMalformed {
		t.Errorf("expected Malformed, got %v", result.Status)
	}
}

func TestVerifyMessage_BadAlgorithm(t *testing.T) {
	pub, _ := newTestKeypair(t)
	// Manually construct a signed message with an unsupported alg.
	sig := SignedMessage{
		Algorithm: "rsa-pkcs1-sha256", // not supported
		KeyID:     testMessageKeyID,
		Timestamp: time.Now().Unix(),
		Nonce:     newTestNonce(t),
		Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)
	cfg := MessageVerifyConfig{
		PublicKey: pub,
		KeyID:     testMessageKeyID,
		MaxAge:    5 * time.Minute,
	}
	result := VerifyMessage(signed, cfg)
	if result.Status != MessageSigBadAlg {
		t.Errorf("expected BadAlg, got %v / %s", result.Status, result.Reason)
	}
}

func TestVerifyMessage_BadPublicKey(t *testing.T) {
	_, priv := newTestKeypair(t)
	ts := time.Now()
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	cfg := MessageVerifyConfig{
		PublicKey: make(ed25519.PublicKey, 8), // wrong size
		KeyID:     testMessageKeyID,
		MaxAge:    5 * time.Minute,
		Clock:     func() time.Time { return ts },
	}
	result := VerifyMessage(signed, cfg)
	if result.Status != MessageSigInvalid {
		t.Errorf("expected Invalid for bad pub key, got %v", result.Status)
	}
}

func TestVerifyMessage_RequiresTrustAnchorKeyID(t *testing.T) {
	pub, priv := newTestKeypair(t)
	ts := time.Now()
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	cfg := MessageVerifyConfig{
		PublicKey: pub,
		MaxAge:    5 * time.Minute,
		Clock:     func() time.Time { return ts },
	}
	result := VerifyMessage(signed, cfg)
	if result.Status != MessageSigInvalid {
		t.Errorf("expected Invalid for missing trust-anchor key ID, got %v / %s", result.Status, result.Reason)
	}
	if !strings.Contains(result.Reason, "key ID") {
		t.Errorf("expected reason to mention key ID, got %q", result.Reason)
	}
}

func TestVerifyMessage_RequiresPositiveMaxAge(t *testing.T) {
	pub, priv := newTestKeypair(t)
	ts := time.Now()
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	for _, maxAge := range []time.Duration{0, -1 * time.Second, -5 * time.Minute} {
		t.Run(maxAge.String(), func(t *testing.T) {
			cfg := MessageVerifyConfig{
				PublicKey: pub,
				KeyID:     testMessageKeyID,
				MaxAge:    maxAge,
				Clock:     func() time.Time { return ts },
			}
			result := VerifyMessage(signed, cfg)
			if result.Status != MessageSigInvalid {
				t.Errorf("expected Invalid for max-age %s, got %v / %s", maxAge, result.Status, result.Reason)
			}
			if !strings.Contains(result.Reason, "max-age") {
				t.Errorf("expected reason to mention max-age, got %q", result.Reason)
			}
		})
	}
}

func TestVerifyMessage_DifferentSigner(t *testing.T) {
	_, priv := newTestKeypair(t)
	pub2, _ := newTestKeypair(t) // separate keypair
	ts := time.Now()
	sig, _ := SignMessage("tools/call", nil, nil, priv, testMessageKeyID, newTestNonce(t), ts)
	signed := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	cfg := MessageVerifyConfig{
		PublicKey: pub2, // verifier holds a different key
		KeyID:     testMessageKeyID,
		MaxAge:    5 * time.Minute,
		Clock:     func() time.Time { return ts.Add(1 * time.Second) },
	}
	result := VerifyMessage(signed, cfg)
	if result.Status != MessageSigInvalid {
		t.Errorf("expected Invalid for wrong public key, got %v", result.Status)
	}
}

// --- MemoryReplayCache directly ---

func TestMemoryReplayCache_BasicSeenRecord(t *testing.T) {
	c := NewMemoryReplayCache()
	now := time.Now()
	if c.Seen("abc", now.Add(-1*time.Minute)) {
		t.Fatal("empty cache should not report seen")
	}
	c.Record("abc", now)
	if !c.Seen("abc", now.Add(-1*time.Minute)) {
		t.Fatal("just-recorded nonce should be seen")
	}
}

func TestMemoryReplayCache_EvictsAfterTTL(t *testing.T) {
	c := NewMemoryReplayCache()
	c.SetMaxTTL(1 * time.Minute)

	// Record an old nonce at t=0.
	t0 := time.Now().Add(-10 * time.Minute)
	c.Record("old", t0)

	// Record a new nonce at t=now; the eviction sweep should drop "old".
	c.Record("new", time.Now())

	if c.Seen("old", t0) {
		t.Error("old nonce should have been evicted by SetMaxTTL")
	}
	if !c.Seen("new", time.Now().Add(-1*time.Second)) {
		t.Error("new nonce should still be present")
	}
}

func TestExtractSignedMessage_RoundTrip(t *testing.T) {
	sig := SignedMessage{
		Algorithm: MessageSigAlgEd25519,
		KeyID:     "k1",
		Timestamp: 1234567890,
		Nonce:     newTestNonce(t),
		Signature: "AA==",
	}
	env := mustEmbed(t, envelopeWithoutMeta(t, nil, nil), sig)

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(env, &parsed); err != nil {
		t.Fatal(err)
	}
	got, ok := extractSignedMessage(parsed["_meta"])
	if !ok {
		t.Fatal("should extract signature")
	}
	if got.KeyID != sig.KeyID || got.Nonce != sig.Nonce {
		t.Errorf("round-trip mismatch: got %+v", got)
	}
}

func TestExtractSignedMessage_MissingKey(t *testing.T) {
	// _meta exists but doesn't contain the message-signature key.
	otherMeta := json.RawMessage(`{"com.other/key": {"foo": "bar"}}`)
	_, ok := extractSignedMessage(otherMeta)
	if ok {
		t.Error("should not extract signature from unrelated _meta")
	}
}
