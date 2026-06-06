// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/jcs"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	testCardOrigin = "https://agent.example.com"
	testKeyID      = "vendor-agent-v1"
)

// baseCard returns a minimal Agent Card object (no signatures) for signing.
func baseCard() map[string]any {
	return map[string]any{
		"name":        "Vendor Agent",
		"description": "does things",
		"version":     "1.0.0",
		"skills": []any{
			map[string]any{"id": "s1", "name": "search"},
		},
	}
}

func preimageOf(t *testing.T, card map[string]any) []byte {
	t.Helper()
	cp := map[string]any{}
	for k, v := range card {
		if k == "signatures" {
			continue
		}
		cp[k] = v
	}
	b, err := jcs.Marshal(cp)
	if err != nil {
		t.Fatalf("jcs.Marshal preimage: %v", err)
	}
	return b
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signingInputEncoded builds the JWS signing input for the default (b64=true) case.
func signingInputEncoded(protectedB64 string, preimage []byte) []byte {
	return []byte(protectedB64 + "." + b64u(preimage))
}

// signCard signs card with priv using the given protected header and returns the
// full signed card JSON. extraSigs are appended verbatim after the real signature.
func signCard(t *testing.T, card map[string]any, priv ed25519.PrivateKey, protectedHdr map[string]any, extraSigs ...map[string]any) []byte {
	t.Helper()
	pre := preimageOf(t, card)
	pb, err := json.Marshal(protectedHdr)
	if err != nil {
		t.Fatalf("marshal protected: %v", err)
	}
	protectedB64 := b64u(pb)
	sig := ed25519.Sign(priv, signingInputEncoded(protectedB64, pre))
	sigs := []any{map[string]any{"protected": protectedB64, "signature": b64u(sig)}}
	for _, e := range extraSigs {
		sigs = append(sigs, e)
	}
	card["signatures"] = sigs
	out, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	return out
}

func trustCfg(t *testing.T, pub ed25519.PublicKey, origins ...string) *config.A2AScanning {
	t.Helper()
	if len(origins) == 0 {
		origins = []string{testCardOrigin}
	}
	return &config.A2AScanning{
		Enabled: true,
		Action:  config.ActionBlock,
		TrustedAgentCardKeys: []config.A2ATrustedCardKey{
			{KeyID: testKeyID, PublicKey: signing.EncodePublicKey(pub), AllowedOrigins: origins},
		},
	}
}

func edHeader() map[string]any { return map[string]any{"alg": "EdDSA", "kid": testKeyID} }

// --- Happy path ---

func TestVerify_ValidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeVerified {
		t.Fatalf("want Verified, got %v (%s)", res.Outcome, res.Reason)
	}
	if res.KeyID != testKeyID {
		t.Fatalf("want KeyID %q, got %q", testKeyID, res.KeyID)
	}
}

func TestVerify_ValidSignature_NoKidStillVerifies(t *testing.T) {
	// kid is a hint only: omit it entirely and the origin-scoped key must still verify.
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, map[string]any{"alg": "EdDSA"})
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeVerified {
		t.Fatalf("want Verified with no kid, got %v (%s)", res.Outcome, res.Reason)
	}
}

// --- Adversarial: each MUST fail closed (SigOutcomeFailed) ---

func TestVerify_ForgedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	// Replace the signature with random-but-correct-length bytes.
	forged := make([]byte, ed25519.SignatureSize)
	for i := range forged {
		forged[i] = byte(i)
	}
	card = replaceSig(t, card, b64u(forged))
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("forged signature must fail closed, got %v", res.Outcome)
	}
}

func TestVerify_SubstitutedSignature(t *testing.T) {
	// Sign card A, then present a DIFFERENT card B carrying A's signature.
	pub, priv, _ := ed25519.GenerateKey(nil)
	signed := signCard(t, baseCard(), priv, edHeader())
	var cardA map[string]any
	if err := json.Unmarshal(signed, &cardA); err != nil {
		t.Fatal(err)
	}
	// Tamper: change a scanned field, keep the (now stale) signature.
	cardB := baseCard()
	cardB["description"] = "ELEVATED PRIVILEGES"
	cardB["signatures"] = cardA["signatures"]
	body, _ := json.Marshal(cardB)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("substituted signature must fail, got %v", res.Outcome)
	}
}

func TestVerify_UntrustedKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)       // signer
	pubTrusted, _, _ := ed25519.GenerateKey(nil) // unrelated trusted key
	card := signCard(t, baseCard(), priv, edHeader())
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pubTrusted))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("untrusted signing key must fail, got %v", res.Outcome)
	}
}

func TestVerify_AlgNone(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, map[string]any{"alg": "none", "kid": testKeyID})
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("alg:none must fail, got %v", res.Outcome)
	}
}

func TestVerify_AlgConfusionRS256(t *testing.T) {
	// Header claims RS256; even though the bytes were ed25519-signed, we must
	// refuse to verify anything but EdDSA.
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, map[string]any{"alg": "RS256", "kid": testKeyID})
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("alg confusion (RS256) must fail, got %v", res.Outcome)
	}
}

func TestVerify_EmptySignatureField(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	card = replaceSig(t, card, "")
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("empty signature must fail, got %v", res.Outcome)
	}
}

func TestVerify_ShortSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	card = replaceSig(t, card, b64u(make([]byte, 32))) // wrong length
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("short signature must fail, got %v", res.Outcome)
	}
}

func TestVerify_OriginMismatch(t *testing.T) {
	// Valid signature by a key scoped to origin A; card fetched from origin B.
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	res := VerifyAgentCardSignatures(card, "https://evil.example.net", trustCfg(t, pub, testCardOrigin))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("origin mismatch must fail, got %v", res.Outcome)
	}
}

func TestVerify_DuplicateTopLevelKeys(t *testing.T) {
	// A card with duplicate top-level keys has an ambiguous preimage and must fail.
	pub, priv, _ := ed25519.GenerateKey(nil)
	signed := signCard(t, baseCard(), priv, edHeader())
	// Inject a duplicate "name" key by string surgery (json.Marshal won't make one).
	dup := `{"name":"x",` + string(signed[1:])
	res := VerifyAgentCardSignatures([]byte(dup), testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("duplicate keys must fail closed, got %v (%s)", res.Outcome, res.Reason)
	}
}

func TestVerify_TrailingTokens(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signed := signCard(t, baseCard(), priv, edHeader())
	withTrailer := append(append([]byte{}, signed...), []byte(" {}")...)
	res := VerifyAgentCardSignatures(withTrailer, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("trailing tokens must fail closed, got %v", res.Outcome)
	}
}

func TestVerify_DuplicateSignaturesField(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signed := signCard(t, baseCard(), priv, edHeader())
	dup := append([]byte(`{"signatures":null,`), signed[1:]...)
	res := VerifyAgentCardSignatures(dup, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("duplicate signatures field must fail closed, got %v (%s)", res.Outcome, res.Reason)
	}
}

func TestVerify_TamperedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := baseCard()
	signed := signCard(t, card, priv, edHeader())
	var m map[string]any
	_ = json.Unmarshal(signed, &m)
	m["description"] = "tampered after signing"
	body, _ := json.Marshal(m)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("tampered body must fail, got %v", res.Outcome)
	}
}

func TestVerify_DuplicateProtectedHeaderField(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := baseCard()
	pre := preimageOf(t, card)
	protectedB64 := b64u([]byte(`{"alg":"none","alg":"EdDSA","kid":"` + testKeyID + `"}`))
	sig := ed25519.Sign(priv, signingInputEncoded(protectedB64, pre))
	card["signatures"] = []any{map[string]any{"protected": protectedB64, "signature": b64u(sig)}}
	body, _ := json.Marshal(card)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("duplicate protected header must fail closed, got %v", res.Outcome)
	}
}

func TestVerify_UnknownCriticalProtectedHeader(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, map[string]any{
		"alg":  "EdDSA",
		"kid":  testKeyID,
		"crit": []any{"exp"},
		"exp":  true,
	})
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("unknown critical header must fail closed, got %v", res.Outcome)
	}
}

func TestVerify_UnsupportedSignatureEntryField(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	var m map[string]any
	if err := json.Unmarshal(card, &m); err != nil {
		t.Fatal(err)
	}
	sigs := m["signatures"].([]any)
	sigs[0].(map[string]any)["payload"] = "unsigned-payload-confuser"
	body, _ := json.Marshal(m)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("unsupported signature entry field must fail closed, got %v", res.Outcome)
	}
}

// --- Adversarial: must NOT block (Verified/Unsigned as appropriate) ---

func TestVerify_UnknownKidButAnotherValid(t *testing.T) {
	// One signature has an unknown kid + garbage; a second is genuinely valid.
	// kid is a hint, so the valid signature must carry the card.
	pub, priv, _ := ed25519.GenerateKey(nil)
	garbage := map[string]any{
		"protected": b64u([]byte(`{"alg":"EdDSA","kid":"who-knows"}`)),
		"signature": b64u(make([]byte, ed25519.SignatureSize)),
	}
	card := signCard(t, baseCard(), priv, edHeader(), garbage)
	res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeVerified {
		t.Fatalf("a valid sig alongside an unknown-kid sig must verify, got %v (%s)", res.Outcome, res.Reason)
	}
}

func TestVerify_Unsigned(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	body, _ := json.Marshal(baseCard())
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeUnsigned {
		t.Fatalf("unsigned card must report Unsigned, got %v", res.Outcome)
	}
}

func TestVerify_EmptySignaturesArray(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	card := baseCard()
	card["signatures"] = []any{}
	body, _ := json.Marshal(card)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeUnsigned {
		t.Fatalf("empty signatures array must report Unsigned, got %v", res.Outcome)
	}
}

func TestVerify_B64FalsePayload(t *testing.T) {
	// RFC 7797 unencoded payload (b64:false with crit) must verify.
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := baseCard()
	pre := preimageOf(t, card)
	hdr := map[string]any{"alg": "EdDSA", "kid": testKeyID, "b64": false, "crit": []any{"b64"}}
	pb, _ := json.Marshal(hdr)
	protectedB64 := b64u(pb)
	signingInput := append([]byte(protectedB64+"."), pre...)
	sig := ed25519.Sign(priv, signingInput)
	card["signatures"] = []any{map[string]any{"protected": protectedB64, "signature": b64u(sig)}}
	body, _ := json.Marshal(card)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeVerified {
		t.Fatalf("b64:false payload must verify, got %v (%s)", res.Outcome, res.Reason)
	}
}

func TestVerify_MalformedProtectedHeader(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	var m map[string]any
	_ = json.Unmarshal(card, &m)
	sigs := m["signatures"].([]any)
	sigs[0].(map[string]any)["protected"] = "!!!not base64url!!!"
	body, _ := json.Marshal(m)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("malformed protected header must fail, got %v", res.Outcome)
	}
}

// --- Origin helper ---

func TestCardOriginFromURL(t *testing.T) {
	cases := map[string]string{
		"https://agent.example.com/.well-known/agent-card.json": "https://agent.example.com",
		"https://agent.example.com:8443/extendedAgentCard":      "https://agent.example.com:8443",
		"https://[2001:db8::1]:8443/card":                       "https://[2001:db8::1]:8443",
		"http://h/x":                                            "http://h",
	}
	for in, want := range cases {
		if got := CardOriginFromURL(in); got != want {
			t.Fatalf("CardOriginFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// replaceSig swaps the signature value of the first signature entry.
func replaceSig(t *testing.T, card []byte, newSig string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(card, &m); err != nil {
		t.Fatal(err)
	}
	sigs := m["signatures"].([]any)
	sigs[0].(map[string]any)["signature"] = newSig
	out, _ := json.Marshal(m)
	return out
}
