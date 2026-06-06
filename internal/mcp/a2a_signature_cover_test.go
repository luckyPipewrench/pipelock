// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestCardSignatureVerificationActive(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	cases := []struct {
		name string
		cfg  *config.A2AScanning
		want bool
	}{
		{"nil", nil, false},
		{"disabled", &config.A2AScanning{Enabled: false, TrustedAgentCardKeys: trustCfg(t, pub).TrustedAgentCardKeys}, false},
		{"no_keys", &config.A2AScanning{Enabled: true}, false},
		{"active", trustCfg(t, pub), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CardSignatureVerificationActive(tc.cfg); got != tc.want {
				t.Fatalf("CardSignatureVerificationActive = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCardOriginFromURL_Invalid(t *testing.T) {
	for _, in := range []string{
		"",
		"   ",
		"not a url",
		"ftp://host/x",       // non-http scheme
		"/relative/path",     // no host
		"agent.example.com",  // no scheme
		"file:///etc/passwd", // no host, non-http
		"://noscheme",        // malformed
		"https://h:0",        // port out of range
		"https://h:99999",    // port out of range
		"https://h:notaport", // non-numeric port
		"https://:443",       // empty host
	} {
		if got := CardOriginFromURL(in); got != "" {
			t.Fatalf("CardOriginFromURL(%q) = %q, want empty", in, got)
		}
	}
}

func TestCardOriginFromURL_IPv6(t *testing.T) {
	cases := map[string]string{
		"https://[::1]/.well-known/agent-card.json": "https://[::1]",
		"https://[2001:db8::1]:8443/x":              "https://[2001:db8::1]:8443",
		"https://[2001:DB8::1]/x":                   "https://[2001:db8::1]",
		"http://[::1]:80/x":                         "http://[::1]", // default port stripped
	}
	for in, want := range cases {
		if got := CardOriginFromURL(in); got != want {
			t.Fatalf("CardOriginFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestVerify_ExceedsSignatureCap proves the maxCardSignatures DoS bound: a card
// stuffed with > 16 invalid signatures still fails closed (and only the first 16
// are evaluated).
func TestVerify_ExceedsSignatureCap(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	card := baseCard()
	sigs := make([]any, 0, 20)
	for i := 0; i < 20; i++ {
		sigs = append(sigs, map[string]any{
			"protected": b64u([]byte(`{"alg":"EdDSA"}`)),
			"signature": b64u(make([]byte, ed25519.SignatureSize)),
		})
	}
	card["signatures"] = sigs
	body, _ := json.Marshal(card)
	if res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub)); res.Outcome != SigOutcomeFailed {
		t.Fatalf("oversized signature set must fail closed, got %v", res.Outcome)
	}
}

// TestVerify_KidRoutesAcrossMultipleKeys covers orderByKidHint with several
// trusted keys: the card is signed by the second key and its kid points there.
func TestVerify_KidRoutesAcrossMultipleKeys(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv2, map[string]any{"alg": "EdDSA", "kid": "second"})
	cfg := &config.A2AScanning{
		Enabled: true,
		Action:  config.ActionBlock,
		TrustedAgentCardKeys: []config.A2ATrustedCardKey{
			{KeyID: "first", PublicKey: signing.EncodePublicKey(pub1), AllowedOrigins: []string{testCardOrigin}},
			{KeyID: "second", PublicKey: signing.EncodePublicKey(pub2), AllowedOrigins: []string{testCardOrigin}},
		},
	}
	res := VerifyAgentCardSignatures(card, testCardOrigin, cfg)
	if res.Outcome != SigOutcomeVerified || res.KeyID != "second" {
		t.Fatalf("expected verification by 'second', got %v/%q", res.Outcome, res.KeyID)
	}
}

// TestVerify_MalformedDetection covers the streaming detector / value-skipper on
// truncated cards: detection fails safely (treated as unsigned, handed to the
// caller's unparseable path).
func TestVerify_MalformedDetection(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	for _, body := range []string{
		`{"a":[1,2`,   // truncated nested array
		`{"a":{"b":1`, // truncated nested object
		`{"a":1,`,     // truncated after value
		`[1,2,3]`,     // not an object
	} {
		res := VerifyAgentCardSignatures([]byte(body), testCardOrigin, trustCfg(t, pub))
		if res.Outcome != SigOutcomeUnsigned {
			t.Fatalf("malformed/non-object %q should report Unsigned, got %v", body, res.Outcome)
		}
	}
}

// TestVerify_DeeplyNestedCardNoPanic proves the signature-claim detector bounds
// recursion: a card with deeply nested JSON before the signatures key returns a
// safe outcome (no stack-overflow panic).
func TestVerify_DeeplyNestedCardNoPanic(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	deep := strings.Repeat("[", 2000) + strings.Repeat("]", 2000)
	body := `{"a":` + deep + `,"signatures":[{"protected":"YQ","signature":"Yg"}]}`
	// Must not panic; detection bails out safely on the over-deep field.
	res := VerifyAgentCardSignatures([]byte(body), testCardOrigin, trustCfg(t, pub))
	if res.Outcome == SigOutcomeVerified {
		t.Fatalf("deeply nested card must not verify, got %v", res.Outcome)
	}
}

// cardWithProtected builds a card whose single signature carries the given
// protected header object (signature bytes are a zero placeholder).
func cardWithProtected(t *testing.T, hdr map[string]any) []byte {
	t.Helper()
	pb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	card := baseCard()
	card["signatures"] = []any{map[string]any{
		"protected": b64u(pb),
		"signature": b64u(make([]byte, ed25519.SignatureSize)),
	}}
	out, _ := json.Marshal(card)
	return out
}

// TestVerify_ProtectedHeaderRejections covers the strict protected-header parser:
// every malformed header must fail closed (the signature never verifies).
func TestVerify_ProtectedHeaderRejections(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	cases := map[string]map[string]any{
		"alg_not_string":     {"alg": 1},
		"kid_not_string":     {"alg": "EdDSA", "kid": 5},
		"b64_not_bool":       {"alg": "EdDSA", "b64": "false"},
		"crit_not_array":     {"alg": "EdDSA", "crit": "b64"},
		"crit_entry_not_str": {"alg": "EdDSA", "crit": []any{1}},
		"crit_unknown":       {"alg": "EdDSA", "crit": []any{"x5u"}},
		"crit_duplicate":     {"alg": "EdDSA", "b64": false, "crit": []any{"b64", "b64"}},
	}
	for name, hdr := range cases {
		t.Run(name, func(t *testing.T) {
			body := cardWithProtected(t, hdr)
			if res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub)); res.Outcome != SigOutcomeFailed {
				t.Fatalf("malformed protected header must fail, got %v", res.Outcome)
			}
		})
	}
}

// TestVerify_SignatureEntryRejections covers the strict signatures-array parser.
func TestVerify_SignatureEntryRejections(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	cases := map[string]string{
		"unknown_field":     `{"name":"x","signatures":[{"protected":"a","signature":"b","payload":"c"}]}`,
		"entry_not_object":  `{"name":"x","signatures":["nope"]}`,
		"protected_not_str": `{"name":"x","signatures":[{"protected":1,"signature":"b"}]}`,
		"signature_not_str": `{"name":"x","signatures":[{"protected":"a","signature":2}]}`,
		"header_not_object": `{"name":"x","signatures":[{"protected":"a","signature":"b","header":"nope"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if res := VerifyAgentCardSignatures([]byte(body), testCardOrigin, trustCfg(t, pub)); res.Outcome != SigOutcomeFailed {
				t.Fatalf("malformed signature entry must fail, got %v", res.Outcome)
			}
		})
	}
}

// TestVerify_DetectionSkipsNestedStructures exercises the streaming signatures
// detector across nested object/array values that precede the signatures key.
func TestVerify_DetectionSkipsNestedStructures(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	// "artifacts" (array) and "capabilities" (object) sort before "signatures";
	// the detector must skip their nested values and still find the signature.
	body := `{"artifacts":[1,[2,3],{"x":4}],"capabilities":{"a":{"b":1}},"signatures":[{"protected":"YQ","signature":"Yg"}]}`
	res := VerifyAgentCardSignatures([]byte(body), testCardOrigin, trustCfg(t, pub))
	// Detected as signed (not Unsigned); the placeholder signature is invalid -> Failed.
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("nested-structure card with a signature must be detected and fail, got %v", res.Outcome)
	}
}

// TestVerify_B64FalseWithoutCrit covers the RFC 7797 rule: an unencoded payload
// is only valid if "b64" is listed in "crit". Omitting crit must reject.
func TestVerify_B64FalseWithoutCrit(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := baseCard()
	pre := preimageOf(t, card)
	hdr := map[string]any{"alg": "EdDSA", "kid": testKeyID, "b64": false} // no crit
	pb, _ := json.Marshal(hdr)
	protectedB64 := b64u(pb)
	signingInput := append([]byte(protectedB64+"."), pre...)
	sig := ed25519.Sign(priv, signingInput)
	card["signatures"] = []any{map[string]any{"protected": protectedB64, "signature": b64u(sig)}}
	body, _ := json.Marshal(card)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("b64:false without crit must fail, got %v", res.Outcome)
	}
}

// TestVerify_UnknownOriginReason exercises the "(unknown)" reason path when the
// card origin cannot be derived.
func TestVerify_UnknownOriginReason(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())
	res := VerifyAgentCardSignatures(card, "not-a-url", trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("unknown origin must fail, got %v", res.Outcome)
	}
	if !strings.Contains(res.Reason, "(unknown)") {
		t.Fatalf("reason should mention unknown origin, got %q", res.Reason)
	}
}

// TestVerify_MalformedSignaturesContainer covers a signatures field that is not
// a JSON array.
func TestVerify_MalformedSignaturesContainer(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"name":"x","signatures":"not-an-array"}`)
	res := VerifyAgentCardSignatures(body, testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeFailed {
		t.Fatalf("malformed signatures container must fail, got %v", res.Outcome)
	}
}

// TestVerify_NotAJSONObject covers a non-object top-level body (left to the
// caller's unparseable path -> reported Unsigned here).
func TestVerify_NotAJSONObject(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	res := VerifyAgentCardSignatures([]byte(`["array","card"]`), testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeUnsigned {
		t.Fatalf("non-object body should report Unsigned, got %v", res.Outcome)
	}
}

// TestVerify_NullSignatures covers an explicit JSON null signatures member.
func TestVerify_NullSignatures(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	res := VerifyAgentCardSignatures([]byte(`{"name":"x","signatures":null}`), testCardOrigin, trustCfg(t, pub))
	if res.Outcome != SigOutcomeUnsigned {
		t.Fatalf("null signatures should report Unsigned, got %v", res.Outcome)
	}
}

// TestVerify_DefaultPortNormalization proves RFC 6454 origin semantics: a key
// pinned to "https://host:443" verifies a card served at "https://host" (and
// vice versa), since the default port is not a distinct origin.
func TestVerify_DefaultPortNormalization(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())

	// Key pinned WITH explicit :443; card fetched WITHOUT a port.
	cfg443 := trustCfg(t, pub, "https://agent.example.com:443")
	if res := VerifyAgentCardSignatures(card, "https://agent.example.com", cfg443); res.Outcome != SigOutcomeVerified {
		t.Fatalf(":443 key should verify a no-port card, got %v (%s)", res.Outcome, res.Reason)
	}

	// Key pinned WITHOUT a port; card fetched WITH explicit :443.
	cfgBare := trustCfg(t, pub, "https://agent.example.com")
	if res := VerifyAgentCardSignatures(card, "https://agent.example.com:443", cfgBare); res.Outcome != SigOutcomeVerified {
		t.Fatalf("no-port key should verify a :443 card, got %v (%s)", res.Outcome, res.Reason)
	}

	// A NON-default port stays distinct (no spurious match).
	cfg8443 := trustCfg(t, pub, "https://agent.example.com:8443")
	if res := VerifyAgentCardSignatures(card, "https://agent.example.com", cfg8443); res.Outcome != SigOutcomeFailed {
		t.Fatalf(":8443 key must NOT match a no-port card, got %v", res.Outcome)
	}
}

// TestVerify_RevocationByKeyRemoval proves that removing a key from the trusted
// set (the hot-reload revocation path) makes a previously-trusted signature fail.
func TestVerify_RevocationByKeyRemoval(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	card := signCard(t, baseCard(), priv, edHeader())

	// Before revocation: the signing key is trusted -> verifies.
	if res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, pub)); res.Outcome != SigOutcomeVerified {
		t.Fatalf("pre-revocation should verify, got %v (%s)", res.Outcome, res.Reason)
	}

	// After revocation: config reloaded with a different key for the same origin;
	// the old signature no longer maps to any trusted key -> fails closed.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if res := VerifyAgentCardSignatures(card, testCardOrigin, trustCfg(t, otherPub)); res.Outcome != SigOutcomeFailed {
		t.Fatalf("post-revocation should fail closed, got %v", res.Outcome)
	}
}

// TestVerify_SkipsUnparseableTrustedKey verifies a malformed trusted key entry
// is skipped without widening trust (a valid entry still verifies).
func TestVerify_SkipsUnparseableTrustedKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	cfg := trustCfg(t, pub)
	cfg.TrustedAgentCardKeys = append([]config.A2ATrustedCardKey{
		{KeyID: "broken", PublicKey: "not-a-key", AllowedOrigins: []string{testCardOrigin}},
	}, cfg.TrustedAgentCardKeys...)
	card := signCard(t, baseCard(), priv, edHeader())
	res := VerifyAgentCardSignatures(card, testCardOrigin, cfg)
	if res.Outcome != SigOutcomeVerified {
		t.Fatalf("valid key alongside a broken entry must still verify, got %v (%s)", res.Outcome, res.Reason)
	}
}
