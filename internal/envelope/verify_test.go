// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVerifier_VerifyRequestAcceptsSignedEnvelope(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedVerifierRequest(t, priv, now, strings.Repeat("a", 16))

	verifier := newTestVerifier(t, pub, now)
	env, err := verifier.VerifyRequest(req, []byte(strings.Repeat("a", 16)))
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if env.Actor != "spiffe://example.test/agent/alpha" {
		t.Fatalf("actor = %q", env.Actor)
	}
}

func TestVerifier_VerifyRequestRejectsTamperReplayExpiredAndUnknownSigner(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	otherPub, _ := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	t.Run("tampered", func(t *testing.T) {
		req := signedVerifierRequest(t, priv, now, "")
		req.Header.Set(HeaderName, strings.Replace(req.Header.Get(HeaderName), `vd="allow"`, `vd="block"`, 1))
		verifier := newTestVerifier(t, pub, now)
		if _, err := verifier.VerifyRequest(req, nil); err == nil {
			t.Fatal("tampered mediation header should fail verification")
		}
	})

	t.Run("replay", func(t *testing.T) {
		req := signedVerifierRequest(t, priv, now, "")
		verifier := newTestVerifier(t, pub, now)
		if _, err := verifier.VerifyRequest(req, nil); err != nil {
			t.Fatalf("first VerifyRequest: %v", err)
		}
		if _, err := verifier.VerifyRequest(req, nil); err == nil {
			t.Fatal("replayed nonce should fail verification")
		}
	})

	t.Run("expired", func(t *testing.T) {
		req := signedVerifierRequest(t, priv, now, "")
		verifier := newTestVerifier(t, pub, now.Add(10*time.Minute))
		if _, err := verifier.VerifyRequest(req, nil); err == nil {
			t.Fatal("expired signature should fail verification")
		}
	})

	t.Run("unknown signer", func(t *testing.T) {
		req := signedVerifierRequest(t, priv, now, "")
		verifier := newTestVerifier(t, otherPub, now)
		if _, err := verifier.VerifyRequest(req, nil); err == nil {
			t.Fatal("unknown signer should fail verification")
		}
	})
}

func TestReplayCacheConcurrentAndEviction(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	cache := newReplayCache(time.Minute, 1000, func() time.Time { return now })
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- cache.CheckAndStore("nonce-"+strconv.Itoa(i), now.Add(time.Minute))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent CheckAndStore: %v", err)
		}
	}
	if err := cache.CheckAndStore("nonce-0", now.Add(time.Minute)); err == nil {
		t.Fatal("duplicate nonce should be rejected")
	}

	evict := newReplayCache(time.Minute, 1, func() time.Time { return now })
	if err := evict.CheckAndStore("old", now.Add(time.Minute)); err != nil {
		t.Fatalf("store old: %v", err)
	}
	if err := evict.CheckAndStore("new", now.Add(time.Minute)); err != nil {
		t.Fatalf("store new: %v", err)
	}
	if err := evict.CheckAndStore("old", now.Add(time.Minute)); err != nil {
		t.Fatalf("old nonce should have been cap-evicted: %v", err)
	}

	expired := newReplayCache(time.Minute, 2, func() time.Time { return now })
	if err := expired.CheckAndStore("gone", now.Add(time.Second)); err != nil {
		t.Fatalf("store gone: %v", err)
	}
	now = now.Add(2 * time.Second)
	if err := expired.CheckAndStore("gone", now.Add(time.Minute)); err != nil {
		t.Fatalf("expired nonce should have been window-evicted: %v", err)
	}
}

func TestReplayCacheHonorsVerifierSkew(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	cache := newReplayCache(time.Minute, 10, func() time.Time { return now })

	if err := cache.CheckAndStoreWithSkew("near-expired", now.Add(-30*time.Second), time.Minute); err != nil {
		t.Fatalf("near-expired signature should be accepted within skew: %v", err)
	}
	if err := cache.CheckAndStoreWithSkew("near-expired", now.Add(-30*time.Second), time.Minute); err == nil {
		t.Fatal("nonce accepted within skew must still be replay-protected")
	}
	if err := cache.CheckAndStoreWithSkew("too-old", now.Add(-2*time.Minute), time.Minute); err == nil {
		t.Fatal("signature older than skew should be rejected")
	}
}

func TestParseAndFormatActor(t *testing.T) {
	t.Parallel()

	legacy, err := ParseActor("agent:legacy")
	if err != nil {
		t.Fatalf("ParseActor legacy: %v", err)
	}
	if legacy.IsSPIFFE {
		t.Fatal("legacy actor parsed as SPIFFE")
	}

	spiffe, err := ParseActor("spiffe://Example.Test/agent/alpha")
	if err != nil {
		t.Fatalf("ParseActor spiffe: %v", err)
	}
	if !spiffe.IsSPIFFE || spiffe.TrustDomain != "example.test" || spiffe.Workload != "/agent/alpha" {
		t.Fatalf("unexpected parsed SPIFFE actor: %+v", spiffe)
	}

	upper, err := ParseActor("SPIFFE://Example.Test/agent/alpha")
	if err != nil {
		t.Fatalf("ParseActor uppercase scheme: %v", err)
	}
	if !upper.IsSPIFFE || upper.TrustDomain != "example.test" {
		t.Fatalf("uppercase scheme parsed as %+v", upper)
	}

	formatted, err := FormatActor("Alpha Agent", ActorFormatSPIFFE, "Example.Test")
	if err != nil {
		t.Fatalf("FormatActor: %v", err)
	}
	if formatted != "spiffe://example.test/agent/Alpha-Agent" {
		t.Fatalf("FormatActor = %q", formatted)
	}
	preserved, err := FormatActor("SPIFFE://Example.Test/agent/alpha", ActorFormatSPIFFE, "example.test")
	if err != nil {
		t.Fatalf("FormatActor uppercase SPIFFE actor: %v", err)
	}
	if preserved != "SPIFFE://Example.Test/agent/alpha" {
		t.Fatalf("FormatActor preserved = %q", preserved)
	}
	if _, err := ParseActor("spiffe:///missing-domain"); err == nil {
		t.Fatal("malformed SPIFFE actor should fail")
	}
}

// TestParseActor_StrictSPIFFE pins the strictness gates added in the
// federation-hardening pass: SPIFFE-ID §2 prohibits userinfo and ports
// in the trust domain, and the workload path must be canonical so an
// allowlist comparison on Workload cannot be bypassed via ".." or empty
// segments. Each case is a real bypass surface, not a style preference.
func TestParseActor_StrictSPIFFE(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
	}{
		{"userinfo", "spiffe://user:pass@trust.example/agent/x"},
		{"port", "spiffe://trust.example:8443/agent/x"},
		{"path traversal", "spiffe://trust.example/agent/../admin"},
		{"empty segment", "spiffe://trust.example/agent//x"},
		{"dot segment", "spiffe://trust.example/./agent/x"},
		{"trailing slash", "spiffe://trust.example/agent/x/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ParseActor(tc.raw); err == nil {
				t.Fatalf("ParseActor(%q) accepted, got %+v; want error", tc.raw, got)
			}
		})
	}
}

func TestIsValidTrustDomain(t *testing.T) {
	t.Parallel()
	good := []string{"trust.example", "partner.internal", "a", "single-label"}
	for _, d := range good {
		if !IsValidTrustDomain(d) {
			t.Errorf("IsValidTrustDomain(%q) = false; want true", d)
		}
	}
	bad := []string{"", "trust.example/agent/x", "trust.example:8443", "u@trust.example", "scheme://trust", "with spaces", "trailing/"}
	for _, d := range bad {
		if IsValidTrustDomain(d) {
			t.Errorf("IsValidTrustDomain(%q) = true; want false", d)
		}
	}
}

// TestVerifier_RejectsLifetimeOverWindow proves the cap added in
// validateTime: a signature whose expires-created span exceeds the
// configured MaxSignatureLifetime is refused, even if signed by a
// trusted key. Without the cap, an attacker who captured a long-lived
// signature could replay it after the nonce was evicted from the
// replay cache.
func TestVerifier_RejectsLifetimeOverWindow(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	// Signer emits a 10-minute signature.
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "trusted-key",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerPipelockMediation},
		Expires:          10 * time.Minute,
		NowFn:            func() time.Time { return now },
		RandReader:       bytes.NewReader([]byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash:  strings.Repeat("a", 64),
		Signer:      signer,
		ActorFormat: ActorFormatSPIFFE,
		TrustDomain: "example.test",
	})
	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000003",
		Action:    "read",
		Verdict:   "allow",
		Actor:     "alpha",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}

	// Verifier caps lifetime at 5 minutes; the 10-min signature must be rejected.
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys:          []TrustedKey{{KeyID: "trusted-key", PublicKey: pub}},
		ReplayCache:          newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:                 time.Minute,
		MaxSignatureLifetime: 5 * time.Minute,
		NowFn:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.VerifyRequest(req, nil); err == nil {
		t.Fatal("over-window signature should fail verification")
	}
}

// TestVerifier_RejectsActorTrustDomainMismatch proves the per-key actor
// binding: a TrustedKey with a TrustDomains allowlist refuses to attest
// envelopes whose actor's trust domain is not in the list. Without this
// binding, a single compromised partner key signs envelopes for any
// other federation peer.
func TestVerifier_RejectsActorTrustDomainMismatch(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedVerifierRequest(t, priv, now, "")

	// Trust list pins this key to "other.example", but the request's
	// actor is spiffe://example.test/agent/alpha — must reject.
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:        "trusted-key",
			PublicKey:    pub,
			TrustDomains: []string{"other.example"},
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.VerifyRequest(req, nil); err == nil {
		t.Fatal("actor trust domain mismatch should fail verification")
	}

	// Same key, but allowlist now includes the actor's trust domain — must accept.
	req2 := signedVerifierRequest(t, priv, now, "")
	verifier2, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:        "trusted-key",
			PublicKey:    pub,
			TrustDomains: []string{"example.test"},
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier2.VerifyRequest(req2, nil); err != nil {
		t.Fatalf("matching trust domain should verify: %v", err)
	}
}

func TestVerifier_TrustDomainPinRequiresSPIFFEActor(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	req := signedLegacyActorRequest(t, priv, now)
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:        "trusted-key",
			PublicKey:    pub,
			TrustDomains: []string{"example.test"},
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.VerifyRequest(req, nil); err == nil {
		t.Fatal("trust-domain-pinned key should reject legacy actor")
	}
}

func TestVerifier_EmptyPOSTBodyDoesNotRequireContentDigest(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	req := signedEmptyPostRequest(t, priv, now)
	req.Body = io.NopCloser(strings.NewReader(""))
	req.ContentLength = 0

	verifier := newTestVerifier(t, pub, now)
	if _, err := verifier.VerifyRequest(req, nil); err != nil {
		t.Fatalf("empty POST should verify without content-digest: %v", err)
	}
}

func signedEmptyPostRequest(t *testing.T, priv ed25519.PrivateKey, now time.Time) *http.Request {
	t.Helper()
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "trusted-key",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation},
		MaxBodyBytes:     1 << 20,
		NowFn:            func() time.Time { return now },
		RandReader:       bytes.NewReader([]byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash:  strings.Repeat("a", 64),
		Signer:      signer,
		ActorFormat: ActorFormatSPIFFE,
		TrustDomain: "example.test",
	})
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000005",
		Action:    "read",
		Verdict:   "allow",
		Actor:     "alpha",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}
	return req
}

func signedLegacyActorRequest(t *testing.T, priv ed25519.PrivateKey, now time.Time) *http.Request {
	t.Helper()
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "trusted-key",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerPipelockMediation},
		NowFn:            func() time.Time { return now },
		RandReader:       bytes.NewReader([]byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash: strings.Repeat("a", 64),
		Signer:     signer,
	})
	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000004",
		Action:    "read",
		Verdict:   "allow",
		Actor:     "legacy-agent",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}
	return req
}

func signedVerifierRequest(t *testing.T, priv ed25519.PrivateKey, now time.Time, bodyText string) *http.Request {
	t.Helper()
	var bodyBytes []byte
	var body *strings.Reader
	if bodyText != "" {
		bodyBytes = []byte(bodyText)
		body = strings.NewReader(bodyText)
	}
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "trusted-key",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation},
		MaxBodyBytes:     1 << 20,
		NowFn:            func() time.Time { return now },
		RandReader:       bytes.NewReader([]byte("0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{
		ConfigHash:  strings.Repeat("a", 64),
		Signer:      signer,
		ActorFormat: ActorFormatSPIFFE,
		TrustDomain: "example.test",
	})
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", body)
	if body == nil {
		req = newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	}
	err = em.InjectAndSign(req, bodyBytes, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-000000000001",
		Action:    "read",
		Verdict:   "allow",
		Actor:     "alpha",
		ActorAuth: ActorAuthBound,
	})
	if err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}
	return req
}

func newTestVerifier(t *testing.T, pub []byte, now time.Time) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(VerifierConfig{
		TrustedKeys: []TrustedKey{{
			KeyID:     "trusted-key",
			PublicKey: pub,
		}},
		ReplayCache: newReplayCache(5*time.Minute, 1000, func() time.Time { return now }),
		Skew:        time.Minute,
		NowFn:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}
