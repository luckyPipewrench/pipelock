// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestEmitter_InjectAndSign_StripsHeadersOnSignError covers GPT-5.4 review
// finding #3 on PR #403: on a sign failure InjectAndSign must leave req in
// the same header shape as before the call, so a caller that logs-and-
// continues cannot ship a request with a Pipelock-Mediation header but no
// signature. The test forces a sign failure by installing a signer whose
// SignedComponents reference the pipelock-mediation header but then
// pre-clobbering that header after the emitter has Build()-stamped it.
//
// The simpler path the test actually uses: make the signer fail by
// pointing it at a request with a nil URL — buildComponentValue
// errors on @target-uri, SignRequest bubbles the error out, and the
// emitter's strip branch fires.
func TestEmitter_InjectAndSign_StripsHeadersOnSignError(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	_ = pub
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "strip-on-error",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerPipelockMediation},
		MaxBodyBytes:     1024,
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	em := NewEmitter(EmitterConfig{ConfigHash: "aa", Signer: signer})

	// Stomp the URL to nil so buildComponentValue("@target-uri")
	// returns an error. The emitter should (a) have set
	// Pipelock-Mediation in InjectHTTP, then (b) hit the sign-error
	// path and strip it before returning.
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", strings.NewReader("body"))
	req.URL = nil

	err = em.InjectAndSign(req, []byte("body"), BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-0000000000aa",
		Action:    "write",
		Verdict:   "allow",
		ActorAuth: ActorAuthBound,
	})
	if err == nil {
		t.Fatal("InjectAndSign should have returned an error for nil URL")
	}

	if v := req.Header.Get("Pipelock-Mediation"); v != "" {
		t.Errorf("Pipelock-Mediation should be stripped on error, got %q", v)
	}
	if v := req.Header.Get("Signature"); v != "" {
		t.Errorf("Signature should be stripped on error, got %q", v)
	}
	if v := req.Header.Get("Signature-Input"); v != "" {
		t.Errorf("Signature-Input should be stripped on error, got %q", v)
	}
	if v := req.Header.Get("Content-Digest"); v != "" {
		t.Errorf("Content-Digest should be stripped on error, got %q", v)
	}
}

// TestStripEnvelopeHeaders_NilSafe documents that the strip helper is
// a no-op on a nil request and on a request with nil header, matching
// the nil-safety convention used by the rest of the package.
func TestStripEnvelopeHeaders_NilSafe(t *testing.T) {
	t.Parallel()

	// Nil request: must not panic.
	stripEnvelopeHeaders(nil)

	// Nil header: must not panic.
	req := &http.Request{}
	stripEnvelopeHeaders(req)
}

// TestEmitter_InjectAndSign_NilRequestReturnsError proves the nil-request
// guard still errors and returns a message that identifies this call
// site in logs.
func TestEmitter_InjectAndSign_NilRequestReturnsError(t *testing.T) {
	t.Parallel()

	em := NewEmitter(EmitterConfig{ConfigHash: "aa"})
	if err := em.InjectAndSign(nil, nil, BuildOpts{Action: "read", Verdict: "allow"}); err == nil {
		t.Error("InjectAndSign(nil, ...) should return an error")
	}
}

// TestEmitter_InjectAndSign_NilEmitterIsNoOp proves the nil-receiver
// convention holds for InjectAndSign — nil-safe like every other method
// on Emitter.
func TestEmitter_InjectAndSign_NilEmitterIsNoOp(t *testing.T) {
	t.Parallel()

	var em *Emitter
	req := newTestRequest(t, http.MethodGet, "https://upstream.example/", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{Action: "read", Verdict: "allow"}); err != nil {
		t.Errorf("nil emitter should no-op, got err = %v", err)
	}
	if v := req.Header.Get("Pipelock-Mediation"); v != "" {
		t.Errorf("nil emitter should not write headers, got %q", v)
	}
}

// TestEmitter_InjectAndSign_NoSignerHeaderOnly proves the header-only
// path: an emitter with ConfigHash but no Signer still writes
// Pipelock-Mediation but attaches no signature. Exercises the
// `if e.signer == nil { return nil }` early-exit branch.
func TestEmitter_InjectAndSign_NoSignerHeaderOnly(t *testing.T) {
	t.Parallel()

	em := NewEmitter(EmitterConfig{ConfigHash: "aa"})
	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	if err := em.InjectAndSign(req, nil, BuildOpts{
		ActionID:  "01961f3a-7b2c-7000-8000-0000000000bb",
		Action:    "read",
		Verdict:   "allow",
		ActorAuth: ActorAuthBound,
	}); err != nil {
		t.Fatalf("InjectAndSign: %v", err)
	}
	if v := req.Header.Get("Pipelock-Mediation"); v == "" {
		t.Error("header-only path must still set Pipelock-Mediation")
	}
	if v := req.Header.Get("Signature"); v != "" {
		t.Errorf("header-only path must not sign, got Signature = %q", v)
	}
}

// TestBufferRequestBody_NilBodyReturnsNil covers the fast-exit path for
// body-less requests.
func TestBufferRequestBody_NilBodyReturnsNil(t *testing.T) {
	t.Parallel()

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	req.Body = nil
	data, err := bufferRequestBody(req, 1024)
	if err != nil {
		t.Fatalf("bufferRequestBody: %v", err)
	}
	if data != nil {
		t.Errorf("nil body should return nil, got %d bytes", len(data))
	}
}

// TestBufferRequestBody_NoBodySentinelReturnsNil exercises the
// http.NoBody branch — same semantics as nil but a different code
// path in requestHasBody/bufferRequestBody.
func TestBufferRequestBody_NoBodySentinelReturnsNil(t *testing.T) {
	t.Parallel()

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	req.Body = http.NoBody
	data, err := bufferRequestBody(req, 1024)
	if err != nil {
		t.Fatalf("bufferRequestBody(NoBody): %v", err)
	}
	if data != nil {
		t.Errorf("http.NoBody should return nil bytes, got %d", len(data))
	}
}

// TestBufferRequestBody_ContentLengthSkipsBuffering proves the known-
// oversize fast path: a request with ContentLength > maxBytes bypasses
// buffering entirely, preserving the original body for upstream.
func TestBufferRequestBody_ContentLengthSkipsBuffering(t *testing.T) {
	t.Parallel()

	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", strings.NewReader("XXXXXXXXXX"))
	req.ContentLength = 100 // declared > maxBytes
	data, err := bufferRequestBody(req, 16)
	if err != nil {
		t.Fatalf("bufferRequestBody: %v", err)
	}
	if data != nil {
		t.Errorf("known-oversize should return nil data, got %d bytes", len(data))
	}
	// Original body is left in place; callers still deliver the full
	// payload to upstream.
	drained, _ := io.ReadAll(req.Body)
	if got := string(drained); got != "XXXXXXXXXX" {
		t.Errorf("original body not preserved: got %q", got)
	}
}

// TestOverCapGetBody_ReturnsSentinelError covers the sentinel GetBody
// closure installed when an over-cap unknown-length body cannot be
// replayed. Documented in GPT-5.4 review fix #4 on PR #403.
func TestOverCapGetBody_ReturnsSentinelError(t *testing.T) {
	t.Parallel()

	rc, err := overCapGetBody()
	if !errors.Is(err, ErrOverCapRedirectReplay) {
		t.Errorf("overCapGetBody error = %v, want ErrOverCapRedirectReplay", err)
	}
	if rc != nil {
		t.Error("overCapGetBody should return nil ReadCloser")
	}
}

// TestSigner_DerivedAuthority_FallsBackToURLHost proves the second
// branch of the @authority resolution: when req.Host is blank, the
// signer falls back to req.URL.Host. buildComponentValue is
// exercised via a direct SignRequest.
func TestSigner_DerivedAuthority_FallsBackToURLHost(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "auth-fallback",
		SignedComponents: []string{derivedMethod, derivedAuthority, headerPipelockMediation},
		MaxBodyBytes:     1024,
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	req := newTestRequest(t, http.MethodGet, "https://from-url-host.example/api", nil)
	req.Host = "" // force fallback to req.URL.Host
	// Pre-set a mediation header so the signer can cover it.
	req.Header.Set("Pipelock-Mediation", `v=1, act="read", vd="allow", rid="id-x", ts=1712345678`)

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if req.Header.Get("Signature") == "" {
		t.Error("expected Signature header after fallback-auth sign")
	}
}

// TestSigner_DerivedAuthority_ErrorsOnNoAuthority proves the third
// branch: both req.Host and req.URL.Host blank → error.
func TestSigner_DerivedAuthority_ErrorsOnNoAuthority(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "auth-missing",
		SignedComponents: []string{derivedMethod, derivedAuthority, headerPipelockMediation},
		MaxBodyBytes:     1024,
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// Build a request with a blank authority on both sides.
	parsedURL, perr := url.Parse("/api") // relative → URL.Host is ""
	if perr != nil {
		t.Fatalf("url.Parse: %v", perr)
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL:    parsedURL,
		Header: http.Header{},
	}
	req.Host = ""
	req.Header.Set("Pipelock-Mediation", `v=1, act="read", vd="allow", rid="id-x", ts=1712345678`)

	if err := signer.SignRequest(req, nil); err == nil {
		t.Error("SignRequest should fail when both req.Host and req.URL.Host are blank")
	}
}

// TestSigner_KeyID proves the trivial accessor on Signer — hit by
// test helpers and runtime inventory alike.
func TestSigner_KeyID(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	s, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "accessor-test",
		SignedComponents: []string{derivedMethod, headerPipelockMediation},
		MaxBodyBytes:     1024,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if got := s.KeyID(); got != "accessor-test" {
		t.Errorf("KeyID = %q, want %q", got, "accessor-test")
	}

	// Nil signer must return empty string, matching the package-wide
	// nil-safe receiver convention.
	var nilSigner *Signer
	if got := nilSigner.KeyID(); got != "" {
		t.Errorf("nil signer KeyID = %q, want empty", got)
	}
}

// TestSigner_ClearsStaleContentDigest exercises GPT/CodeRabbit fix: if
// the effective component list omits content-digest (e.g. because body
// was nil on a GET), any carry-over Content-Digest header from a prior
// inbound request must be deleted before signing so a verifier does not
// see a digest that isn't covered by the signature.
func TestSigner_ClearsStaleContentDigest(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	_ = pub
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "stale-digest",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation},
		MaxBodyBytes:     1024,
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	// Pre-set a stale Content-Digest header that does NOT match any
	// body the signer will see. Without the fix, the signer would
	// either sign the stale value or leave it on the request with a
	// Signature-Input that omits content-digest.
	req.Header.Set("Content-Digest", "sha-256=:aaaa==:")
	req.Header.Set("Pipelock-Mediation", `v=1, act="read", vd="allow", rid="id-x", ts=1712345678`)

	// nil body → signer must drop content-digest from effective
	// components AND strip the stale header.
	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if got := req.Header.Get("Content-Digest"); got != "" {
		t.Errorf("stale Content-Digest not cleared, got %q", got)
	}
}
