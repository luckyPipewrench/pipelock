// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
)

// newTestRequest wraps http.NewRequestWithContext with a background
// context so the tests stay noctx-lint clean without any per-caller
// ceremony. Tests never need a deadline — the signer does not talk
// to the network.
func newTestRequest(t *testing.T, method, url string, body *strings.Reader) *http.Request {
	t.Helper()
	var r *http.Request
	var err error
	if body == nil {
		r, err = http.NewRequestWithContext(context.Background(), method, url, nil)
	} else {
		r, err = http.NewRequestWithContext(context.Background(), method, url, body)
	}
	if err != nil {
		t.Fatalf("http.NewRequestWithContext: %v", err)
	}
	return r
}

// testSignerKey returns a fresh Ed25519 private key for a test. Each
// test owns its own key so parallel runs cannot accidentally verify
// one test's signature with another test's public key.
func testSignerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// newTestSigner constructs a Signer with the default max component
// list and a fixed clock. Tests that want a custom component list or
// MaxBodyBytes construct their own Signer via NewSigner directly.
func newTestSigner(t *testing.T, priv ed25519.PrivateKey) *Signer {
	t.Helper()
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "pipelock-mediation-test",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation},
		MaxBodyBytes:     1 << 20,
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func TestNewSigner_RejectsShortKey(t *testing.T) {
	t.Parallel()
	_, err := NewSigner(SignerConfig{
		PrivKey:          ed25519.PrivateKey([]byte("too short")),
		KeyID:            "test",
		SignedComponents: []string{"@method"},
	})
	if err == nil {
		t.Error("expected error for short private key")
	}
}

func TestNewSigner_RejectsEmptyKeyID(t *testing.T) {
	t.Parallel()
	_, priv := testSignerKey(t)
	_, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "   ",
		SignedComponents: []string{"@method"},
	})
	if err == nil {
		t.Error("expected error for whitespace-only key_id")
	}
}

func TestNewSigner_RejectsEmptyComponents(t *testing.T) {
	t.Parallel()
	_, priv := testSignerKey(t)
	_, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "test",
		SignedComponents: nil,
	})
	if err == nil {
		t.Error("expected error for empty signed_components")
	}
}

func TestSignRequest_NilSignerReturnsErrSignerDisabled(t *testing.T) {
	t.Parallel()
	var s *Signer
	req := newTestRequest(t, http.MethodGet, "https://example.test/", nil)
	err := s.SignRequest(req, nil)
	if err == nil {
		t.Fatal("nil signer should return an error")
	}
	if err != ErrSignerDisabled { //nolint:errorlint // sentinel comparison is intentional
		t.Errorf("nil signer error = %v, want ErrSignerDisabled", err)
	}
}

func TestSignRequest_NilRequest(t *testing.T) {
	t.Parallel()
	_, priv := testSignerKey(t)
	s := newTestSigner(t, priv)
	if err := s.SignRequest(nil, nil); err == nil {
		t.Error("nil request should fail")
	}
}

// TestSignRequest_POSTWithBodyHasContentDigest proves the end-to-end
// signing path on a body-bearing request: content-digest is computed
// and set, Signature-Input declares all four components with the
// pipelock1 label and pipelock-mediation tag, Signature carries a
// valid Ed25519 signature over the signature base, and
// ed25519.Verify against the matching public key succeeds.
func TestSignRequest_POSTWithBodyHasContentDigest(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	s := newTestSigner(t, priv)

	body := []byte(`{"action":"write","actor":"agent:test"}`)
	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", strings.NewReader(string(body)))
	req.Header.Set(HeaderName, `v=1, act="write", vd="allow"`)

	if err := s.SignRequest(req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Content-Digest must match SHA-256 of body.
	gotDigest := req.Header.Get("Content-Digest")
	sum := sha256.Sum256(body)
	wantDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if gotDigest != wantDigest {
		t.Errorf("Content-Digest = %q, want %q", gotDigest, wantDigest)
	}

	// Signature-Input must be a valid structured-field dictionary
	// containing exactly one member, pipelock1, whose inner list has
	// all four declared components and the pipelock-mediation tag.
	sigInputDict, err := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	if err != nil {
		t.Fatalf("Signature-Input parse: %v", err)
	}
	member, ok := sigInputDict.Get(pipelockSigLabel)
	if !ok {
		t.Fatalf("pipelock1 missing from Signature-Input: %q", req.Header.Get("Signature-Input"))
	}
	inner, ok := member.(httpsfv.InnerList)
	if !ok {
		t.Fatalf("pipelock1 is %T, want httpsfv.InnerList", member)
	}

	wantComponents := []string{derivedMethod, derivedTargetURI, headerContentDigest, headerPipelockMediation}
	if len(inner.Items) != len(wantComponents) {
		t.Fatalf("components = %d, want %d", len(inner.Items), len(wantComponents))
	}
	for i, c := range wantComponents {
		got, _ := inner.Items[i].Value.(string)
		if got != c {
			t.Errorf("components[%d] = %q, want %q", i, got, c)
		}
	}

	tagVal, _ := inner.Params.Get("tag")
	if tag, _ := tagVal.(string); tag != pipelockSigTag {
		t.Errorf("tag = %q, want %q", tag, pipelockSigTag)
	}
	keyIDVal, _ := inner.Params.Get("keyid")
	if keyID, _ := keyIDVal.(string); keyID != s.keyID {
		t.Errorf("keyid = %q, want %q", keyID, s.keyID)
	}
	if _, hasCreated := inner.Params.Get("created"); !hasCreated {
		t.Error("Signature-Input missing ;created parameter")
	}

	// Signature dictionary must have pipelock1 with byte-sequence
	// value. Verify with the public key over a freshly reconstructed
	// signature base.
	sigDict, err := httpsfv.UnmarshalDictionary(req.Header.Values("Signature"))
	if err != nil {
		t.Fatalf("Signature parse: %v", err)
	}
	sigMember, ok := sigDict.Get(pipelockSigLabel)
	if !ok {
		t.Fatalf("pipelock1 missing from Signature")
	}
	sigItem, ok := sigMember.(httpsfv.Item)
	if !ok {
		t.Fatalf("pipelock1 Signature value is %T, want httpsfv.Item", sigMember)
	}
	sigBytes, ok := sigItem.Value.([]byte)
	if !ok {
		t.Fatalf("pipelock1 Signature value is %T, want []byte", sigItem.Value)
	}

	base, err := buildSignatureBase(req, body, wantComponents, inner)
	if err != nil {
		t.Fatalf("buildSignatureBase: %v", err)
	}
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		t.Errorf("ed25519.Verify failed over reconstructed base:\n%s", base)
	}
}

// TestSignRequest_GETDropsContentDigest proves the dynamic component
// list path: on a GET with no body, content-digest is dropped from
// the Signature-Input declaration because there is nothing to sign.
func TestSignRequest_GETDropsContentDigest(t *testing.T) {
	t.Parallel()

	pub, priv := testSignerKey(t)
	s := newTestSigner(t, priv)

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/status", nil)
	req.Header.Set(HeaderName, `v=1, act="read", vd="allow"`)

	if err := s.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	if got := req.Header.Get("Content-Digest"); got != "" {
		t.Errorf("Content-Digest should be absent on body-less request, got %q", got)
	}

	sigInputDict, err := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	if err != nil {
		t.Fatalf("Signature-Input parse: %v", err)
	}
	inner := sigInputDict.Names()
	if len(inner) != 1 || inner[0] != pipelockSigLabel {
		t.Fatalf("Signature-Input members = %v, want [pipelock1]", inner)
	}
	member, _ := sigInputDict.Get(pipelockSigLabel)
	list := member.(httpsfv.InnerList) //nolint:errcheck // type is known by construction
	want := []string{derivedMethod, derivedTargetURI, headerPipelockMediation}
	if len(list.Items) != len(want) {
		t.Fatalf("components = %d, want %d (%v)", len(list.Items), len(want), want)
	}
	for i, c := range want {
		got, _ := list.Items[i].Value.(string)
		if got != c {
			t.Errorf("components[%d] = %q, want %q", i, got, c)
		}
	}

	// The signature must still verify over the (shorter) base.
	sigDict, err := httpsfv.UnmarshalDictionary(req.Header.Values("Signature"))
	if err != nil {
		t.Fatalf("Signature parse: %v", err)
	}
	sigMember, _ := sigDict.Get(pipelockSigLabel)
	sigBytes, _ := sigMember.(httpsfv.Item).Value.([]byte)

	base, err := buildSignatureBase(req, nil, want, list)
	if err != nil {
		t.Fatalf("buildSignatureBase: %v", err)
	}
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		t.Error("GET signature failed to verify over reconstructed base")
	}
}

// TestSignRequest_OverSizedBodyDropsContentDigest proves that a body
// larger than MaxBodyBytes is treated as a body-less request from the
// signer's perspective — the declared list drops content-digest
// instead of partially-digesting the payload or failing outright.
func TestSignRequest_OverSizedBodyDropsContentDigest(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "test",
		SignedComponents: []string{"@method", "@target-uri", "content-digest", headerPipelockMediation},
		MaxBodyBytes:     64, // tiny cap for the test
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	req := newTestRequest(t, http.MethodPost, "https://upstream.example/api", nil)
	req.Header.Set(HeaderName, `v=1, act="write", vd="allow"`)

	oversized := make([]byte, 256)
	for i := range oversized {
		oversized[i] = 'A'
	}
	if err := signer.SignRequest(req, oversized); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	if got := req.Header.Get("Content-Digest"); got != "" {
		t.Errorf("Content-Digest should be absent for over-cap body, got %q", got)
	}

	sigInputDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	member, _ := sigInputDict.Get(pipelockSigLabel)
	list := member.(httpsfv.InnerList) //nolint:errcheck // type known by construction
	for _, it := range list.Items {
		if s, _ := it.Value.(string); s == headerContentDigest {
			t.Error("content-digest leaked into declared list when body was over cap")
		}
	}
}

// TestSignRequest_CoexistsWithExistingSig1 proves that an upstream
// Signature-Input / Signature carrying sig1 is preserved when the
// pipelock signature is added.
func TestSignRequest_CoexistsWithExistingSig1(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer := newTestSigner(t, priv)

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	req.Header.Set(HeaderName, `v=1, act="read", vd="allow"`)
	// Pre-existing web-bot-auth signature from upstream.
	req.Header.Set("Signature-Input", `sig1=("@method");keyid="k";tag="web-bot-auth"`)
	req.Header.Set("Signature", `sig1=:dXBzdHJlYW0tc2ln:`)

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInputDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	names := sigInputDict.Names()
	if len(names) != 2 {
		t.Fatalf("Signature-Input members = %v, want [sig1 pipelock1]", names)
	}
	// sig1 must still be present.
	if _, ok := sigInputDict.Get("sig1"); !ok {
		t.Error("sig1 was lost")
	}
	// pipelock1 must be present.
	if _, ok := sigInputDict.Get(pipelockSigLabel); !ok {
		t.Error("pipelock1 was not added")
	}
	// sig1's tag must still be web-bot-auth.
	sig1Member, _ := sigInputDict.Get("sig1")
	sig1Inner := sig1Member.(httpsfv.InnerList) //nolint:errcheck // type known
	tagVal, _ := sig1Inner.Params.Get("tag")
	if tag, _ := tagVal.(string); tag != "web-bot-auth" {
		t.Errorf("sig1 tag = %q, want %q", tag, "web-bot-auth")
	}

	sigDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature"))
	if _, ok := sigDict.Get("sig1"); !ok {
		t.Error("sig1 Signature entry lost")
	}
	if _, ok := sigDict.Get(pipelockSigLabel); !ok {
		t.Error("pipelock1 Signature entry not added")
	}
}

// TestSignRequest_ReplacesStalePipelockSlot proves that a request
// arriving with an existing pipelock1 member has that member replaced
// (not appended alongside) by the new signer output. This is the
// redirect-refresh path: after a redirect, the original pipelock1
// signature is stale and must be overwritten.
func TestSignRequest_ReplacesStalePipelockSlot(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer := newTestSigner(t, priv)

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	req.Header.Set(HeaderName, `v=1, act="read", vd="allow"`)
	req.Header.Set("Signature-Input", `pipelock1=("@method");keyid="stale";tag="pipelock-mediation"`)
	req.Header.Set("Signature", `pipelock1=:c3RhbGU=:`)

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	sigInputDict, _ := httpsfv.UnmarshalDictionary(req.Header.Values("Signature-Input"))
	names := sigInputDict.Names()
	pipelockCount := 0
	for _, n := range names {
		if strings.HasPrefix(n, pipelockMemberPrefix) {
			pipelockCount++
		}
	}
	if pipelockCount != 1 {
		t.Errorf("pipelock members = %d, want 1", pipelockCount)
	}
	member, _ := sigInputDict.Get(pipelockSigLabel)
	inner := member.(httpsfv.InnerList) //nolint:errcheck // type known
	keyIDVal, _ := inner.Params.Get("keyid")
	if keyID, _ := keyIDVal.(string); keyID == "stale" {
		t.Error("stale pipelock1 was not replaced — verifier would accept the old key_id")
	}
}

// TestSignRequest_RefusesToMergeIntoMalformedDict proves fail-closed
// behavior on existing-header corruption. If the inbound
// Signature-Input is not a valid structured-field dictionary, the
// signer refuses to merge rather than blindly overwriting it.
func TestSignRequest_RefusesToMergeIntoMalformedDict(t *testing.T) {
	t.Parallel()

	_, priv := testSignerKey(t)
	signer := newTestSigner(t, priv)

	req := newTestRequest(t, http.MethodGet, "https://upstream.example/api", nil)
	req.Header.Set(HeaderName, `v=1, act="read", vd="allow"`)
	req.Header.Set("Signature-Input", "not a valid dict (((")

	err := signer.SignRequest(req, nil)
	if err == nil {
		t.Error("expected error merging into malformed Signature-Input")
	}
}

// TestContentDigestHeaderValue is a direct check on the RFC 9530
// digest-header formatting helper.
func TestContentDigestHeaderValue(t *testing.T) {
	t.Parallel()
	got := contentDigestHeaderValue([]byte("hello"))
	// Precomputed SHA-256 of "hello" in base64.
	want := "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:"
	if got != want {
		t.Errorf("contentDigestHeaderValue = %q, want %q", got, want)
	}
}
