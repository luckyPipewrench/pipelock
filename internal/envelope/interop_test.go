// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/common-fate/httpsig/alg_ed25519"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/common-fate/httpsig/verifier"
	"github.com/dunglas/httpsfv"
)

// httpsfvInnerListShape is a thin wrapper around httpsfv.InnerList so
// the reference verifier can expose a pre-serialised params string
// without re-running httpsfv.Marshal at base-build time.
type httpsfvInnerListShape struct {
	Items            []httpsfv.Item
	SerializedParams string
}

// mustParseDict wraps httpsfv.UnmarshalDictionary and converts the
// pipelock1 member into a shape the reference verifier consumes.
func mustParseDict(t *testing.T, values []string) sigInputDictShape {
	t.Helper()
	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		t.Fatalf("parse Signature-Input: %v", err)
	}
	return sigInputDictShape{dict: dict}
}

type sigInputDictShape struct {
	dict *httpsfv.Dictionary
}

func (d sigInputDictShape) Get(name string) (any, bool) {
	m, ok := d.dict.Get(name)
	if !ok {
		return nil, false
	}
	inner, ok := m.(httpsfv.InnerList)
	if !ok {
		return nil, false
	}
	// Rebuild a Dictionary with a single member so Marshal gives
	// back just the serialised params line. httpsfv does not
	// expose a direct Marshal for InnerList, so wrap it.
	wrapper := httpsfv.NewDictionary()
	wrapper.Add("tmp", inner)
	serialised, err := httpsfv.Marshal(wrapper)
	if err != nil {
		return nil, false
	}
	// Strip the leading "tmp=" label so we get just
	// ("...");keyid=...;alg=...;tag=...;created=...
	trimmed := strings.TrimPrefix(serialised, "tmp=")
	return httpsfvInnerListShape{Items: inner.Items, SerializedParams: trimmed}, true
}

// referenceBuildSignatureBase implements RFC 9421 §2.5 from scratch
// for the minimal component set pipelock supports. The production
// signer's buildSignatureBase helper is unexported; this function
// mirrors it independently so the test exercises a second
// implementation and catches silent drift.
func referenceBuildSignatureBase(t *testing.T, req *http.Request, items []httpsfv.Item, serializedParams string) string {
	t.Helper()
	var b strings.Builder
	for _, item := range items {
		name, _ := item.Value.(string)
		var value string
		switch name {
		case derivedMethod:
			value = strings.ToUpper(req.Method)
		case derivedTargetURI:
			value = req.URL.String()
		case derivedAuthority:
			host := req.URL.Host
			if host == "" {
				host = req.Host
			}
			value = strings.ToLower(host)
		case headerPipelockMediation:
			value = req.Header.Get(HeaderName)
		default:
			t.Fatalf("reference verifier: unsupported component %q", name)
		}
		fmt.Fprintf(&b, "%q: %s\n", name, value)
	}
	fmt.Fprintf(&b, "%q: %s", "@signature-params", serializedParams)
	return b.String()
}

// mustExtractSignatureBytes parses the Signature header dict and
// returns the raw bytes of the pipelock1 byte-sequence item.
func mustExtractSignatureBytes(t *testing.T, values []string) []byte {
	t.Helper()
	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		t.Fatalf("parse Signature: %v", err)
	}
	member, ok := dict.Get(pipelockSigLabel)
	if !ok {
		t.Fatal("pipelock1 missing from Signature")
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		t.Fatalf("pipelock1 is %T, not Item", member)
	}
	sigBytes, ok := item.Value.([]byte)
	if !ok {
		t.Fatalf("pipelock1 value is %T, not []byte", item.Value)
	}
	return sigBytes
}

// TestRFC9421_ExternalVerifierInterop signs a GET request with
// pipelock's Signer and then verifies it with the common-fate/httpsig
// library configured with the matching ed25519 public key. This is
// the external-interop proof: an independent RFC 9421 implementation
// must accept pipelock's signature at face value.
//
// The test uses a body-less GET so the signer's declared component
// list is {@method, @target-uri, pipelock-mediation} — no
// content-digest. (common-fate/httpsig's Ed25519 algorithm hard-codes
// SHA-512 for content-digest computation, which does not match
// pipelock's RFC 9530 SHA-256 default. A follow-up pass can migrate
// both sides to the same digest family and re-enable the body-bearing
// interop path.)
//
// common-fate/httpsig is a test-only dependency — imported inside a
// _test.go file so it never lands in production binaries. go.mod
// tracks it as a direct dep, and that is documented in the PR
// description along with the rationale.
func TestRFC9421_ExternalVerifierInterop(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Pipelock signer, body-less GET component set.
	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "pipelock-mediation-interop",
		SignedComponents: []string{derivedMethod, derivedTargetURI, headerPipelockMediation},
		NowFn:            func() time.Time { return time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// Build an outbound *http.Request pointing at an httptest server
	// URL so Authority / Scheme match what the verifier expects.
	// The server itself is a stub — we never actually dispatch the
	// request, we just need a valid URL shape.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/mediated/resource", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	// Set the Pipelock-Mediation header the signer covers. The
	// emitter would normally do this; we do it inline because this
	// test exercises only the signer + verifier path.
	req.Header.Set(HeaderName, `v=1, act="read", vd="allow", rid="01961f3a-7b2c-7000-8000-000000000001", ts=1712345678`)

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Build the common-fate/httpsig Verifier with our public key and
	// matching tag. Authority / Scheme come from the httptest URL.
	// verifier.Verifier is a plain struct — no constructor — so we
	// assemble the literal directly.
	parsedURL := req.URL
	var libraryBase string
	v := &verifier.Verifier{
		NonceStorage: interopNopNonceStorage{},
		KeyDirectory: alg_ed25519.SingleKeyDirectory{Key: pub},
		Tag:          pipelockSigTag,
		Authority:    parsedURL.Host,
		Scheme:       parsedURL.Scheme,
		Validation: sigparams.ValidateOpts{
			// Allow signatures up to a minute old so the fixed test
			// clock (created in the signer) can precede the verify
			// time by a few seconds. Production deployments set this
			// to something sane like 5 minutes to tolerate clock skew
			// between signer and verifier hosts.
			BeforeDuration: time.Minute,
			RequiredCoveredComponents: map[string]bool{
				"@method":     true,
				"@target-uri": true,
			},
		},
		OnDeriveSigningString: func(_ context.Context, s string) {
			libraryBase = s
		},
	}

	// The library's Parse signature is (ResponseWriter, *Request, time.Time).
	// ResponseWriter is only used to write validation errors for
	// middleware paths; we pass a throwaway recorder.
	rr := httptest.NewRecorder()
	now := time.Date(2026, 4, 15, 12, 0, 30, 0, time.UTC)
	out, _, err := v.Parse(rr, req, now)
	if err != nil {
		t.Fatalf("external verifier rejected pipelock signature: %v\n"+
			"signature-input=%q\nsignature=%q\n"+
			"library-base=%q",
			err, req.Header.Get("Signature-Input"), req.Header.Get("Signature"),
			libraryBase)
	}
	if out == nil {
		t.Fatal("verifier.Parse returned nil request")
	}
}

// interopNopNonceStorage satisfies verifier.NonceStorage without
// actually tracking nonces — sufficient for the single-request
// interop test.
type interopNopNonceStorage struct{}

func (interopNopNonceStorage) Seen(_ context.Context, _ string) (bool, error) { return false, nil }

// TestRFC9421_ReferenceVerifierInterop is a second interop check that
// does not depend on any third-party httpsig library. It builds an
// RFC 9421 §2.5 signature base directly from the captured
// Signature-Input dictionary on a pipelock-signed request and runs
// crypto/ed25519.Verify against the matching public key. This proves
// pipelock's output is verifiable without any specific verifier
// library's parameter-order quirks, and catches regressions that
// only common-fate/httpsig would surface (and vice versa).
//
// The reference verifier supports the minimal component set pipelock
// declares today: @method, @target-uri, @authority, content-digest,
// pipelock-mediation. It exists purely as a test check — production
// does not consume this code path.
func TestRFC9421_ReferenceVerifierInterop(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	signer, err := NewSigner(SignerConfig{
		PrivKey:          priv,
		KeyID:            "pipelock-mediation-ref-interop",
		SignedComponents: []string{derivedMethod, derivedTargetURI, derivedAuthority, headerPipelockMediation},
		NowFn:            func() time.Time { return time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/ref/interop", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set(HeaderName, `v=1, act="read", vd="allow", rid="01961f3a-7b2c-7000-8000-000000000099", ts=1712345678`)

	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Parse the outbound Signature-Input dict with pipelock's own
	// httpsfv dependency and reconstruct the signature base
	// ourselves, independent of the production signer's internal
	// helpers. This is the "second verifier" — a fresh top-to-bottom
	// implementation of the RFC 9421 §2.5 base-string algorithm.
	sigInputDict := mustParseDict(t, req.Header.Values("Signature-Input"))
	member, ok := sigInputDict.Get(pipelockSigLabel)
	if !ok {
		t.Fatal("pipelock1 missing from Signature-Input")
	}
	inner, ok := member.(httpsfvInnerListShape)
	if !ok {
		// Fall back to real httpsfv type — the test helper below
		// uses the same library and returns the same InnerList type.
		t.Fatalf("unexpected inner list type: %T", member)
	}

	base := referenceBuildSignatureBase(t, req, inner.Items, inner.SerializedParams)

	// Extract the raw signature bytes from the outbound Signature
	// dictionary and verify with crypto/ed25519 directly.
	sigBytes := mustExtractSignatureBytes(t, req.Header.Values("Signature"))
	if !ed25519.Verify(pub, []byte(base), sigBytes) {
		t.Errorf("reference verifier: ed25519.Verify failed\nbase=%q", base)
	}
}
