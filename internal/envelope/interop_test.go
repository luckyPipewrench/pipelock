// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/common-fate/httpsig/alg_ed25519"
	"github.com/common-fate/httpsig/sigparams"
	"github.com/common-fate/httpsig/verifier"
)

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
