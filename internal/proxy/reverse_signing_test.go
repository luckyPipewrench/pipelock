// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// mustBase64SHA256 returns the base64-encoded SHA-256 of data.
func mustBase64SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// reconstructSignatureBaseForTest builds an RFC 9421 §2.5 signature
// base string from the captured outbound request state: method,
// target-uri, body, pipelock-mediation header value, and the
// signature-params inner list the signer emitted. The component list
// dictates which lines appear in the base and in what order.
//
// This is a test-only mirror of envelope.buildSignatureBase so the
// reverse-proxy signing test can independently verify the signature
// without exporting the production signer's internals. The full
// external-verifier interop test (using common-fate/httpsig) lands
// in a follow-up step.
func reconstructSignatureBaseForTest(method, targetURI string, body []byte, mediationHeader string, components []string, sigParams httpsfv.InnerList) (string, error) {
	var b strings.Builder
	for _, comp := range components {
		switch comp {
		case "@method":
			fmt.Fprintf(&b, "\"@method\": %s\n", strings.ToUpper(method))
		case "@target-uri":
			fmt.Fprintf(&b, "\"@target-uri\": %s\n", targetURI)
		case "content-digest":
			fmt.Fprintf(&b, "\"content-digest\": sha-256=:%s:\n", mustBase64SHA256(body))
		case "pipelock-mediation":
			if mediationHeader == "" {
				return "", fmt.Errorf("pipelock-mediation header missing on captured upstream request")
			}
			fmt.Fprintf(&b, "\"pipelock-mediation\": %s\n", mediationHeader)
		default:
			return "", fmt.Errorf("unsupported component %q", comp)
		}
	}
	serialized, err := httpsfv.Marshal(sigParams)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", serialized)
	return b.String(), nil
}

// TestReverseProxy_SigningRoundTripper_TargetURIIsPostDirector is the
// W3.2 regression test: when mediation envelope signing is enabled,
// the Signature-Input's @target-uri component must reflect the URL
// the request is actually being dispatched to — the upstream URL
// after httputil.ReverseProxy's Director rewrote req.URL.
//
// If we were still signing inside ServeHTTP (before Director), the
// @target-uri would be the inbound-relative path (e.g. /api/data)
// and any verifier comparing it against the upstream URL would
// reject the signature. Signing inside the RoundTripper wrapper is
// what makes this test pass.
func TestReverseProxy_SigningRoundTripper_TargetURIIsPostDirector(t *testing.T) {
	t.Parallel()

	// Capture the request the upstream actually receives.
	var mu sync.Mutex
	var capturedURL string
	var capturedSigInput string
	var capturedSig string
	var capturedDigest string
	var capturedMediation string
	var capturedBody []byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		capturedURL = "http://" + r.Host + r.URL.RequestURI()
		capturedSigInput = r.Header.Get("Signature-Input")
		capturedSig = r.Header.Get("Signature")
		capturedDigest = r.Header.Get("Content-Digest")
		capturedMediation = r.Header.Get(envelope.HeaderName)
		capturedBody = body
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	// Enable mediation envelope signing with a fresh key.
	cfg := reverseTestConfig()
	cfg.MediationEnvelope.Enabled = true
	cfg.MediationEnvelope.Sign = true
	cfg.MediationEnvelope.KeyID = config.DefaultEnvelopeSignKeyID
	cfg.MediationEnvelope.SignedComponents = config.DefaultEnvelopeSignedComponents()
	cfg.MediationEnvelope.CreatedSkewSeconds = config.DefaultEnvelopeSignCreatedSkewSecs
	cfg.MediationEnvelope.MaxBodyBytes = config.DefaultEnvelopeSignMaxBodyBytes

	// Build the signer directly (no file round-trip) — the config
	// validator is tested separately; here we only care about the
	// @target-uri plumbing through the RoundTripper wrapper.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := envelope.NewSigner(envelope.SignerConfig{
		PrivKey:          priv,
		KeyID:            cfg.MediationEnvelope.KeyID,
		SignedComponents: cfg.MediationEnvelope.SignedComponents,
		MaxBodyBytes:     cfg.MediationEnvelope.MaxBodyBytes,
		NowFn:            func() time.Time { return time.Unix(1712345678, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	logger, _ := audit.New("json", "stdout", "", false, false)
	t.Cleanup(logger.Close)

	m := metrics.New()
	ks := killswitch.New(cfg)

	handler := NewReverseProxy(upstreamURL, &cfgPtr, &scPtr, logger, m, ks, nil, nil)

	em := envelope.NewEmitter(envelope.EmitterConfig{
		ConfigHash: cfg.CanonicalPolicyHash(),
		Signer:     signer,
	})
	var emPtr atomic.Pointer[envelope.Emitter]
	emPtr.Store(em)
	handler.SetEnvelopeEmitter(&emPtr)

	proxySrv := httptest.NewServer(handler)
	t.Cleanup(proxySrv.Close)

	// POST with a small body so content-digest lands in the
	// declared component list.
	body := []byte(`{"op":"write","resource":"x"}`)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		proxySrv.URL+"/api/data", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, body %s", resp.StatusCode, b)
	}

	mu.Lock()
	defer mu.Unlock()

	// Body must have reached the upstream intact despite the
	// signer draining it along the way.
	if string(capturedBody) != string(body) {
		t.Errorf("upstream body = %q, want %q", string(capturedBody), string(body))
	}

	// Content-Digest must match SHA-256 of the body.
	if capturedDigest == "" {
		t.Fatal("upstream received no Content-Digest header")
	}
	wantDigest := "sha-256=:" + mustBase64SHA256(body) + ":"
	if capturedDigest != wantDigest {
		t.Errorf("Content-Digest = %q, want %q", capturedDigest, wantDigest)
	}

	// Signature-Input and Signature must both be present and
	// carry a pipelock1 member.
	if capturedSigInput == "" || capturedSig == "" {
		t.Fatal("upstream did not receive Signature-Input / Signature headers")
	}

	sigInputDict, err := httpsfv.UnmarshalDictionary([]string{capturedSigInput})
	if err != nil {
		t.Fatalf("Signature-Input parse: %v\nvalue: %q", err, capturedSigInput)
	}
	member, ok := sigInputDict.Get("pipelock1")
	if !ok {
		t.Fatalf("pipelock1 missing from Signature-Input: %q", capturedSigInput)
	}
	inner := member.(httpsfv.InnerList) //nolint:errcheck // type known by construction

	// Reconstruct the component list.
	components := make([]string, 0, len(inner.Items))
	for _, it := range inner.Items {
		s, _ := it.Value.(string)
		components = append(components, s)
	}

	// @target-uri in the signature base must equal the URL the
	// upstream actually received. httptest.NewServer's URL is
	// http://127.0.0.1:NN, so the post-Director target-uri is
	// http://127.0.0.1:NN/api/data. The inbound req.URL was the
	// httptest proxySrv URL — a DIFFERENT host — so if signing ran
	// before Director, @target-uri would be the proxy URL and this
	// assertion would fail.
	captured := capturedURL
	sigBase, err := reconstructSignatureBaseForTest(req.Method, captured, body, capturedMediation, components, inner)
	if err != nil {
		t.Fatalf("reconstruct base: %v", err)
	}

	sigDict, err := httpsfv.UnmarshalDictionary([]string{capturedSig})
	if err != nil {
		t.Fatalf("Signature parse: %v", err)
	}
	sigMember, _ := sigDict.Get("pipelock1")
	sigBytes, _ := sigMember.(httpsfv.Item).Value.([]byte)

	if !ed25519.Verify(pub, []byte(sigBase), sigBytes) {
		t.Errorf("ed25519.Verify failed; @target-uri must be post-Director (%q)\n"+
			"signature base:\n%s", captured, sigBase)
	}

	// And the recovered @target-uri must NOT equal the inbound
	// proxySrv URL — that would prove signing happened too early.
	inboundURL := proxySrv.URL + "/api/data"
	if !strings.Contains(sigBase, captured) {
		t.Errorf("signature base does not contain upstream URL %q", captured)
	}
	if strings.Contains(sigBase, inboundURL) && inboundURL != captured {
		t.Errorf("signature base leaked inbound proxy URL %q — signing ran before Director", inboundURL)
	}
}
