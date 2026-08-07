// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// newSigningProxyForTest builds a Proxy with mediation envelope
// signing turned on against a fresh Ed25519 key. Uses a fixed clock
// so signature-params timestamps are reproducible across runs.
func newSigningProxyForTest(t *testing.T) *Proxy {
	t.Helper()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.MediationEnvelope.Enabled = true
	cfg.MediationEnvelope.Sign = true
	cfg.MediationEnvelope.KeyID = config.DefaultEnvelopeSignKeyID
	cfg.MediationEnvelope.SignedComponents = config.DefaultEnvelopeSignedComponents()
	cfg.MediationEnvelope.CreatedSkewSeconds = config.DefaultEnvelopeSignCreatedSkewSecs
	cfg.MediationEnvelope.MaxBodyBytes = config.DefaultEnvelopeSignMaxBodyBytes

	_, priv, err := ed25519.GenerateKey(rand.Reader)
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

	sc := scanner.MustNew(cfg)
	m := metrics.New()
	logger := audit.NewNop()

	em := envelope.NewEmitter(envelope.EmitterConfig{
		ConfigHash: cfg.CanonicalPolicyHash(),
		Signer:     signer,
	})

	p, err := New(cfg, logger, sc, m, WithEnvelopeEmitter(em))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return p
}

// TestCheckRedirect_RefreshesEnvelopeHop drives a fetch-proxy GET at
// an httptest origin that 302-redirects to a second origin, and
// asserts that the second origin sees a refreshed Pipelock-Mediation
// header whose hop counter is 1 (incremented from 0). The original
// Content-Digest header is stripped and the signature is re-attached
// over the redirected URL.
func TestCheckRedirect_RefreshesEnvelopeHop(t *testing.T) {
	t.Parallel()

	// Capture what the FINAL upstream sees.
	var mu sync.Mutex
	var finalMediation string
	var finalSigInput string
	var finalDigest string
	var finalURL string

	finalUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		finalMediation = r.Header.Get(envelope.HeaderName)
		finalSigInput = r.Header.Get("Signature-Input")
		finalDigest = r.Header.Get("Content-Digest")
		finalURL = "http://" + r.Host + r.URL.RequestURI()
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>hop check</body></html>"))
	}))
	t.Cleanup(finalUpstream.Close)

	firstHop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Issue a 302 to the final origin with a different path so
		// @target-uri changes between hops.
		http.Redirect(w, r, finalUpstream.URL+"/final", http.StatusFound)
	}))
	t.Cleanup(firstHop.Close)

	p := newSigningProxyForTest(t)

	// Drive the fetch handler via httptest so the real CheckRedirect
	// closure runs through p.client.
	proxyServer := httptest.NewServer(http.HandlerFunc(p.handleFetch))
	t.Cleanup(proxyServer.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		proxyServer.URL+"/fetch?url="+firstHop.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %s", resp.StatusCode, body)
	}

	mu.Lock()
	defer mu.Unlock()

	if finalMediation == "" {
		t.Fatal("final upstream received no Pipelock-Mediation header")
	}
	env, err := envelope.Parse(finalMediation)
	if err != nil {
		t.Fatalf("parse refreshed envelope: %v", err)
	}
	if env.Hop != 1 {
		t.Errorf("Hop on refreshed envelope = %d, want 1", env.Hop)
	}
	if env.Action != "read" {
		t.Errorf("refreshed envelope Action = %q, want read", env.Action)
	}

	// Signature-Input must still exist and the signature must still
	// declare @target-uri - the refresh had to re-sign over the new
	// URL, not carry over the stale signature from the first hop.
	if finalSigInput == "" {
		t.Fatal("final upstream received no Signature-Input header")
	}
	dict, err := httpsfv.UnmarshalDictionary([]string{finalSigInput})
	if err != nil {
		t.Fatalf("Signature-Input parse: %v", err)
	}
	if _, ok := dict.Get("pipelock1"); !ok {
		t.Error("refreshed Signature-Input missing pipelock1 member")
	}

	// GET to a text/html origin has no request body → Content-Digest
	// should be absent on the final hop.
	if finalDigest != "" {
		t.Errorf("final Content-Digest should be empty on body-less GET, got %q", finalDigest)
	}

	// Sanity: the captured URL must match the post-redirect target.
	if !strings.HasSuffix(finalURL, "/final") {
		t.Errorf("final captured URL = %q, expected /final suffix", finalURL)
	}
}

// TestCheckRedirect_DropsStaleContentDigest drives a redirect on the
// forward-proxy path with a pre-populated stale Content-Digest on the
// redirect response and verifies that refreshEnvelopeForRedirect
// strips it before re-signing. Without the strip, a downstream
// verifier would see the stale digest and reject the signature.
func TestCheckRedirect_DropsStaleContentDigest(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var finalDigest string

	finalUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		finalDigest = r.Header.Get("Content-Digest")
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(finalUpstream.Close)

	// First hop sets a bogus Content-Digest on the 302 response so
	// the stdlib redirect copy has a chance to propagate it.
	firstHop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Digest", "sha-256=:AAAA:")
		http.Redirect(w, r, finalUpstream.URL+"/final", http.StatusFound)
	}))
	t.Cleanup(firstHop.Close)

	p := newSigningProxyForTest(t)
	proxyServer := httptest.NewServer(http.HandlerFunc(p.handleFetch))
	t.Cleanup(proxyServer.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		proxyServer.URL+"/fetch?url="+firstHop.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)

	mu.Lock()
	defer mu.Unlock()
	if finalDigest == "sha-256=:AAAA:" {
		t.Error("stale Content-Digest propagated through redirect — refresh did not strip")
	}
}

// TestCheckRedirect_PreservesRequiresReauth verifies that redirect refresh
// carries forward the reauth bit from the original envelope. Without this,
// the redirected leg silently weakens the mediation contract even though it
// is the same logical action.
func TestCheckRedirect_PreservesRequiresReauth(t *testing.T) {
	t.Parallel()

	p := newSigningProxyForTest(t)
	em := p.envelopeEmitterPtr.Load()
	if em == nil {
		t.Fatal("expected startup signing emitter")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://redirected.example/final", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	ctx := context.WithValue(req.Context(), ctxKeyClientIP, "127.0.0.1")
	ctx = context.WithValue(ctx, ctxKeyRequestID, "req-reauth")
	req = req.WithContext(ctx)

	prev, err := em.Build(envelope.BuildOpts{
		ActionID:       "01961f3a-7b2c-7000-8000-000000000020",
		Action:         "read",
		Verdict:        config.ActionAllow,
		Actor:          "agent",
		ActorAuth:      envelope.ActorAuthBound,
		RequiresReauth: true,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := envelope.InjectHTTP(req.Header, prev); err != nil {
		t.Fatalf("inject previous envelope: %v", err)
	}

	if err := p.refreshEnvelopeForRedirect(req, nil, p.cfgPtr.Load()); err != nil {
		t.Fatalf("refreshEnvelopeForRedirect: %v", err)
	}

	refreshed, err := envelope.Parse(req.Header.Get(envelope.HeaderName))
	if err != nil {
		t.Fatalf("parse refreshed envelope: %v", err)
	}
	if !refreshed.RequiresReauth {
		t.Fatal("redirect refresh dropped reauth bit")
	}
	if refreshed.Hop != 1 {
		t.Errorf("Hop = %d, want 1", refreshed.Hop)
	}
}

func TestCheckRedirect_DropsAuthorityOnRedirect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		authorityKind string
		authorityRef  string
	}{
		{
			name:          "kind and reference",
			authorityKind: "user-exact",
			authorityRef:  "grant-123",
		},
		{
			name:          "kind only",
			authorityKind: "delegated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := newSigningProxyForTest(t)
			em := p.envelopeEmitterPtr.Load()
			if em == nil {
				t.Fatal("expected startup signing emitter")
			}

			original := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://origin.example/start", nil)
			prev, err := em.Build(envelope.BuildOpts{
				ActionID:       "01961f3a-7b2c-7000-8000-000000000022",
				Action:         "write",
				Verdict:        config.ActionAllow,
				Actor:          "agent",
				ActorAuth:      envelope.ActorAuthBound,
				SessionTaint:   "restricted",
				TaskID:         "task-123",
				AuthorityKind:  tt.authorityKind,
				AuthorityRef:   tt.authorityRef,
				RequiresReauth: true,
			})
			if err != nil {
				t.Fatalf("build previous envelope: %v", err)
			}
			if err := envelope.InjectHTTP(original.Header, prev); err != nil {
				t.Fatalf("inject previous envelope: %v", err)
			}

			// Prove authority actually crossed the serialized boundary
			// before asserting the redirect removed it. Without this, an
			// emitter that silently dropped authority would make the
			// removal assertion below pass even with the carry-over
			// restored, so the test would prove nothing about redirects.
			injected, err := envelope.Parse(original.Header.Get(envelope.HeaderName))
			if err != nil {
				t.Fatalf("parse injected envelope: %v", err)
			}
			if injected.AuthorityKind != tt.authorityKind || injected.AuthorityRef != tt.authorityRef {
				t.Fatalf("injected authority = %q/%q, want %q/%q",
					injected.AuthorityKind, injected.AuthorityRef, tt.authorityKind, tt.authorityRef)
			}

			redirected := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://redirected.example/final", nil)
			if err := p.refreshEnvelopeForRedirect(redirected, []*http.Request{original}, p.cfgPtr.Load()); err != nil {
				t.Fatalf("refreshEnvelopeForRedirect: %v", err)
			}

			refreshed, err := envelope.Parse(redirected.Header.Get(envelope.HeaderName))
			if err != nil {
				t.Fatalf("parse refreshed envelope: %v", err)
			}
			if refreshed.AuthorityKind != "" || refreshed.AuthorityRef != "" {
				t.Fatalf("redirected authority = %q/%q, want empty", refreshed.AuthorityKind, refreshed.AuthorityRef)
			}
			// The redirect switched POST to GET, so the action must be
			// recomputed from the new method rather than carried over.
			// Preserving "write" here would misreport the hop.
			if wantAction := string(receipt.ClassifyHTTP(http.MethodGet)); refreshed.Action != wantAction {
				t.Fatalf("refreshed Action = %q, want %q recomputed from the redirected method",
					refreshed.Action, wantAction)
			}
			if refreshed.Actor != prev.Actor || refreshed.ActorAuth != prev.ActorAuth ||
				refreshed.ReceiptID != prev.ReceiptID || refreshed.SessionTaint != prev.SessionTaint ||
				refreshed.TaskID != prev.TaskID || refreshed.RequiresReauth != prev.RequiresReauth {
				t.Fatalf("redirect lost identity metadata: got %+v, want actor=%q actor_auth=%q receipt=%q taint=%q task=%q reauth=%t",
					refreshed, prev.Actor, prev.ActorAuth, prev.ReceiptID, prev.SessionTaint, prev.TaskID, prev.RequiresReauth)
			}
			if refreshed.Hop != 1 {
				t.Errorf("Hop = %d, want 1", refreshed.Hop)
			}
		})
	}
}

func TestCheckRedirect_MalformedPriorEnvelopeBlocks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		// extra values are Added after raw, so the header carries more
		// than one value. Header.Get reads only the first, so without a
		// Values-based read a malformed later value reads as absent and
		// skips the block entirely.
		extra []string
		// validFirst makes the FIRST header value a genuinely valid signed
		// envelope. Without it a repeated-header case proves nothing about
		// the repeated-header guard, because an incomplete first value is
		// rejected by envelope.Parse whether or not that guard exists.
		validFirst bool
	}{
		{name: "invalid structured field", raw: "not a valid dictionary ((("},
		{name: "missing required verdict", raw: "v=1, act=\"read\", rid=\"01961f3a-7b2c-7000-8000-000000000023\", ts=1"},
		{name: "present but empty", raw: ""},
		{name: "present but whitespace only", raw: "   "},
		{name: "empty then malformed", raw: "", extra: []string{"not a valid dictionary ((("}},
		{
			name:       "valid then malformed",
			validFirst: true,
			extra:      []string{"not a valid dictionary ((("},
		},
		{
			name:       "valid then valid",
			validFirst: true,
			extra:      []string{"v=1, act=\"read\", rid=\"01961f3a-7b2c-7000-8000-000000000024\", ts=1, vd=\"allow\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := newSigningProxyForTest(t)
			original := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://origin.example/start", nil)
			if tt.validFirst {
				em := p.envelopeEmitterPtr.Load()
				if em == nil {
					t.Fatal("expected startup signing emitter")
				}
				prev, err := em.Build(envelope.BuildOpts{
					ActionID:  "01961f3a-7b2c-7000-8000-000000000025",
					Action:    "read",
					Verdict:   config.ActionAllow,
					Actor:     "agent",
					ActorAuth: envelope.ActorAuthBound,
				})
				if err != nil {
					t.Fatalf("build valid first envelope: %v", err)
				}
				if err := envelope.InjectHTTP(original.Header, prev); err != nil {
					t.Fatalf("inject valid first envelope: %v", err)
				}
			} else {
				original.Header.Set(envelope.HeaderName, tt.raw)
			}
			for _, value := range tt.extra {
				original.Header.Add(envelope.HeaderName, value)
			}
			redirected := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://redirected.example/final", nil)

			err := p.refreshEnvelopeForRedirect(redirected, []*http.Request{original}, p.cfgPtr.Load())
			if err == nil {
				t.Fatal("malformed prior envelope was allowed")
			}
			blocked, ok := blockedRequestErrorFrom(err)
			if !ok {
				t.Fatalf("expected blockedRequestError, got %T", err)
			}
			if blocked.layer != blockLayerMediationEnvelope {
				t.Fatalf("blocked layer = %q, want %q", blocked.layer, blockLayerMediationEnvelope)
			}
		})
	}
}

func TestCheckRedirect_ExplicitNilEmitterSnapshotDoesNotFallback(t *testing.T) {
	t.Parallel()

	p := newSigningProxyForTest(t)
	em := p.envelopeEmitterPtr.Load()
	if em == nil {
		t.Fatal("expected startup signing emitter")
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://redirected.example/final", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	ctx := context.WithValue(req.Context(), ctxKeyEnvelopeEmitter, envelopeEmitterSnapshot{})
	req = req.WithContext(ctx)

	prev, err := em.Build(envelope.BuildOpts{
		ActionID: "01961f3a-7b2c-7000-8000-000000000021",
		Action:   "read",
		Verdict:  config.ActionAllow,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := envelope.InjectHTTP(req.Header, prev); err != nil {
		t.Fatalf("inject previous envelope: %v", err)
	}

	if err := p.refreshEnvelopeForRedirect(req, nil, p.cfgPtr.Load()); err != nil {
		t.Fatalf("refreshEnvelopeForRedirect: %v", err)
	}

	refreshed, err := envelope.Parse(req.Header.Get(envelope.HeaderName))
	if err != nil {
		t.Fatalf("parse envelope: %v", err)
	}
	if refreshed.Hop != 0 {
		t.Fatalf("Hop = %d, want unchanged 0", refreshed.Hop)
	}
	if got := req.Header.Get("Signature-Input"); got != "" {
		t.Fatalf("Signature-Input = %q, want empty", got)
	}
}

// TestCheckRedirect_ChainRefreshesHopMonotonically drives a 3-hop
// redirect chain through the fetch proxy and verifies that each
// refresh increments hop, each leg carries a fresh @target-uri, and
// the final destination sees hop=3 with a valid signature.
//
// The single-hop test (TestCheckRedirect_RefreshesEnvelopeHop) only
// exercises the hop=0 → hop=1 transition. A subtle bug in
// refreshEnvelopeForRedirect that reads via[0] instead of the
// current req header would pass the single-hop test but silently
// cap hop at 1 for the full chain. This test catches that class.
func TestCheckRedirect_ChainRefreshesHopMonotonically(t *testing.T) {
	t.Parallel()

	// capturedHop remembers what the final upstream saw.
	var mu sync.Mutex
	var finalMediation string
	var finalURL string

	finalUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		finalMediation = r.Header.Get(envelope.HeaderName)
		finalURL = "http://" + r.Host + r.URL.RequestURI()
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html><body>final</body></html>"))
	}))
	t.Cleanup(finalUpstream.Close)

	// hop2: 302 to the final destination.
	hop2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, finalUpstream.URL+"/leg3", http.StatusFound)
	}))
	t.Cleanup(hop2.Close)

	// hop1: 302 to hop2 - this is the first hop after the original.
	hop1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop2.URL+"/leg2", http.StatusFound)
	}))
	t.Cleanup(hop1.Close)

	// hop0: the initial redirect. Three hops total before the request
	// lands at finalUpstream with hop=3 stamped on the envelope.
	hop0 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hop1.URL+"/leg1", http.StatusFound)
	}))
	t.Cleanup(hop0.Close)

	p := newSigningProxyForTest(t)
	proxyServer := httptest.NewServer(http.HandlerFunc(p.handleFetch))
	t.Cleanup(proxyServer.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		proxyServer.URL+"/fetch?url="+hop0.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()

	if finalMediation == "" {
		t.Fatal("final upstream received no Pipelock-Mediation header")
	}
	env, err := envelope.Parse(finalMediation)
	if err != nil {
		t.Fatalf("parse final envelope: %v", err)
	}
	// CheckRedirect fires once per redirect hop. Three 302s → three
	// refreshes → hop counter at 3 on the request the final upstream
	// receives.
	if env.Hop != 3 {
		t.Errorf("Hop on final refreshed envelope = %d, want 3", env.Hop)
	}
	// The final leg's target URL must match finalUpstream's /leg3
	// path - proves @target-uri tracked the chain, not the original.
	if !strings.HasSuffix(finalURL, "/leg3") {
		t.Errorf("final captured URL = %q, expected /leg3 suffix", finalURL)
	}
}
