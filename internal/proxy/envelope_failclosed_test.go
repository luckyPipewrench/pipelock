// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestForwardHTTP_EnvelopeSigningReadFailureBlocks(t *testing.T) {
	t.Parallel()

	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.ForwardProxy.Enabled = true
	cfg.RequestBodyScanning.Enabled = false
	enableEnvelopeSigning(t, cfg, writeEnvelopeKey(t))

	sc := scanner.New(cfg)
	logger := audit.NewNop()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	handler := p.buildHandler(mux)

	req := httptest.NewRequest(http.MethodPost, upstream.URL+"/upload",
		&errorReader{n: 8, err: io.ErrUnexpectedEOF})
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if upstreamHit.Load() {
		t.Fatal("upstream should not be reached after envelope signing failure")
	}
	if !strings.Contains(w.Body.String(), mediationEnvelopeBlockReason) {
		t.Fatalf("expected block reason in response, got %q", w.Body.String())
	}
}

func TestInterceptHandler_EnvelopeSigningReadFailureBlocks(t *testing.T) {
	t.Parallel()

	var upstreamHit atomic.Bool
	upstreamRT := roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
		upstreamHit.Store(true)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"text/plain"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	})

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	// We intentionally do NOT set cfg.TLSInterception.Enabled here —
	// the test exercises newInterceptHandler directly with a fake
	// upstream RoundTripper, so no real TLS interception runs, and
	// enabling it would force cfg.Validate() to demand a CA cert at
	// ~/.pipelock/ca.pem that CI runners do not have.
	cfg.RequestBodyScanning.Enabled = false
	enableEnvelopeSigning(t, cfg, writeEnvelopeKey(t))

	sc := scanner.New(cfg)
	logger := audit.NewNop()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)

	handler := newInterceptHandler(&InterceptContext{
		TargetHost: testLoopbackIP,
		TargetPort: "443",
		Config:     cfg,
		Scanner:    sc,
		Logger:     logger,
		Metrics:    m,
		ClientIP:   "10.0.0.1",
		RequestID:  "intercept-sign-fail",
		Agent:      "test-agent",
		Proxy:      p,
	}, upstreamRT)

	req := httptest.NewRequest(http.MethodPost, "https://"+testLoopbackIP+"/upload",
		&errorReader{n: 8, err: io.ErrUnexpectedEOF})
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if upstreamHit.Load() {
		t.Fatal("upstream should not be reached after envelope signing failure")
	}
	if !strings.Contains(w.Body.String(), mediationEnvelopeBlockReason) {
		t.Fatalf("expected block reason in response, got %q", w.Body.String())
	}
}

func TestReverseProxy_EnvelopeSigningReadFailureBlocks(t *testing.T) {
	t.Parallel()

	var upstreamHit atomic.Bool
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit.Store(true)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	cfg := reverseTestConfig()
	cfg.RequestBodyScanning.Enabled = false
	enableEnvelopeSigning(t, cfg, writeEnvelopeKey(t))

	sc := scanner.New(cfg)
	t.Cleanup(sc.Close)

	var cfgPtr atomic.Pointer[config.Config]
	var scPtr atomic.Pointer[scanner.Scanner]
	cfgPtr.Store(cfg)
	scPtr.Store(sc)

	handler := NewReverseProxy(
		upstreamURL,
		&cfgPtr,
		&scPtr,
		audit.NewNop(),
		metrics.New(),
		killswitch.New(cfg),
		nil,
		nil,
	)
	signingProxy, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(signingProxy.Close)
	handler.SetEnvelopeEmitter(&signingProxy.envelopeEmitterPtr)

	req := httptest.NewRequest(http.MethodPost, "http://proxy.example/api/upload",
		&errorReader{n: 8, err: io.ErrUnexpectedEOF})
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if upstreamHit.Load() {
		t.Fatal("upstream should not be reached after envelope signing failure")
	}
	if !strings.Contains(w.Body.String(), mediationEnvelopeBlockReason) {
		t.Fatalf("expected block reason in response, got %q", w.Body.String())
	}
}

func TestCheckRedirect_RefreshFailureBlocks(t *testing.T) {
	t.Parallel()

	p := newSigningProxyForTest(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://redirected.example/final", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	prev := p.envelopeEmitterPtr.Load().Build(envelope.BuildOpts{
		ActionID:  receipt.NewActionID(),
		Action:    string(receipt.ActionRead),
		Verdict:   config.ActionAllow,
		Actor:     "agent",
		ActorAuth: envelope.ActorAuthSelfDeclared,
		PolicyHash: envelope.PolicyHashFromHex(
			p.cfgPtr.Load().CanonicalPolicyHash(),
		),
	})
	if err := envelope.InjectHTTP(req.Header, prev); err != nil {
		t.Fatalf("InjectHTTP: %v", err)
	}
	req.Header.Set("Signature-Input", "not a valid dict (((")

	err = p.refreshEnvelopeForRedirect(req, nil, p.cfgPtr.Load())
	if err == nil {
		t.Fatal("expected redirect refresh to fail closed on malformed Signature-Input")
	}
	blockedErr, ok := blockedRequestErrorFrom(err)
	if !ok {
		t.Fatalf("expected blockedRequestError, got %T", err)
	}
	if blockedErr.layer != blockLayerMediationEnvelope {
		t.Fatalf("blocked layer = %q, want %q", blockedErr.layer, blockLayerMediationEnvelope)
	}
	if blockedErr.reason != "redirect blocked: "+mediationEnvelopeBlockReason {
		t.Fatalf("blocked reason = %q", blockedErr.reason)
	}
}
