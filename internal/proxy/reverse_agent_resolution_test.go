// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

func TestReverseProxyUsesConfiguredAgentResolverForMediationEnvelope(t *testing.T) {
	var mediationHeader headerCapture
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.MediationEnvelope.Enabled = true

	proxySrv, handler := reverseTestSetupWithHandler(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		mediationHeader.Set(r.Header.Get(envelope.HeaderName))
		w.WriteHeader(http.StatusOK)
	})

	emitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})
	var emitterPtr atomic.Pointer[envelope.Emitter]
	emitterPtr.Store(emitter)
	handler.SetEnvelopeEmitter(&emitterPtr)

	var resolveCalls atomic.Int32
	handler.setAgentResolver(func(*http.Request) edition.AgentIdentity {
		resolveCalls.Add(1)
		return edition.AgentIdentity{Name: "cidr-bound-agent", Auth: envelope.ActorAuthBound}
	})

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxySrv.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// The resolver's infrastructure identity must win over an untrusted hint.
	req.Header.Set(AgentHeader, "caller-supplied-agent")
	resp, err := proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("reverse request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resolveCalls.Load(); got != 1 {
		t.Fatalf("agent resolver calls = %d, want 1", got)
	}

	got, err := envelope.Parse(mediationHeader.Get())
	if err != nil {
		t.Fatalf("parse mediation envelope: %v", err)
	}
	if got.Actor != "cidr-bound-agent" {
		t.Errorf("envelope actor = %q, want cidr-bound-agent", got.Actor)
	}
	if got.ActorAuth != envelope.ActorAuthBound {
		t.Errorf("envelope actor auth = %q, want %q", got.ActorAuth, envelope.ActorAuthBound)
	}
}

func TestReverseProxyUnavailableWithoutConfigFailsClosed(t *testing.T) {
	_, handler := reverseTestSetupWithHandler(t, reverseTestConfig(), func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("request reached upstream without config or scanner")
	})
	handler.cfgPtr.Store(nil)
	handler.scPtr.Store(nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/resource", nil)
	req.Header.Set(AgentHeader, "header-agent")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
}
