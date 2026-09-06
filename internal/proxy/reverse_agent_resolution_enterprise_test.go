//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package proxy

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"

	_ "github.com/luckyPipewrench/pipelock/enterprise/testinit"
)

func TestReverseProxySourceCIDRIdentityOverridesAgentHeader(t *testing.T) {
	var mediationHeader headerCapture
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.MediationEnvelope.Enabled = true
	cfg.Agents = map[string]config.AgentProfile{
		"reverse-cidr-agent": {SourceCIDRs: []string{"127.0.0.0/8"}},
	}

	identityScanner := scanner.MustNew(cfg)
	defer identityScanner.Close()
	ed, err := edition.NewEditionFunc(cfg, identityScanner)
	if err != nil {
		t.Fatalf("new edition: %v", err)
	}
	defer ed.Close()

	proxySrv, handler := reverseTestSetupWithHandler(t, cfg, func(w http.ResponseWriter, r *http.Request) {
		mediationHeader.Set(r.Header.Get(envelope.HeaderName))
		w.WriteHeader(http.StatusOK)
	})
	emitter := envelope.NewEmitter(envelope.EmitterConfig{ConfigHash: testEnvelopeConfigHash})
	var emitterPtr atomic.Pointer[envelope.Emitter]
	emitterPtr.Store(emitter)
	handler.SetEnvelopeEmitter(&emitterPtr)
	identityProxy := &Proxy{}
	identityProxy.editionPtr.Store(&editionSnapshot{Edition: ed})
	identityProxy.BindReverseProxyIdentity(handler)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxySrv.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(AgentHeader, "spoofed-header-agent")
	resp, err := proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("reverse request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	_ = resp.Body.Close()

	got, err := envelope.Parse(mediationHeader.Get())
	if err != nil {
		t.Fatalf("parse mediation envelope: %v", err)
	}
	if got.Actor != "reverse-cidr-agent" {
		t.Errorf("envelope actor = %q, want reverse-cidr-agent", got.Actor)
	}
	if got.ActorAuth != envelope.ActorAuthBound {
		t.Errorf("envelope actor auth = %q, want %q", got.ActorAuth, envelope.ActorAuthBound)
	}

	cfg2 := *cfg
	cfg2.Agents = map[string]config.AgentProfile{
		"reloaded-cidr-agent": {SourceCIDRs: []string{"127.0.0.0/8"}},
	}
	reloadedScanner := scanner.MustNew(&cfg2)
	defer reloadedScanner.Close()
	reloadedEdition, err := edition.NewEditionFunc(&cfg2, reloadedScanner)
	if err != nil {
		t.Fatalf("new reloaded edition: %v", err)
	}
	defer reloadedEdition.Close()
	identityProxy.editionPtr.Store(&editionSnapshot{Edition: reloadedEdition})

	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, proxySrv.URL+"/resource", nil)
	if err != nil {
		t.Fatalf("new reloaded request: %v", err)
	}
	req.Header.Set(AgentHeader, "spoofed-header-agent")
	resp, err = proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("reloaded reverse request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reloaded status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	got, err = envelope.Parse(mediationHeader.Get())
	if err != nil {
		t.Fatalf("parse reloaded mediation envelope: %v", err)
	}
	if got.Actor != "reloaded-cidr-agent" {
		t.Errorf("reloaded envelope actor = %q, want reloaded-cidr-agent", got.Actor)
	}
	if got.ActorAuth != envelope.ActorAuthBound {
		t.Errorf("reloaded envelope actor auth = %q, want %q", got.ActorAuth, envelope.ActorAuthBound)
	}
}
