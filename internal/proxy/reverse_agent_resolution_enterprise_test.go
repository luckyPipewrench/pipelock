//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
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
	// Reserved request labels are ignored when the network identity is bound.
	req.Header.Set(AgentHeader, "pipelock")
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

func TestReverseProxySourceCIDRScannerUnavailableReceipt(t *testing.T) {
	for _, unavailable := range []string{"nil", "closed"} {
		t.Run(unavailable, func(t *testing.T) {
			cfg := reverseTestConfig()
			cfg.Agents = map[string]config.AgentProfile{
				"network-agent": {SourceCIDRs: []string{"127.0.0.0/8"}},
			}
			identityScanner := scanner.MustNew(cfg)
			defer identityScanner.Close()
			ed, err := edition.NewEditionFunc(cfg, identityScanner)
			if err != nil {
				t.Fatalf("new edition: %v", err)
			}
			defer ed.Close()
			var upstreamCalls atomic.Int32
			srv, handler := reverseTestSetupWithHandler(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusOK)
			})
			identityProxy := &Proxy{}
			identityProxy.editionPtr.Store(&editionSnapshot{Edition: ed})
			identityProxy.BindReverseProxyIdentity(handler)
			if unavailable == "nil" {
				handler.scPtr.Store(nil)
			} else {
				handler.scPtr.Load().Close()
			}
			dir := t.TempDir()
			emitter, rec, _ := newCoverageEmitter(t, dir)
			t.Cleanup(func() { _ = rec.Close() })
			var emitterPtr atomic.Pointer[receipt.Emitter]
			emitterPtr.Store(emitter)
			handler.SetReceiptEmitter(&emitterPtr)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/resource", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(AgentHeader, "header-agent")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", resp.StatusCode)
			}
			if upstreamCalls.Load() != 0 {
				t.Fatal("unavailable scanner forwarded request")
			}
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}
			assertScannerUnavailableReceipt(t, dir, TransportReverse)
			got := findReceiptByLayer(t, extractReceiptsFromDir(t, dir), scannerLabelUnavailable)
			if got.ActionRecord.Actor != "network-agent" {
				t.Fatalf("receipt agent = %q, want network-agent", got.ActionRecord.Actor)
			}
		})
	}
}

func TestReverseProxySourceCIDRPreservesListenerPolicy(t *testing.T) {
	cfg := reverseTestConfig()
	cfg.RequestBodyScanning.ContentEntropyEnabled = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "listener marker", Regex: "listener-only-marker", Severity: config.SeverityHigh}}
	cfg.Agents = map[string]config.AgentProfile{
		"network-agent": {SourceCIDRs: []string{"127.0.0.0/8"}, DLP: &config.AgentDLP{Patterns: []config.DLPPattern{{Name: "network marker", Regex: "network-only-marker", Severity: config.SeverityHigh}}}},
		"header-agent":  {DLP: &config.AgentDLP{Patterns: []config.DLPPattern{{Name: "header marker", Regex: "header-only-marker", Severity: config.SeverityHigh}}}},
	}
	identityScanner := scanner.MustNew(cfg)
	defer identityScanner.Close()
	ed, err := edition.NewEditionFunc(cfg, identityScanner)
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()
	// Prove both profile-only rules are active before testing the reverse
	// listener. A missing profile must not make this policy assertion pass.
	for _, tt := range []struct{ remote, actor, marker string }{
		{"127.0.0.1:1234", "network-agent", "network-only-marker"},
		{"203.0.113.1:1234", "header-agent", "header-only-marker"},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://api.vendor.example/resource", nil)
		req.RemoteAddr = tt.remote
		req.Header.Set(AgentHeader, "header-agent")
		resolved, identity := ed.ResolveAgent(t.Context(), req)
		if identity.Name != tt.actor {
			t.Fatalf("profile actor = %q, want %q", identity.Name, tt.actor)
		}
		if len(resolved.Scanner.ScanTextForDLP(t.Context(), tt.marker).Matches) == 0 {
			t.Fatalf("profile %s did not detect its marker", tt.actor)
		}
	}
	var upstreamCalls atomic.Int32
	srv, handler := reverseTestSetupWithHandler(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	identityProxy := &Proxy{}
	identityProxy.editionPtr.Store(&editionSnapshot{Edition: ed})
	identityProxy.BindReverseProxyIdentity(handler)
	for _, tt := range []struct {
		body   string
		status int
	}{
		{"listener-only-marker", http.StatusForbidden},
		{"network-only-marker", http.StatusOK},
		{"header-only-marker", http.StatusOK},
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/resource", strings.NewReader(tt.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(AgentHeader, "header-agent")
		req.Header.Set("Content-Type", "text/plain")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tt.status {
			t.Errorf("body %q: status = %d, want %d", tt.body, resp.StatusCode, tt.status)
		}
	}
	if upstreamCalls.Load() != 2 {
		t.Fatalf("upstream calls = %d, want 2", upstreamCalls.Load())
	}
}
