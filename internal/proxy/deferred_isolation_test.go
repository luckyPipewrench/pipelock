// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// TestDeferredRoutesNotOnAgentMux is the confused-deputy guard: the deferred
// operator control surface (list/approve/deny) must NEVER be routed on the
// agent-facing proxy port. An agent that could reach /api/v1/deferred could
// approve its own held actions and defeat the entire point of deferral, so the
// deferred routes are excluded from the agent mux by construction.
//
// The test runs with api_listen empty - the default shared-port config where
// the kill-switch admin API IS mounted on the main port - to prove the deferred
// surface is excluded even when other admin routes share the agent port.
func TestDeferredRoutesNotOnAgentMux(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.ApplyDefaults()
	cfg.KillSwitch.APIToken = "test-token"

	logger, _ := audit.New("json", "stdout", "", false, false)
	defer logger.Close()
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	m := metrics.New()

	ks := killswitch.New(cfg)
	ksAPI := killswitch.NewAPIHandler(ks)
	p, err := New(cfg, logger, sc, m, WithKillSwitch(ks), WithKillSwitchAPI(ksAPI))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	mux := p.buildMux()

	// Precondition: the kill-switch admin API IS routed on the main port in
	// this config, so a 404 below is meaningful (routes CAN live here; the
	// deferred ones deliberately do not).
	pre := httptest.NewRecorder()
	mux.ServeHTTP(pre, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/killswitch/status", nil))
	if pre.Code == http.StatusNotFound {
		t.Fatalf("precondition: /api/v1/killswitch/status should be routed on the main port when api_listen is empty")
	}

	deferredProbes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/deferred"},
		{http.MethodPost, "/api/v1/deferred/0193defer00000000000000000001/approve"},
		{http.MethodPost, "/api/v1/deferred/0193defer00000000000000000001/deny"},
	}
	for _, tc := range deferredProbes {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s on agent mux = %d, want 404 (deferred control must not be reachable on the agent port)",
				tc.method, tc.path, rr.Code)
		}
	}
}
