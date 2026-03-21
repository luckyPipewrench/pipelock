// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// --- Forward proxy body DLP exempt tests ---

// TestForwardProxy_BodyDLP_ExemptHost_NoEscalationUpgrade verifies that
// body DLP findings on adaptive-exempt destinations are NOT upgraded by adaptive
// enforcement. When the session is pre-escalated, a DLP finding on a
// non-exempt host gets upgraded from warn to block. The same finding on
// an exempt host stays at warn and the request is forwarded.
func TestForwardProxy_BodyDLP_ExemptHost_NoEscalationUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	upstreamHost := upstreamURL.Hostname()

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
		cfg.SessionProfiling.Enabled = true
		cfg.SessionProfiling.MaxSessions = 100
		cfg.SessionProfiling.DomainBurst = 100
		cfg.SessionProfiling.WindowMinutes = 5
		cfg.SessionProfiling.SessionTTLMinutes = 30
		cfg.SessionProfiling.CleanupIntervalSeconds = 600
		cfg.AdaptiveEnforcement.Enabled = true
		cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
		cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0
		cfg.AdaptiveEnforcement.ExemptDomains = []string{upstreamHost}
	})
	defer cleanup()

	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)
	escalateRec(rec, 1)

	scoreBefore := rec.ThreatScore()

	body := `{"key": "` + fakeAPIKey() + `"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("expected 200 for body DLP on exempt host (warn not upgraded), got 403")
	}

	scoreAfter := rec.ThreatScore()
	if scoreAfter > scoreBefore {
		t.Errorf("threat score should not increase for exempt host DLP, before=%.1f after=%.1f",
			scoreBefore, scoreAfter)
	}
}

// TestForwardProxy_BodyDLP_NonExemptHost_EscalationUpgrade verifies the
// baseline: body DLP findings on non-exempt hosts ARE upgraded by adaptive
// enforcement when the session is escalated.
func TestForwardProxy_BodyDLP_NonExemptHost_EscalationUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
		cfg.SessionProfiling.Enabled = true
		cfg.SessionProfiling.MaxSessions = 100
		cfg.SessionProfiling.DomainBurst = 100
		cfg.SessionProfiling.WindowMinutes = 5
		cfg.SessionProfiling.SessionTTLMinutes = 30
		cfg.SessionProfiling.CleanupIntervalSeconds = 600
		cfg.AdaptiveEnforcement.Enabled = true
		cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
		cfg.AdaptiveEnforcement.DecayPerCleanRequest = 0
		cfg.APIAllowlist = nil
	})
	defer cleanup()

	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)
	escalateRec(rec, 1)

	body := `{"key": "` + fakeAPIKey() + `"}`
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: proxyAddr}, nil
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		respBody, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403 for body DLP on non-exempt host with escalated session, got %d: %s",
			resp.StatusCode, respBody)
	}
}

// --- Forward proxy header DLP exempt tests ---

// TestForwardHTTP_HeaderDLP_ExemptHost_NoSignal verifies that header DLP
// findings on adaptive-exempt hosts do NOT record adaptive signals.
func TestForwardHTTP_HeaderDLP_ExemptHost_NoSignal(t *testing.T) {
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	cfg := adaptiveConfig()
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	// Exempt the upstream host from adaptive scoring.
	upstreamURL, _ := url.Parse(upstream.URL)
	cfg.AdaptiveEnforcement.ExemptDomains = []string{upstreamURL.Hostname()}
	savedInternal := cfg.Internal
	cfg.ApplyDefaults()
	cfg.Internal = savedInternal

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	rec := sm.GetOrCreate(adaptiveSessionKeyHTTPTest)
	scoreBefore := rec.ThreatScore()

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/ok", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()

	handler := p.buildHandler(http.NewServeMux())
	handler.ServeHTTP(w, req)

	// Audit mode: request allowed regardless.
	if w.Code == http.StatusForbidden {
		t.Errorf("expected request allowed in audit mode, got 403: %s", w.Body.String())
	}

	// Score should NOT increase because the host is exempt.
	scoreAfter := rec.ThreatScore()
	if scoreAfter > scoreBefore {
		t.Errorf("threat score should not increase for exempt host header DLP, before=%f after=%f",
			scoreBefore, scoreAfter)
	}
}

// TestForwardHTTP_HeaderDLP_NonExemptHost_SignalRecorded verifies the baseline:
// header DLP findings on non-exempt hosts DO record adaptive signals.
func TestForwardHTTP_HeaderDLP_NonExemptHost_SignalRecorded(t *testing.T) {
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	cfg := adaptiveConfig()
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.Action = config.ActionWarn
	// No exempt domains — all hosts feed scoring.
	cfg.AdaptiveEnforcement.ExemptDomains = nil
	savedInternal := cfg.Internal
	cfg.ApplyDefaults()
	cfg.Internal = savedInternal

	logger := audit.NewNop()
	sc := scanner.New(cfg)
	defer sc.Close()
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	rec := sm.GetOrCreate(adaptiveSessionKeyHTTPTest)
	scoreBefore := rec.ThreatScore()

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/ok", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	w := httptest.NewRecorder()

	handler := p.buildHandler(http.NewServeMux())
	handler.ServeHTTP(w, req)

	scoreAfter := rec.ThreatScore()
	if scoreAfter <= scoreBefore {
		t.Errorf("expected threat score to increase for non-exempt host header DLP, before=%f after=%f",
			scoreBefore, scoreAfter)
	}
}

// --- Score neutrality ---

// TestExemptHost_ScoreNeutral verifies that DLP findings on exempt hosts
// neither increase nor decrease the session threat score. This prevents
// exempt traffic from actively decaying escalation caused by real threats.
func TestExemptHost_ScoreNeutral(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	upstreamHost := upstreamURL.Hostname()

	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.RequestBodyScanning.Enabled = true
		cfg.RequestBodyScanning.Action = config.ActionWarn
		cfg.RequestBodyScanning.MaxBodyBytes = 1024 * 1024
		cfg.SessionProfiling.Enabled = true
		cfg.SessionProfiling.MaxSessions = 100
		cfg.SessionProfiling.DomainBurst = 100
		cfg.SessionProfiling.WindowMinutes = 5
		cfg.SessionProfiling.SessionTTLMinutes = 30
		cfg.SessionProfiling.CleanupIntervalSeconds = 600
		cfg.AdaptiveEnforcement.Enabled = true
		cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
		cfg.AdaptiveEnforcement.DecayPerCleanRequest = 1.0 // aggressive decay to detect leaks
		cfg.AdaptiveEnforcement.ExemptDomains = []string{upstreamHost}
	})
	defer cleanup()

	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	rec := sm.GetOrCreate(adaptiveSessionKeyLoopback)
	// Set a non-zero score that's below escalation threshold.
	rec.RecordSignal(signalForTest(), adaptiveTestThreshold)
	scoreBefore := rec.ThreatScore()
	if scoreBefore <= 0 {
		t.Fatalf("expected positive score after signal, got %f", scoreBefore)
	}

	// Send 3 requests with secrets to the exempt host.
	// Score should remain unchanged: no increase AND no decay.
	for range 3 {
		body := `{"key": "` + fakeAPIKey() + `"}`
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL+"/test", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{
			Transport: &http.Transport{
				Proxy: func(_ *http.Request) (*url.URL, error) {
					return &url.URL{Scheme: "http", Host: proxyAddr}, nil
				},
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	scoreAfter := rec.ThreatScore()
	// Allow tiny float tolerance but score should not move significantly.
	if scoreAfter > scoreBefore+0.1 {
		t.Errorf("exempt host DLP should not increase score, before=%.1f after=%.1f",
			scoreBefore, scoreAfter)
	}
	if scoreAfter < scoreBefore-0.1 {
		t.Errorf("exempt host DLP should not decay score, before=%.1f after=%.1f",
			scoreBefore, scoreAfter)
	}
}

// signalForTest returns a signal type suitable for seeding a non-zero score.
func signalForTest() session.SignalType {
	return session.SignalNearMiss
}

// --- isAdaptiveExempt matching ---

// TestIsAdaptiveExempt_Matching covers the domain matching logic used to
// gate adaptive enforcement scoring. Uses scanner.MatchDomain semantics:
// *.discord.com matches both sub.discord.com AND discord.com itself.
func TestIsAdaptiveExempt_Matching(t *testing.T) {
	exemptDomains := []string{"api.anthropic.com", "*.discord.com", "api.telegram.org"}

	tests := []struct {
		host   string
		exempt bool
	}{
		{"api.anthropic.com", true},
		{"cdn.discord.com", true},
		{"gateway.discord.com", true},
		{"discord.com", true}, // *.discord.com matches base domain
		{"api.telegram.org", true},
		{"API.ANTHROPIC.COM", true},  // case-insensitive
		{"api.anthropic.com.", true}, // trailing dot normalized
		{"evil.com", false},
		{"discord.com.evil.com", false}, // not a subdomain match
		{"anthropic.com", false},        // not api.anthropic.com
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			got := isAdaptiveExempt(tc.host, exemptDomains)
			if got != tc.exempt {
				t.Errorf("isAdaptiveExempt(%q) = %v, want %v", tc.host, got, tc.exempt)
			}
		})
	}
}

// TestIsAdaptiveExempt_EmptyList verifies empty exempt list exempts nothing.
func TestIsAdaptiveExempt_EmptyList(t *testing.T) {
	if isAdaptiveExempt("api.anthropic.com", nil) {
		t.Error("nil exempt list should not exempt anything")
	}
	if isAdaptiveExempt("api.anthropic.com", []string{}) {
		t.Error("empty exempt list should not exempt anything")
	}
}
