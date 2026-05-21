// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	adaptiveAPIIdentityKey   = "agent-a|203.0.113.9"
	adaptiveAPIInvocationKey = "mcp-stdio-adaptive"
	adaptiveAPIAgent         = "agent-a"
	adaptiveAPIClientIP      = "203.0.113.9"
	adaptiveAPIAuthHeader    = "Bearer " + testSessionAPIToken
)

func TestSessionManager_AdaptiveStatusAggregatesOperatorView(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)

	identity := sm.GetOrCreate(adaptiveAPIIdentityKey)
	identity.RecordSignal(session.SignalBlock, 1.0)
	identity.SetBlockAll(true)
	identity.RecordEvent(SessionEvent{Kind: "anomaly", Type: testDomainBurst, Target: "a.example"})
	identity.RecordEvent(SessionEvent{Kind: "anomaly", Type: testDomainBurst, Target: "b.example"})
	identity.RecordEvent(SessionEvent{Kind: "anomaly", Type: testIPDomainBurst, Target: "c.example"})
	_, _, _ = identity.Airlock().SetTierWithProvenance(config.AirlockTierSoft, airlockTriggerOnHigh, airlockSourceTriggers)

	invocation := sm.GetOrCreate(adaptiveAPIInvocationKey)
	invocation.RecordEvent(SessionEvent{Kind: "block", Target: "tool"})

	status := sm.AdaptiveStatus()
	if status.ActiveSessions != 2 {
		t.Fatalf("ActiveSessions: got %d, want 2", status.ActiveSessions)
	}
	if status.MaxEscalationLevel != testLevelElevated || status.MaxEscalationInt != 1 {
		t.Fatalf("max escalation: got %q/%d", status.MaxEscalationLevel, status.MaxEscalationInt)
	}
	if status.SessionsByLevel[testLevelElevated] != 1 || status.SessionsByLevel[testLevelNormal] != 1 {
		t.Errorf("sessions by level: %+v", status.SessionsByLevel)
	}
	if status.AirlockTiers[config.AirlockTierSoft] != 1 || status.AirlockTiers[config.AirlockTierNone] != 1 {
		t.Errorf("airlock tiers: %+v", status.AirlockTiers)
	}
	if status.RecentSignalCounts["anomaly"] != 3 || status.RecentSignalCounts["block"] != 1 {
		t.Errorf("recent signal counts: %+v", status.RecentSignalCounts)
	}
	if len(status.TopAnomalies) < 2 || status.TopAnomalies[0].Name != testDomainBurst || status.TopAnomalies[0].Count != 2 {
		t.Fatalf("top anomalies: %+v", status.TopAnomalies)
	}
	if len(status.Sessions) != 2 || status.Sessions[0].Key != adaptiveAPIIdentityKey || status.Sessions[1].Kind != sessionKindInvocation {
		t.Fatalf("sessions sorted identity before invocation: %+v", status.Sessions)
	}
	if status.LockdownTTLSeconds <= 0 {
		t.Error("expected positive lockdown TTL for soft airlock tier")
	}
}

func TestSignalForSessionAnomaly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		anomalyType string
		cooperative bool
		wantSignal  session.SignalType
		wantOK      bool
	}{
		{"domain", testDomainBurst, false, session.SignalDomainAnomaly, true},
		{"domain cooperative", testDomainBurst, true, session.SignalDomainAnomalyCooperative, true},
		{"ip domain", testIPDomainBurst, false, session.SignalIPDomainAnomaly, true},
		{"ip domain cooperative", testIPDomainBurst, true, session.SignalIPDomainAnomalyCooperative, true},
		{"unknown", "volume_spike", false, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := signalForSessionAnomaly(tt.anomalyType, tt.cooperative)
			if got != tt.wantSignal || ok != tt.wantOK {
				t.Fatalf("signalForSessionAnomaly(%q, %t) = %v/%t, want %v/%t",
					tt.anomalyType, tt.cooperative, got, ok, tt.wantSignal, tt.wantOK)
			}
		})
	}
}

func TestAdaptiveLockdownTTLSeconds(t *testing.T) {
	t.Parallel()
	cfg := &config.Airlock{Timers: config.AirlockTimers{SoftMinutes: 5}}
	if got := adaptiveLockdownTTLSeconds(config.AirlockTierNone, time.Now(), cfg); got != 0 {
		t.Fatalf("none tier TTL = %d, want 0", got)
	}
	if got := adaptiveLockdownTTLSeconds(config.AirlockTierSoft, time.Time{}, cfg); got != 0 {
		t.Fatalf("zero entered-at TTL = %d, want 0", got)
	}
	if got := adaptiveLockdownTTLSeconds(config.AirlockTierSoft, time.Now(), nil); got != 0 {
		t.Fatalf("nil config TTL = %d, want 0", got)
	}
	if got := adaptiveLockdownTTLSeconds(config.AirlockTierSoft, time.Now().Add(-10*time.Minute), cfg); got != 0 {
		t.Fatalf("expired TTL = %d, want 0", got)
	}
	if got := adaptiveLockdownTTLSeconds(config.AirlockTierSoft, time.Now(), cfg); got <= 0 {
		t.Fatalf("active TTL = %d, want positive", got)
	}
}

func TestTopAdaptiveAnomaliesSortsAndCaps(t *testing.T) {
	t.Parallel()
	got := topAdaptiveAnomalies(map[string]int{
		"zeta":    1,
		"alpha":   3,
		"beta":    3,
		"gamma":   2,
		"delta":   1,
		"epsilon": 1,
	})
	if len(got) != 5 {
		t.Fatalf("len = %d, want cap at 5: %+v", len(got), got)
	}
	if got[0].Name != "alpha" || got[1].Name != "beta" {
		t.Fatalf("top anomaly sort = %+v", got)
	}
	if got[4].Name == "zeta" {
		t.Fatalf("expected lexical cap to drop zeta, got %+v", got)
	}
}

func TestSessionManager_AdaptiveWhoamiClassifiesIdentity(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)

	missing := sm.AdaptiveWhoami(adaptiveAPIClientIP, adaptiveAPIAgent)
	if missing.Exists || missing.Classification != config.ActionAllow || missing.SessionKey != adaptiveAPIIdentityKey {
		t.Fatalf("missing whoami response: %+v", missing)
	}

	sess := sm.GetOrCreate(adaptiveAPIIdentityKey)
	sess.RecordSignal(session.SignalBlock, 1.0)

	observed := sm.AdaptiveWhoami(adaptiveAPIClientIP, adaptiveAPIAgent)
	if !observed.Exists || observed.Classification != adaptiveClassificationObserve || observed.EscalationLevel != testLevelElevated {
		t.Fatalf("observed whoami response: %+v", observed)
	}

	sess.SetBlockAll(true)
	blocked := sm.AdaptiveWhoami(adaptiveAPIClientIP, adaptiveAPIAgent)
	if blocked.Classification != config.ActionBlock || !blocked.BlockAll {
		t.Fatalf("blocked whoami response: %+v", blocked)
	}

	ipOnly := sm.AdaptiveWhoami(adaptiveAPIClientIP, "")
	if ipOnly.SessionKey != adaptiveAPIClientIP || ipOnly.Agent != "" {
		t.Fatalf("ip-only whoami response: %+v", ipOnly)
	}
}

func TestSessionManager_ResetAllIdentitySessionsSkipsInvocationsAndClearsIPState(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)
	cfg := adaptiveOperatorSessionConfig()

	identity := sm.GetOrCreate(adaptiveAPIIdentityKey)
	identity.RecordSignal(session.SignalBlock, 1.0)
	identity.SetBlockAll(true)
	_, _, _ = identity.Airlock().SetTierWithProvenance(config.AirlockTierHard, airlockTriggerOnCritical, airlockSourceTriggers)
	sm.GetOrCreate(adaptiveAPIInvocationKey).RecordSignal(session.SignalBlock, 1.0)
	sm.RecordIPDomain(adaptiveAPIClientIP, "a.example", cfg)
	sm.RecordIPDomain(adaptiveAPIClientIP, "b.example", cfg)

	reset, skipped := sm.ResetAllIdentitySessions()
	if reset != 1 || skipped != 1 {
		t.Fatalf("reset/skipped = %d/%d, want 1/1", reset, skipped)
	}
	if identity.ThreatScore() != 0 || identity.EscalationLevel() != 0 || identity.BlockAll() {
		t.Fatalf("identity not reset: score=%.2f level=%d block_all=%t", identity.ThreatScore(), identity.EscalationLevel(), identity.BlockAll())
	}
	if tier := identity.Airlock().Tier(); tier != config.AirlockTierNone {
		t.Fatalf("identity airlock tier = %q, want none", tier)
	}
	if got := sm.GetOrCreate(adaptiveAPIInvocationKey).ThreatScore(); got == 0 {
		t.Fatal("invocation session should be skipped, not reset")
	}
	sm.mu.RLock()
	ipDomainCount := len(sm.ipDomains)
	cooldownCount := len(sm.ipBurstCooldown)
	sm.mu.RUnlock()
	if ipDomainCount != 0 || cooldownCount != 0 {
		t.Fatalf("IP-domain state not cleared: domains=%d cooldowns=%d", ipDomainCount, cooldownCount)
	}
}

func TestSessionAPI_HandleAdaptiveStatus(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)
	sm.GetOrCreate(adaptiveAPIIdentityKey).RecordEvent(SessionEvent{Kind: "anomaly", Type: testDomainBurst})
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/adaptive/status", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w := httptest.NewRecorder()

	handler.HandleAdaptiveStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp AdaptiveStatus
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ActiveSessions != 1 || len(resp.TopAnomalies) != 1 {
		t.Fatalf("unexpected adaptive status: %+v", resp)
	}
}

func TestSessionAPI_HandleAdaptiveStatusRejectsWrongMethodAndMissingManager(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)
	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/adaptive/status", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w := httptest.NewRecorder()

	handler.HandleAdaptiveStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method: got %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow: got %q, want GET", allow)
	}

	handler = newTestSessionAPIHandler(t, nil)
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/adaptive/status", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w = httptest.NewRecorder()

	handler.HandleAdaptiveStatus(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager: got %d, want 503", w.Code)
	}
}

func TestSessionAPI_HandleAdaptiveFlush(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)
	sm.GetOrCreate(adaptiveAPIIdentityKey).RecordSignal(session.SignalBlock, 1.0)
	sm.GetOrCreate(adaptiveAPIInvocationKey).RecordSignal(session.SignalBlock, 1.0)
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/adaptive/flush", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w := httptest.NewRecorder()

	handler.HandleAdaptiveFlush(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp AdaptiveFlushResult
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Flushed || resp.IdentitySessions != 1 || resp.SkippedInvocations != 1 || !resp.IPDomainStateCleared {
		t.Fatalf("unexpected flush result: %+v", resp)
	}
	if sm.GetOrCreate(adaptiveAPIIdentityKey).ThreatScore() != 0 {
		t.Fatal("identity session should be reset after adaptive flush")
	}
	if sm.GetOrCreate(adaptiveAPIInvocationKey).ThreatScore() == 0 {
		t.Fatal("invocation session should remain untouched after adaptive flush")
	}
}

func TestSessionAPI_HandleAdaptiveFlushRejectsMethodAndBadBody(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/adaptive/flush", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w := httptest.NewRecorder()

	handler.HandleAdaptiveFlush(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method: got %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodPost {
		t.Fatalf("Allow: got %q, want POST", allow)
	}

	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/adaptive/flush", strings.NewReader(`{"unexpected":true}`))
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w = httptest.NewRecorder()

	handler.HandleAdaptiveFlush(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad body: got %d, want 400", w.Code)
	}
}

func TestSessionAPI_HandleAdaptiveFlushRejectsMissingManagerAndRateLimit(t *testing.T) {
	handler := newTestSessionAPIHandler(t, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/adaptive/flush", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w := httptest.NewRecorder()

	handler.HandleAdaptiveFlush(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager: got %d, want 503", w.Code)
	}

	sm := newAdaptiveOperatorTestManager(t)
	handler = newTestSessionAPIHandler(t, sm)
	for range sessionAPIRateLimitMax {
		req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/adaptive/flush", nil)
		req.Header.Set("Authorization", adaptiveAPIAuthHeader)
		w = httptest.NewRecorder()
		handler.HandleAdaptiveFlush(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("warmup flush: got %d, want 200; body=%s", w.Code, w.Body.String())
		}
	}

	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/adaptive/flush", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w = httptest.NewRecorder()
	handler.HandleAdaptiveFlush(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limited flush: got %d, want 429", w.Code)
	}
	if retryAfter := w.Header().Get("Retry-After"); retryAfter != "60" {
		t.Fatalf("Retry-After: got %q, want 60", retryAfter)
	}
}

func TestSessionAPI_HandleAdaptiveWhoami(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)
	sm.GetOrCreate(adaptiveAPIIdentityKey).RecordSignal(session.SignalBlock, 1.0)
	handler := newTestSessionAPIHandler(t, sm)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/adaptive/whoami", nil)
	req.RemoteAddr = adaptiveAPIClientIP + ":4567"
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	req.Header.Set("X-Pipelock-Agent", " "+adaptiveAPIAgent+" ")
	w := httptest.NewRecorder()

	handler.HandleAdaptiveWhoami(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp AdaptiveWhoami
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ClientIP != adaptiveAPIClientIP || resp.Agent != adaptiveAPIAgent || resp.SessionKey != adaptiveAPIIdentityKey {
		t.Fatalf("unexpected whoami identity: %+v", resp)
	}
	if !resp.Exists || resp.Classification != adaptiveClassificationObserve {
		t.Fatalf("unexpected whoami classification: %+v", resp)
	}
}

func TestSessionAPI_HandleAdaptiveWhoamiRejectsWrongMethodAndMissingManager(t *testing.T) {
	sm := newAdaptiveOperatorTestManager(t)
	handler := newTestSessionAPIHandler(t, sm)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/adaptive/whoami", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w := httptest.NewRecorder()

	handler.HandleAdaptiveWhoami(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method: got %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow: got %q, want GET", allow)
	}

	handler = newTestSessionAPIHandler(t, nil)
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/adaptive/whoami", nil)
	req.Header.Set("Authorization", adaptiveAPIAuthHeader)
	w = httptest.NewRecorder()

	handler.HandleAdaptiveWhoami(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing manager: got %d, want 503", w.Code)
	}
}

func TestSessionAPI_AdaptiveRoutesViaProxyMux(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 100
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 300
	cfg.SessionProfiling.DomainBurst = 10
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.KillSwitch.APIToken = testSessionAPIToken
	cfg.KillSwitch.APIListen = ""

	p, err := New(cfg, nil, nil, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	sm := p.sessionMgrPtr.Load()
	if sm == nil {
		t.Fatal("expected session manager")
	}
	sm.GetOrCreate(adaptiveAPIIdentityKey).RecordSignal(session.SignalBlock, 1.0)
	handler := p.buildHandler(p.buildMux())

	for _, tt := range []struct {
		name   string
		method string
		path   string
		check  func(*testing.T, []byte)
	}{
		{
			name:   "status",
			method: http.MethodGet,
			path:   "/api/v1/adaptive/status",
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var resp AdaptiveStatus
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("unmarshal status: %v", err)
				}
				if resp.ActiveSessions != 1 {
					t.Fatalf("active sessions: got %d, want 1", resp.ActiveSessions)
				}
			},
		},
		{
			name:   "whoami",
			method: http.MethodGet,
			path:   "/api/v1/adaptive/whoami",
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var resp AdaptiveWhoami
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("unmarshal whoami: %v", err)
				}
				if resp.SessionKey != adaptiveAPIIdentityKey {
					t.Fatalf("session key: got %q, want %q", resp.SessionKey, adaptiveAPIIdentityKey)
				}
			},
		},
		{
			name:   "flush",
			method: http.MethodPost,
			path:   "/api/v1/adaptive/flush",
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var resp AdaptiveFlushResult
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("unmarshal flush: %v", err)
				}
				if !resp.Flushed || resp.IdentitySessions != 1 {
					t.Fatalf("flush result: %+v", resp)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
			req.RemoteAddr = adaptiveAPIClientIP + ":4567"
			req.Header.Set("Authorization", adaptiveAPIAuthHeader)
			req.Header.Set("X-Pipelock-Agent", adaptiveAPIAgent)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200; body=%s", w.Code, w.Body.String())
			}
			tt.check(t, w.Body.Bytes())
		})
	}
}

func newAdaptiveOperatorTestManager(t *testing.T) *SessionManager {
	t.Helper()
	sm := NewSessionManager(adaptiveOperatorSessionConfig(), nil, metrics.New())
	t.Cleanup(sm.Close)
	setAirlockConfigForTest(sm, &config.Airlock{
		Enabled: true,
		Timers:  config.AirlockTimers{SoftMinutes: 5, HardMinutes: 10},
	})
	return sm
}

func adaptiveOperatorSessionConfig() *config.SessionProfiling {
	return &config.SessionProfiling{
		MaxSessions:            100,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 300,
		DomainBurst:            2,
		WindowMinutes:          5,
	}
}
