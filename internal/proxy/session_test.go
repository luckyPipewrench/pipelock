// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	testClientIP      = "10.0.0.1"
	testIPDomainBurst = "ip_domain_burst"
	testDomainBurst   = "domain_burst"
	testLevelNormal   = "normal"
	testLevelElevated = "elevated"
	testLevelHigh     = "high"
	testLevelCritical = "critical"
	testClient        = "test-client"

	// Prometheus metric/label names used across gauge assertions.
	metricAdaptiveSessions = "pipelock_adaptive_sessions_current"
	metricLabelLevel       = "level"
)

func testSessionConfig() *config.SessionProfiling {
	return &config.SessionProfiling{
		Enabled:                true,
		AnomalyAction:          "warn",
		DomainBurst:            5,
		WindowMinutes:          5,
		VolumeSpikeRatio:       3.0,
		MaxSessions:            100,
		SessionTTLMinutes:      30,
		CleanupIntervalSeconds: 60,
	}
}

func TestSessionManager_GetOrCreate(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	s1 := sm.GetOrCreate("192.168.1.1")
	s2 := sm.GetOrCreate("192.168.1.1")
	if s1 != s2 {
		t.Error("same key should return same session")
	}

	s3 := sm.GetOrCreate("192.168.1.2")
	if s1 == s3 {
		t.Error("different key should return different session")
	}

	if sm.Len() != 2 {
		t.Errorf("expected 2 sessions, got %d", sm.Len())
	}
}

func TestSessionManager_DomainBurst(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// First 2 domains are below threshold
	for _, d := range []string{"a.com", "b.com"} {
		anomalies := sess.RecordRequest(d, cfg)
		if len(anomalies) > 0 {
			t.Errorf("domain %s should not trigger anomaly", d)
		}
	}

	// 3rd new domain hits threshold (>= 3) and triggers burst
	anomalies := sess.RecordRequest("c.com", cfg)
	found := false
	for _, a := range anomalies {
		if a.Type == testDomainBurst {
			found = true
		}
	}
	if !found {
		t.Error("3rd new domain should trigger domain_burst anomaly")
	}
}

func TestSessionManager_DomainBurst_RepeatedDomainNoTrigger(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// 2 unique domains (below threshold of 3)
	for _, d := range []string{"a.com", "b.com"} {
		sess.RecordRequest(d, cfg)
	}

	// Revisiting already-seen domain should NOT trigger burst
	anomalies := sess.RecordRequest("a.com", cfg)
	for _, a := range anomalies {
		if a.Type == testDomainBurst {
			t.Error("revisiting known domain should not trigger domain_burst")
		}
	}
}

func TestSessionManager_DomainBurst_WindowExpiry(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	cfg.WindowMinutes = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Add 3 domains
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		sess.RecordRequest(d, cfg)
	}

	// Backdate all domain entries past the window
	sess.mu.Lock()
	past := time.Now().Add(-2 * time.Minute)
	for i := range sess.domainWindows {
		sess.domainWindows[i].at = past
	}
	sess.mu.Unlock()

	// 4th domain should NOT trigger burst because old entries expired
	anomalies := sess.RecordRequest("d.com", cfg)
	for _, a := range anomalies {
		if a.Type == testDomainBurst {
			t.Error("domain_burst should not trigger after window expiry")
		}
	}
}

func TestSessionManager_MaxSessions(t *testing.T) {
	cfg := testSessionConfig()
	cfg.MaxSessions = 3
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sm.GetOrCreate("1.1.1.1")
	sm.GetOrCreate("2.2.2.2")
	sm.GetOrCreate("3.3.3.3")

	// 4th session should trigger eviction of oldest idle
	s4 := sm.GetOrCreate("4.4.4.4")
	if s4 == nil {
		t.Error("should create 4th session after evicting oldest")
	}
	if sm.Len() > 3 {
		t.Errorf("session count %d exceeds max 3", sm.Len())
	}
}

func TestSessionManager_MaxSessions_EvictsOldestIdle(t *testing.T) {
	cfg := testSessionConfig()
	cfg.MaxSessions = 2
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	// Create two sessions
	sm.GetOrCreate("old")
	time.Sleep(time.Millisecond) // ensure time difference
	sm.GetOrCreate("new")

	// 3rd session evicts "old" (oldest lastActivity)
	sm.GetOrCreate("newest")
	if sm.Len() != 2 {
		t.Errorf("expected 2 sessions, got %d", sm.Len())
	}

	// "old" should be evicted
	sm.mu.RLock()
	_, oldExists := sm.sessions["old"]
	_, newExists := sm.sessions["new"]
	sm.mu.RUnlock()

	if oldExists {
		t.Error("oldest session should be evicted")
	}
	if !newExists {
		t.Error("newer session should still exist")
	}
}

func TestSessionManager_TTLEviction(t *testing.T) {
	cfg := testSessionConfig()
	cfg.SessionTTLMinutes = 1
	cfg.CleanupIntervalSeconds = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Backdate the session's last activity
	sess.mu.Lock()
	sess.lastActivity = time.Now().Add(-2 * time.Minute)
	sess.mu.Unlock()

	// Run cleanup
	sm.cleanup()

	if sm.Len() != 0 {
		t.Error("expired session should be evicted")
	}
}

func TestSessionManager_TTLEviction_ActiveNotEvicted(t *testing.T) {
	cfg := testSessionConfig()
	cfg.SessionTTLMinutes = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sm.GetOrCreate(testClientIP) // fresh, within TTL

	sm.cleanup()

	if sm.Len() != 1 {
		t.Error("active session should not be evicted")
	}
}

func TestSessionManager_Concurrent(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("10.0.0.%d", n%10)
			sess := sm.GetOrCreate(key)
			sess.RecordRequest("example.com", cfg)
		}(i)
	}
	wg.Wait()

	if sm.Len() > 10 {
		t.Errorf("expected at most 10 unique sessions, got %d", sm.Len())
	}
}

func TestSessionManager_Close(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	sm.Close()
	// Double close should not panic
	sm.Close()
}

func TestSessionState_ThreatScore(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// DLP near-miss adds +1
	sess.RecordSignal(session.SignalNearMiss, 5.0)
	if sess.ThreatScore() != 1.0 {
		t.Errorf("expected score 1.0, got %f", sess.ThreatScore())
	}

	// Block adds +3
	sess.RecordSignal(session.SignalBlock, 5.0)
	if sess.ThreatScore() != 4.0 {
		t.Errorf("expected score 4.0, got %f", sess.ThreatScore())
	}

	// Clean request decays by 0.5
	sess.RecordClean(0.5)
	if sess.ThreatScore() != 3.5 {
		t.Errorf("expected score 3.5, got %f", sess.ThreatScore())
	}
}

func TestSessionState_ScoreNeverNegative(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Decay without any signals should floor at 0
	sess.RecordClean(10.0)
	if sess.ThreatScore() != 0 {
		t.Errorf("expected score 0, got %f", sess.ThreatScore())
	}
}

func TestSessionState_Escalation(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	if sess.IsEscalated() {
		t.Error("new session should not be escalated")
	}

	// Add signals to reach threshold of 5
	sess.RecordSignal(session.SignalBlock, 5.0)    // +3, total 3
	sess.RecordSignal(session.SignalNearMiss, 5.0) // +1, total 4

	if sess.IsEscalated() {
		t.Error("should not escalate below threshold")
	}

	// Cross threshold
	escalated, from, to := sess.RecordSignal(session.SignalDomainAnomaly, 5.0) // +2, total 6
	if !escalated {
		t.Error("should escalate at threshold")
	}
	if from != testLevelNormal {
		t.Errorf("expected from=normal, got %s", from)
	}
	if to != testLevelElevated {
		t.Errorf("expected to=elevated, got %s", to)
	}

	if !sess.IsEscalated() {
		t.Error("session should be escalated")
	}
	if sess.EscalationLevel() != 1 {
		t.Errorf("expected level 1, got %d", sess.EscalationLevel())
	}
}

func TestSessionState_EscalationThresholdDoubles(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// First escalation at threshold 5
	for range 5 {
		sess.RecordSignal(session.SignalNearMiss, 5.0) // +1 each
	}

	if sess.EscalationLevel() != 1 {
		t.Fatalf("expected first escalation at score 5, level=%d score=%f", sess.EscalationLevel(), sess.ThreatScore())
	}

	// Threshold is now 10. Need to reach 10 total (currently at 5).
	for range 5 {
		sess.RecordSignal(session.SignalNearMiss, 10.0) // +1 each, total reaches 10
	}

	if sess.EscalationLevel() != 2 {
		t.Errorf("expected second escalation at score 10, level=%d score=%f", sess.EscalationLevel(), sess.ThreatScore())
	}
}

func TestSessionState_EscalationSticky(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Escalate
	for range 5 {
		sess.RecordSignal(session.SignalNearMiss, 5.0)
	}

	// Decay score to near 0
	for range 20 {
		sess.RecordClean(0.5)
	}

	// Escalation is sticky: level doesn't decrease
	if !sess.IsEscalated() {
		t.Error("escalation should be sticky even after score decay")
	}
	if sess.EscalationLevel() != 1 {
		t.Errorf("expected level 1, got %d", sess.EscalationLevel())
	}
}

func TestSessionState_EntropyBudgetSignal(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)
	sess.RecordSignal(session.SignalEntropyBudget, 10.0) // +2

	if sess.ThreatScore() != 2.0 {
		t.Errorf("expected score 2.0, got %f", sess.ThreatScore())
	}
}

func TestSessionState_FragmentDLPSignal(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)
	sess.RecordSignal(session.SignalFragmentDLP, 10.0) // +3

	if sess.ThreatScore() != 3.0 {
		t.Errorf("expected score 3.0, got %f", sess.ThreatScore())
	}
}

func TestSessionState_EntropySignals_Escalation(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Build up score: 2 entropy budget signals (+2 each = 4) below threshold 5
	sess.RecordSignal(session.SignalEntropyBudget, 5.0) // +2, total 2
	sess.RecordSignal(session.SignalEntropyBudget, 5.0) // +2, total 4

	if sess.IsEscalated() {
		t.Error("should not escalate below threshold")
	}

	// Fragment DLP signal crosses threshold: +3, total 7
	escalated, from, to := sess.RecordSignal(session.SignalFragmentDLP, 5.0)
	if !escalated {
		t.Error("should escalate when entropy signals cross threshold")
	}
	if from != testLevelNormal {
		t.Errorf("expected from=normal, got %s", from)
	}
	if to != testLevelElevated {
		t.Errorf("expected to=elevated, got %s", to)
	}

	if sess.EscalationLevel() != 1 {
		t.Errorf("expected level 1, got %d", sess.EscalationLevel())
	}
}

func TestSessionState_DomainAnomalySignal(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)
	sess.RecordSignal(session.SignalDomainAnomaly, 5.0) // +2

	if sess.ThreatScore() != 2.0 {
		t.Errorf("expected score 2.0, got %f", sess.ThreatScore())
	}
}

func TestSessionState_LastActivity(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)
	before := time.Now()
	sess.RecordRequest("example.com", cfg)
	after := time.Now()

	sess.mu.Lock()
	la := sess.lastActivity
	sess.mu.Unlock()

	if la.Before(before) || la.After(after) {
		t.Error("lastActivity should be updated by RecordRequest")
	}
}

// scrapeMetric reads the prometheus HTTP handler and checks for a metric substring.
func scrapeMetric(t *testing.T, m *metrics.Metrics, want string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	return strings.Contains(string(body), want)
}

// adaptiveElevatedGaugeValue reads the pipelock_adaptive_sessions_current gauge
// value for the "elevated" level label from the metrics registry. Returns 0 if absent.
func adaptiveElevatedGaugeValue(t *testing.T, m *metrics.Metrics) float64 {
	t.Helper()
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, fam := range fams {
		if fam.GetName() != metricAdaptiveSessions {
			continue
		}
		for _, metric := range fam.GetMetric() {
			for _, lbl := range metric.GetLabel() {
				if lbl.GetName() == metricLabelLevel && lbl.GetValue() == testLevelElevated {
					return metric.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}

func TestSessionManager_Metrics_EvictOnCapacity(t *testing.T) {
	cfg := testSessionConfig()
	cfg.MaxSessions = 2
	m := metrics.New()
	sm := NewSessionManager(cfg, nil, m)
	defer sm.Close()

	sm.GetOrCreate("a")
	sm.GetOrCreate("b")
	sm.GetOrCreate("c") // triggers eviction of oldest

	if sm.Len() != 2 {
		t.Errorf("expected 2 sessions, got %d", sm.Len())
	}
	if !scrapeMetric(t, m, "pipelock_sessions_evicted_total") {
		t.Error("expected eviction metric after capacity eviction")
	}
}

func TestSessionManager_Metrics_CleanupSetsGauge(t *testing.T) {
	cfg := testSessionConfig()
	cfg.SessionTTLMinutes = 1
	m := metrics.New()
	sm := NewSessionManager(cfg, nil, m)
	defer sm.Close()

	// Create 3 sessions, backdate 2 past TTL
	sm.GetOrCreate("active")
	for _, key := range []string{"old1", "old2"} {
		sess := sm.GetOrCreate(key)
		sess.mu.Lock()
		sess.lastActivity = time.Now().Add(-2 * time.Minute)
		sess.mu.Unlock()
	}

	sm.cleanup()

	if sm.Len() != 1 {
		t.Errorf("expected 1 session after cleanup, got %d", sm.Len())
	}
	if !scrapeMetric(t, m, "pipelock_sessions_active") {
		t.Error("expected sessions_active gauge after cleanup")
	}
	if !scrapeMetric(t, m, "pipelock_sessions_evicted_total") {
		t.Error("expected eviction metric after TTL cleanup")
	}
}

func TestSessionManager_NilMetrics(t *testing.T) {
	cfg := testSessionConfig()
	cfg.MaxSessions = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sm.GetOrCreate("a")
	sm.GetOrCreate("b") // eviction with nil metrics should not panic

	sm.cleanup() // cleanup with nil metrics should not panic
}

func TestSessionManager_IPDomainBurst(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	ip := testClientIP

	// First 2 domains are below threshold
	for _, d := range []string{"a.com", "b.com"} {
		anomalies := sm.RecordIPDomain(ip, d, cfg)
		if len(anomalies) > 0 {
			t.Errorf("domain %s should not trigger IP anomaly", d)
		}
	}

	// 3rd new domain hits threshold (>= 3) and triggers IP-level burst
	anomalies := sm.RecordIPDomain(ip, "c.com", cfg)
	found := false
	for _, a := range anomalies {
		if a.Type == testIPDomainBurst {
			found = true
			if a.Score != 3.0 {
				t.Errorf("expected ip_domain_burst score 3.0, got %f", a.Score)
			}
		}
	}
	if !found {
		t.Error("3rd domain should trigger ip_domain_burst anomaly")
	}
}

func TestSessionManager_IPDomainBurst_HeaderRotation(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	ip := testClientIP

	// Simulate header rotation: different agent sessions, same IP, different domains.
	// Per-agent sessions see only 1 domain each (no burst), but IP tracker sees all 4.
	agents := []string{"agent-1|" + ip, "agent-2|" + ip, "agent-3|" + ip, "agent-4|" + ip}
	domains := []string{"a.com", "b.com", "c.com", "d.com"}

	for i, agent := range agents {
		sess := sm.GetOrCreate(agent)
		agentAnomalies := sess.RecordRequest(domains[i], cfg)
		if len(agentAnomalies) > 0 {
			t.Errorf("agent %s should not trigger per-agent burst for single domain", agent)
		}
	}

	// Now check IP-level: record all 4 domains against the same IP.
	// With DomainBurst=3, the 3rd domain triggers (>= threshold).
	for i, d := range domains {
		anomalies := sm.RecordIPDomain(ip, d, cfg)
		if i < 2 && len(anomalies) > 0 {
			t.Errorf("domain %d should not trigger IP burst yet", i+1)
		}
		if i == 2 {
			found := false
			for _, a := range anomalies {
				if a.Type == testIPDomainBurst {
					found = true
				}
			}
			if !found {
				t.Error("3rd domain should trigger ip_domain_burst despite different agent headers")
			}
		}
	}
}

func TestSessionManager_IPDomainBurst_RepeatedDomainNoTrigger(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	ip := testClientIP

	// 2 unique domains (below threshold of 3)
	for _, d := range []string{"a.com", "b.com"} {
		sm.RecordIPDomain(ip, d, cfg)
	}

	// Revisiting a known domain should not trigger burst
	anomalies := sm.RecordIPDomain(ip, "a.com", cfg)
	for _, a := range anomalies {
		if a.Type == testIPDomainBurst {
			t.Error("revisiting known domain should not trigger ip_domain_burst")
		}
	}
}

func TestSessionManager_IPDomainBurst_WindowExpiry(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	cfg.WindowMinutes = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	ip := testClientIP

	// 2 unique domains (below threshold)
	for _, d := range []string{"a.com", "b.com"} {
		sm.RecordIPDomain(ip, d, cfg)
	}

	// Backdate all IP domain entries past the window
	sm.mu.Lock()
	past := time.Now().Add(-2 * time.Minute)
	entries := sm.ipDomains[ip]
	for i := range entries {
		entries[i].at = past
	}
	sm.ipDomains[ip] = entries
	sm.mu.Unlock()

	// 3rd domain should NOT trigger burst because old entries expired (only 1 in window)
	anomalies := sm.RecordIPDomain(ip, "c.com", cfg)
	for _, a := range anomalies {
		if a.Type == testIPDomainBurst {
			t.Error("ip_domain_burst should not trigger after window expiry")
		}
	}
}

func TestSessionManager_IPDomainBurst_DifferentIPs(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	// Two different IPs each access 2 domains: neither should trigger (below 3)
	for _, d := range []string{"a.com", "b.com"} {
		sm.RecordIPDomain(testClientIP, d, cfg)
		sm.RecordIPDomain("10.0.0.2", d, cfg)
	}

	// 3rd domain on IP1 hits threshold for IP1 only
	anomalies1 := sm.RecordIPDomain(testClientIP, "c.com", cfg)
	found := false
	for _, a := range anomalies1 {
		if a.Type == testIPDomainBurst {
			found = true
		}
	}
	if !found {
		t.Error("IP 10.0.0.1 should trigger ip_domain_burst with 3rd domain")
	}

	// IP2 still at 2 domains, revisiting should not trigger
	anomalies2 := sm.RecordIPDomain("10.0.0.2", "b.com", cfg)
	for _, a := range anomalies2 {
		if a.Type == testIPDomainBurst {
			t.Error("IP 10.0.0.2 should not trigger burst (only 2 unique domains)")
		}
	}
}

func TestEscalationLabel_HighLevel(t *testing.T) {
	// Levels beyond the defined range clamp to the last label ("critical").
	label := session.EscalationLabel(5)
	if label != testLevelCritical {
		t.Errorf("expected critical, got %s", label)
	}

	// Test known labels
	if got := session.EscalationLabel(0); got != testLevelNormal {
		t.Errorf("expected normal, got %s", got)
	}
	if got := session.EscalationLabel(1); got != testLevelElevated {
		t.Errorf("expected elevated, got %s", got)
	}
	if got := session.EscalationLabel(2); got != testLevelHigh {
		t.Errorf("expected high, got %s", got)
	}
}

func TestSessionManager_IPDomainCleanup_PartialExpiry(t *testing.T) {
	cfg := testSessionConfig()
	cfg.WindowMinutes = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	// Add 2 domains, backdate only 1
	sm.RecordIPDomain(testClientIP, "a.com", cfg)
	sm.RecordIPDomain(testClientIP, "b.com", cfg)

	sm.mu.Lock()
	entries := sm.ipDomains[testClientIP]
	entries[0].at = time.Now().Add(-2 * time.Minute) // expire first only
	sm.ipDomains[testClientIP] = entries
	sm.mu.Unlock()

	sm.cleanup()

	// IP should still exist with 1 entry (partial cleanup, not full delete)
	sm.mu.RLock()
	remaining := sm.ipDomains[testClientIP]
	sm.mu.RUnlock()

	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining IP domain entry, got %d", len(remaining))
	}
}

func TestSessionManager_IPDomainCleanup(t *testing.T) {
	cfg := testSessionConfig()
	cfg.WindowMinutes = 1
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sm.RecordIPDomain(testClientIP, "a.com", cfg)
	sm.RecordIPDomain(testClientIP, "b.com", cfg)

	// Backdate entries
	sm.mu.Lock()
	past := time.Now().Add(-2 * time.Minute)
	entries := sm.ipDomains[testClientIP]
	for i := range entries {
		entries[i].at = past
	}
	sm.ipDomains[testClientIP] = entries
	sm.mu.Unlock()

	// Cleanup should prune expired IP domain entries
	sm.cleanup()

	sm.mu.RLock()
	_, exists := sm.ipDomains[testClientIP]
	sm.mu.RUnlock()

	if exists {
		t.Error("expired IP domain entries should be cleaned up")
	}
}

// TestSessionManager_Cleanup_EscalatedGaugeDecrement verifies that when an
// escalated session is evicted by TTL cleanup, the adaptive session level gauge
// is decremented.
func TestSessionManager_Cleanup_EscalatedGaugeDecrement(t *testing.T) {
	cfg := testSessionConfig()
	cfg.SessionTTLMinutes = 1
	m := metrics.New()
	sm := NewSessionManager(cfg, nil, m)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Escalate the session so escalationLevel > 0.
	sess.RecordSignal(session.SignalBlock, 5.0)                            // +3
	sess.RecordSignal(session.SignalNearMiss, 5.0)                         // +1
	escalated, _, _ := sess.RecordSignal(session.SignalDomainAnomaly, 5.0) // +2, total 6 >= 5
	if !escalated {
		t.Fatal("pre-condition: session should be escalated before cleanup test")
	}

	// Backdate the session's last activity past TTL.
	sess.mu.Lock()
	sess.lastActivity = time.Now().Add(-2 * time.Minute)
	sess.mu.Unlock()

	// Simulate the gauge increment that proxy code would emit on escalation.
	// cleanup() must decrement this back to zero when the session is evicted.
	m.SetAdaptiveSessionLevel(testLevelElevated, 1)

	if got := adaptiveElevatedGaugeValue(t, m); got != 1 {
		t.Fatalf("pre-condition: gauge for %q = %.0f, want 1", testLevelElevated, got)
	}

	sm.cleanup()

	if sm.Len() != 0 {
		t.Error("escalated session should be evicted after TTL expiry")
	}
	// After cleanup the gauge must be decremented back to zero.
	if got := adaptiveElevatedGaugeValue(t, m); got != 0 {
		t.Errorf("adaptive gauge for %q after cleanup = %.0f, want 0", testLevelElevated, got)
	}
}

// TestSessionManager_EvictOldest_EscalatedGaugeDecrement verifies that when
// an escalated session is evicted due to capacity overflow, the adaptive session
// level gauge is decremented.
func TestSessionManager_EvictOldest_EscalatedGaugeDecrement(t *testing.T) {
	cfg := testSessionConfig()
	cfg.MaxSessions = 2
	m := metrics.New()
	sm := NewSessionManager(cfg, nil, m)
	defer sm.Close()

	// Create and escalate the first session.
	sess := sm.GetOrCreate("escalated-session")
	sess.RecordSignal(session.SignalBlock, 5.0)                            // +3
	sess.RecordSignal(session.SignalNearMiss, 5.0)                         // +1
	escalated, _, _ := sess.RecordSignal(session.SignalDomainAnomaly, 5.0) // +2, total 6 >= 5
	if !escalated {
		t.Fatal("pre-condition: first session should be escalated")
	}

	// Simulate the gauge increment that proxy code would emit on escalation.
	// evictOldest() must decrement this back to zero when the session is evicted.
	m.SetAdaptiveSessionLevel(testLevelElevated, 1)

	if got := adaptiveElevatedGaugeValue(t, m); got != 1 {
		t.Fatalf("pre-condition: gauge for %q = %.0f, want 1", testLevelElevated, got)
	}

	// Ensure "escalated-session" has older lastActivity than "second-session".
	// RecordSignal doesn't update lastActivity, so we just need to ensure the
	// second session is created after with a newer timestamp.
	time.Sleep(time.Millisecond)
	sm.GetOrCreate("second-session")

	// Adding a third session when at capacity evicts "escalated-session"
	// (oldest lastActivity). This must decrement the adaptive gauge.
	sm.GetOrCreate("third-session")

	if sm.Len() != 2 {
		t.Errorf("expected 2 sessions after capacity eviction, got %d", sm.Len())
	}

	// Eviction metric must be recorded.
	if !scrapeMetric(t, m, "pipelock_sessions_evicted_total") {
		t.Error("expected eviction metric after capacity eviction of escalated session")
	}
	// After eviction the gauge must be decremented back to zero.
	if got := adaptiveElevatedGaugeValue(t, m); got != 0 {
		t.Errorf("adaptive gauge for %q after eviction = %.0f, want 0", testLevelElevated, got)
	}
}

// TestSessionManager_SessionStore_Disabled verifies that SessionStore returns
// nil when session profiling is disabled (no SessionManager created).
func TestProxy_SessionStore_Disabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	// SessionProfiling is disabled by default in config.Defaults().
	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	if got := p.SessionStore(); got != nil {
		t.Errorf("expected nil SessionStore when profiling disabled, got %T", got)
	}
}

// TestSessionManager_AsStore verifies that AsStore returns a non-nil
// session.Store that delegates GetOrCreate to the underlying SessionManager.
func TestSessionManager_AsStore(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	store := sm.AsStore()
	if store == nil {
		t.Fatal("expected non-nil store from AsStore()")
	}

	// GetOrCreate via the store must return a valid Recorder.
	rec := store.GetOrCreate("test-key")
	if rec == nil {
		t.Fatal("expected non-nil Recorder from store.GetOrCreate()")
	}

	// The recorder must be the same underlying session as direct access.
	direct := sm.GetOrCreate("test-key")
	if rec != direct {
		t.Error("store.GetOrCreate and sm.GetOrCreate should return the same session for the same key")
	}
}

// TestProxy_SessionStore_Enabled verifies that SessionStore returns a non-nil
// store when session profiling is enabled.
func TestProxy_SessionStore_Enabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SessionProfiling.Enabled = true
	p, err := New(cfg, audit.NewNop(), scanner.New(cfg), metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	if got := p.SessionStore(); got == nil {
		t.Error("expected non-nil SessionStore when profiling enabled")
	}
}

func TestSessionState_TimeBasedDeescalation(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Escalate to level 1 (threshold 5, +3 block = 3, +3 block = 6 -> escalate)
	sess.RecordSignal(session.SignalBlock, 5.0) // +3, total 3
	sess.RecordSignal(session.SignalBlock, 5.0) // +3, total 6 -> escalate to 1

	if sess.EscalationLevel() != 1 {
		t.Fatalf("expected level 1, got %d", sess.EscalationLevel())
	}

	// Simulate time passing beyond maxLevelDuration.
	sess.mu.Lock()
	sess.lastEscalation = time.Now().Add(-maxLevelDuration - time.Second)
	sess.mu.Unlock()

	// TryAutoRecover is now the sole time-based recovery path.
	blockAllCheck := func(level int) bool { return level >= 3 }
	changed, _, _ := sess.TryAutoRecover(blockAllCheck)

	if !changed {
		t.Fatal("expected TryAutoRecover to de-escalate after max dwell time")
	}
	if sess.EscalationLevel() != 0 {
		t.Errorf("expected de-escalation to level 0 after max dwell time, got %d", sess.EscalationLevel())
	}
}

func TestSessionState_CriticalDeescalation(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Escalate to critical (level 3) by sending many signals.
	// Use threshold 5.0; each block = +3. After 2 blocks (6 pts) -> level 1.
	// Threshold doubles to 10. 2 more blocks (6 pts, total 12) -> level 2.
	// Threshold doubles to 20. 3 more blocks (9 pts, total 21) -> level 3.
	for range 7 {
		sess.RecordSignal(session.SignalBlock, 5.0)
	}

	level := sess.EscalationLevel()
	if level < 3 {
		t.Fatalf("expected critical (level 3+), got %d", level)
	}

	// Simulate time passing -- de-escalate one level via TryAutoRecover.
	sess.mu.Lock()
	levelBefore := sess.escalationLevel
	sess.lastEscalation = time.Now().Add(-maxLevelDuration - time.Second)
	sess.mu.Unlock()

	blockAllCheck := func(lvl int) bool { return lvl >= 3 }
	changed, _, _ := sess.TryAutoRecover(blockAllCheck)

	if !changed {
		t.Fatal("expected TryAutoRecover to de-escalate after max dwell time")
	}

	levelAfter := sess.EscalationLevel()
	if levelAfter >= levelBefore {
		t.Errorf("expected level to decrease from %d, got %d", levelBefore, levelAfter)
	}
}

func TestSessionState_RecordClean_NoImplicitDeescalation(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Escalate to critical (level 3).
	for range 7 {
		sess.RecordSignal(session.SignalBlock, 5.0)
	}
	if sess.EscalationLevel() < 3 {
		t.Fatalf("expected critical (level 3+), got %d", sess.EscalationLevel())
	}

	// Simulate time passing beyond maxLevelDuration.
	sess.mu.Lock()
	sess.lastEscalation = time.Now().Add(-maxLevelDuration - time.Second)
	sess.mu.Unlock()

	// RecordClean must NOT de-escalate. Time-based recovery is handled
	// exclusively by TryAutoRecover (called from on-entry fast paths
	// and background sweep).
	sess.RecordClean(0.5)

	if sess.EscalationLevel() < 3 {
		t.Errorf("RecordClean should not implicitly de-escalate; got level %d", sess.EscalationLevel())
	}
}

func TestRecordSignal_NoImplicitDeescalation(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClient)

	// Push to level 2, set lastEscalation far in the past.
	sess.mu.Lock()
	sess.escalationLevel = 2
	sess.lastEscalation = time.Now().Add(-10 * time.Minute)
	sess.currentThreshold = 20.0
	sess.threatScore = 5.0
	sess.mu.Unlock()

	// RecordSignal should NOT de-escalate anymore. Time-based recovery is
	// handled exclusively by TryAutoRecover.
	sess.RecordSignal(session.SignalNearMiss, 5.0)

	if sess.EscalationLevel() < 2 {
		t.Errorf("RecordSignal should not implicitly de-escalate; got level %d", sess.EscalationLevel())
	}
}

func TestSessionState_CriticalNoActivityRefresh(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Escalate to critical.
	for range 10 {
		sess.RecordSignal(session.SignalBlock, 2.0)
	}

	if sess.EscalationLevel() < 3 {
		t.Fatalf("expected critical, got level %d", sess.EscalationLevel())
	}

	// Simulate proxy setting block_all flag after escalation.
	sess.SetBlockAll(true)

	// Record the last activity time.
	sess.mu.Lock()
	activityBefore := sess.lastActivity
	sess.mu.Unlock()

	// Wait a moment, then RecordRequest at block_all.
	time.Sleep(10 * time.Millisecond)
	sess.RecordRequest("example.com", cfg)

	sess.mu.Lock()
	activityAfter := sess.lastActivity
	sess.mu.Unlock()

	// At block_all, lastActivity should NOT be refreshed.
	if activityAfter.After(activityBefore) {
		t.Error("lastActivity should not be refreshed at critical level (prevents death spiral from idle eviction starvation)")
	}
}

func TestSessionState_SubCriticalActivityRefresh(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// Escalate to level 1 (below critical).
	sess.RecordSignal(session.SignalBlock, 5.0) // +3, total 3
	sess.RecordSignal(session.SignalBlock, 5.0) // +3, total 6 → level 1

	if sess.EscalationLevel() < 1 || sess.EscalationLevel() >= 3 {
		t.Fatalf("expected level 1-2, got %d", sess.EscalationLevel())
	}

	sess.mu.Lock()
	activityBefore := sess.lastActivity
	sess.mu.Unlock()

	time.Sleep(10 * time.Millisecond)
	sess.RecordRequest("example.com", cfg)

	sess.mu.Lock()
	activityAfter := sess.lastActivity
	sess.mu.Unlock()

	// Below critical, lastActivity SHOULD be refreshed.
	if !activityAfter.After(activityBefore) {
		t.Error("lastActivity should be refreshed at sub-critical escalation levels")
	}
}

func TestSessionManager_CleanupLoop_DoneStops(t *testing.T) {
	cfg := testSessionConfig()
	cfg.CleanupIntervalSeconds = 1 // short interval for test speed
	sm := NewSessionManager(cfg, nil, nil)

	// Create a session with expired activity.
	sess := sm.GetOrCreate(testClientIP)
	sess.mu.Lock()
	sess.lastActivity = time.Now().Add(-time.Hour)
	sess.mu.Unlock()

	// Close should stop the cleanup loop goroutine cleanly.
	sm.Close()

	// After Close, the session should still exist (cleanup loop stopped before
	// the timer fired, or the timer fired and cleaned up — both are valid).
	// The key invariant: no panic, no goroutine leak, no race.
}

func TestSessionManager_CleanupLoop_RunsCleanup(t *testing.T) {
	cfg := testSessionConfig()
	cfg.CleanupIntervalSeconds = 1
	cfg.SessionTTLMinutes = 0 // immediate expiry
	m := metrics.New()
	sm := NewSessionManager(cfg, nil, m)
	defer sm.Close()

	// Create a session that is immediately stale.
	sess := sm.GetOrCreate("stale-session")
	sess.mu.Lock()
	sess.lastActivity = time.Now().Add(-time.Hour)
	sess.mu.Unlock()

	// Manually invoke cleanup to verify it works.
	sm.cleanup()
	if sm.Len() != 0 {
		t.Errorf("expected 0 sessions after cleanup, got %d", sm.Len())
	}
}

func TestSessionState_SetBlockAll(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClientIP)

	// At block_all, RecordRequest should NOT refresh lastActivity.
	sess.SetBlockAll(true)
	sess.mu.Lock()
	sess.lastActivity = time.Now().Add(-10 * time.Minute)
	frozen := sess.lastActivity
	sess.mu.Unlock()

	sess.RecordRequest("example.com", cfg)

	sess.mu.Lock()
	after := sess.lastActivity
	sess.mu.Unlock()

	if !after.Equal(frozen) {
		t.Error("lastActivity should NOT be refreshed when at block_all")
	}

	// Clear block_all; activity should resume.
	sess.SetBlockAll(false)
	sess.RecordRequest("other.com", cfg)

	sess.mu.Lock()
	afterClear := sess.lastActivity
	sess.mu.Unlock()

	if !afterClear.After(frozen) {
		t.Error("lastActivity should be refreshed after clearing block_all")
	}
}

func TestSessionManager_IPDomainBurstCooldown(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 2
	cfg.WindowMinutes = 5
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	// First burst: should have score > 0.
	sm.RecordIPDomain(testClientIP, "a.com", cfg)
	anomalies := sm.RecordIPDomain(testClientIP, "b.com", cfg)
	if len(anomalies) == 0 {
		t.Fatal("expected ip_domain_burst anomaly")
	}
	if anomalies[0].Score == 0 {
		t.Error("first burst should have non-zero score")
	}

	// Second burst: same window, score should be 0 (cooldown).
	anomalies2 := sm.RecordIPDomain(testClientIP, "c.com", cfg)
	if len(anomalies2) == 0 {
		t.Fatal("expected ip_domain_burst anomaly on repeat")
	}
	if anomalies2[0].Score != 0 {
		t.Error("repeat burst in same window should have score 0 (cooldown)")
	}
}

// escalateToLevel is a test helper that forces a session to a given
// escalation level by directly manipulating internal state under lock.
func escalateToLevel(s *SessionState, level int, lastEsc time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.escalationLevel = level
	s.lastEscalation = lastEsc
	s.currentThreshold = 10.0 // arbitrary non-zero threshold
	s.threatScore = 5.0       // arbitrary mid-range score
}

func TestSessionState_TryAutoRecover_Expired(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("recover-expired")

	// Place session at level 3, last escalation 6 min ago (beyond 5 min maxLevelDuration).
	escalateToLevel(sess, 3, time.Now().Add(-6*time.Minute))

	// blockAllCheck returns true for level >= 3, false otherwise.
	blockAllCheck := func(level int) bool { return level >= 3 }

	changed, from, to := sess.TryAutoRecover(blockAllCheck)

	if !changed {
		t.Fatal("expected changed=true for expired escalation")
	}
	if from != 3 {
		t.Errorf("expected from=3, got %d", from)
	}
	if to != 2 {
		t.Errorf("expected to=2, got %d", to)
	}
	if sess.EscalationLevel() != 2 {
		t.Errorf("expected escalation level 2, got %d", sess.EscalationLevel())
	}
	// Level 2 < 3, so blockAllCheck(2) returns false.
	if sess.BlockAll() {
		t.Error("expected atBlockAll=false at level 2")
	}
}

func TestSessionState_TryAutoRecover_NotExpired(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("recover-not-expired")

	// Place session at level 3, last escalation only 3 min ago (within 5 min maxLevelDuration).
	escalateToLevel(sess, 3, time.Now().Add(-3*time.Minute))

	blockAllCheck := func(level int) bool { return level >= 3 }

	changed, _, _ := sess.TryAutoRecover(blockAllCheck)

	if changed {
		t.Fatal("expected changed=false for non-expired escalation")
	}
	if sess.EscalationLevel() != 3 {
		t.Errorf("expected escalation level still 3, got %d", sess.EscalationLevel())
	}
}

func TestSessionState_TryAutoRecover_CustomBlockAllAtLowerLevel(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("recover-custom-blockall")

	// Place session at level 2, last escalation 6 min ago.
	escalateToLevel(sess, 2, time.Now().Add(-6*time.Minute))

	// Custom config: blockAllCheck returns true for level >= 1.
	// Even after dropping from 2 to 1, the session is still blocked.
	blockAllCheck := func(level int) bool { return level >= 1 }

	changed, from, to := sess.TryAutoRecover(blockAllCheck)

	if !changed {
		t.Fatal("expected changed=true for expired escalation")
	}
	if from != 2 {
		t.Errorf("expected from=2, got %d", from)
	}
	if to != 1 {
		t.Errorf("expected to=1, got %d", to)
	}
	// blockAllCheck(1) returns true — session stays blocked at the lower level.
	if !sess.BlockAll() {
		t.Error("expected atBlockAll=true at level 1 with custom config")
	}
}

func TestSessionState_TryAutoRecover_AtLevelZero(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("recover-level-zero")

	// Level 0 session cannot de-escalate further.
	blockAllCheck := func(level int) bool { return level >= 3 }

	changed, _, _ := sess.TryAutoRecover(blockAllCheck)

	if changed {
		t.Fatal("expected changed=false at level 0")
	}
	if sess.EscalationLevel() != 0 {
		t.Errorf("expected escalation level 0, got %d", sess.EscalationLevel())
	}
}

func TestSessionState_OnEntryRecovery(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("agent|127.0.0.1")

	// Push to critical with expired timer.
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	frozenActivity := sess.lastActivity
	sess.mu.Unlock()

	blockAllCheck := func(level int) bool { return level >= 3 }

	// Simulate what recordSessionActivity does: TryAutoRecover then RecordRequest.
	changed, _, _ := sess.TryAutoRecover(blockAllCheck)
	if !changed {
		t.Fatal("expected on-entry recovery to fire")
	}

	// RecordRequest should refresh lastActivity (no longer at block_all).
	sess.RecordRequest("example.com", cfg)

	sess.mu.Lock()
	activityRefreshed := sess.lastActivity.After(frozenActivity)
	sess.mu.Unlock()

	if !activityRefreshed {
		t.Error("lastActivity should refresh after on-entry recovery clears block_all")
	}
}

func TestSessionManager_DeescalationSweep(t *testing.T) {
	cfg := testSessionConfig()
	m := metrics.New()

	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}

	sm := NewSessionManager(cfg, adaptiveCfg, m)
	defer sm.Close()

	sess := sm.GetOrCreate(testClient)

	// Push to critical with expired timer.
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	// Call sweep directly (don't wait for ticker).
	sm.sweepDeescalation()

	if sess.EscalationLevel() != 2 {
		t.Errorf("expected level 2 after sweep, got %d", sess.EscalationLevel())
	}
	if sess.BlockAll() {
		t.Error("expected atBlockAll=false after de-escalation to high")
	}
}

func TestSessionManager_SweepNoAdaptiveConfig(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClient)
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.mu.Unlock()

	// With nil adaptive config, sweep should be a no-op.
	sm.sweepDeescalation()

	if sess.EscalationLevel() != 3 {
		t.Errorf("sweep without adaptive config should not de-escalate; got level %d", sess.EscalationLevel())
	}
}

// TestSessionState_FullRecoveryCycle exercises the complete block_all recovery
// lifecycle: escalate to critical, timer expires, background sweep de-escalates,
// clean requests flow and decay, re-escalation is possible.
func TestSessionState_FullRecoveryCycle(t *testing.T) {
	cfg := testSessionConfig()
	m := metrics.New()

	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:              true,
		EscalationThreshold:  5.0,
		DecayPerCleanRequest: 0.5,
		Levels: config.EscalationLevels{
			Elevated: config.EscalationActions{},
			High:     config.EscalationActions{},
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}

	sm := NewSessionManager(cfg, adaptiveCfg, m)
	defer sm.Close()

	sess := sm.GetOrCreate("test-agent|10.0.0.1")

	// 1. Escalate to critical.
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now()
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	// 2. Verify blocked.
	if !sess.BlockAll() {
		t.Fatal("expected block_all at critical")
	}

	// 3. Simulate 6 minutes passing (beyond 5 min maxLevelDuration).
	sess.mu.Lock()
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.mu.Unlock()

	// 4. Background sweep fires.
	sm.sweepDeescalation()

	// 5. Should be at high (level 2), no longer blocked.
	if sess.EscalationLevel() != 2 {
		t.Errorf("expected level 2, got %d", sess.EscalationLevel())
	}
	if sess.BlockAll() {
		t.Error("expected block_all cleared at high")
	}

	// 6. Clean requests now flow and decay works.
	sess.RecordClean(0.5)
	score := sess.ThreatScore()
	if score >= 20.0 {
		t.Errorf("expected score to decay below 20, got %.1f", score)
	}

	// 7. Re-escalation: bad signal pushes score up but stays at high
	//    because threshold was halved (20.0) and score is below it.
	escalated, _, _ := sess.RecordSignal(session.SignalBlock, 5.0) // +3 points
	_ = escalated                                                  // may or may not cross threshold
	if sess.EscalationLevel() < 2 {
		t.Error("should not drop below high without more time")
	}
}

// TestSessionManager_SweepAfterConfigReload verifies that the background sweep
// uses the NEW adaptive config after a hot-reload, not the stale original.
func TestSessionManager_SweepAfterConfigReload(t *testing.T) {
	cfg := testSessionConfig()
	m := metrics.New()

	// Start with block_all only at critical (default).
	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}

	sm := NewSessionManager(cfg, adaptiveCfg, m)
	defer sm.Close()

	sess := sm.GetOrCreate(testClient)

	// Push to critical with expired timer.
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	// Hot-reload: now block_all also applies at high (level 2).
	newAdaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			High:     config.EscalationActions{BlockAll: &blockAllTrue},
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm.UpdateConfig(cfg, newAdaptiveCfg)

	// Sweep should use NEW config for blockAllCheck.
	sm.sweepDeescalation()

	// De-escalated from critical to high, but high now also has block_all.
	if sess.EscalationLevel() != 2 {
		t.Errorf("expected level 2, got %d", sess.EscalationLevel())
	}
	// atBlockAll should STILL be true because high has block_all in new config.
	if !sess.BlockAll() {
		t.Error("expected atBlockAll=true at high with updated config")
	}
}

func TestSessionManager_ClearBlockAllOnAdaptiveDisable(t *testing.T) {
	cfg := testSessionConfig()
	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm := NewSessionManager(cfg, adaptiveCfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClient)
	sess.SetBlockAll(true)

	if !sess.BlockAll() {
		t.Fatal("expected block_all before disable")
	}

	// Hot-reload with adaptive disabled (nil).
	sm.UpdateConfig(cfg, nil)

	if sess.BlockAll() {
		t.Error("expected atBlockAll cleared after adaptive enforcement disabled via nil")
	}

	// Reset for second variant: Enabled=false.
	sess.SetBlockAll(true)
	disabledCfg := &config.AdaptiveEnforcement{Enabled: false}
	sm.UpdateConfig(cfg, disabledCfg)

	if sess.BlockAll() {
		t.Error("expected atBlockAll cleared after adaptive enforcement Enabled=false")
	}
}

func TestSessionManager_RecomputeBlockAllOnConfigChange(t *testing.T) {
	cfg := testSessionConfig()
	blockAllTrue := true
	// Start with block_all only at critical (level 3+).
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm := NewSessionManager(cfg, adaptiveCfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClient)

	// Session at level 2 (high) — not block_all in current config.
	sess.mu.Lock()
	sess.escalationLevel = 2
	sess.mu.Unlock()
	sess.SetBlockAll(false)

	if sess.BlockAll() {
		t.Fatal("level 2 should not be block_all with initial config")
	}

	// Hot-reload: now block_all applies at high (level 2) too.
	newAdaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			High:     config.EscalationActions{BlockAll: &blockAllTrue},
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm.UpdateConfig(cfg, newAdaptiveCfg)

	// atBlockAll should now be true for the level 2 session.
	if !sess.BlockAll() {
		t.Error("expected atBlockAll=true at level 2 after config reload added block_all at high")
	}
}

func TestSessionState_OnEntryRecovery_EmitsMetrics(t *testing.T) {
	cfg := testSessionConfig()
	m := metrics.New()
	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm := NewSessionManager(cfg, adaptiveCfg, m)
	defer sm.Close()

	sess := sm.GetOrCreate("agent|127.0.0.1")

	// Push to critical with expired timer.
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	// Simulate what recordSessionActivity does: build blockAllCheck, call TryAutoRecover.
	blockAllCheck := func(level int) bool {
		return decide.UpgradeAction("", level, adaptiveCfg) == config.ActionBlock
	}
	changed, from, to := sess.TryAutoRecover(blockAllCheck)
	if !changed {
		t.Fatal("expected recovery")
	}

	// Emit metrics like recordSessionActivity does.
	fromLabel := session.EscalationLabel(from)
	toLabel := session.EscalationLabel(to)
	m.RecordSessionAutoDeescalation(fromLabel, toLabel)
	m.SetAdaptiveSessionLevel(fromLabel, -1)
	m.SetAdaptiveSessionLevel(toLabel, 1)

	// Verify metrics were recorded.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	text := string(body)

	want := `pipelock_session_auto_deescalation_total{from="` + testLevelCritical + `",to="` + testLevelHigh + `"} 1`
	if !strings.Contains(text, want) {
		t.Errorf("expected %q in metrics output", want)
	}
}

func TestSessionState_TypeAssertRecovery(t *testing.T) {
	// This tests the pattern used in websocket.go and intercept.go:
	// type-assert session.Recorder to *SessionState, then call TryAutoRecover.
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("test-ws-client")

	// Push to critical with expired timer.
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	// Simulate the pattern: session.Recorder -> type assert -> TryAutoRecover.
	var rec session.Recorder = sess
	ss, ok := rec.(*SessionState)
	if !ok {
		t.Fatal("SessionState should implement session.Recorder")
	}

	blockAllCheck := func(level int) bool { return level >= 3 }
	changed, from, to := ss.TryAutoRecover(blockAllCheck)
	if !changed {
		t.Fatal("expected recovery via type assertion")
	}
	if from != 3 || to != 2 {
		t.Errorf("expected 3->2, got %d->%d", from, to)
	}
}

func TestSessionManager_RecomputeBlockAllMultipleSessions(t *testing.T) {
	cfg := testSessionConfig()
	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm := NewSessionManager(cfg, adaptiveCfg, nil)
	defer sm.Close()

	// Session at level 1 (elevated).
	sess1 := sm.GetOrCreate("client-1")
	sess1.mu.Lock()
	sess1.escalationLevel = 1
	sess1.mu.Unlock()

	// Session at level 2 (high).
	sess2 := sm.GetOrCreate("client-2")
	sess2.mu.Lock()
	sess2.escalationLevel = 2
	sess2.mu.Unlock()

	// Session at level 3 (critical).
	sess3 := sm.GetOrCreate("client-3")
	sess3.mu.Lock()
	sess3.escalationLevel = 3
	sess3.mu.Unlock()
	sess3.SetBlockAll(true)

	// Reload: block_all now applies at high (level 2) and above.
	newAdaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			High:     config.EscalationActions{BlockAll: &blockAllTrue},
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm.UpdateConfig(cfg, newAdaptiveCfg)

	if sess1.BlockAll() {
		t.Error("level 1 should not be block_all")
	}
	if !sess2.BlockAll() {
		t.Error("level 2 should now be block_all")
	}
	if !sess3.BlockAll() {
		t.Error("level 3 should still be block_all")
	}
}

// TestSessionManager_SweepMetrics_MultiLevel exercises sweepDeescalation with
// sessions at multiple escalation levels to cover the from > 0 and to > 0
// gauge-update guards plus the deescalation counter emission path.
func TestSessionManager_SweepMetrics_MultiLevel(t *testing.T) {
	cfg := testSessionConfig()
	m := metrics.New()
	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm := NewSessionManager(cfg, adaptiveCfg, m)
	defer sm.Close()

	// Session 1: level 3 (critical) -- will recover to 2 (high).
	s1 := sm.GetOrCreate("client-1")
	s1.mu.Lock()
	s1.escalationLevel = 3
	s1.lastEscalation = time.Now().Add(-6 * time.Minute)
	s1.currentThreshold = 40.0
	s1.threatScore = 20.0
	s1.atBlockAll = true
	s1.mu.Unlock()

	// Session 2: level 1 (elevated) -- will recover to 0 (normal).
	s2 := sm.GetOrCreate("client-2")
	s2.mu.Lock()
	s2.escalationLevel = 1
	s2.lastEscalation = time.Now().Add(-6 * time.Minute)
	s2.currentThreshold = 10.0
	s2.threatScore = 5.0
	s2.mu.Unlock()

	sm.sweepDeescalation()

	// Session 1: level 2 (high), gauge updated.
	if s1.EscalationLevel() != 2 {
		t.Errorf("s1: expected level 2, got %d", s1.EscalationLevel())
	}

	// Session 2: level 0 (normal), gauge should NOT increment "normal" (level > 0 guard).
	if s2.EscalationLevel() != 0 {
		t.Errorf("s2: expected level 0, got %d", s2.EscalationLevel())
	}

	// Verify metrics.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	text := string(body)

	// Should have critical->high deescalation counter.
	wantCritToHigh := `pipelock_session_auto_deescalation_total{from="` + testLevelCritical + `",to="` + testLevelHigh + `"} 1`
	if !strings.Contains(text, wantCritToHigh) {
		t.Errorf("missing critical->high deescalation counter; want %q in output", wantCritToHigh)
	}
	// Should have elevated->normal deescalation counter.
	wantElevToNorm := `pipelock_session_auto_deescalation_total{from="` + testLevelElevated + `",to="` + testLevelNormal + `"} 1`
	if !strings.Contains(text, wantElevToNorm) {
		t.Errorf("missing elevated->normal deescalation counter; want %q in output", wantElevToNorm)
	}
}

// TestSessionState_TryAutoRecover_ConfigDerivedCheck verifies the recovery
// pattern used by proxy.go and websocket.go: build blockAllCheck from the
// live adaptive config via decide.UpgradeAction, then call TryAutoRecover.
func TestSessionState_TryAutoRecover_ConfigDerivedCheck(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()

	sess := sm.GetOrCreate(testClient)

	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	// Build blockAllCheck the same way proxy.go and websocket.go do.
	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	blockAllCheck := func(level int) bool {
		return decide.UpgradeAction("", level, adaptiveCfg) == config.ActionBlock
	}

	changed, from, to := sess.TryAutoRecover(blockAllCheck)
	if !changed {
		t.Fatal("expected recovery")
	}
	if from != 3 || to != 2 {
		t.Errorf("expected 3->2, got %d->%d", from, to)
	}
	if sess.BlockAll() {
		t.Error("level 2 should not have block_all in this config")
	}
}

// TestSessionManager_SweepNilMetrics verifies that sweepDeescalation with
// nil metrics does not panic and still de-escalates sessions correctly.
// This covers the `changed && sm.metrics != nil` guard in sweepDeescalation.
func TestSessionManager_SweepNilMetrics(t *testing.T) {
	cfg := testSessionConfig()
	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	// Pass nil for metrics -- the sweep should still de-escalate without panicking.
	sm := NewSessionManager(cfg, adaptiveCfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("nil-metrics-client")
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	// Sweep with nil metrics must not panic and must still de-escalate.
	sm.sweepDeescalation()

	if sess.EscalationLevel() != 2 {
		t.Errorf("expected level 2 after sweep with nil metrics, got %d", sess.EscalationLevel())
	}
	if sess.BlockAll() {
		t.Error("expected atBlockAll=false after de-escalation from critical to high")
	}
}

// TestSessionManager_SweepMetrics_ToZeroSkipsGaugeIncrement verifies that
// when a session de-escalates to level 0, the sweep emits the deescalation
// counter but does NOT call SetAdaptiveSessionLevel for the "normal" label
// (the to > 0 guard prevents incrementing a gauge for un-escalated sessions).
func TestSessionManager_SweepMetrics_ToZeroSkipsGaugeIncrement(t *testing.T) {
	cfg := testSessionConfig()
	m := metrics.New()
	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}
	sm := NewSessionManager(cfg, adaptiveCfg, m)
	defer sm.Close()

	// Single session at level 1 (elevated), will recover to level 0 (normal).
	sess := sm.GetOrCreate("to-zero-client")
	sess.mu.Lock()
	sess.escalationLevel = 1
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 10.0
	sess.threatScore = 5.0
	sess.mu.Unlock()

	sm.sweepDeescalation()

	if sess.EscalationLevel() != 0 {
		t.Errorf("expected level 0, got %d", sess.EscalationLevel())
	}

	// Deescalation counter should exist for elevated->normal.
	wantCounter := `pipelock_session_auto_deescalation_total{from="` + testLevelElevated + `",to="` + testLevelNormal + `"} 1`
	if !scrapeMetric(t, m, wantCounter) {
		t.Errorf("expected deescalation counter %q", wantCounter)
	}

	// The "normal" level gauge should NOT have been incremented (to > 0 guard).
	// Gather raw metrics and check that "normal" label does not appear in
	// pipelock_adaptive_sessions_current.
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, fam := range fams {
		if fam.GetName() != metricAdaptiveSessions {
			continue
		}
		for _, metric := range fam.GetMetric() {
			for _, lbl := range metric.GetLabel() {
				if lbl.GetName() == metricLabelLevel && lbl.GetValue() == testLevelNormal && metric.GetGauge().GetValue() > 0 {
					t.Error("should not increment gauge for normal level (to > 0 guard)")
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// trySessionRecovery helper tests
// ---------------------------------------------------------------------------

func TestTrySessionRecovery_Success(t *testing.T) {
	cfg := testSessionConfig()
	m := metrics.New()
	sm := NewSessionManager(cfg, nil, m)
	defer sm.Close()

	sess := sm.GetOrCreate(testClient)
	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}

	changed, fromLabel, toLabel := trySessionRecovery(sess, adaptiveCfg, m)
	if !changed {
		t.Fatal("expected recovery")
	}
	if fromLabel != testLevelCritical || toLabel != testLevelHigh {
		t.Errorf("expected critical->high, got %s->%s", fromLabel, toLabel)
	}

	// Verify metrics.
	wantCounter := `pipelock_session_auto_deescalation_total{from="` + testLevelCritical + `",to="` + testLevelHigh + `"} 1`
	if !scrapeMetric(t, m, wantCounter) {
		t.Error("missing deescalation counter")
	}
}

func TestTrySessionRecovery_NilAdaptive(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()
	sess := sm.GetOrCreate(testClient)

	changed, _, _ := trySessionRecovery(sess, nil, nil)
	if changed {
		t.Error("should be no-op with nil adaptive config")
	}
}

func TestTrySessionRecovery_DisabledAdaptive(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()
	sess := sm.GetOrCreate(testClient)

	adaptiveCfg := &config.AdaptiveEnforcement{Enabled: false}
	changed, _, _ := trySessionRecovery(sess, adaptiveCfg, nil)
	if changed {
		t.Error("should be no-op with disabled adaptive")
	}
}

func TestTrySessionRecovery_NonSessionState(t *testing.T) {
	// Pass a session.Recorder that is NOT *SessionState.
	adaptiveCfg := &config.AdaptiveEnforcement{Enabled: true}
	var rec session.Recorder // nil interface
	changed, _, _ := trySessionRecovery(rec, adaptiveCfg, nil)
	if changed {
		t.Error("should be no-op with nil recorder")
	}
}

func TestTrySessionRecovery_NotExpired(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()
	sess := sm.GetOrCreate(testClient)

	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-2 * time.Minute) // NOT expired
	sess.currentThreshold = 40.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}

	changed, _, _ := trySessionRecovery(sess, adaptiveCfg, nil)
	if changed {
		t.Error("should not recover before maxLevelDuration")
	}
}

func TestTrySessionRecovery_ToZeroSkipsGauge(t *testing.T) {
	cfg := testSessionConfig()
	m := metrics.New()
	sm := NewSessionManager(cfg, nil, m)
	defer sm.Close()
	sess := sm.GetOrCreate(testClient)

	sess.mu.Lock()
	sess.escalationLevel = 1
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 10.0
	sess.threatScore = 5.0
	sess.mu.Unlock()

	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels:  config.EscalationLevels{},
	}

	changed, fromLabel, toLabel := trySessionRecovery(sess, adaptiveCfg, m)
	if !changed {
		t.Fatal("expected recovery")
	}
	if fromLabel != testLevelElevated || toLabel != testLevelNormal {
		t.Errorf("expected elevated->normal, got %s->%s", fromLabel, toLabel)
	}

	// Verify "normal" gauge was NOT incremented (to > 0 guard).
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, fam := range fams {
		if fam.GetName() != metricAdaptiveSessions {
			continue
		}
		for _, metric := range fam.GetMetric() {
			for _, lbl := range metric.GetLabel() {
				if lbl.GetName() == metricLabelLevel && lbl.GetValue() == testLevelNormal && metric.GetGauge().GetValue() > 0 {
					t.Error("should not increment normal gauge for to-zero recovery")
				}
			}
		}
	}
}

func TestTrySessionRecovery_NilMetrics(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil, nil)
	defer sm.Close()
	sess := sm.GetOrCreate(testClient)

	sess.mu.Lock()
	sess.escalationLevel = 3
	sess.lastEscalation = time.Now().Add(-6 * time.Minute)
	sess.currentThreshold = 40.0
	sess.threatScore = 20.0
	sess.atBlockAll = true
	sess.mu.Unlock()

	blockAllTrue := true
	adaptiveCfg := &config.AdaptiveEnforcement{
		Enabled: true,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: &blockAllTrue},
		},
	}

	// Must not panic with nil metrics.
	changed, fromLabel, toLabel := trySessionRecovery(sess, adaptiveCfg, nil)
	if !changed {
		t.Fatal("expected recovery even with nil metrics")
	}
	if fromLabel != testLevelCritical || toLabel != testLevelHigh {
		t.Errorf("expected critical->high, got %s->%s", fromLabel, toLabel)
	}
}
