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

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
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
	sm := NewSessionManager(cfg, nil)
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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

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
		if a.Type == "domain_burst" { //nolint:goconst // test value
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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

	// 2 unique domains (below threshold of 3)
	for _, d := range []string{"a.com", "b.com"} {
		sess.RecordRequest(d, cfg)
	}

	// Revisiting already-seen domain should NOT trigger burst
	anomalies := sess.RecordRequest("a.com", cfg)
	for _, a := range anomalies {
		if a.Type == "domain_burst" { //nolint:goconst // test value
			t.Error("revisiting known domain should not trigger domain_burst")
		}
	}
}

func TestSessionManager_DomainBurst_WindowExpiry(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	cfg.WindowMinutes = 1
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

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
		if a.Type == "domain_burst" {
			t.Error("domain_burst should not trigger after window expiry")
		}
	}
}

func TestSessionManager_MaxSessions(t *testing.T) {
	cfg := testSessionConfig()
	cfg.MaxSessions = 3
	sm := NewSessionManager(cfg, nil)
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
	sm := NewSessionManager(cfg, nil)
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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sm.GetOrCreate("10.0.0.1") // fresh, within TTL

	sm.cleanup()

	if sm.Len() != 1 {
		t.Error("active session should not be evicted")
	}
}

func TestSessionManager_Concurrent(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil)
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
	sm := NewSessionManager(cfg, nil)
	sm.Close()
	// Double close should not panic
	sm.Close()
}

func TestSessionState_ThreatScore(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

	// DLP near-miss adds +1
	sess.RecordSignal(SignalDLPNearMiss, 5.0)
	if sess.ThreatScore() != 1.0 {
		t.Errorf("expected score 1.0, got %f", sess.ThreatScore())
	}

	// Block adds +3
	sess.RecordSignal(SignalBlock, 5.0)
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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

	// Decay without any signals should floor at 0
	sess.RecordClean(10.0)
	if sess.ThreatScore() != 0 {
		t.Errorf("expected score 0, got %f", sess.ThreatScore())
	}
}

func TestSessionState_Escalation(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

	if sess.IsEscalated() {
		t.Error("new session should not be escalated")
	}

	// Add signals to reach threshold of 5
	sess.RecordSignal(SignalBlock, 5.0)       // +3, total 3
	sess.RecordSignal(SignalDLPNearMiss, 5.0) // +1, total 4

	if sess.IsEscalated() {
		t.Error("should not escalate below threshold")
	}

	// Cross threshold
	escalated, from, to := sess.RecordSignal(SignalDomainAnomaly, 5.0) // +2, total 6
	if !escalated {
		t.Error("should escalate at threshold")
	}
	if from != "normal" { //nolint:goconst // test value
		t.Errorf("expected from=normal, got %s", from)
	}
	if to != "elevated" { //nolint:goconst // test value
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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

	// First escalation at threshold 5
	for range 5 {
		sess.RecordSignal(SignalDLPNearMiss, 5.0) // +1 each
	}

	if sess.EscalationLevel() != 1 {
		t.Fatalf("expected first escalation at score 5, level=%d score=%f", sess.EscalationLevel(), sess.ThreatScore())
	}

	// Threshold is now 10. Need to reach 10 total (currently at 5).
	for range 5 {
		sess.RecordSignal(SignalDLPNearMiss, 10.0) // +1 each, total reaches 10
	}

	if sess.EscalationLevel() != 2 {
		t.Errorf("expected second escalation at score 10, level=%d score=%f", sess.EscalationLevel(), sess.ThreatScore())
	}
}

func TestSessionState_EscalationSticky(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")

	// Escalate
	for range 5 {
		sess.RecordSignal(SignalDLPNearMiss, 5.0)
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

func TestSessionState_DomainAnomalySignal(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")
	sess.RecordSignal(SignalDomainAnomaly, 5.0) // +2

	if sess.ThreatScore() != 2.0 {
		t.Errorf("expected score 2.0, got %f", sess.ThreatScore())
	}
}

func TestSessionState_LastActivity(t *testing.T) {
	cfg := testSessionConfig()
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sess := sm.GetOrCreate("10.0.0.1")
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

func TestSessionManager_Metrics_EvictOnCapacity(t *testing.T) {
	cfg := testSessionConfig()
	cfg.MaxSessions = 2
	m := metrics.New()
	sm := NewSessionManager(cfg, m)
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
	sm := NewSessionManager(cfg, m)
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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sm.GetOrCreate("a")
	sm.GetOrCreate("b") // eviction with nil metrics should not panic

	sm.cleanup() // cleanup with nil metrics should not panic
}

func TestSessionManager_IPDomainBurst(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	ip := "10.0.0.1" //nolint:goconst // test value

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
		if a.Type == "ip_domain_burst" { //nolint:goconst // test value
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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	ip := "10.0.0.1"

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
				if a.Type == "ip_domain_burst" {
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
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	ip := "10.0.0.1"

	// 2 unique domains (below threshold of 3)
	for _, d := range []string{"a.com", "b.com"} {
		sm.RecordIPDomain(ip, d, cfg)
	}

	// Revisiting a known domain should not trigger burst
	anomalies := sm.RecordIPDomain(ip, "a.com", cfg)
	for _, a := range anomalies {
		if a.Type == "ip_domain_burst" {
			t.Error("revisiting known domain should not trigger ip_domain_burst")
		}
	}
}

func TestSessionManager_IPDomainBurst_WindowExpiry(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	cfg.WindowMinutes = 1
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	ip := "10.0.0.1"

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
		if a.Type == "ip_domain_burst" {
			t.Error("ip_domain_burst should not trigger after window expiry")
		}
	}
}

func TestSessionManager_IPDomainBurst_DifferentIPs(t *testing.T) {
	cfg := testSessionConfig()
	cfg.DomainBurst = 3
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	// Two different IPs each access 2 domains: neither should trigger (below 3)
	for _, d := range []string{"a.com", "b.com"} {
		sm.RecordIPDomain("10.0.0.1", d, cfg)
		sm.RecordIPDomain("10.0.0.2", d, cfg)
	}

	// 3rd domain on IP1 hits threshold for IP1 only
	anomalies1 := sm.RecordIPDomain("10.0.0.1", "c.com", cfg)
	found := false
	for _, a := range anomalies1 {
		if a.Type == "ip_domain_burst" {
			found = true
		}
	}
	if !found {
		t.Error("IP 10.0.0.1 should trigger ip_domain_burst with 3rd domain")
	}

	// IP2 still at 2 domains, revisiting should not trigger
	anomalies2 := sm.RecordIPDomain("10.0.0.2", "b.com", cfg)
	for _, a := range anomalies2 {
		if a.Type == "ip_domain_burst" {
			t.Error("IP 10.0.0.2 should not trigger burst (only 2 unique domains)")
		}
	}
}

func TestEscalationLabel_HighLevel(t *testing.T) {
	// Test the fallback format for levels beyond the label array
	label := escalationLabel(5)
	if label != "level_5" {
		t.Errorf("expected level_5, got %s", label)
	}

	// Test known labels
	if got := escalationLabel(0); got != "normal" {
		t.Errorf("expected normal, got %s", got)
	}
	if got := escalationLabel(1); got != "elevated" {
		t.Errorf("expected elevated, got %s", got)
	}
	if got := escalationLabel(2); got != "high" {
		t.Errorf("expected high, got %s", got)
	}
}

func TestSessionManager_IPDomainCleanup_PartialExpiry(t *testing.T) {
	cfg := testSessionConfig()
	cfg.WindowMinutes = 1
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	// Add 2 domains, backdate only 1
	sm.RecordIPDomain("10.0.0.1", "a.com", cfg) //nolint:goconst // test value
	sm.RecordIPDomain("10.0.0.1", "b.com", cfg) //nolint:goconst // test value

	sm.mu.Lock()
	entries := sm.ipDomains["10.0.0.1"]              //nolint:goconst // test value
	entries[0].at = time.Now().Add(-2 * time.Minute) // expire first only
	sm.ipDomains["10.0.0.1"] = entries
	sm.mu.Unlock()

	sm.cleanup()

	// IP should still exist with 1 entry (partial cleanup, not full delete)
	sm.mu.RLock()
	remaining := sm.ipDomains["10.0.0.1"]
	sm.mu.RUnlock()

	if len(remaining) != 1 {
		t.Errorf("expected 1 remaining IP domain entry, got %d", len(remaining))
	}
}

func TestSessionManager_IPDomainCleanup(t *testing.T) {
	cfg := testSessionConfig()
	cfg.WindowMinutes = 1
	sm := NewSessionManager(cfg, nil)
	defer sm.Close()

	sm.RecordIPDomain("10.0.0.1", "a.com", cfg)
	sm.RecordIPDomain("10.0.0.1", "b.com", cfg)

	// Backdate entries
	sm.mu.Lock()
	past := time.Now().Add(-2 * time.Minute)
	entries := sm.ipDomains["10.0.0.1"]
	for i := range entries {
		entries[i].at = past
	}
	sm.ipDomains["10.0.0.1"] = entries
	sm.mu.Unlock()

	// Cleanup should prune expired IP domain entries
	sm.cleanup()

	sm.mu.RLock()
	_, exists := sm.ipDomains["10.0.0.1"]
	sm.mu.RUnlock()

	if exists {
		t.Error("expired IP domain entries should be cleaned up")
	}
}
