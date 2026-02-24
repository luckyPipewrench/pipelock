package metrics

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecordAllowed(t *testing.T) {
	m := New()
	m.RecordAllowed(100 * time.Millisecond)
	m.RecordAllowed(200 * time.Millisecond)

	m.mu.Lock()
	if m.allowedCount != 2 {
		t.Errorf("expected 2 allowed, got %d", m.allowedCount)
	}
	m.mu.Unlock()
}

func TestRecordBlocked(t *testing.T) {
	m := New()
	m.RecordBlocked("evil.com", "blocklist", 50*time.Millisecond)
	m.RecordBlocked("evil.com", "blocklist", 50*time.Millisecond)
	m.RecordBlocked("bad.org", "dlp", 30*time.Millisecond)

	m.mu.Lock()
	if m.blockedCount != 3 {
		t.Errorf("expected 3 blocked, got %d", m.blockedCount)
	}
	if m.topBlockedDomains["evil.com"] != 2 {
		t.Errorf("expected evil.com=2, got %d", m.topBlockedDomains["evil.com"])
	}
	if m.topScannerHits["blocklist"] != 2 {
		t.Errorf("expected blocklist=2, got %d", m.topScannerHits["blocklist"])
	}
	m.mu.Unlock()
}

func TestPrometheusHandler(t *testing.T) {
	m := New()
	m.RecordAllowed(100 * time.Millisecond)
	m.RecordBlocked("evil.com", "dlp", 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	text := string(body)

	if !strings.Contains(text, "pipelock_requests_total") {
		t.Error("expected pipelock_requests_total in /metrics output")
	}
	if !strings.Contains(text, `result="allowed"`) {
		t.Error("expected allowed label in /metrics output")
	}
	if !strings.Contains(text, `result="blocked"`) {
		t.Error("expected blocked label in /metrics output")
	}
	if !strings.Contains(text, "pipelock_request_duration_seconds") {
		t.Error("expected pipelock_request_duration_seconds in /metrics output")
	}
	if !strings.Contains(text, "pipelock_scanner_hits_total") {
		t.Error("expected pipelock_scanner_hits_total in /metrics output")
	}
}

func TestStatsHandler(t *testing.T) {
	m := New()
	m.RecordAllowed(100 * time.Millisecond)
	m.RecordAllowed(200 * time.Millisecond)
	m.RecordBlocked("evil.com", "dlp", 50*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var stats statsResponse
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats JSON: %v", err)
	}

	if stats.Requests.Total != 3 {
		t.Errorf("expected total=3, got %d", stats.Requests.Total)
	}
	if stats.Requests.Allowed != 2 {
		t.Errorf("expected allowed=2, got %d", stats.Requests.Allowed)
	}
	if stats.Requests.Blocked != 1 {
		t.Errorf("expected blocked=1, got %d", stats.Requests.Blocked)
	}
	if stats.UptimeSeconds <= 0 {
		t.Error("expected positive uptime")
	}
	if len(stats.TopBlockedDomains) != 1 {
		t.Errorf("expected 1 top blocked domain, got %d", len(stats.TopBlockedDomains))
	}
	if len(stats.TopScanners) != 1 {
		t.Errorf("expected 1 top scanner, got %d", len(stats.TopScanners))
	}
}

func TestStatsHandler_BlockRate(t *testing.T) {
	m := New()
	m.RecordAllowed(10 * time.Millisecond)
	m.RecordBlocked("x.com", "dlp", 10*time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, req)

	var stats statsResponse
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if stats.Requests.BlockRate != 0.5 {
		t.Errorf("expected block_rate=0.5, got %f", stats.Requests.BlockRate)
	}
}

func TestStatsHandler_Empty(t *testing.T) {
	m := New()

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, req)

	var stats statsResponse
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if stats.Requests.Total != 0 {
		t.Errorf("expected total=0, got %d", stats.Requests.Total)
	}
	if stats.Requests.BlockRate != 0 {
		t.Errorf("expected block_rate=0, got %f", stats.Requests.BlockRate)
	}
}

func TestTopDomainsCapped(t *testing.T) {
	m := New()
	// Fill to the cap
	for i := range maxTopEntries {
		m.RecordBlocked("domain"+string(rune('A'+i%26))+string(rune('0'+i/26))+".com", "dlp", time.Millisecond)
	}

	// This domain should be ignored (cap reached, new key)
	m.RecordBlocked("overflow.com", "dlp", time.Millisecond)

	m.mu.Lock()
	if len(m.topBlockedDomains) > maxTopEntries {
		t.Errorf("expected at most %d domains, got %d", maxTopEntries, len(m.topBlockedDomains))
	}
	if _, exists := m.topBlockedDomains["overflow.com"]; exists {
		t.Error("overflow domain should not be tracked after cap")
	}
	m.mu.Unlock()
}

func TestTopDomainsExistingKeyStillIncrements(t *testing.T) {
	m := New()
	// Fill to the cap with one domain
	for range maxTopEntries {
		m.RecordBlocked("same.com", "dlp", time.Millisecond)
	}
	// Existing key should still increment even after cap
	m.RecordBlocked("same.com", "dlp", time.Millisecond)

	m.mu.Lock()
	if m.topBlockedDomains["same.com"] != maxTopEntries+1 {
		t.Errorf("expected %d, got %d", maxTopEntries+1, m.topBlockedDomains["same.com"])
	}
	m.mu.Unlock()
}

func TestConcurrentAccess(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			m.RecordAllowed(time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			m.RecordBlocked("x.com", "dlp", time.Millisecond)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	total := m.allowedCount + m.blockedCount
	m.mu.Unlock()

	if total != 200 {
		t.Errorf("expected 200 total, got %d", total)
	}
}

func TestTopScannersCapped(t *testing.T) {
	m := New()
	// Fill scanner hits to the cap with unique scanner names
	for i := range maxTopEntries {
		name := "scanner" + string(rune('A'+i%26)) + string(rune('0'+i/26))
		m.RecordBlocked("test.com", name, time.Millisecond)
	}

	// This scanner should be ignored (cap reached, new key)
	m.RecordBlocked("test.com", "overflow_scanner", time.Millisecond)

	m.mu.Lock()
	if len(m.topScannerHits) > maxTopEntries {
		t.Errorf("expected at most %d scanners, got %d", maxTopEntries, len(m.topScannerHits))
	}
	if _, exists := m.topScannerHits["overflow_scanner"]; exists {
		t.Error("overflow scanner should not be tracked after cap")
	}
	m.mu.Unlock()
}

func TestRecordSessionAnomaly(t *testing.T) {
	m := New()
	m.RecordSessionAnomaly("domain_burst")
	m.RecordSessionAnomaly("domain_burst")
	m.RecordSessionAnomaly("volume_spike")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, `pipelock_session_anomalies_total{type="domain_burst"}`) {
		t.Error("expected domain_burst anomaly counter in /metrics")
	}
	if !strings.Contains(text, `pipelock_session_anomalies_total{type="volume_spike"}`) {
		t.Error("expected volume_spike anomaly counter in /metrics")
	}
}

func TestRecordSessionEscalation(t *testing.T) {
	m := New()
	m.RecordSessionEscalation("warn", "block")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, `pipelock_session_escalations_total{from="warn",to="block"}`) {
		t.Error("expected escalation counter in /metrics")
	}
}

func TestSetSessionsActive(t *testing.T) {
	m := New()
	m.SetSessionsActive(42)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, "pipelock_sessions_active") {
		t.Error("expected pipelock_sessions_active gauge in /metrics")
	}
}

func TestRecordSessionEvicted(t *testing.T) {
	m := New()
	m.RecordSessionEvicted()
	m.RecordSessionEvicted()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, "pipelock_sessions_evicted_total") {
		t.Error("expected pipelock_sessions_evicted_total counter in /metrics")
	}
}

func TestTopScannersExistingKeyStillIncrements(t *testing.T) {
	m := New()
	// Fill scanners to cap with same key
	for range maxTopEntries {
		m.RecordBlocked("test.com", "dlp", time.Millisecond)
	}
	// Existing key should still increment
	m.RecordBlocked("test.com", "dlp", time.Millisecond)

	m.mu.Lock()
	if m.topScannerHits["dlp"] != int64(maxTopEntries)+1 {
		t.Errorf("expected %d, got %d", maxTopEntries+1, m.topScannerHits["dlp"])
	}
	m.mu.Unlock()
}

func TestRecordBlocked_MultipleScanners(t *testing.T) {
	m := New()
	m.RecordBlocked("evil.com", "dlp", time.Millisecond)
	m.RecordBlocked("evil.com", "ssrf", time.Millisecond)
	m.RecordBlocked("evil.com", "ratelimit", time.Millisecond)

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.blockedCount != 3 {
		t.Errorf("expected 3 blocked, got %d", m.blockedCount)
	}
	if len(m.topScannerHits) != 3 {
		t.Errorf("expected 3 scanner types, got %d", len(m.topScannerHits))
	}
}

func TestTopN_SortedByCount(t *testing.T) {
	m := map[string]int64{
		"low":    1,
		"high":   100,
		"medium": 50,
	}
	result := topN(m)
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(result))
	}
	if result[0].Name != "high" || result[0].Count != 100 {
		t.Errorf("expected high=100 first, got %s=%d", result[0].Name, result[0].Count)
	}
	if result[1].Name != "medium" || result[1].Count != 50 {
		t.Errorf("expected medium=50 second, got %s=%d", result[1].Name, result[1].Count)
	}
}

func TestRecordTunnel(t *testing.T) {
	m := New()
	m.RecordTunnel(5*time.Second, 4096)
	m.RecordTunnel(10*time.Second, 8192)

	m.mu.Lock()
	if m.tunnelCount != 2 {
		t.Errorf("expected 2 tunnels, got %d", m.tunnelCount)
	}
	m.mu.Unlock()
}

func TestRecordTunnelBlocked(t *testing.T) {
	m := New()
	m.RecordTunnelBlocked()
	m.RecordTunnelBlocked()

	// Verify the Prometheus counter was incremented (check via /metrics)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, `pipelock_tunnels_total{result="blocked"}`) {
		t.Error("expected pipelock_tunnels_total with blocked label in /metrics output")
	}
}

func TestIncrDecrActiveTunnels(t *testing.T) {
	m := New()
	m.IncrActiveTunnels()
	m.IncrActiveTunnels()
	m.IncrActiveTunnels()
	m.DecrActiveTunnels()

	// Check gauge via /metrics
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, "pipelock_active_tunnels") {
		t.Error("expected pipelock_active_tunnels in /metrics output")
	}
}

func TestStatsHandler_IncludesTunnels(t *testing.T) {
	m := New()
	m.RecordTunnel(5*time.Second, 4096)
	m.RecordTunnel(10*time.Second, 8192)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, req)

	var stats statsResponse
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if stats.Tunnels != 2 {
		t.Errorf("expected tunnels=2, got %d", stats.Tunnels)
	}
}

func TestPrometheusHandler_TunnelMetrics(t *testing.T) {
	m := New()
	m.RecordTunnel(5*time.Second, 4096)
	m.IncrActiveTunnels()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Body)
	text := string(body)

	if !strings.Contains(text, "pipelock_tunnels_total") {
		t.Error("expected pipelock_tunnels_total in /metrics output")
	}
	if !strings.Contains(text, "pipelock_tunnel_duration_seconds") {
		t.Error("expected pipelock_tunnel_duration_seconds in /metrics output")
	}
	if !strings.Contains(text, "pipelock_tunnel_bytes_total") {
		t.Error("expected pipelock_tunnel_bytes_total in /metrics output")
	}
	if !strings.Contains(text, "pipelock_active_tunnels") {
		t.Error("expected pipelock_active_tunnels in /metrics output")
	}
}

func TestConcurrentTunnelAccess(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			m.RecordTunnel(time.Millisecond, 100)
		}()
		go func() {
			defer wg.Done()
			m.IncrActiveTunnels()
		}()
		go func() {
			defer wg.Done()
			m.DecrActiveTunnels()
		}()
	}
	wg.Wait()

	m.mu.Lock()
	if m.tunnelCount != 50 {
		t.Errorf("expected 50 tunnels, got %d", m.tunnelCount)
	}
	m.mu.Unlock()
}
