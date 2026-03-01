package metrics

import (
	"encoding/json"
	"fmt"
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

	// Also verify JSON stats tracking
	m.mu.Lock()
	if m.sessionAnomalyCount != 3 {
		t.Errorf("expected 3 anomalies in stats, got %d", m.sessionAnomalyCount)
	}
	if m.topAnomalyTypes["domain_burst"] != 2 {
		t.Errorf("expected domain_burst=2, got %d", m.topAnomalyTypes["domain_burst"])
	}
	if m.topAnomalyTypes["volume_spike"] != 1 {
		t.Errorf("expected volume_spike=1, got %d", m.topAnomalyTypes["volume_spike"])
	}
	m.mu.Unlock()
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

func TestStatsHandler_IncludesSessionData(t *testing.T) {
	m := New()
	m.SetSessionsActive(5)
	m.RecordSessionAnomaly("domain_burst")
	m.RecordSessionAnomaly("domain_burst")
	m.RecordSessionAnomaly("ip_domain_burst")
	m.RecordSessionEscalation("normal", "elevated")

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, req)

	var stats statsResponse
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}

	if stats.Sessions.Active != 5 {
		t.Errorf("expected sessions.active=5, got %d", stats.Sessions.Active)
	}
	if stats.Sessions.Anomalies != 3 {
		t.Errorf("expected sessions.anomalies=3, got %d", stats.Sessions.Anomalies)
	}
	if stats.Sessions.Escalations != 1 {
		t.Errorf("expected sessions.escalations=1, got %d", stats.Sessions.Escalations)
	}
	if len(stats.Sessions.TopAnomalies) != 2 {
		t.Errorf("expected 2 anomaly types, got %d", len(stats.Sessions.TopAnomalies))
	}
	// Verify sorted by count (domain_burst=2 first)
	if len(stats.Sessions.TopAnomalies) >= 1 && stats.Sessions.TopAnomalies[0].Name != "domain_burst" {
		t.Errorf("expected domain_burst first (highest count), got %s", stats.Sessions.TopAnomalies[0].Name)
	}
}

func TestStatsHandler_EmptySessionData(t *testing.T) {
	m := New()

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, req)

	var stats statsResponse
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}

	if stats.Sessions.Active != 0 {
		t.Errorf("expected sessions.active=0, got %d", stats.Sessions.Active)
	}
	if stats.Sessions.Anomalies != 0 {
		t.Errorf("expected sessions.anomalies=0, got %d", stats.Sessions.Anomalies)
	}
	if stats.Sessions.Escalations != 0 {
		t.Errorf("expected sessions.escalations=0, got %d", stats.Sessions.Escalations)
	}
}

func TestRecordWSCompleted(t *testing.T) {
	m := New()
	m.RecordWSCompleted()
	m.RecordWSCompleted()

	m.mu.Lock()
	if m.wsConnectionCount != 2 {
		t.Errorf("expected 2 WS completions, got %d", m.wsConnectionCount)
	}
	m.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), `pipelock_ws_connections_total{result="completed"}`) {
		t.Error("expected ws_connections_total with completed label")
	}
}

func TestRecordWSBlocked(t *testing.T) {
	m := New()
	m.RecordWSBlocked()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), `pipelock_ws_connections_total{result="blocked"}`) {
		t.Error("expected ws_connections_total with blocked label")
	}
}

func TestRecordWSStats(t *testing.T) {
	m := New()
	m.RecordWSStats(5*time.Second, 1024, 2048)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, "pipelock_ws_duration_seconds") {
		t.Error("expected pipelock_ws_duration_seconds in /metrics")
	}
	if !strings.Contains(text, `pipelock_ws_bytes_total{direction="client_to_server"}`) {
		t.Error("expected ws_bytes_total client_to_server")
	}
	if !strings.Contains(text, `pipelock_ws_bytes_total{direction="server_to_client"}`) {
		t.Error("expected ws_bytes_total server_to_client")
	}
}

func TestIncrDecrActiveWS(t *testing.T) {
	m := New()
	m.IncrActiveWS()
	m.IncrActiveWS()
	m.DecrActiveWS()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "pipelock_ws_active_connections") {
		t.Error("expected pipelock_ws_active_connections gauge")
	}
}

func TestRecordWSFrame(t *testing.T) {
	m := New()
	m.RecordWSFrame("text")
	m.RecordWSFrame("binary")
	m.RecordWSFrame("text")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, `pipelock_ws_frames_total{type="text"}`) {
		t.Error("expected ws_frames_total with text type")
	}
	if !strings.Contains(text, `pipelock_ws_frames_total{type="binary"}`) {
		t.Error("expected ws_frames_total with binary type")
	}
}

func TestRecordWSScanHit(t *testing.T) {
	m := New()
	m.RecordWSScanHit("dlp")
	m.RecordWSScanHit("injection")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	text := string(body)
	if !strings.Contains(text, `pipelock_ws_scan_hits_total{scanner="dlp"}`) {
		t.Error("expected ws_scan_hits_total with dlp scanner")
	}
	if !strings.Contains(text, `pipelock_ws_scan_hits_total{scanner="injection"}`) {
		t.Error("expected ws_scan_hits_total with injection scanner")
	}
}

func TestRecordWSRedirectHint(t *testing.T) {
	m := New()
	m.RecordWSRedirectHint()
	m.RecordWSRedirectHint()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	m.PrometheusHandler().ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "pipelock_forward_ws_redirect_hint_total") {
		t.Error("expected forward_ws_redirect_hint_total counter")
	}
}

func TestStatsHandler_IncludesWebSockets(t *testing.T) {
	m := New()
	m.RecordWSCompleted()
	m.RecordWSCompleted()
	m.RecordWSCompleted()

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	m.StatsHandler().ServeHTTP(w, req)

	var stats statsResponse
	if err := json.NewDecoder(w.Body).Decode(&stats); err != nil {
		t.Fatalf("failed to decode stats: %v", err)
	}
	if stats.WebSockets != 3 {
		t.Errorf("expected websockets=3, got %d", stats.WebSockets)
	}
}

func TestTopAnomalyTypesCapped(t *testing.T) {
	m := New()
	// Fill anomaly types to the cap
	for i := range maxTopEntries {
		m.RecordSessionAnomaly("type" + string(rune('A'+i%26)) + string(rune('0'+i/26)))
	}

	// New type should be ignored after cap
	m.RecordSessionAnomaly("overflow_type")

	m.mu.Lock()
	if len(m.topAnomalyTypes) > maxTopEntries {
		t.Errorf("expected at most %d anomaly types, got %d", maxTopEntries, len(m.topAnomalyTypes))
	}
	if _, exists := m.topAnomalyTypes["overflow_type"]; exists {
		t.Error("overflow anomaly type should not be tracked after cap")
	}
	m.mu.Unlock()
}

func TestConcurrentSessionMetrics(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			m.RecordSessionAnomaly("domain_burst")
		}()
		go func() {
			defer wg.Done()
			m.RecordSessionEscalation("normal", "elevated")
		}()
		go func() {
			defer wg.Done()
			m.SetSessionsActive(10)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	if m.sessionAnomalyCount != 50 {
		t.Errorf("expected 50 anomalies, got %d", m.sessionAnomalyCount)
	}
	if m.sessionEscalationCount != 50 {
		t.Errorf("expected 50 escalations, got %d", m.sessionEscalationCount)
	}
	m.mu.Unlock()
}

func TestRecordKillSwitchDenial(t *testing.T) {
	m := New()
	m.RecordKillSwitchDenial("http", "/fetch")
	m.RecordKillSwitchDenial("mcp", "tools/call")
	m.RecordKillSwitchDenial("http", "/fetch")

	// Verify Prometheus metric incremented.
	handler := m.PrometheusHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `pipelock_kill_switch_denials_total{endpoint="/fetch",transport="http"} 2`) {
		t.Errorf("expected 2 http /fetch denials in metrics output:\n%s", body)
	}
	if !strings.Contains(body, `pipelock_kill_switch_denials_total{endpoint="tools/call",transport="mcp"} 1`) {
		t.Errorf("expected 1 mcp tools/call denial in metrics output:\n%s", body)
	}
}

func TestRecordChainDetection(t *testing.T) {
	m := New()
	m.RecordChainDetection("read-then-exec", "high", "warn")
	m.RecordChainDetection("read-then-exec", "high", "warn")
	m.RecordChainDetection("env-then-network", "critical", "block")

	handler := m.PrometheusHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `pipelock_chain_detections_total{action="warn",pattern="read-then-exec",severity="high"} 2`) {
		t.Errorf("expected 2 read-then-exec detections:\n%s", body)
	}
	if !strings.Contains(body, `pipelock_chain_detections_total{action="block",pattern="env-then-network",severity="critical"} 1`) {
		t.Errorf("expected 1 env-then-network detection:\n%s", body)
	}
}

func TestRecordSessionAnomaly_ExistingTypeAfterCap(t *testing.T) {
	m := New()
	// Fill anomaly types to cap.
	for i := range maxTopEntries {
		m.RecordSessionAnomaly("type" + string(rune('A'+i%26)) + string(rune('0'+i/26)))
	}
	// Existing type should still increment even after cap.
	m.RecordSessionAnomaly("typeA0")
	m.mu.Lock()
	if m.topAnomalyTypes["typeA0"] != 2 {
		t.Errorf("expected existing anomaly type count 2, got %d", m.topAnomalyTypes["typeA0"])
	}
	m.mu.Unlock()
}

func TestConcurrentWSMetrics(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(4)
		go func() {
			defer wg.Done()
			m.RecordWSCompleted()
		}()
		go func() {
			defer wg.Done()
			m.IncrActiveWS()
		}()
		go func() {
			defer wg.Done()
			m.DecrActiveWS()
		}()
		go func() {
			defer wg.Done()
			m.RecordWSStats(time.Millisecond, 100, 200)
		}()
	}
	wg.Wait()

	m.mu.Lock()
	if m.wsConnectionCount != 50 {
		t.Errorf("expected 50 WS completions, got %d", m.wsConnectionCount)
	}
	m.mu.Unlock()
}

func TestRegisterKillSwitchState(t *testing.T) {
	m := New()
	m.RegisterKillSwitchState(func() map[string]bool {
		return map[string]bool{
			"config":   false,
			"api":      true,
			"signal":   false,
			"sentinel": false,
		}
	})

	handler := m.PrometheusHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `pipelock_kill_switch_active{source="api"} 1`) {
		t.Errorf("expected api source active (1):\n%s", body)
	}
	if !strings.Contains(body, `pipelock_kill_switch_active{source="config"} 0`) {
		t.Errorf("expected config source inactive (0):\n%s", body)
	}
	if !strings.Contains(body, `pipelock_kill_switch_active{source="signal"} 0`) {
		t.Errorf("expected signal source inactive (0):\n%s", body)
	}
	if !strings.Contains(body, `pipelock_kill_switch_active{source="sentinel"} 0`) {
		t.Errorf("expected sentinel source inactive (0):\n%s", body)
	}
}

func TestRegisterKillSwitchState_AllActive(t *testing.T) {
	m := New()
	m.RegisterKillSwitchState(func() map[string]bool {
		return map[string]bool{
			"config":   true,
			"api":      true,
			"signal":   true,
			"sentinel": true,
		}
	})

	handler := m.PrometheusHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, src := range []string{"config", "api", "signal", "sentinel"} {
		expected := fmt.Sprintf(`pipelock_kill_switch_active{source="%s"} 1`, src)
		if !strings.Contains(body, expected) {
			t.Errorf("expected %s active (1):\n%s", src, body)
		}
	}
}

func TestRegisterInfo(t *testing.T) {
	m := New()
	m.RegisterInfo("0.3.1-test")

	handler := m.PrometheusHandler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `pipelock_info{version="0.3.1-test"} 1`) {
		t.Errorf("expected pipelock_info with version label:\n%s", body)
	}
}
