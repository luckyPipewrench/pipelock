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
