package scanner

import (
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := NewRateLimiter(10)
	defer rl.Close()

	for i := 0; i < 10; i++ {
		if !rl.IsAllowed("example.com") {
			t.Errorf("request %d should be allowed (limit=10)", i)
		}
		rl.Record("example.com")
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(5)
	defer rl.Close()

	for i := 0; i < 5; i++ {
		rl.Record("example.com")
	}

	if rl.IsAllowed("example.com") {
		t.Error("request 6 should be blocked (limit=5)")
	}
}

func TestRateLimiter_PerDomain(t *testing.T) {
	rl := NewRateLimiter(2)
	defer rl.Close()

	rl.Record("example.com")
	rl.Record("example.com")

	if !rl.IsAllowed("other.com") {
		t.Error("other.com should have separate quota")
	}
	if rl.IsAllowed("example.com") {
		t.Error("example.com should be blocked")
	}
}

func TestRateLimiter_SlidingWindowEviction(t *testing.T) {
	rl := NewRateLimiter(3)
	defer rl.Close()

	// Inject old timestamps directly to simulate window sliding
	rl.mu.Lock()
	rl.requests["example.com"] = []time.Time{
		time.Now().Add(-2 * time.Minute),
		time.Now().Add(-90 * time.Second),
		time.Now().Add(-61 * time.Second),
	}
	rl.mu.Unlock()

	// All timestamps are older than 1 minute — IsAllowed should evict them
	if !rl.IsAllowed("example.com") {
		t.Error("expected allowed after stale timestamps evicted")
	}
}

func TestRateLimiter_WindowRollover(t *testing.T) {
	rl := NewRateLimiter(2)
	defer rl.Close()

	// Fill to limit
	rl.Record("example.com")
	rl.Record("example.com")
	if rl.IsAllowed("example.com") {
		t.Fatal("expected blocked after hitting limit")
	}

	// Replace timestamps with ones older than the 1-minute window
	rl.mu.Lock()
	rl.requests["example.com"] = []time.Time{
		time.Now().Add(-61 * time.Second),
		time.Now().Add(-62 * time.Second),
	}
	rl.mu.Unlock()

	// After window expires, domain should be unblocked
	if !rl.IsAllowed("example.com") {
		t.Error("expected allowed after window rollover")
	}
}

func TestRateLimiter_ConcurrentAccess(_ *testing.T) {
	rl := NewRateLimiter(1000)
	defer rl.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				rl.IsAllowed("example.com")
				rl.Record("example.com")
			}
		}()
	}
	wg.Wait()
}

func TestRateLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	rl := NewRateLimiter(10)
	defer rl.Close()

	rl.mu.Lock()
	rl.requests["old.com"] = []time.Time{time.Now().Add(-2 * time.Minute)}
	rl.mu.Unlock()

	rl.cleanup()

	rl.mu.Lock()
	_, exists := rl.requests["old.com"]
	rl.mu.Unlock()

	if exists {
		t.Error("stale entry should be removed by cleanup")
	}
}

func TestRateLimiter_CleanupKeepsRecentEntries(t *testing.T) {
	rl := NewRateLimiter(10)
	defer rl.Close()

	rl.Record("recent.com")
	rl.cleanup()

	rl.mu.Lock()
	count := len(rl.requests["recent.com"])
	rl.mu.Unlock()

	if count != 1 {
		t.Errorf("recent entry should be kept, got count=%d", count)
	}
}

func TestRateLimiter_CloseIsIdempotent(_ *testing.T) {
	rl := NewRateLimiter(10)
	rl.Close()
	rl.Close() // should not panic
}

func TestScanner_CheckRateLimit_Disabled(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	s := New(cfg)

	result := s.checkRateLimit("example.com")
	if !result.Allowed {
		t.Error("rate limit should be disabled when MaxReqPerMinute=0")
	}
}

func TestScanner_CheckRateLimit_Blocked(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 2
	s := New(cfg)
	defer s.Close()

	s.rateLimiter.Record("example.com")
	s.rateLimiter.Record("example.com")

	result := s.checkRateLimit("example.com")
	if result.Allowed {
		t.Error("should be blocked after limit reached")
	}
	if result.Scanner != "ratelimit" {
		t.Errorf("expected scanner=ratelimit, got %s", result.Scanner)
	}
	if result.Score != 0.7 {
		t.Errorf("expected score=0.7, got %f", result.Score)
	}
}

func TestScanner_Scan_RateLimitIntegration(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 3
	s := New(cfg)
	defer s.Close()

	for i := 0; i < 3; i++ {
		result := s.Scan("https://example.com/page")
		if !result.Allowed {
			t.Errorf("scan %d should be allowed", i)
		}
		s.RecordRequest("example.com")
	}

	result := s.Scan("https://example.com/page")
	if result.Allowed {
		t.Error("fourth scan should be blocked by rate limiter")
	}
	if result.Scanner != "ratelimit" {
		t.Errorf("expected scanner=ratelimit, got %s", result.Scanner)
	}
}

func TestScanner_RecordRequest_NilRateLimiter(_ *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	s := New(cfg)

	// Should not panic
	s.RecordRequest("example.com")
}

func TestScanner_Close_NilRateLimiter(_ *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	s := New(cfg)

	// Should not panic
	s.Close()
}

func TestScanner_RateLimit_DifferentDomainsIndependent(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 1
	s := New(cfg)
	defer s.Close()

	s.RecordRequest("a.com")

	// a.com should be blocked
	result := s.Scan("https://a.com/page")
	if result.Allowed {
		t.Error("expected a.com blocked after rate limit reached")
	}

	// b.com should still work
	result = s.Scan("https://b.com/page")
	if !result.Allowed {
		t.Errorf("expected b.com allowed (independent limit), got: %s", result.Reason)
	}
}
