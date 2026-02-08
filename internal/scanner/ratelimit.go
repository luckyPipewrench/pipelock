package scanner

import (
	"sync"
	"time"
)

// RateLimiter enforces per-domain sliding window rate limits.
// It tracks request timestamps per domain and removes stale entries
// via a background cleanup goroutine.
type RateLimiter struct {
	mu           sync.Mutex
	maxPerMinute int
	requests     map[string][]time.Time
	stopCleanup  chan struct{}
}

// NewRateLimiter creates a rate limiter with the specified limit.
// It starts a background goroutine to clean up stale entries every 60 seconds.
func NewRateLimiter(maxPerMinute int) *RateLimiter {
	rl := &RateLimiter{
		maxPerMinute: maxPerMinute,
		requests:     make(map[string][]time.Time),
		stopCleanup:  make(chan struct{}),
	}

	go rl.cleanupLoop()

	return rl
}

// IsAllowed checks if a new request for the domain would be within the limit.
// It uses a sliding window: only timestamps within the last 60 seconds count.
func (rl *RateLimiter) IsAllowed(domain string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-time.Minute)

	timestamps := rl.requests[domain]
	valid := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	rl.requests[domain] = valid

	return len(valid) < rl.maxPerMinute
}

// Record adds a timestamp for the domain. Call this AFTER the request
// has been allowed by all scanners and will be fetched.
func (rl *RateLimiter) Record(domain string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.requests[domain] = append(rl.requests[domain], time.Now())
}

// Close stops the cleanup goroutine. Safe to call multiple times.
func (rl *RateLimiter) Close() {
	select {
	case <-rl.stopCleanup:
		return
	default:
		close(rl.stopCleanup)
	}
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-time.Minute)

	for domain, timestamps := range rl.requests {
		valid := timestamps[:0]
		for _, ts := range timestamps {
			if ts.After(cutoff) {
				valid = append(valid, ts)
			}
		}

		if len(valid) == 0 {
			delete(rl.requests, domain)
		} else {
			rl.requests[domain] = valid
		}
	}
}
