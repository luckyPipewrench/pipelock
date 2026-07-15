// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sync"
	"time"
)

// RateLimiter enforces per-domain sliding window rate limits.
// It tracks request timestamps per domain and removes stale entries
// opportunistically while holding the request lock.
type RateLimiter struct {
	mu           sync.Mutex
	maxPerMinute int
	requests     map[string][]time.Time
	lastCleanup  time.Time
}

// NewRateLimiter creates a rate limiter with the specified limit.
// Stale entries are pruned opportunistically under the request lock instead of
// assigning a background goroutine to every scanner instance.
func NewRateLimiter(maxPerMinute int) *RateLimiter {
	return &RateLimiter{
		maxPerMinute: maxPerMinute,
		requests:     make(map[string][]time.Time),
		lastCleanup:  time.Now(),
	}
}

// IsAllowed checks if a new request for the domain would be within the limit.
// It uses a sliding window: only timestamps within the last 60 seconds count.
func (rl *RateLimiter) IsAllowed(domain string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.maybeCleanupLocked(now)
	cutoff := now.Add(-time.Minute)

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

	now := time.Now()
	rl.maybeCleanupLocked(now)
	rl.requests[domain] = append(rl.requests[domain], now)
}

// CheckAndRecord atomically checks the rate limit and records a request
// if allowed. Returns true if the request is within the limit.
// This prevents TOCTOU races where concurrent requests could both pass
// IsAllowed() before either calls Record().
func (rl *RateLimiter) CheckAndRecord(domain string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.maybeCleanupLocked(now)
	cutoff := now.Add(-time.Minute)

	timestamps := rl.requests[domain]
	valid := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}

	if len(valid) >= rl.maxPerMinute {
		rl.requests[domain] = valid
		return false
	}

	rl.requests[domain] = append(valid, now)
	return true
}

// Close is retained for scanner lifecycle symmetry. RateLimiter owns no
// background resources, so closing it is intentionally a no-op.
func (rl *RateLimiter) Close() {}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.cleanupLocked(time.Now())
}

func (rl *RateLimiter) maybeCleanupLocked(now time.Time) {
	if now.Sub(rl.lastCleanup) < time.Minute {
		return
	}
	rl.cleanupLocked(now)
	rl.lastCleanup = now
}

func (rl *RateLimiter) cleanupLocked(now time.Time) {
	cutoff := now.Add(-time.Minute)

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
