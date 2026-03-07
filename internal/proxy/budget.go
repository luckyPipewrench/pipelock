// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// BudgetTracker enforces per-agent request budgets within a rolling window.
// Zero-value budget fields mean unlimited (no enforcement).
// All methods are nil-safe: a nil tracker permits everything.
type BudgetTracker struct {
	mu            sync.Mutex
	cfg           *config.BudgetConfig
	requestCount  int
	byteCount     int
	uniqueDomains map[string]struct{}
	windowStart   time.Time
	now           func() time.Time // injectable clock for testing
}

// NewBudgetTracker creates a budget tracker from the given config.
// Returns nil if cfg is nil or all budget fields are zero (unlimited).
func NewBudgetTracker(cfg *config.BudgetConfig) *BudgetTracker {
	if cfg == nil {
		return nil
	}
	if cfg.MaxRequestsPerSession == 0 && cfg.MaxBytesPerSession == 0 &&
		cfg.MaxUniqueDomainsPerSession == 0 {
		return nil
	}
	return &BudgetTracker{
		cfg:           cfg,
		uniqueDomains: make(map[string]struct{}),
		windowStart:   time.Now(),
		now:           time.Now,
	}
}

// RecordRequest checks budget limits and records the request if within budget.
// Returns (exceeded bool, reason string). Thread-safe.
// A nil tracker always returns (false, "").
func (b *BudgetTracker) RecordRequest(domain string, bytes int) (bool, string) {
	if b == nil {
		return false, ""
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.maybeResetWindow()

	// Check request count limit.
	if b.cfg.MaxRequestsPerSession > 0 && b.requestCount >= b.cfg.MaxRequestsPerSession {
		return true, fmt.Sprintf("request budget exceeded: %d/%d requests",
			b.requestCount, b.cfg.MaxRequestsPerSession)
	}

	// Check byte count limit.
	if b.cfg.MaxBytesPerSession > 0 && b.byteCount+bytes > b.cfg.MaxBytesPerSession {
		return true, fmt.Sprintf("byte budget exceeded: %d/%d bytes",
			b.byteCount+bytes, b.cfg.MaxBytesPerSession)
	}

	// Check unique domain limit.
	if b.cfg.MaxUniqueDomainsPerSession > 0 {
		if _, seen := b.uniqueDomains[domain]; !seen {
			if len(b.uniqueDomains) >= b.cfg.MaxUniqueDomainsPerSession {
				return true, fmt.Sprintf("domain budget exceeded: %d/%d unique domains",
					len(b.uniqueDomains)+1, b.cfg.MaxUniqueDomainsPerSession)
			}
		}
	}

	// All checks passed: record the request.
	b.requestCount++
	b.byteCount += bytes
	b.uniqueDomains[domain] = struct{}{}

	return false, ""
}

// Reset clears all counters and starts a new window.
// Safe to call on a nil tracker (no-op).
func (b *BudgetTracker) Reset() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.requestCount = 0
	b.byteCount = 0
	b.uniqueDomains = make(map[string]struct{})
	b.windowStart = b.now()
}

// maybeResetWindow resets counters if the rolling window has expired.
// Must be called with b.mu held.
func (b *BudgetTracker) maybeResetWindow() {
	if b.cfg.WindowMinutes <= 0 {
		return
	}
	window := time.Duration(b.cfg.WindowMinutes) * time.Minute
	if b.now().Sub(b.windowStart) > window {
		b.requestCount = 0
		b.byteCount = 0
		b.uniqueDomains = make(map[string]struct{})
		b.windowStart = b.now()
	}
}
