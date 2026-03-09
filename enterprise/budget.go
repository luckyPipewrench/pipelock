//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"fmt"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// BudgetTracker enforces per-agent request budgets within a rolling window.
// Zero-value budget fields mean unlimited (no enforcement).
// All methods are nil-safe: a nil tracker permits everything.
//
// BudgetTracker implements edition.BudgetChecker.
type BudgetTracker struct {
	mu            sync.Mutex
	cfg           *config.BudgetConfig
	requestCount  int
	byteCount     int64
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

// CheckAdmission verifies request count and domain budget limits, then records
// the request. Call BEFORE making the outbound request. Byte budget is tracked
// separately via RecordBytes. Thread-safe.
// Returns nil when within budget, or an error describing the exceeded limit.
// A nil tracker always returns nil (unlimited).
func (b *BudgetTracker) CheckAdmission(domain string) error {
	if b == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.maybeResetWindow()

	if b.cfg.MaxRequestsPerSession > 0 && b.requestCount >= b.cfg.MaxRequestsPerSession {
		return fmt.Errorf("request budget exceeded: %d/%d requests",
			b.requestCount, b.cfg.MaxRequestsPerSession)
	}

	if b.cfg.MaxUniqueDomainsPerSession > 0 {
		if _, seen := b.uniqueDomains[domain]; !seen {
			if len(b.uniqueDomains) >= b.cfg.MaxUniqueDomainsPerSession {
				return fmt.Errorf("domain budget exceeded: %d/%d unique domains",
					len(b.uniqueDomains)+1, b.cfg.MaxUniqueDomainsPerSession)
			}
		}
	}

	b.requestCount++
	if b.cfg.MaxUniqueDomainsPerSession > 0 {
		b.uniqueDomains[domain] = struct{}{}
	}

	return nil
}

// RecordBytes adds bytes to the budget counter and checks the byte limit.
// Call AFTER reading the response. Thread-safe.
// Returns nil when within budget, or an error describing the exceeded limit.
// A nil tracker always returns nil (unlimited).
func (b *BudgetTracker) RecordBytes(n int64) error {
	if b == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.maybeResetWindow()

	b.byteCount += n
	if b.cfg.MaxBytesPerSession > 0 && b.byteCount > int64(b.cfg.MaxBytesPerSession) {
		return fmt.Errorf("byte budget exceeded: %d/%d bytes",
			b.byteCount, b.cfg.MaxBytesPerSession)
	}

	return nil
}

// RemainingBytes returns the number of bytes still available before the byte
// budget is exceeded. Returns -1 if no byte limit is configured or the
// tracker is nil (unlimited). Thread-safe.
func (b *BudgetTracker) RemainingBytes() int64 {
	if b == nil {
		return -1
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.maybeResetWindow()

	if b.cfg.MaxBytesPerSession <= 0 {
		return -1
	}
	remaining := int64(b.cfg.MaxBytesPerSession) - b.byteCount
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RecordRequest checks all budget limits and records the request if within
// budget. Combines admission check and byte recording in a single call.
// Returns nil when within budget, or an error describing the exceeded limit.
// Thread-safe. A nil tracker always returns nil (unlimited).
func (b *BudgetTracker) RecordRequest(domain string, bodyBytes int64) error {
	if b == nil {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.maybeResetWindow()

	// Check request count limit.
	if b.cfg.MaxRequestsPerSession > 0 && b.requestCount >= b.cfg.MaxRequestsPerSession {
		return fmt.Errorf("request budget exceeded: %d/%d requests",
			b.requestCount, b.cfg.MaxRequestsPerSession)
	}

	// Check byte count limit.
	if b.cfg.MaxBytesPerSession > 0 && b.byteCount+bodyBytes > int64(b.cfg.MaxBytesPerSession) {
		return fmt.Errorf("byte budget exceeded: %d/%d bytes",
			b.byteCount+bodyBytes, b.cfg.MaxBytesPerSession)
	}

	// Check unique domain limit.
	if b.cfg.MaxUniqueDomainsPerSession > 0 {
		if _, seen := b.uniqueDomains[domain]; !seen {
			if len(b.uniqueDomains) >= b.cfg.MaxUniqueDomainsPerSession {
				return fmt.Errorf("domain budget exceeded: %d/%d unique domains",
					len(b.uniqueDomains)+1, b.cfg.MaxUniqueDomainsPerSession)
			}
		}
	}

	// All checks passed: record the request.
	b.requestCount++
	b.byteCount += bodyBytes
	if b.cfg.MaxUniqueDomainsPerSession > 0 {
		b.uniqueDomains[domain] = struct{}{}
	}

	return nil
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
