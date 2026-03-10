// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sync"
	"time"
)

// entropyEntry tracks bits of entropy recorded at a point in time.
type entropyEntry struct {
	bits      float64
	timestamp time.Time
}

// EntropyTracker tracks cumulative Shannon entropy of outbound data per session
// within a sliding window. High entropy is a scored signal (not proof of
// exfiltration): legitimate traffic like JWTs, base64 uploads, and code can
// also produce high entropy.
type EntropyTracker struct {
	mu          sync.Mutex
	budget      float64 // bits per window
	windowSecs  int     // sliding window duration in seconds
	sessions    map[string][]entropyEntry
	stopCleanup chan struct{}
	closeOnce   sync.Once
}

// NewEntropyTracker creates an entropy tracker with the given budget (bits per
// window) and window duration (seconds). A cleanup goroutine runs every 60
// seconds to evict expired entries.
func NewEntropyTracker(budgetBits float64, windowSecs int) *EntropyTracker {
	et := &EntropyTracker{
		budget:      budgetBits,
		windowSecs:  windowSecs,
		sessions:    make(map[string][]entropyEntry),
		stopCleanup: make(chan struct{}),
	}
	go et.cleanupLoop()
	return et
}

// Record adds a payload's entropy to the session's running total and returns
// the bits recorded. Total bits = ShannonEntropy(payload) * len(payload).
// Returns 0 for nil or empty payloads.
func (et *EntropyTracker) Record(sessionKey string, payload []byte) float64 {
	if len(payload) == 0 {
		return 0
	}

	s := string(payload)
	bits := ShannonEntropy(s) * float64(len(payload))

	et.mu.Lock()
	defer et.mu.Unlock()

	et.sessions[sessionKey] = append(et.sessions[sessionKey], entropyEntry{
		bits:      bits,
		timestamp: time.Now(),
	})

	return bits
}

// CurrentUsage returns the total entropy bits recorded for a session within the
// current sliding window.
func (et *EntropyTracker) CurrentUsage(sessionKey string) float64 {
	et.mu.Lock()
	defer et.mu.Unlock()

	return et.currentUsageLocked(sessionKey)
}

// Remaining returns the entropy budget remaining for a session. Returns 0 (not
// negative) when the budget is exceeded.
func (et *EntropyTracker) Remaining(sessionKey string) float64 {
	et.mu.Lock()
	defer et.mu.Unlock()

	usage := et.currentUsageLocked(sessionKey)
	remaining := et.budget - usage
	if remaining < 0 {
		return 0
	}
	return remaining
}

// BudgetExceeded returns true if the session's entropy usage within the sliding
// window exceeds the configured budget.
func (et *EntropyTracker) BudgetExceeded(sessionKey string) bool {
	et.mu.Lock()
	defer et.mu.Unlock()

	return et.currentUsageLocked(sessionKey) >= et.budget
}

// Budget returns the configured entropy budget in bits per window.
func (et *EntropyTracker) Budget() float64 {
	return et.budget
}

// Close stops the cleanup goroutine. Safe to call multiple times.
func (et *EntropyTracker) Close() {
	et.closeOnce.Do(func() { close(et.stopCleanup) })
}

// currentUsageLocked sums entropy bits within the sliding window.
// Caller must hold et.mu.
func (et *EntropyTracker) currentUsageLocked(sessionKey string) float64 {
	cutoff := time.Now().Add(-time.Duration(et.windowSecs) * time.Second)
	var total float64
	for _, e := range et.sessions[sessionKey] {
		if e.timestamp.After(cutoff) {
			total += e.bits
		}
	}
	return total
}

// cleanupLoop runs every 60 seconds to evict expired entries.
func (et *EntropyTracker) cleanupLoop() {
	// 60s: matches DataBudget cleanup interval
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			et.cleanup()
		case <-et.stopCleanup:
			return
		}
	}
}

func (et *EntropyTracker) cleanup() {
	et.mu.Lock()
	defer et.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(et.windowSecs) * time.Second)
	for key, entries := range et.sessions {
		valid := entries[:0]
		for _, e := range entries {
			if e.timestamp.After(cutoff) {
				valid = append(valid, e)
			}
		}
		if len(valid) == 0 {
			delete(et.sessions, key)
		} else {
			et.sessions[key] = valid
		}
	}
}
