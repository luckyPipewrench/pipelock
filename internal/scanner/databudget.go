// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"sync"
	"time"
)

// dataEntry tracks bytes transferred in a sliding window.
type dataEntry struct {
	bytes     int
	timestamp time.Time
}

// DataBudget enforces per-domain data transfer limits using a sliding window.
type DataBudget struct {
	mu             sync.Mutex
	maxBytesPerMin int
	records        map[string][]dataEntry
	lastCleanup    time.Time
}

// NewDataBudget creates a data budget tracker with the given limit in bytes/minute.
func NewDataBudget(maxBytesPerMinute int) *DataBudget {
	return &DataBudget{
		maxBytesPerMin: maxBytesPerMinute,
		records:        make(map[string][]dataEntry),
		lastCleanup:    time.Now(),
	}
}

// IsAllowed checks if a domain is within its data budget.
func (db *DataBudget) IsAllowed(domain string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now()
	db.maybeCleanupLocked(now)
	cutoff := now.Add(-time.Minute)
	total := 0
	entries := db.records[domain]
	for _, e := range entries {
		if e.timestamp.After(cutoff) {
			total += e.bytes
		}
	}
	return total < db.maxBytesPerMin
}

// Record adds bytes for a domain.
func (db *DataBudget) Record(domain string, bytes int) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now()
	db.maybeCleanupLocked(now)
	db.records[domain] = append(db.records[domain], dataEntry{
		bytes:     bytes,
		timestamp: now,
	})
}

// Close is retained for scanner lifecycle symmetry. DataBudget owns no
// background resources, so closing it is intentionally a no-op.
func (db *DataBudget) Close() {}

func (db *DataBudget) cleanup() {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.cleanupLocked(time.Now())
}

func (db *DataBudget) maybeCleanupLocked(now time.Time) {
	if now.Sub(db.lastCleanup) < time.Minute {
		return
	}
	db.cleanupLocked(now)
	db.lastCleanup = now
}

func (db *DataBudget) cleanupLocked(now time.Time) {
	cutoff := now.Add(-time.Minute)
	for domain, entries := range db.records {
		valid := entries[:0]
		for _, e := range entries {
			if e.timestamp.After(cutoff) {
				valid = append(valid, e)
			}
		}
		if len(valid) == 0 {
			delete(db.records, domain)
		} else {
			db.records[domain] = valid
		}
	}
}
