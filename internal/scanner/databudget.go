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
	stopCleanup    chan struct{}
}

// NewDataBudget creates a data budget tracker with the given limit in bytes/minute.
func NewDataBudget(maxBytesPerMinute int) *DataBudget {
	db := &DataBudget{
		maxBytesPerMin: maxBytesPerMinute,
		records:        make(map[string][]dataEntry),
		stopCleanup:    make(chan struct{}),
	}
	go db.cleanupLoop()
	return db
}

// IsAllowed checks if a domain is within its data budget.
func (db *DataBudget) IsAllowed(domain string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()

	cutoff := time.Now().Add(-time.Minute)
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

	db.records[domain] = append(db.records[domain], dataEntry{
		bytes:     bytes,
		timestamp: time.Now(),
	})
}

// Close stops the cleanup goroutine.
func (db *DataBudget) Close() {
	select {
	case <-db.stopCleanup:
		return
	default:
		close(db.stopCleanup)
	}
}

func (db *DataBudget) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			db.cleanup()
		case <-db.stopCleanup:
			return
		}
	}
}

func (db *DataBudget) cleanup() {
	db.mu.Lock()
	defer db.mu.Unlock()

	cutoff := time.Now().Add(-time.Minute)
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
