package scanner

import (
	"sync"
	"testing"
	"time"
)

func TestNewDataBudget(t *testing.T) {
	db := NewDataBudget(1024)
	defer db.Close()

	if db.maxBytesPerMin != 1024 {
		t.Errorf("maxBytesPerMin = %d, want 1024", db.maxBytesPerMin)
	}
	if db.records == nil {
		t.Error("records map not initialized")
	}
}

func TestDataBudget_IsAllowed_UnderLimit(t *testing.T) {
	db := NewDataBudget(1000)
	defer db.Close()

	db.Record("example.com", 500)
	if !db.IsAllowed("example.com") {
		t.Error("500 bytes should be under 1000 limit")
	}
}

func TestDataBudget_IsAllowed_OverLimit(t *testing.T) {
	db := NewDataBudget(1000)
	defer db.Close()

	db.Record("example.com", 1000)
	if db.IsAllowed("example.com") {
		t.Error("1000 bytes should NOT be under 1000 limit (>=)")
	}
}

func TestDataBudget_IsAllowed_ExactLimit(t *testing.T) {
	db := NewDataBudget(1000)
	defer db.Close()

	db.Record("example.com", 999)
	if !db.IsAllowed("example.com") {
		t.Error("999 bytes should be under 1000 limit")
	}
}

func TestDataBudget_MultipleDomains(t *testing.T) {
	db := NewDataBudget(1000)
	defer db.Close()

	db.Record("a.com", 1100) // exceed limit
	db.Record("b.com", 100)  // under limit

	if db.IsAllowed("a.com") {
		t.Error("a.com at 1100 should exceed 1000 limit")
	}
	if !db.IsAllowed("b.com") {
		t.Error("b.com at 100 should be under 1000 limit")
	}
}

func TestDataBudget_MultipleRecords(t *testing.T) {
	db := NewDataBudget(500)
	defer db.Close()

	db.Record("example.com", 100)
	db.Record("example.com", 100)
	db.Record("example.com", 100)

	if !db.IsAllowed("example.com") {
		t.Error("300 bytes should be under 500 limit")
	}

	db.Record("example.com", 200)
	if db.IsAllowed("example.com") {
		t.Error("500 bytes should NOT be under 500 limit (>=)")
	}
}

func TestDataBudget_UnknownDomain(t *testing.T) {
	db := NewDataBudget(1000)
	defer db.Close()

	if !db.IsAllowed("unknown.com") {
		t.Error("unknown domain with 0 bytes should be allowed")
	}
}

func TestDataBudget_Close_Idempotent(t *testing.T) {
	db := NewDataBudget(1000)
	db.Close()
	db.Close() // should not panic
}

func TestDataBudget_Cleanup(t *testing.T) {
	db := NewDataBudget(1000)
	defer db.Close()

	// Add an entry with a backdated timestamp
	db.mu.Lock()
	db.records["old.com"] = []dataEntry{
		{bytes: 500, timestamp: time.Now().Add(-2 * time.Minute)},
	}
	db.records["new.com"] = []dataEntry{
		{bytes: 200, timestamp: time.Now()},
	}
	db.mu.Unlock()

	db.cleanup()

	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.records["old.com"]; exists {
		t.Error("old.com should have been cleaned up")
	}
	if _, exists := db.records["new.com"]; !exists {
		t.Error("new.com should still exist")
	}
}

func TestDataBudget_CleanupPartial(t *testing.T) {
	db := NewDataBudget(1000)
	defer db.Close()

	// Mix old and new entries for the same domain
	db.mu.Lock()
	db.records["mixed.com"] = []dataEntry{
		{bytes: 500, timestamp: time.Now().Add(-2 * time.Minute)}, // expired
		{bytes: 200, timestamp: time.Now()},                       // still valid
	}
	db.mu.Unlock()

	db.cleanup()

	db.mu.Lock()
	defer db.mu.Unlock()

	entries := db.records["mixed.com"]
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry after cleanup, got %d", len(entries))
	}
	if entries[0].bytes != 200 {
		t.Errorf("expected 200 bytes entry to remain, got %d", entries[0].bytes)
	}
}

func TestDataBudget_Concurrent(t *testing.T) {
	db := NewDataBudget(100000)
	defer db.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db.Record("concurrent.com", 10)
			db.IsAllowed("concurrent.com")
		}()
	}
	wg.Wait()
}
