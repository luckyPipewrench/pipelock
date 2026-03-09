//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
)

const (
	testDomainA = "a.com"
	testDomainB = "b.com"
	testDomainC = "c.com"

	// testByteSize is a small payload used in most budget tests.
	testByteSize int64 = 100
)

// Compile-time check: *BudgetTracker satisfies edition.BudgetChecker.
var _ edition.BudgetChecker = (*BudgetTracker)(nil)

func TestBudgetMaxRequests(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 3,
		WindowMinutes:         60,
	}
	tracker := NewBudgetTracker(&budget)

	for i := range 3 {
		if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
			t.Fatalf("request %d should not exceed budget: %v", i+1, err)
		}
	}

	if err := tracker.RecordRequest(testDomainA, testByteSize); err == nil {
		t.Fatal("expected budget exceeded after 3 requests")
	}
}

func TestBudgetMaxBytes(t *testing.T) {
	// Budget: 250 bytes total.
	budget := config.BudgetConfig{
		MaxBytesPerSession: 250,
		WindowMinutes:      60,
	}
	tracker := NewBudgetTracker(&budget)

	// 100 + 100 = 200, within budget.
	for i := range 2 {
		if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
			t.Fatalf("request %d (100 bytes) should not exceed 250-byte budget: %v", i+1, err)
		}
	}

	// 200 + 100 = 300 > 250: should exceed.
	if err := tracker.RecordRequest(testDomainA, testByteSize); err == nil {
		t.Fatal("expected byte budget exceeded")
	}
}

func TestBudgetMaxUniqueDomains(t *testing.T) {
	budget := config.BudgetConfig{
		MaxUniqueDomainsPerSession: 2,
		WindowMinutes:              60,
	}
	tracker := NewBudgetTracker(&budget)

	// First two unique domains are fine.
	if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
		t.Fatalf("first domain should not exceed budget: %v", err)
	}
	if err := tracker.RecordRequest(testDomainB, testByteSize); err != nil {
		t.Fatalf("second domain should not exceed budget: %v", err)
	}

	// Third unique domain should exceed.
	if err := tracker.RecordRequest(testDomainC, testByteSize); err == nil {
		t.Fatal("expected budget exceeded on 3rd unique domain")
	}

	// Repeating a known domain should NOT exceed.
	if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
		t.Fatalf("repeated domain should not exceed budget: %v", err)
	}
}

func TestBudgetNilTracker(t *testing.T) {
	var tracker *BudgetTracker

	if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
		t.Fatalf("nil tracker should never report exceeded: %v", err)
	}

	// Reset on nil should not panic.
	tracker.Reset()
}

func TestBudgetAllZeroConfig(t *testing.T) {
	budget := config.BudgetConfig{}
	tracker := NewBudgetTracker(&budget)
	if tracker != nil {
		t.Fatal("expected nil tracker for all-zero config")
	}
}

func TestBudgetNilConfig(t *testing.T) {
	tracker := NewBudgetTracker(nil)
	if tracker != nil {
		t.Fatal("expected nil tracker for nil config")
	}
}

func TestBudgetWindowReset(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 2,
		WindowMinutes:         10,
	}
	tracker := NewBudgetTracker(&budget)

	// Inject a clock that we control.
	now := time.Now()
	tracker.now = func() time.Time { return now }
	tracker.windowStart = now

	// Exhaust the budget.
	for range 2 {
		_ = tracker.RecordRequest(testDomainA, testByteSize)
	}
	if err := tracker.RecordRequest(testDomainA, testByteSize); err == nil {
		t.Fatal("expected budget exceeded before window reset")
	}

	// Advance time past the window (11 minutes > 10-minute window).
	now = now.Add(11 * time.Minute)

	// Budget should have reset: requests succeed again.
	if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
		t.Fatalf("expected budget reset after window expiry: %v", err)
	}
}

func TestBudgetExplicitReset(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 1,
		WindowMinutes:         60,
	}
	tracker := NewBudgetTracker(&budget)

	// Use up the budget.
	_ = tracker.RecordRequest(testDomainA, testByteSize)
	if err := tracker.RecordRequest(testDomainA, testByteSize); err == nil {
		t.Fatal("expected budget exceeded before reset")
	}

	// Explicit reset should clear counters.
	tracker.Reset()

	if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
		t.Fatalf("expected budget available after explicit reset: %v", err)
	}
}

func TestBudgetNoWindowExpiry(t *testing.T) {
	// WindowMinutes=0 means no automatic reset.
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 2,
	}
	tracker := NewBudgetTracker(&budget)

	// Inject a clock and advance time significantly.
	now := time.Now()
	tracker.now = func() time.Time { return now }
	tracker.windowStart = now

	for range 2 {
		_ = tracker.RecordRequest(testDomainA, testByteSize)
	}

	// Advance time by a year: should still be exceeded (no window reset).
	now = now.Add(365 * 24 * time.Hour)

	if err := tracker.RecordRequest(testDomainA, testByteSize); err == nil {
		t.Fatal("expected budget exceeded even after long time with WindowMinutes=0")
	}
}

func TestBudgetConcurrentAccess(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession:      1000,
		MaxBytesPerSession:         1000000, // 1MB
		MaxUniqueDomainsPerSession: 100,
		WindowMinutes:              60,
	}
	tracker := NewBudgetTracker(&budget)

	// 50 goroutines each making 10 requests should not race.
	const goroutines = 50
	const requestsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range requestsPerGoroutine {
				_ = tracker.RecordRequest(testDomainA, testByteSize)
			}
		}()
	}
	wg.Wait()
	// Race detector will catch any issues. No assertion needed beyond no panic.
}

func TestBudgetByteExactBoundary(t *testing.T) {
	// Budget of exactly 200 bytes.
	budget := config.BudgetConfig{
		MaxBytesPerSession: 200,
		WindowMinutes:      60,
	}
	tracker := NewBudgetTracker(&budget)

	// 200 bytes exactly should succeed.
	if err := tracker.RecordRequest(testDomainA, 200); err != nil {
		t.Fatalf("200 bytes should fit in 200-byte budget: %v", err)
	}

	// 1 more byte should exceed.
	if err := tracker.RecordRequest(testDomainA, 1); err == nil {
		t.Fatal("201 bytes should exceed 200-byte budget")
	}
}

func TestBudgetDomainExactBoundary(t *testing.T) {
	budget := config.BudgetConfig{
		MaxUniqueDomainsPerSession: 1,
		WindowMinutes:              60,
	}
	tracker := NewBudgetTracker(&budget)

	// First domain succeeds.
	if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
		t.Fatalf("first domain should fit in 1-domain budget: %v", err)
	}

	// Same domain again should succeed (not a new unique domain).
	if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
		t.Fatalf("same domain should not exceed budget: %v", err)
	}

	// New domain should exceed.
	if err := tracker.RecordRequest(testDomainB, testByteSize); err == nil {
		t.Fatal("second unique domain should exceed 1-domain budget")
	}
}

func TestBudgetPartialConfig(t *testing.T) {
	// Only MaxRequestsPerSession set, others zero (unlimited).
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 2,
	}
	tracker := NewBudgetTracker(&budget)
	if tracker == nil {
		t.Fatal("tracker should be non-nil when at least one field is set")
	}

	// Large byte payloads should not trigger any byte limit.
	if err := tracker.RecordRequest(testDomainA, 999999999); err != nil {
		t.Fatalf("no byte limit set, should not exceed: %v", err)
	}

	// Many unique domains should not trigger domain limit.
	if err := tracker.RecordRequest(testDomainB, 1); err != nil {
		t.Fatalf("no domain limit set, should not exceed: %v", err)
	}

	// But the third request should exceed the request limit.
	if err := tracker.RecordRequest(testDomainC, 1); err == nil {
		t.Fatal("expected request budget exceeded")
	}
}

func TestCheckAdmissionRequestLimit(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 2,
		WindowMinutes:         60,
	}
	tracker := NewBudgetTracker(&budget)

	// Two admissions should succeed.
	for i := range 2 {
		if err := tracker.CheckAdmission(testDomainA); err != nil {
			t.Fatalf("admission %d should not exceed: %v", i+1, err)
		}
	}

	// Third should be rejected.
	if err := tracker.CheckAdmission(testDomainA); err == nil {
		t.Fatal("expected admission rejected after 2 requests")
	}
}

func TestCheckAdmissionDomainLimit(t *testing.T) {
	budget := config.BudgetConfig{
		MaxUniqueDomainsPerSession: 1,
		WindowMinutes:              60,
	}
	tracker := NewBudgetTracker(&budget)

	// First domain: allowed.
	if err := tracker.CheckAdmission(testDomainA); err != nil {
		t.Fatalf("first domain should be admitted: %v", err)
	}

	// Same domain again: allowed (not new).
	if err := tracker.CheckAdmission(testDomainA); err != nil {
		t.Fatalf("same domain should still be admitted: %v", err)
	}

	// New domain: rejected.
	if err := tracker.CheckAdmission(testDomainB); err == nil {
		t.Fatal("second unique domain should be rejected")
	}
}

func TestCheckAdmissionNil(t *testing.T) {
	var tracker *BudgetTracker
	if err := tracker.CheckAdmission(testDomainA); err != nil {
		t.Fatalf("nil tracker should never report exceeded: %v", err)
	}
}

func TestRecordBytesLimit(t *testing.T) {
	budget := config.BudgetConfig{
		MaxBytesPerSession: 200,
		WindowMinutes:      60,
	}
	tracker := NewBudgetTracker(&budget)

	// Record 150 bytes: within budget.
	if err := tracker.RecordBytes(150); err != nil {
		t.Fatalf("150 bytes should fit in 200-byte budget: %v", err)
	}

	// Record 100 more: 250 > 200, should exceed.
	if err := tracker.RecordBytes(100); err == nil {
		t.Fatal("expected byte budget exceeded at 250/200")
	}
}

func TestRecordBytesNil(t *testing.T) {
	var tracker *BudgetTracker
	if err := tracker.RecordBytes(1000); err != nil {
		t.Fatalf("nil tracker should never report exceeded: %v", err)
	}
}

func TestRemainingBytesTracking(t *testing.T) {
	budget := config.BudgetConfig{
		MaxBytesPerSession: 300,
		WindowMinutes:      60,
	}
	tracker := NewBudgetTracker(&budget)

	// Initially: 300 remaining.
	if r := tracker.RemainingBytes(); r != 300 {
		t.Fatalf("remaining = %d, want 300", r)
	}

	// Record 100 bytes: 200 remaining.
	_ = tracker.RecordBytes(100)
	if r := tracker.RemainingBytes(); r != 200 {
		t.Fatalf("remaining = %d, want 200", r)
	}

	// Record 250 more: exceeded (0 remaining, not negative).
	_ = tracker.RecordBytes(250)
	if r := tracker.RemainingBytes(); r != 0 {
		t.Fatalf("remaining = %d, want 0", r)
	}
}

func TestRemainingBytesNil(t *testing.T) {
	var tracker *BudgetTracker
	if r := tracker.RemainingBytes(); r != -1 {
		t.Fatalf("nil tracker remaining = %d, want -1 (unlimited)", r)
	}
}

func TestRemainingBytesNoLimit(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 10, // only request limit, no byte limit
		WindowMinutes:         60,
	}
	tracker := NewBudgetTracker(&budget)
	if r := tracker.RemainingBytes(); r != -1 {
		t.Fatalf("no byte limit: remaining = %d, want -1 (unlimited)", r)
	}
}

func TestBudgetWindowResetsAllCounters(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession:      2,
		MaxBytesPerSession:         200,
		MaxUniqueDomainsPerSession: 2,
		WindowMinutes:              5,
	}
	tracker := NewBudgetTracker(&budget)

	now := time.Now()
	tracker.now = func() time.Time { return now }
	tracker.windowStart = now

	// Exhaust all budgets.
	_ = tracker.RecordRequest(testDomainA, testByteSize)
	_ = tracker.RecordRequest(testDomainB, testByteSize)

	// All three limits should be at their boundaries now.
	if err := tracker.RecordRequest(testDomainC, testByteSize); err == nil {
		t.Fatal("expected exceeded on all three limits")
	}

	// Advance past window.
	now = now.Add(6 * time.Minute)

	// All counters should reset: request, bytes, and domains.
	if err := tracker.RecordRequest(testDomainA, testByteSize); err != nil {
		t.Fatalf("all counters should reset after window expiry: %v", err)
	}
}
