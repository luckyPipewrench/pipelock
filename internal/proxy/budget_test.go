// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testDomainA = "a.com"
	testDomainB = "b.com"
	testDomainC = "c.com"

	// testByteSize is a small payload used in most budget tests.
	testByteSize = 100
)

func TestBudgetMaxRequests(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 3,
		WindowMinutes:         60,
	}
	tracker := NewBudgetTracker(&budget)

	for i := range 3 {
		exceeded, _ := tracker.RecordRequest(testDomainA, testByteSize)
		if exceeded {
			t.Fatalf("request %d should not exceed budget", i+1)
		}
	}

	exceeded, reason := tracker.RecordRequest(testDomainA, testByteSize)
	if !exceeded {
		t.Fatal("expected budget exceeded after 3 requests")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
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
		exceeded, _ := tracker.RecordRequest(testDomainA, testByteSize)
		if exceeded {
			t.Fatalf("request %d (100 bytes) should not exceed 250-byte budget", i+1)
		}
	}

	// 200 + 100 = 300 > 250: should exceed.
	exceeded, reason := tracker.RecordRequest(testDomainA, testByteSize)
	if !exceeded {
		t.Fatal("expected byte budget exceeded")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason for byte budget")
	}
}

func TestBudgetMaxUniqueDomains(t *testing.T) {
	budget := config.BudgetConfig{
		MaxUniqueDomainsPerSession: 2,
		WindowMinutes:              60,
	}
	tracker := NewBudgetTracker(&budget)

	// First two unique domains are fine.
	if exceeded, _ := tracker.RecordRequest(testDomainA, testByteSize); exceeded {
		t.Fatal("first domain should not exceed budget")
	}
	if exceeded, _ := tracker.RecordRequest(testDomainB, testByteSize); exceeded {
		t.Fatal("second domain should not exceed budget")
	}

	// Third unique domain should exceed.
	exceeded, reason := tracker.RecordRequest(testDomainC, testByteSize)
	if !exceeded {
		t.Fatal("expected budget exceeded on 3rd unique domain")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason for domain budget")
	}

	// Repeating a known domain should NOT exceed.
	exceeded, _ = tracker.RecordRequest(testDomainA, testByteSize)
	if exceeded {
		t.Fatal("repeated domain should not exceed budget")
	}
}

func TestBudgetNilTracker(t *testing.T) {
	var tracker *BudgetTracker

	exceeded, reason := tracker.RecordRequest(testDomainA, testByteSize)
	if exceeded {
		t.Fatal("nil tracker should never report exceeded")
	}
	if reason != "" {
		t.Fatalf("nil tracker should return empty reason, got %q", reason)
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
		tracker.RecordRequest(testDomainA, testByteSize)
	}
	exceeded, _ := tracker.RecordRequest(testDomainA, testByteSize)
	if !exceeded {
		t.Fatal("expected budget exceeded before window reset")
	}

	// Advance time past the window (11 minutes > 10-minute window).
	now = now.Add(11 * time.Minute)

	// Budget should have reset: requests succeed again.
	exceeded, _ = tracker.RecordRequest(testDomainA, testByteSize)
	if exceeded {
		t.Fatal("expected budget reset after window expiry")
	}
}

func TestBudgetExplicitReset(t *testing.T) {
	budget := config.BudgetConfig{
		MaxRequestsPerSession: 1,
		WindowMinutes:         60,
	}
	tracker := NewBudgetTracker(&budget)

	// Use up the budget.
	tracker.RecordRequest(testDomainA, testByteSize)
	exceeded, _ := tracker.RecordRequest(testDomainA, testByteSize)
	if !exceeded {
		t.Fatal("expected budget exceeded before reset")
	}

	// Explicit reset should clear counters.
	tracker.Reset()

	exceeded, _ = tracker.RecordRequest(testDomainA, testByteSize)
	if exceeded {
		t.Fatal("expected budget available after explicit reset")
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
		tracker.RecordRequest(testDomainA, testByteSize)
	}

	// Advance time by a year: should still be exceeded (no window reset).
	now = now.Add(365 * 24 * time.Hour)

	exceeded, _ := tracker.RecordRequest(testDomainA, testByteSize)
	if !exceeded {
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
				tracker.RecordRequest(testDomainA, testByteSize)
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
	exceeded, _ := tracker.RecordRequest(testDomainA, 200)
	if exceeded {
		t.Fatal("200 bytes should fit in 200-byte budget")
	}

	// 1 more byte should exceed.
	exceeded, reason := tracker.RecordRequest(testDomainA, 1)
	if !exceeded {
		t.Fatal("201 bytes should exceed 200-byte budget")
	}
	if reason == "" {
		t.Fatal("expected reason for byte budget exceeded")
	}
}

func TestBudgetDomainExactBoundary(t *testing.T) {
	budget := config.BudgetConfig{
		MaxUniqueDomainsPerSession: 1,
		WindowMinutes:              60,
	}
	tracker := NewBudgetTracker(&budget)

	// First domain succeeds.
	exceeded, _ := tracker.RecordRequest(testDomainA, testByteSize)
	if exceeded {
		t.Fatal("first domain should fit in 1-domain budget")
	}

	// Same domain again should succeed (not a new unique domain).
	exceeded, _ = tracker.RecordRequest(testDomainA, testByteSize)
	if exceeded {
		t.Fatal("same domain should not exceed budget")
	}

	// New domain should exceed.
	exceeded, _ = tracker.RecordRequest(testDomainB, testByteSize)
	if !exceeded {
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
	exceeded, _ := tracker.RecordRequest(testDomainA, 999999999)
	if exceeded {
		t.Fatal("no byte limit set, should not exceed")
	}

	// Many unique domains should not trigger domain limit.
	exceeded, _ = tracker.RecordRequest(testDomainB, 1)
	if exceeded {
		t.Fatal("no domain limit set, should not exceed")
	}

	// But the third request should exceed the request limit.
	exceeded, _ = tracker.RecordRequest(testDomainC, 1)
	if !exceeded {
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
		exceeded, _ := tracker.CheckAdmission(testDomainA)
		if exceeded {
			t.Fatalf("admission %d should not exceed", i+1)
		}
	}

	// Third should be rejected.
	exceeded, reason := tracker.CheckAdmission(testDomainA)
	if !exceeded {
		t.Fatal("expected admission rejected after 2 requests")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestCheckAdmissionDomainLimit(t *testing.T) {
	budget := config.BudgetConfig{
		MaxUniqueDomainsPerSession: 1,
		WindowMinutes:              60,
	}
	tracker := NewBudgetTracker(&budget)

	// First domain: allowed.
	exceeded, _ := tracker.CheckAdmission(testDomainA)
	if exceeded {
		t.Fatal("first domain should be admitted")
	}

	// Same domain again: allowed (not new).
	exceeded, _ = tracker.CheckAdmission(testDomainA)
	if exceeded {
		t.Fatal("same domain should still be admitted")
	}

	// New domain: rejected.
	exceeded, reason := tracker.CheckAdmission(testDomainB)
	if !exceeded {
		t.Fatal("second unique domain should be rejected")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestCheckAdmissionNil(t *testing.T) {
	var tracker *BudgetTracker
	exceeded, reason := tracker.CheckAdmission(testDomainA)
	if exceeded {
		t.Fatal("nil tracker should never report exceeded")
	}
	if reason != "" {
		t.Fatalf("nil tracker should return empty reason, got %q", reason)
	}
}

func TestRecordBytesLimit(t *testing.T) {
	budget := config.BudgetConfig{
		MaxBytesPerSession: 200,
		WindowMinutes:      60,
	}
	tracker := NewBudgetTracker(&budget)

	// Record 150 bytes: within budget.
	exceeded, _ := tracker.RecordBytes(150)
	if exceeded {
		t.Fatal("150 bytes should fit in 200-byte budget")
	}

	// Record 100 more: 250 > 200, should exceed.
	exceeded, reason := tracker.RecordBytes(100)
	if !exceeded {
		t.Fatal("expected byte budget exceeded at 250/200")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestRecordBytesNil(t *testing.T) {
	var tracker *BudgetTracker
	exceeded, reason := tracker.RecordBytes(1000)
	if exceeded {
		t.Fatal("nil tracker should never report exceeded")
	}
	if reason != "" {
		t.Fatalf("nil tracker should return empty reason, got %q", reason)
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
	tracker.RecordRequest(testDomainA, testByteSize)
	tracker.RecordRequest(testDomainB, testByteSize)

	// All three limits should be at their boundaries now.
	exceeded, _ := tracker.RecordRequest(testDomainC, testByteSize)
	if !exceeded {
		t.Fatal("expected exceeded on all three limits")
	}

	// Advance past window.
	now = now.Add(6 * time.Minute)

	// All counters should reset: request, bytes, and domains.
	exceeded, _ = tracker.RecordRequest(testDomainA, testByteSize)
	if exceeded {
		t.Fatal("all counters should reset after window expiry")
	}
}
