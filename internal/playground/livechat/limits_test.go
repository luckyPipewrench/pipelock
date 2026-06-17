// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimiter_BurstThenDeny(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	rl := NewRateLimiter(RateConfig{
		RefillPerSec: 1,
		Burst:        3,
		Now:          func() time.Time { return clock },
	})
	for i := 0; i < 3; i++ {
		if !rl.Allow("ip1") {
			t.Fatalf("burst token %d denied; want allow", i)
		}
	}
	if rl.Allow("ip1") {
		t.Error("4th request allowed; want deny (burst exhausted)")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	rl := NewRateLimiter(RateConfig{
		RefillPerSec: 2, // one token every 500ms
		Burst:        1,
		Now:          func() time.Time { return clock },
	})
	if !rl.Allow("k") {
		t.Fatal("first allow denied")
	}
	if rl.Allow("k") {
		t.Fatal("second immediate allow; want deny")
	}
	clock = clock.Add(500 * time.Millisecond) // one token refilled
	if !rl.Allow("k") {
		t.Error("after refill, allow denied")
	}
}

func TestRateLimiter_NilDenies(t *testing.T) {
	t.Parallel()
	var rl *RateLimiter
	if rl.Allow("x") {
		t.Error("nil limiter allowed; want deny (fail-closed)")
	}
	if rl.Len() != 0 {
		t.Error("nil limiter Len != 0")
	}
	rl.Sweep() // must not panic
}

func TestRateLimiter_ClampsBadConfig(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	// All-zero config must not disable limiting.
	rl := NewRateLimiter(RateConfig{Now: func() time.Time { return clock }})
	if !rl.Allow("k") {
		t.Fatal("first allow denied under clamped config")
	}
	if rl.Allow("k") {
		t.Error("second allow permitted; clamped burst should be 1")
	}
}

func TestRateLimiter_MaxKeysFailClosed(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	rl := NewRateLimiter(RateConfig{
		RefillPerSec: 1,
		Burst:        1,
		MaxKeys:      3,
		IdleTTL:      time.Hour, // nothing is idle, so nothing can be evicted
		Now:          func() time.Time { return clock },
	})
	// Fill the key table with active (non-idle) keys.
	for i, k := range []string{"a", "b", "c"} {
		if !rl.Allow(k) {
			t.Fatalf("key %d (%s) denied while under cap", i, k)
		}
	}
	// A brand-new key cannot be tracked: refuse rather than grow unbounded.
	if rl.Allow("d") {
		t.Error("new key admitted past MaxKeys; want fail-closed deny")
	}
	if rl.Len() > 3 {
		t.Errorf("tracked keys = %d, want <= 3", rl.Len())
	}
}

func TestRateLimiter_SweepEvictsIdle(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	rl := NewRateLimiter(RateConfig{
		RefillPerSec: 100,
		Burst:        1,
		IdleTTL:      time.Minute,
		Now:          func() time.Time { return clock },
	})
	if !rl.Allow("k") {
		t.Fatal("allow denied")
	}
	if rl.Len() != 1 {
		t.Fatalf("Len = %d, want 1", rl.Len())
	}
	clock = clock.Add(2 * time.Minute) // recovered + idle past TTL
	rl.Sweep()
	if rl.Len() != 0 {
		t.Errorf("Len after sweep = %d, want 0", rl.Len())
	}
}

func TestRateLimiter_ConcurrentAllow(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(RateConfig{RefillPerSec: 1000, Burst: 1000})
	var allowed int64
	var wg sync.WaitGroup
	const g, each = 8, 50
	wg.Add(g)
	for i := 0; i < g; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if rl.Allow("shared") {
					atomic.AddInt64(&allowed, 1)
				}
			}
		}()
	}
	wg.Wait()
	if allowed == 0 || allowed > g*each {
		t.Errorf("allowed = %d, want in (0, %d]", allowed, g*each)
	}
}

func TestConcurrencyLimiter_CapEnforced(t *testing.T) {
	t.Parallel()
	cl := NewConcurrencyLimiter(2)
	r1, ok1 := cl.Acquire()
	r2, ok2 := cl.Acquire()
	if !ok1 || !ok2 {
		t.Fatal("first two acquires should succeed")
	}
	if _, ok3 := cl.Acquire(); ok3 {
		t.Error("third acquire succeeded past cap; want refuse")
	}
	if cl.InUse() != 2 {
		t.Errorf("InUse = %d, want 2", cl.InUse())
	}
	r1()
	if r3, ok := cl.Acquire(); !ok {
		t.Error("acquire after release failed; want success")
	} else {
		r3()
	}
	r2()
	if cl.InUse() != 0 {
		t.Errorf("InUse after releases = %d, want 0", cl.InUse())
	}
}

func TestConcurrencyLimiter_ReleaseIdempotent(t *testing.T) {
	t.Parallel()
	cl := NewConcurrencyLimiter(1)
	r, ok := cl.Acquire()
	if !ok {
		t.Fatal("acquire failed")
	}
	r()
	r() // double release must not drive the counter negative or free a phantom slot
	if cl.InUse() != 0 {
		t.Errorf("InUse = %d, want 0", cl.InUse())
	}
	if _, ok := cl.Acquire(); !ok {
		t.Error("acquire after release failed")
	}
}

func TestConcurrencyLimiter_NilFailsClosed(t *testing.T) {
	t.Parallel()
	var cl *ConcurrencyLimiter
	if _, ok := cl.Acquire(); ok {
		t.Error("nil limiter acquire succeeded; want fail-closed")
	}
	if cl.InUse() != 0 || cl.Cap() != 0 {
		t.Error("nil limiter InUse/Cap nonzero")
	}
}

func TestConcurrencyLimiter_NeverExceedsCapUnderRace(t *testing.T) {
	t.Parallel()
	const capN = 5
	cl := NewConcurrencyLimiter(capN)
	var peak int64
	var wg sync.WaitGroup
	const workers = 50
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if release, ok := cl.Acquire(); ok {
					if u := int64(cl.InUse()); u > atomic.LoadInt64(&peak) {
						atomic.StoreInt64(&peak, u)
					}
					release()
				}
			}
		}()
	}
	wg.Wait()
	if peak > capN {
		t.Errorf("peak concurrency = %d, exceeded cap %d", peak, capN)
	}
}

func TestLimits_Clamp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   Limits
		want Limits
	}{
		{"zero->defaults", Limits{}, Limits{defaultMaxInputBytes, defaultSessionTTL}},
		{"oversized-input", Limits{MaxInputBytes: 1 << 20, SessionTTL: time.Minute}, Limits{maxMaxInputBytes, time.Minute}},
		{"tiny-ttl", Limits{MaxInputBytes: 100, SessionTTL: time.Second}, Limits{100, minSessionTTL}},
		{"huge-ttl", Limits{MaxInputBytes: 100, SessionTTL: time.Hour}, Limits{100, maxSessionTTL}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.Clamp(); got != tc.want {
				t.Errorf("Clamp() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLimits_CheckInput(t *testing.T) {
	t.Parallel()
	l := Limits{MaxInputBytes: 10}
	if err := l.CheckInput(""); !errors.Is(err, ErrInputEmpty) {
		t.Errorf("empty err = %v, want ErrInputEmpty", err)
	}
	if err := l.CheckInput(strings.Repeat("x", 11)); !errors.Is(err, ErrInputTooLarge) {
		t.Errorf("oversized err = %v, want ErrInputTooLarge", err)
	}
	if err := l.CheckInput("ok"); err != nil {
		t.Errorf("valid input err = %v, want nil", err)
	}
}
