// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package authlimit

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(t *testing.T, maxFailures int) (*Limiter, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := New(maxFailures, time.Minute)
	l.SetClock(clk.now)
	return l, clk
}

func TestLimiter_BlocksAfterBudgetAndRecovers(t *testing.T) {
	l, clk := newTestLimiter(t, 3)
	const key = "203.0.113.7"

	for i := range 3 {
		if allowed, _ := l.Admit(key); !allowed {
			t.Fatalf("attempt %d: refused before budget spent", i)
		}
	}
	allowed, retry := l.Admit(key)
	if allowed {
		t.Fatal("expected refusal after three admitted attempts")
	}
	if blocked, _ := l.Blocked(key); !blocked {
		t.Fatal("Blocked disagrees with Admit")
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("retry = %v, want within (0, 1m]", retry)
	}

	// The window is anchored on the oldest failure: further attempts while
	// blocked do not extend the lockout.
	clk.advance(30 * time.Second)
	_, retry2 := l.Admit(key)
	if retry2 > 30*time.Second {
		t.Fatalf("further failures extended the lockout: retry = %v", retry2)
	}

	clk.advance(31 * time.Second)
	if allowed, _ := l.Admit(key); !allowed {
		t.Fatal("still refused after the window passed")
	}
}

func TestLimiter_ResetClearsFailures(t *testing.T) {
	l, _ := newTestLimiter(t, 2)
	const key = "198.51.100.4"
	l.Admit(key)
	l.Admit(key)
	if allowed, _ := l.Admit(key); allowed {
		t.Fatal("expected refusal")
	}
	l.Reset(key)
	if allowed, _ := l.Admit(key); !allowed {
		t.Fatal("Reset did not clear the refusal")
	}
	l.Reset(key)
	if l.Len() != 0 {
		t.Fatalf("Len = %d after Reset, want 0", l.Len())
	}
}

func TestLimiter_KeysAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(t, 1)
	l.Admit("a")
	if allowed, _ := l.Admit("a"); allowed {
		t.Fatal("a should be refused")
	}
	if allowed, _ := l.Admit("b"); !allowed {
		t.Fatal("b must not inherit a's reservations")
	}
}

func TestLimiter_BoundsTrackedKeys(t *testing.T) {
	l, clk := newTestLimiter(t, 5)
	l.maxKeys = 3
	for i := range 3 {
		l.Admit("k" + strconv.Itoa(i))
		clk.advance(time.Second)
	}
	if l.Len() != 3 {
		t.Fatalf("Len = %d, want 3", l.Len())
	}
	// A fourth key evicts the entry with the oldest failure (k0).
	l.Admit("k3")
	if l.Len() != 3 {
		t.Fatalf("Len = %d after eviction, want 3", l.Len())
	}
	if _, ok := l.entries["k0"]; ok {
		t.Fatal("expected the oldest key to be evicted")
	}
	// Once every tracked entry has expired, insertion prefers dropping those.
	clk.advance(2 * time.Minute)
	l.Admit("k4")
	if l.Len() != 1 {
		t.Fatalf("Len = %d after expiry, want 1 (only k4)", l.Len())
	}
}

func TestLimiter_DefaultsOnBadArguments(t *testing.T) {
	l := New(0, 0)
	if l.maxFailures != DefaultMaxFailures || l.window != DefaultWindow {
		t.Fatalf("New(0,0) = %d/%v, want defaults", l.maxFailures, l.window)
	}
	if l.maxKeys != DefaultMaxKeys {
		t.Fatalf("maxKeys = %d, want %d", l.maxKeys, DefaultMaxKeys)
	}
}

func TestLimiter_NilIsInert(t *testing.T) {
	var l *Limiter
	l.Reset("x")
	if allowed, _ := l.Admit("x"); !allowed {
		t.Fatal("nil limiter must admit everything")
	}
	if blocked, _ := l.Blocked("x"); blocked {
		t.Fatal("nil limiter must never block")
	}
	if l.Len() != 0 {
		t.Fatal("nil limiter Len must be 0")
	}
}

func TestClientKey_IgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:51234"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("Forwarded", "for=10.0.0.2")
	if got := ClientKey(r); got != "203.0.113.9" {
		t.Fatalf("ClientKey = %q, want the transport peer", got)
	}
	r.RemoteAddr = "[2001:db8::1]:443"
	if got := ClientKey(r); got != "2001:db8::1" {
		t.Fatalf("ClientKey v6 = %q", got)
	}
	r.RemoteAddr = "pipe"
	if got := ClientKey(r); got != "pipe" {
		t.Fatalf("ClientKey unparsable = %q, want raw RemoteAddr", got)
	}
	if got := ClientKey(nil); got != "" {
		t.Fatalf("ClientKey(nil) = %q", got)
	}
}

func TestRefuse_SetsRetryAfterRoundedUp(t *testing.T) {
	cases := []struct {
		retry time.Duration
		want  string
	}{
		{retry: 0, want: "1"},
		{retry: 900 * time.Millisecond, want: "1"},
		{retry: 1500 * time.Millisecond, want: "2"},
		{retry: 60 * time.Second, want: "60"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			rec := httptest.NewRecorder()
			Refuse(rec, tc.retry)
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d", rec.Code)
			}
			if got := rec.Header().Get("Retry-After"); got != tc.want {
				t.Fatalf("Retry-After = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLimiter_ConcurrentUse(t *testing.T) {
	l := NewDefault()
	done := make(chan struct{})
	for g := range 8 {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			key := "k" + strconv.Itoa(g%2)
			for range 200 {
				_, _ = l.Admit(key)
				_, _ = l.Blocked(key)
				if g%4 == 0 {
					l.Reset(key)
				}
			}
		}(g)
	}
	for range 8 {
		<-done
	}
}

// TestLimiter_ParallelBurstCannotExceedBudget pins the property the atomic
// reservation exists for: however many guesses arrive at once, at most
// maxFailures of them are admitted to a credential compare.
func TestLimiter_ParallelBurstCannotExceedBudget(t *testing.T) {
	l := New(10, time.Minute)
	const burst = 500
	start := make(chan struct{})
	results := make(chan bool, burst)
	var wg sync.WaitGroup
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			allowed, _ := l.Admit("203.0.113.44")
			results <- allowed
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	admitted := 0
	for allowed := range results {
		if allowed {
			admitted++
		}
	}
	if admitted != 10 {
		t.Fatalf("admitted = %d of %d parallel attempts, want exactly 10", admitted, burst)
	}
}

func TestLimiter_ReleaseReturnsOnlyTheCallersSlot(t *testing.T) {
	l, _ := newTestLimiter(t, 3)
	const key = "203.0.113.50"
	// Request A reserves first, request B then records a real failure, and A
	// releases afterwards: B's slot must survive.
	resA, ok, _ := l.Reserve(key)
	if !ok {
		t.Fatal("A not admitted")
	}
	if _, ok, _ := l.Reserve(key); !ok { // B, a real failure
		t.Fatal("B not admitted")
	}
	l.Release(resA)
	if l.entries[key] == nil || len(l.entries[key].failures) != 1 {
		t.Fatalf("after releasing A, slots = %+v, want exactly B's", l.entries[key])
	}
	// Releasing A twice, the zero reservation, or an unknown key changes nothing.
	l.Release(resA)
	l.Release(Reservation{})
	l.Release(Reservation{key: "unknown", id: 99})
	if len(l.entries[key].failures) != 1 {
		t.Fatalf("idempotent release changed the count: %+v", l.entries[key])
	}
	var nilLimiter *Limiter
	nilLimiter.Release(resA)
	// Reset then Release of a stale handle is a no-op.
	l.Reset(key)
	l.Release(resA)
	if l.Len() != 0 {
		t.Fatalf("Len = %d after Reset, want 0", l.Len())
	}
}

// TestLimiter_ReleaseOutOfOrderKeepsWindowAnchor pins the accounting the
// ownership-aware handle exists for: with A admitted before B, releasing A
// leaves B's own timestamp as the window anchor, so B's failure still counts
// for its full window rather than expiring early on A's older timestamp.
func TestLimiter_ReleaseOutOfOrderKeepsWindowAnchor(t *testing.T) {
	l, clk := newTestLimiter(t, 1)
	const key = "203.0.113.51"
	resA, _, _ := l.Reserve(key)
	clk.advance(50 * time.Second)
	l.Release(resA)
	if _, ok, _ := l.Reserve(key); !ok { // B, at t+50s
		t.Fatal("B not admitted after A released")
	}
	clk.advance(11 * time.Second) // t+61s: A's slot would have expired, B's must not
	if _, ok, retry := l.Reserve(key); ok || retry <= 0 {
		t.Fatalf("B's failure expired early: admitted=%v retry=%v", ok, retry)
	}
}
