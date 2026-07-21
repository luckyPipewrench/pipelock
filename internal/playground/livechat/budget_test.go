// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestDailyBudget_Unlimited(t *testing.T) {
	t.Parallel()
	b := NewDailyBudget(0)
	for i := 0; i < 5; i++ {
		if !b.Charge(1) {
			t.Fatal("cap 0 must be unlimited")
		}
	}
	if b.Remaining() != -1 {
		t.Errorf("unlimited Remaining = %d, want -1", b.Remaining())
	}
	if !b.Open() {
		t.Error("unlimited Open must be true")
	}

	// A nil budget also allows (a server without a budget configured).
	var nb *DailyBudget
	if !nb.Charge(1) || !nb.Open() || nb.Remaining() != -1 {
		t.Error("nil budget must allow and report unlimited")
	}
}

func TestDailyBudget_CapAndDailyReset(t *testing.T) {
	t.Parallel()
	day1 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	b := NewDailyBudget(2)
	b.now = func() time.Time { return day1 }

	if !b.Charge(1) {
		t.Fatal("first charge must fit cap 2")
	}
	if !b.Charge(1) {
		t.Fatal("second charge must fit cap 2")
	}
	if b.Charge(1) {
		t.Error("third charge must fail at the cap")
	}
	if b.Remaining() != 0 {
		t.Errorf("Remaining at cap = %d, want 0", b.Remaining())
	}
	if b.Open() {
		t.Error("Open at cap must be false")
	}

	// Crossing into the next UTC day resets the count.
	b.now = func() time.Time { return day1.Add(24 * time.Hour) }
	if b.Remaining() != 2 {
		t.Errorf("Remaining after daily reset = %d, want 2", b.Remaining())
	}
	if !b.Open() || !b.Charge(1) {
		t.Error("budget must reopen on a new UTC day")
	}
}

func TestDailyBudget_RefundSameDayOnly(t *testing.T) {
	t.Parallel()
	day1 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	b := NewDailyBudget(2)
	b.now = func() time.Time { return day1 }

	if !b.Charge(1) || b.Remaining() != 1 {
		t.Fatalf("initial charge failed or remaining = %d, want 1", b.Remaining())
	}
	b.Refund(1)
	if b.Remaining() != 2 {
		t.Fatalf("refund remaining = %d, want 2", b.Remaining())
	}

	if !b.Charge(1) {
		t.Fatal("second charge failed")
	}
	b.now = func() time.Time { return day1.Add(24 * time.Hour) }
	b.Refund(1)
	if b.Remaining() != 2 {
		t.Fatalf("cross-day refund must not affect new day, remaining = %d", b.Remaining())
	}
}

func TestDailyBudget_ChargeNAllOrNothing(t *testing.T) {
	t.Parallel()
	day1 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	b := NewDailyBudget(5)
	b.now = func() time.Time { return day1 }

	if !b.Charge(3) {
		t.Fatal("charge of 3 must fit cap 5")
	}
	if b.Remaining() != 2 {
		t.Fatalf("remaining after charging 3 = %d, want 2", b.Remaining())
	}
	// A 3-unit message does not fit the remaining 2: all-or-nothing records
	// NOTHING and leaves the budget intact (no partial leak).
	if b.Charge(3) {
		t.Fatal("charge of 3 must fail when only 2 remain")
	}
	if b.Remaining() != 2 {
		t.Fatalf("a rejected over-charge must not consume budget; remaining = %d, want 2", b.Remaining())
	}
	if !b.Charge(2) {
		t.Fatal("charge of 2 must fit the remaining 2")
	}
	if b.Remaining() != 0 {
		t.Fatalf("remaining after exhausting = %d, want 0", b.Remaining())
	}

	// Refund of n returns exactly n and clamps at the cap.
	b.Refund(2)
	if b.Remaining() != 2 {
		t.Fatalf("remaining after refunding 2 = %d, want 2", b.Remaining())
	}
	b.Refund(100)
	if b.Remaining() != 5 {
		t.Fatalf("over-refund must clamp at the cap; remaining = %d, want 5", b.Remaining())
	}
}

func TestKeyedDailyBudget_PerKeyCapAndIsolation(t *testing.T) {
	t.Parallel()
	day1 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	b := NewKeyedDailyBudget(2, 0)
	b.now = func() time.Time { return day1 }

	if !b.Charge("a", 1) {
		t.Fatal("key a first charge should fit cap 2")
	}
	if !b.Charge("a", 1) {
		t.Fatal("key a second charge should fit cap 2")
	}
	if b.Charge("a", 1) {
		t.Error("key a third charge must fail at its cap")
	}
	// A different identity has its own independent budget.
	if !b.Charge("b", 2) {
		t.Error("key b must have its own full budget")
	}
	// Refund returns budget to that key only, no mint past the cap.
	b.Refund("a", 5)
	if !b.Charge("a", 2) {
		t.Error("after refund, key a should have its full cap again")
	}
	// Empty key is refused; disabled budget always allows.
	if b.Charge("", 1) {
		t.Error("empty key must be refused")
	}
	if !NewKeyedDailyBudget(0, 0).Charge("x", 99) {
		t.Error("disabled per-key budget (cap 0) must always allow")
	}
}

func TestKeyedDailyBudget_DayResetAndRefundSameDayOnly(t *testing.T) {
	t.Parallel()
	day1 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	b := NewKeyedDailyBudget(1, 0)
	b.now = func() time.Time { return day1 }

	if !b.Charge("a", 1) || b.Charge("a", 1) {
		t.Fatal("key a: first charge fits, second exceeds cap 1")
	}
	// Next UTC day resets the per-key count.
	b.now = func() time.Time { return day1.Add(24 * time.Hour) }
	if !b.Charge("a", 1) {
		t.Error("key a must reset on a new UTC day")
	}
	// A refund dated to a different day than the recorded count must not apply.
	b.now = func() time.Time { return day1.Add(48 * time.Hour) }
	b.Refund("a", 1) // a's count is for day1+24h, not this day: no-op
	b.now = func() time.Time { return day1.Add(24 * time.Hour) }
	if b.Charge("a", 1) {
		t.Error("cross-day refund must not have minted budget for the recorded day")
	}
}

// TestKeyedDailyBudget_AtCapKeyNotResetByEvictionSpray is the security-critical
// case: an attacker at their per-key cap must not be able to spray unique keys to
// force their own key out of the bounded map and reset its count. Live same-day
// keys are never evicted, so a saturated map fails closed for new keys instead.
func TestKeyedDailyBudget_AtCapKeyNotResetByEvictionSpray(t *testing.T) {
	t.Parallel()
	day1 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	b := NewKeyedDailyBudget(1, 2) // cap 1 per key, room for only 2 keys
	b.now = func() time.Time { return day1 }

	if !b.Charge("victim", 1) {
		t.Fatal("victim's first charge must fit")
	}
	if !b.Charge("filler", 1) {
		t.Fatal("filler charge must fit; map now full with two live same-day keys")
	}
	// Spray a new key: the map is full of LIVE same-day keys, so nothing is
	// evictable and the new key is refused (fail-closed) -- it does NOT push the
	// victim out.
	if b.Charge("spray", 1) {
		t.Error("new key must be refused when the map is saturated with live keys")
	}
	if b.Len() != 2 {
		t.Errorf("tracked keys = %d, want 2 (no live key evicted)", b.Len())
	}
	// The victim is still at its cap: it was not evicted/reset.
	if b.Charge("victim", 1) {
		t.Error("victim must remain at its cap; the spray must not reset it")
	}
	// On a new UTC day, stale keys are reclaimed and counts reset legitimately.
	b.now = func() time.Time { return day1.Add(24 * time.Hour) }
	if !b.Charge("victim", 1) {
		t.Error("victim must reset on a new UTC day")
	}
}

func TestLiveEntry_TryMessage(t *testing.T) {
	t.Parallel()
	e := &liveEntry{}
	if !e.tryMessage(2) {
		t.Fatal("first message must fit cap 2")
	}
	if !e.tryMessage(2) {
		t.Fatal("second message must fit cap 2")
	}
	if e.tryMessage(2) {
		t.Error("third message must be refused at the cap")
	}
	e.refundMessage(2)
	if !e.tryMessage(2) {
		t.Error("refund should return one message slot")
	}
	// cap 0 is unlimited.
	u := &liveEntry{}
	for i := 0; i < 10; i++ {
		if !u.tryMessage(0) {
			t.Fatal("cap 0 must be unlimited")
		}
	}
}

// --- HTTP integration: the caps refuse over budget without driving a turn ---

func createLiveSession(t *testing.T, ts string) string {
	t.Helper()
	resp := postJSON(t, ts+RouteSession, createReq{Code: "good"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session create status = %d, want 200", resp.StatusCode)
	}
	var cr createResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	return cr.Token
}

func sendLiveMessage(t *testing.T, ts, token, msg string) int {
	t.Helper()
	resp := postJSON(t, ts+RouteMessage, messageReq{Token: token, Message: msg})
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestServer_DailyTurnBudget_KillSwitch(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy per session")
	}
	ts := newTestServer(t, ServerConfig{DailyTurnBudget: 1})
	token := createLiveSession(t, ts.URL)

	if st := sendLiveMessage(t, ts.URL, token, "hello"); st != http.StatusAccepted {
		t.Fatalf("first message status = %d, want 202", st)
	}
	// The day's single-turn budget is spent: the next message is refused (paused).
	if st := sendLiveMessage(t, ts.URL, token, "again"); st != http.StatusServiceUnavailable {
		t.Errorf("over-budget message status = %d, want 503", st)
	}
	resp := postJSON(t, ts.URL+RouteSession, createReq{Code: "good"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("new session after spent budget status = %d, want 503", resp.StatusCode)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+RouteHealth, nil)
	if err != nil {
		t.Fatalf("new health request: %v", err)
	}
	healthResp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	defer func() { _ = healthResp.Body.Close() }()
	var health map[string]any
	if err := json.NewDecoder(healthResp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if ok, _ := health["ok"].(bool); ok {
		t.Fatalf("health ok after spent budget = true, want false: %+v", health)
	}
	if rem, _ := health["budget_remaining"].(float64); rem != 0 {
		t.Fatalf("budget_remaining = %v, want 0", health["budget_remaining"])
	}
}

func TestServer_PerCodeDailyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy per session")
	}
	ts := newTestServer(t, ServerConfig{PerCodeDailyBudget: 1})
	token := createLiveSession(t, ts.URL)

	if st := sendLiveMessage(t, ts.URL, token, "hello"); st != http.StatusAccepted {
		t.Fatalf("first message status = %d, want 202", st)
	}
	// The code's single round-trip budget is spent: the next message is refused
	// for THIS code (the global budget is untouched).
	if st := sendLiveMessage(t, ts.URL, token, "again"); st != http.StatusTooManyRequests {
		t.Errorf("over per-code-budget message status = %d, want 429", st)
	}
}

func TestServer_PerIPDailyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy per session")
	}
	ts := newTestServer(t, ServerConfig{PerIPDailyBudget: 1})
	token := createLiveSession(t, ts.URL)

	if st := sendLiveMessage(t, ts.URL, token, "hello"); st != http.StatusAccepted {
		t.Fatalf("first message status = %d, want 202", st)
	}
	// The client IP's single round-trip budget is spent: the next message is
	// refused for THIS address (without relying on the global budget).
	if st := sendLiveMessage(t, ts.URL, token, "again"); st != http.StatusTooManyRequests {
		t.Errorf("over per-ip-budget message status = %d, want 429", st)
	}
}

func TestServer_PerSessionMessageCap(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy per session")
	}
	ts := newTestServer(t, ServerConfig{MaxMessagesPerSession: 1})
	token := createLiveSession(t, ts.URL)

	if st := sendLiveMessage(t, ts.URL, token, "hello"); st != http.StatusAccepted {
		t.Fatalf("first message status = %d, want 202", st)
	}
	// This session has used its one-message budget.
	if st := sendLiveMessage(t, ts.URL, token, "again"); st != http.StatusTooManyRequests {
		t.Errorf("over-cap message status = %d, want 429", st)
	}
}
