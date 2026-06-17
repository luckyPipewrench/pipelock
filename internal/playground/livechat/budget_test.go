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
		if !b.Charge() {
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
	if !nb.Charge() || !nb.Open() || nb.Remaining() != -1 {
		t.Error("nil budget must allow and report unlimited")
	}
}

func TestDailyBudget_CapAndDailyReset(t *testing.T) {
	t.Parallel()
	day1 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	b := NewDailyBudget(2)
	b.now = func() time.Time { return day1 }

	if !b.Charge() {
		t.Fatal("first charge must fit cap 2")
	}
	if !b.Charge() {
		t.Fatal("second charge must fit cap 2")
	}
	if b.Charge() {
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
	if !b.Open() || !b.Charge() {
		t.Error("budget must reopen on a new UTC day")
	}
}

func TestDailyBudget_RefundSameDayOnly(t *testing.T) {
	t.Parallel()
	day1 := time.Date(2026, 6, 17, 10, 0, 0, 0, time.UTC)
	b := NewDailyBudget(2)
	b.now = func() time.Time { return day1 }

	if !b.Charge() || b.Remaining() != 1 {
		t.Fatalf("initial charge failed or remaining = %d, want 1", b.Remaining())
	}
	b.Refund()
	if b.Remaining() != 2 {
		t.Fatalf("refund remaining = %d, want 2", b.Remaining())
	}

	if !b.Charge() {
		t.Fatal("second charge failed")
	}
	b.now = func() time.Time { return day1.Add(24 * time.Hour) }
	b.Refund()
	if b.Remaining() != 2 {
		t.Fatalf("cross-day refund must not affect new day, remaining = %d", b.Remaining())
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

func createLiveSession(t *testing.T, ts string, code string) string {
	t.Helper()
	resp := postJSON(t, ts+RouteSession, createReq{Code: code})
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
	token := createLiveSession(t, ts.URL, "good")

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
	healthResp, err := http.DefaultClient.Do(req)
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

func TestServer_PerSessionMessageCap(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy per session")
	}
	ts := newTestServer(t, ServerConfig{MaxMessagesPerSession: 1})
	token := createLiveSession(t, ts.URL, "good")

	if st := sendLiveMessage(t, ts.URL, token, "hello"); st != http.StatusAccepted {
		t.Fatalf("first message status = %d, want 202", st)
	}
	// This session has used its one-message budget.
	if st := sendLiveMessage(t, ts.URL, token, "again"); st != http.StatusTooManyRequests {
		t.Errorf("over-cap message status = %d, want 429", st)
	}
}
